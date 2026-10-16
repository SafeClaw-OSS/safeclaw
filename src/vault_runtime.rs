//! All process-local state owned by one vault.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use zeroize::Zeroizing;

use crate::audit::AuditStore;
use crate::state::{AppState, ApprovalEvent, SyncNote, VaultState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TombstoneReason {
    Removed,
    Deleted,
    DeviceRevoked,
}

impl TombstoneReason {
    pub fn merge(self, newer: Self) -> Self {
        use TombstoneReason::*;
        match (self, newer) {
            (DeviceRevoked, _) | (_, DeviceRevoked) => DeviceRevoked,
            (Deleted, _) | (_, Deleted) => Deleted,
            _ => Removed,
        }
    }

    pub fn rejection_reason(self) -> &'static str {
        match self {
            Self::Removed => {
                "this device can no longer use this vault: your account was removed from it"
            }
            Self::Deleted => "This vault was deleted.",
            Self::DeviceRevoked => crate::error::LEDGER_DEVICE_REVOKED_MSG,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gone_reason_projects_to_the_specific_agent_refusal() {
        assert!(matches!(
            VaultGone {
                reason: TombstoneReason::Removed,
            }
            .app_error(),
            crate::error::AppError::VaultAccessRevoked
        ));
        let deleted = VaultGone {
            reason: TombstoneReason::Deleted,
        }
        .app_error();
        assert!(matches!(&deleted, crate::error::AppError::VaultDeleted));
        assert_eq!(deleted.code().0, crate::error::ScCode::VaultDeleted);
        assert_eq!(deleted.code().1, "This vault was deleted.");
        assert!(matches!(
            VaultGone {
                reason: TombstoneReason::DeviceRevoked,
            }
            .app_error(),
            crate::error::AppError::LedgerDeviceRevoked
        ));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    pub reason: TombstoneReason,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultGone {
    pub reason: TombstoneReason,
}

impl VaultGone {
    pub fn app_error(self) -> crate::error::AppError {
        match self.reason {
            TombstoneReason::Removed => crate::error::AppError::VaultAccessRevoked,
            TombstoneReason::Deleted => crate::error::AppError::VaultDeleted,
            TombstoneReason::DeviceRevoked => crate::error::AppError::LedgerDeviceRevoked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeClosed;

pub struct VaultWriteGuard {
    _runtime: Arc<VaultRuntime>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

/// A vault's complete in-memory lifetime. Once `closed` is set, existing
/// holders may finish reading but no writer may enter and no new holder can be
/// obtained from `AppState`.
pub struct VaultRuntime {
    pub vault_id: String,
    pub state: Mutex<VaultState>,
    pub cloud_contact: Mutex<Option<Instant>>,
    pub shared: Mutex<Option<bool>>,
    pub upgrade_required: AtomicBool,
    pub key_changed: AtomicBool,
    pub sync_conflicts: Mutex<BTreeMap<String, SyncNote>>,
    pub catch_up_failure: Mutex<Option<String>>,
    pub pending_rotations: Mutex<BTreeMap<(String, String), Zeroizing<String>>>,
    pub pending_format_mark: AtomicBool,
    pub pending_config_ids: Mutex<Vec<String>>,
    pub oauth_reauth_needed: Mutex<HashSet<String>>,
    pub live_ceremony_ops: Mutex<HashMap<String, String>>,
    pub write_lock: Arc<tokio::sync::Mutex<()>>,
    pub watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub watcher_cell: Mutex<Option<Arc<crate::sync_stream::WakeCell>>>,
    pub access_probe: AtomicBool,
    pub sse_semaphore: Arc<tokio::sync::Semaphore>,
    pub last_host_union: Mutex<Vec<String>>,
    pub audit: Mutex<Option<Arc<AuditStore>>>,
    closed: AtomicBool,
}

impl VaultRuntime {
    pub fn new(vault_id: String, hosts: Vec<String>) -> Self {
        Self {
            vault_id,
            state: Mutex::new(VaultState::Locked),
            cloud_contact: Mutex::new(None),
            shared: Mutex::new(None),
            upgrade_required: AtomicBool::new(false),
            key_changed: AtomicBool::new(false),
            sync_conflicts: Mutex::new(BTreeMap::new()),
            catch_up_failure: Mutex::new(None),
            pending_rotations: Mutex::new(BTreeMap::new()),
            pending_format_mark: AtomicBool::new(false),
            pending_config_ids: Mutex::new(Vec::new()),
            oauth_reauth_needed: Mutex::new(HashSet::new()),
            live_ceremony_ops: Mutex::new(HashMap::new()),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            watcher: Mutex::new(None),
            watcher_cell: Mutex::new(None),
            access_probe: AtomicBool::new(false),
            sse_semaphore: Arc::new(tokio::sync::Semaphore::new(
                crate::server::handlers::events::MAX_SSE_PER_VAULT,
            )),
            last_host_union: Mutex::new(hosts),
            audit: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn write_guard(self: &Arc<Self>) -> Result<VaultWriteGuard, RuntimeClosed> {
        let guard = self.write_lock.clone().lock_owned().await;
        if self.is_closed() {
            return Err(RuntimeClosed);
        }
        Ok(VaultWriteGuard {
            _runtime: self.clone(),
            _guard: guard,
        })
    }

    pub(crate) fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub async fn close(&self, state: &AppState, reason: TombstoneReason) {
        self.mark_closed();
        if let Some(cell) = self.watcher_cell.lock().unwrap().take() {
            cell.set_mode(crate::sync_stream::Mode::Fallback);
        }
        let watcher = self.watcher.lock().unwrap().take();
        if let Some(handle) = watcher {
            handle.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        }
        self.sse_semaphore.close();
        self.access_probe.store(false, Ordering::Release);

        let rejection = reason.rejection_reason();
        let rejected = state
            .approvals
            .lock()
            .unwrap()
            .reject_vault(&self.vault_id, rejection);
        for approval_id in rejected {
            let _ = state.events.send(ApprovalEvent {
                vault_id: self.vault_id.clone(),
                approval_id,
                kind: "rejected".into(),
                op_summary: None,
                response_preview: None,
                reason: Some(rejection.into()),
            });
        }
        state
            .oauth_pending
            .lock()
            .unwrap()
            .retain(|_, pending| pending.vault_id != self.vault_id);

        // A writer which entered before close may finish; taking the same lock
        // makes dropping K and the audit fd the final local action.
        let _write = self.write_lock.lock().await;
        *self.state.lock().unwrap() = VaultState::Locked;
        self.audit.lock().unwrap().take();
    }
}
