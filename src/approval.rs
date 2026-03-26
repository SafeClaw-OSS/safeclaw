/// Approval manager: holds pending approval requests while the proxy waits.
///
/// Flow:
///   1. Proxy creates approval via `create_approval()` → gets (id, rx)
///   2. Proxy awaits rx with a timeout
///   3. Vault confirm/reject endpoint calls `resolve()` → sends through tx
///   4. Proxy receives result, forwards or rejects the upstream request
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::oneshot;

use crate::audit::AuditLog;

// ── Types ──────────────────────────────────────────────────────────────────────

/// Decision sent through the oneshot channel.
#[derive(Debug)]
pub enum ApprovalDecision {
    /// Approved; carries the decrypted auth config for the service (None for standard services).
    Approved(Option<serde_json::Value>),
    Rejected,
}

/// In-memory pending approval (oneshot sender + metadata).
pub struct PendingApproval {
    pub id: String,
    pub service: String,
    pub method: String,
    pub path: String,
    pub tx: oneshot::Sender<ApprovalDecision>,
    pub created_at: Instant,
    pub expires_at: Instant,
    /// Sanitised request details (headers + body preview) — in-memory only.
    pub details: Option<serde_json::Value>,
}

// ── Manager ────────────────────────────────────────────────────────────────────

pub struct ApprovalManager {
    pub pending: Mutex<HashMap<String, PendingApproval>>,
    pub audit: Arc<AuditLog>,
}

impl ApprovalManager {
    pub fn new(audit: Arc<AuditLog>) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            audit,
        }
    }

    /// Create a new pending approval.  Returns (approval_id, receiver).
    /// The caller should await the receiver (with timeout).
    pub fn create_approval(
        &self,
        service: String,
        method: String,
        path: String,
        timeout_secs: u64,
        details: Option<serde_json::Value>,
    ) -> (String, oneshot::Receiver<ApprovalDecision>) {
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let now = Instant::now();
        let expires_at = now + std::time::Duration::from_secs(timeout_secs);

        // SQLite computes expires_at via datetime('now', '+N seconds')
        let _ = self
            .audit
            .create_approval(&id, &service, &method, &path, timeout_secs);

        self.pending.lock().unwrap().insert(
            id.clone(),
            PendingApproval {
                id: id.clone(),
                service,
                method,
                path,
                tx,
                created_at: now,
                expires_at,
                details,
            },
        );

        (id, rx)
    }

    /// Resolve a pending approval (approve or reject).
    /// Returns `true` if the approval was found and signalled.
    pub fn resolve(&self, id: &str, decision: ApprovalDecision) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(approval) = pending.remove(id) {
            let status = match &decision {
                ApprovalDecision::Approved(_) => "approved",
                ApprovalDecision::Rejected => "rejected",
            };
            let _ = self.audit.update_approval(id, status);
            let _ = approval.tx.send(decision);
            true
        } else {
            false
        }
    }

    /// Remove a pending approval without signalling (used on timeout).
    pub fn remove_timed_out(&self, id: &str) {
        let mut pending = self.pending.lock().unwrap();
        pending.remove(id);
        let _ = self.audit.update_approval(id, "timed_out");
    }

    /// Snapshot of pending approval IDs (for listing in the UI).
    pub fn pending_ids(&self) -> Vec<String> {
        self.pending
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
}
