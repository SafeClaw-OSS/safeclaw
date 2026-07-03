//! In-memory approval state.
//!
//! When a brokered request through the credential proxy needs human approval,
//! an `ApprovalRecord` is created. The user approves it via the passkey-gated
//! op ceremony, which validates a passkey-signed grant and caches the
//! authorization. The agent's retry then resolves against that cached grant
//! and the record is consumed.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use uuid::Uuid;

use crate::protocol::operation::Operation;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected { reason: String },
    Consumed,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub id: String,
    pub vault_id: String,
    pub op: Operation,
    /// Challenge `r` issued by the custodian when this op was created. Returned
    /// to U via `GET /op/{op_id}` so U can compute β = H(domain ‖ r ‖ H(o))
    /// for the grant. Validated against the challenge store on
    /// `POST /op/{op_id}/approve`.
    pub r: String,
    pub status: ApprovalStatus,
    /// Cached plaintext result (e.g. for reveal). Available once status=Approved.
    pub cached_value: Option<String>,
    pub created_at: Instant,
    /// Wall-clock unix seconds when this op expires. Exposed verbatim in
    /// `GET /op/{op_id}` responses so the UI can render a countdown.
    pub expires_at_unix: u64,
    pub ttl: Duration,
    /// Number of failed `POST /op/{id}/approve` attempts (passkey verify
    /// failed, wrong grant, etc.). Auto-rejects the op at MAX_APPROVE_ATTEMPTS
    /// to prevent brute-force on expensive crypto operations.
    pub fail_count: u32,
    /// Policy decision context captured when the op was created. Used by
    /// approve.rs to write into the rule-approvals cache after a
    /// successful Use op — so the `ask`-with-TTL semantic kicks in on the
    /// next matching request. Daemon-internal: never appears on the wire,
    /// never signed into the grant.
    pub policy_context: Option<PolicyContext>,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// The decision level when this op was created. `Ask` is the only
    /// value that drives cache writes; we keep the others for audit /
    /// debug. `AskAlways` is explicitly excluded — that's the whole
    /// point of the level.
    pub level: crate::core::policy::AccessLevel,
    /// Matched rule id from `evaluate_with_match`. `None` =
    /// category / global default fired — which is **not** cached (a grant
    /// needs a rule's path scope to bound it; see `record_ask_approval`).
    pub rule_id: Option<String>,
    /// TTL in seconds the approval should remain cached. Threaded from
    /// the matched rule's `ttl`, the service / category default's
    /// `ask_ttl`, or `Policy.timeout` as last resort.
    pub ttl_seconds: u64,
    /// Resolved destination host of the request that created this op. The
    /// approval-cache key is host-scoped (an approval for host A must not
    /// authorize host B in the TTL), so the approve handler reads this when it
    /// writes `record_ask_approval`. Stamped by the proxy at op-create.
    pub host: Option<String>,
}

impl ApprovalRecord {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

/// Default TTL for a pending approval — how long the user has to walk over and
/// tap their passkey before it expires. 30 minutes.
pub const DEFAULT_TTL: Duration = Duration::from_secs(1800);

/// Suggested agent poll pacing for a pending op, surfaced as `Retry-After` and
/// `approval.interval` (the RFC 8628 / async-request-reply convention) so
/// agents don't invent their own loop cadence.
pub const POLL_INTERVAL_HINT_SECS: u64 = 3;

/// Maximum consecutive failed approve attempts before the op is auto-rejected.
/// Generous enough that a legitimate user never hits it, but blocks brute-force
/// on the computationally-expensive ECDSA verify + AEAD decrypt path.
pub const MAX_APPROVE_ATTEMPTS: u32 = 10;

#[derive(Default)]
pub struct ApprovalStore {
    inner: HashMap<String, ApprovalRecord>,
}

impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new pending approval. Returns the new approval id.
    pub fn create(&mut self, vault_id: String, op: Operation, r: String) -> String {
        self.create_with_policy(vault_id, op, r, None)
    }

    /// Same as [`create`] but stashes the policy-decision context that led
    /// to this op being created. Used by /use; ops created by other paths
    /// (export, write, lifecycle) pass `None`.
    pub fn create_with_policy(
        &mut self,
        vault_id: String,
        op: Operation,
        r: String,
        policy_context: Option<PolicyContext>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rec = ApprovalRecord {
            id: id.clone(),
            vault_id,
            op,
            r,
            status: ApprovalStatus::Pending,
            cached_value: None,
            created_at: Instant::now(),
            expires_at_unix: now_unix + DEFAULT_TTL.as_secs(),
            ttl: DEFAULT_TTL,
            policy_context,
            fail_count: 0,
        };
        self.inner.insert(id.clone(), rec);
        id
    }

    pub fn get(&self, id: &str) -> Option<&ApprovalRecord> {
        self.inner.get(id).filter(|r| !r.is_expired())
    }


    pub fn approve(&mut self, id: &str, value: Option<String>) -> Option<&ApprovalRecord> {
        if let Some(rec) = self.inner.get_mut(id) {
            if !matches!(rec.status, ApprovalStatus::Pending) || rec.is_expired() {
                return None;
            }
            rec.status = ApprovalStatus::Approved;
            rec.cached_value = value;
        }
        self.inner.get(id)
    }

    pub fn reject(&mut self, id: &str, reason: impl Into<String>) -> Option<&ApprovalRecord> {
        if let Some(rec) = self.inner.get_mut(id) {
            if !matches!(rec.status, ApprovalStatus::Pending) || rec.is_expired() {
                return None;
            }
            rec.status = ApprovalStatus::Rejected {
                reason: reason.into(),
            };
        }
        self.inner.get(id)
    }

    /// Consume an approved record. Returns the cached value if available.
    pub fn consume(&mut self, id: &str) -> Option<String> {
        let rec = self.inner.get_mut(id)?;
        if rec.is_expired() {
            return None;
        }
        if !matches!(rec.status, ApprovalStatus::Approved) {
            return None;
        }
        let v = rec.cached_value.take();
        rec.status = ApprovalStatus::Consumed;
        v
    }

    /// Increment the failure counter for `id`. If the counter reaches
    /// `MAX_APPROVE_ATTEMPTS`, auto-rejects the op and returns `true` so
    /// the caller can emit an audit event / SSE notification.
    pub fn record_failure(&mut self, id: &str) -> bool {
        if let Some(rec) = self.inner.get_mut(id) {
            rec.fail_count += 1;
            if rec.fail_count >= MAX_APPROVE_ATTEMPTS {
                rec.status = ApprovalStatus::Rejected {
                    reason: "too many failed approve attempts".into(),
                };
                return true;
            }
        }
        false
    }

    /// Drop expired and consumed records.
    pub fn cleanup(&mut self) {
        self.inner.retain(|_, r| {
            !r.is_expired() && !matches!(r.status, ApprovalStatus::Consumed)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::operation::{Act, ActType, Bind, Valid};

    fn fake_op() -> Operation {
        Operation {
            act: Act {
                kind: ActType::Export,
                target: "env.x".into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "vault1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    // Keep test fixture consistent with the new ApprovalRecord shape.
    // (no behaviour change; just satisfies the struct literal in create_approve_consume.)

    #[test]
    fn create_approve_consume() {
        let mut s = ApprovalStore::new();
        let id = s.create("vault1".into(), fake_op(), "fake_r".into());
        assert!(matches!(s.get(&id).unwrap().status, ApprovalStatus::Pending));
        s.approve(&id, Some("secret".into()));
        assert!(matches!(
            s.get(&id).unwrap().status,
            ApprovalStatus::Approved
        ));
        let v = s.consume(&id);
        assert_eq!(v.as_deref(), Some("secret"));
        assert!(matches!(
            s.get(&id).unwrap().status,
            ApprovalStatus::Consumed
        ));
        // Second consume returns None (already consumed).
        assert!(s.consume(&id).is_none());
    }

    #[test]
    fn reject_blocks_consume() {
        let mut s = ApprovalStore::new();
        let id = s.create("vault1".into(), fake_op(), "fake_r".into());
        s.reject(&id, "user denied");
        assert!(s.consume(&id).is_none());
    }
}
