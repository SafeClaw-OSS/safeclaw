//! In-memory approval state.
//!
//! When the agent calls `:23295/env/<key>` and the daemon decides
//! human approval is required, an `ApprovalRecord` is created. The user
//! approves it via `/approve/{id}/confirm`, which validates a passkey-signed
//! grant and caches the resulting plaintext value. The agent's next poll
//! retrieves the cached value and the record is consumed.

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
    pub tenant_id: String,
    pub op: Operation,
    pub status: ApprovalStatus,
    /// Cached plaintext result (e.g. for reveal). Available once status=Approved.
    pub cached_value: Option<String>,
    pub created_at: Instant,
    /// Wall-clock unix seconds when this approval expires. Exposed verbatim
    /// in /approve/:id responses so the UI can render a countdown without a
    /// pro-side mapping table (replaces the old supabase.approvals TTL).
    pub expires_at_unix: u64,
    pub ttl: Duration,
}

impl ApprovalRecord {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

/// Default TTL for approvals. Demo v0 = 5 minutes.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct ApprovalStore {
    inner: HashMap<String, ApprovalRecord>,
}

impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new pending approval. Returns the new approval id.
    pub fn create(&mut self, tenant_id: String, op: Operation) -> String {
        let id = Uuid::new_v4().to_string();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rec = ApprovalRecord {
            id: id.clone(),
            tenant_id,
            op,
            status: ApprovalStatus::Pending,
            cached_value: None,
            created_at: Instant::now(),
            expires_at_unix: now_unix + DEFAULT_TTL.as_secs(),
            ttl: DEFAULT_TTL,
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
                redeemer: "tenant1".into(),
                recipient: None,
            },
            valid: Valid { iat: 0, exp: None },
        }
    }

    // Keep test fixture consistent with the new ApprovalRecord shape.
    // (no behaviour change; just satisfies the struct literal in create_approve_consume.)

    #[test]
    fn create_approve_consume() {
        let mut s = ApprovalStore::new();
        let id = s.create("tenant1".into(), fake_op());
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
        let id = s.create("tenant1".into(), fake_op());
        s.reject(&id, "user denied");
        assert!(s.consume(&id).is_none());
    }
}
