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
    /// Prefix of the agent api-key that TRIGGERED this op (op-agent binding,
    /// team §C1) — the daemon-side enforcement handle. Every agent-facing
    /// consumption surface (proxy op poll, op_grants redeem, ask-cache
    /// write/read) compares the acting key against this. The same value rides
    /// in `o.act.scope.agent` so the human's signature covers it; this copy
    /// exists so enforcement never re-parses the signed op. `None` = op not
    /// created by an agent request (ceremonies) — no agent gate applies.
    pub agent_prefix: Option<String>,
    /// Daemon-local intent key (design/approvals-inbox.md D1): set only for
    /// `use` ops minted with a PolicyContext. Never trusted from (or sent
    /// to) the wire. Ops sharing a key form one intent chain.
    pub intent_key: Option<[u8; 32]>,
    /// DISPLAY state only: the chain head that superseded this op (path-
    /// compressed — every live op of the chain points at the newest one).
    /// A superseded op stays approvable; nothing reads this for authority.
    pub superseded_by: Option<String>,
    /// Set when this op was resolved because ANOTHER op of its intent chain
    /// applied (approved, no value of its own) — the poll mirrors the applied
    /// op's body plus this pointer.
    pub satisfied_by: Option<String>,
    /// Attempt number within the intent chain (1 = first ask).
    pub retry_count: u32,
    /// SHA-256 of the Export waiter secret (E1). The plaintext value is
    /// released only to a poll presenting the secret. `None` for every
    /// non-Export op.
    pub waiter_hash: Option<[u8; 32]>,
    /// Last poll that presented the valid waiter secret (create time until
    /// the first one). Drives the liveness backstop for abandoned Exports.
    pub last_waiter_poll: Instant,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// The decision level when this op was created. `Ask` is the only
    /// value that drives cache writes; we keep the others for audit /
    /// debug. `AskAlways` is explicitly excluded — that's the whole
    /// point of the level.
    pub level: crate::core::policy::AccessLevel,
    /// What decided the request (`evaluate_decision`): the matched rule
    /// (id + label) or a default floor. Picks the ledger unit an `ask`
    /// approval reuses by (`crate::approval::Reuse`).
    pub decided_by: crate::core::policy::DecidedBy,
    /// TTL in seconds the approval should remain cached. Threaded from
    /// the matched rule's `ttl`, the service / tag default's
    /// `ask_ttl`, or `Policy.timeout` as last resort.
    pub ttl_seconds: u64,
    /// Resolved destination host of the request that created this op. The
    /// ask-grant ledger is host-scoped (an approval for host A must not
    /// authorize host B in the TTL), so the approve handler reads this when it
    /// writes `record_ask_grant`. Stamped by the proxy at op-create.
    pub host: Option<String>,
}

impl ApprovalRecord {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }

    fn is_live(&self) -> bool {
        matches!(self.status, ApprovalStatus::Pending) && !self.is_expired()
    }

    /// Does `secret` match this op's waiter secret? Constant-time over the
    /// SHA-256 digests. An op without a waiter secret matches nothing.
    pub fn waiter_matches(&self, secret: Option<&str>) -> bool {
        match (&self.waiter_hash, secret) {
            (Some(h), Some(s)) => crate::crypto::binding::constant_time_eq(&waiter_digest(s), h),
            _ => false,
        }
    }
}

/// Domain tag for [`intent_key`]. ASCII, directly concatenated with the JCS
/// bytes (no separator) — the key is daemon-local and never on the wire.
pub const INTENT_TAG: &[u8] = b"safeclaw/v1/intent";

/// The intent key of a `use` op (design/approvals-inbox.md D1):
/// SHA-256(INTENT_TAG ‖ JCS({redeemer, recipient, act, level, ttl})).
/// `r` and `valid.*` are excluded, so byte-identical retries of one request
/// collide; the PolicyContext level + ttl are included so ops minted under
/// different policy never merge. `None` for any other kind, or when the op
/// can't be canonicalized (floats) — such an op simply never chains.
pub fn intent_key(op: &Operation, pc: &PolicyContext) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    if op.act.kind != crate::protocol::operation::ActType::Use {
        return None;
    }
    let v = serde_json::json!({
        "redeemer": op.bind.redeemer,
        "recipient": op.bind.recipient,
        "act": op.act,
        "level": pc.level.to_string(),
        "ttl": pc.ttl_seconds,
    });
    let bytes = sudp::canonical::canonicalize_strict(&v).ok()?;
    let mut h = Sha256::new();
    h.update(INTENT_TAG);
    h.update(&bytes);
    Some(h.finalize().into())
}

/// SHA-256 of an Export waiter secret — the only form the daemon keeps.
pub fn waiter_digest(secret: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(secret.as_bytes()).into()
}

/// What a chained create did: the new op, and the live ops it superseded
/// (the relay register's `supersedes`).
#[derive(Debug, Clone)]
pub struct ChainedCreate {
    pub id: String,
    pub expires_at_unix: u64,
    pub supersedes: Vec<String>,
    pub retry_count: u32,
}

/// Ops resolved alongside an apply / user reject in the same intent chain.
#[derive(Debug, Clone)]
pub struct ChainSibling {
    pub id: String,
    pub vault_id: String,
}

/// Default TTL for a pending approval — how long the user has to walk over and
/// tap their passkey before it expires. 30 minutes.
pub const DEFAULT_TTL: Duration = Duration::from_secs(1800);

/// Absolute ceiling on a record's lifetime, however generous the op's own
/// window: bounds zombie waiters if a caller mints a huge exp. User-tuned
/// approval windows (aux.policy.timeout) pass through untouched below this
/// — the old cap at DEFAULT_TTL silently clipped them, advertising a grant
/// window the record couldn't honor.
pub const MAX_TTL: Duration = Duration::from_secs(86_400);

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
        self.create_bound(vault_id, op, r, None, None)
    }

    /// Same as [`create`] but stashes the policy-decision context that led
    /// to this op being created.
    pub fn create_with_policy(
        &mut self,
        vault_id: String,
        op: Operation,
        r: String,
        policy_context: Option<PolicyContext>,
    ) -> String {
        self.create_bound(vault_id, op, r, policy_context, None)
    }

    /// Full-fat create: policy context + the triggering agent's key prefix
    /// (op-agent binding). Used by the broker paths; ceremonies (export,
    /// write, lifecycle) have no agent and pass `None`.
    pub fn create_bound(
        &mut self,
        vault_id: String,
        op: Operation,
        r: String,
        policy_context: Option<PolicyContext>,
        agent_prefix: Option<String>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The record's lifetime tracks the op's own Valid window (capped by
        // MAX_TTL): a pending record that outlives its op advertises an
        // `expires_at` no passkey tap can meet — a waiter would spin on a
        // zombie. Ops without an exp keep the default ceiling.
        let ttl_secs = op
            .valid
            .exp
            .map(|e| e.saturating_sub(now_unix))
            .filter(|&s| s > 0)
            .map(|s| s.min(MAX_TTL.as_secs()))
            .unwrap_or(DEFAULT_TTL.as_secs());
        let rec = ApprovalRecord {
            id: id.clone(),
            vault_id,
            op,
            r,
            status: ApprovalStatus::Pending,
            cached_value: None,
            created_at: Instant::now(),
            expires_at_unix: now_unix + ttl_secs,
            ttl: Duration::from_secs(ttl_secs),
            policy_context,
            agent_prefix,
            fail_count: 0,
            intent_key: None,
            superseded_by: None,
            satisfied_by: None,
            retry_count: 1,
            waiter_hash: None,
            last_waiter_poll: Instant::now(),
        };
        self.inner.insert(id.clone(), rec);
        id
    }

    /// [`create_bound`] plus the intent chain (design/approvals-inbox.md D1),
    /// in ONE store mutation: a `use` op with a PolicyContext gets its intent
    /// key; every LIVE op with the same key (same vault) is marked
    /// `superseded_by = <new id>` (path-compressed onto the new head) and the
    /// new op inherits `retry_count = max + 1`. Display state only — the
    /// superseded ops stay approvable. Every other op is created exactly as
    /// [`create_bound`] does.
    pub fn create_chained(
        &mut self,
        vault_id: String,
        op: Operation,
        r: String,
        policy_context: Option<PolicyContext>,
        agent_prefix: Option<String>,
    ) -> ChainedCreate {
        let key = policy_context.as_ref().and_then(|pc| intent_key(&op, pc));
        let mut supersedes = Vec::new();
        let mut max_retry = 0u32;
        if let Some(k) = key {
            for rec in self.inner.values() {
                if rec.intent_key == Some(k) && rec.vault_id == vault_id && rec.is_live() {
                    supersedes.push(rec.id.clone());
                    max_retry = max_retry.max(rec.retry_count);
                }
            }
        }
        let id = self.create_bound(vault_id, op, r, policy_context, agent_prefix);
        let retry_count = max_retry + 1;
        if let Some(rec) = self.inner.get_mut(&id) {
            rec.intent_key = key;
            rec.retry_count = retry_count;
        }
        for sid in &supersedes {
            if let Some(rec) = self.inner.get_mut(sid) {
                rec.superseded_by = Some(id.clone());
            }
        }
        supersedes.sort();
        let expires_at_unix = self.inner.get(&id).map(|r| r.expires_at_unix).unwrap_or(0);
        ChainedCreate {
            id,
            expires_at_unix,
            supersedes,
            retry_count,
        }
    }

    /// Attach an Export waiter secret (stored as its SHA-256 only). Resets the
    /// liveness clock.
    pub fn set_waiter(&mut self, id: &str, secret: &str) {
        if let Some(rec) = self.inner.get_mut(id) {
            rec.waiter_hash = Some(waiter_digest(secret));
            rec.last_waiter_poll = Instant::now();
        }
    }

    /// Record a poll that presented the valid waiter secret.
    pub fn touch_waiter(&mut self, id: &str) {
        if let Some(rec) = self.inner.get_mut(id) {
            rec.last_waiter_poll = Instant::now();
        }
    }

    /// Approve `id` and, under the SAME store borrow (one `approvals` mutex
    /// acquisition at the caller), resolve every other live op of its intent
    /// chain as approved with `satisfied_by = id` and the applied op's value
    /// (a `use` caches none). Returns `None` when `id` is no longer pending.
    pub fn approve_chain(
        &mut self,
        id: &str,
        value: Option<String>,
    ) -> Option<(ApprovalRecord, Vec<ChainSibling>)> {
        let applied = self.approve(id, value.clone())?.clone();
        let mut siblings = Vec::new();
        if let Some(k) = applied.intent_key {
            for rec in self.inner.values_mut() {
                if rec.id != applied.id
                    && rec.intent_key == Some(k)
                    && rec.vault_id == applied.vault_id
                    && rec.is_live()
                {
                    rec.status = ApprovalStatus::Approved;
                    rec.cached_value = value.clone();
                    rec.satisfied_by = Some(applied.id.clone());
                    siblings.push(ChainSibling {
                        id: rec.id.clone(),
                        vault_id: rec.vault_id.clone(),
                    });
                }
            }
        }
        Some((applied, siblings))
    }

    /// Reject `id`; when `propagate` (a USER rejection), every other live op
    /// of its intent chain resolves rejected with the same reason under the
    /// same store borrow. Returns `None` when `id` is no longer pending.
    pub fn reject_chain(
        &mut self,
        id: &str,
        reason: &str,
        propagate: bool,
    ) -> Option<(ApprovalRecord, Vec<ChainSibling>)> {
        let rejected = self.reject(id, reason)?.clone();
        let mut siblings = Vec::new();
        if let (true, Some(k)) = (propagate, rejected.intent_key) {
            for rec in self.inner.values_mut() {
                if rec.id != rejected.id
                    && rec.intent_key == Some(k)
                    && rec.vault_id == rejected.vault_id
                    && rec.is_live()
                {
                    rec.status = ApprovalStatus::Rejected {
                        reason: reason.to_string(),
                    };
                    siblings.push(ChainSibling {
                        id: rec.id.clone(),
                        vault_id: rec.vault_id.clone(),
                    });
                }
            }
        }
        Some((rejected, siblings))
    }

    /// Pending Exports whose waiter has not polled within `idle` (the E1
    /// liveness backstop). Returns `(id, vault_id)` pairs; the caller
    /// withdraws them.
    pub fn abandoned_exports(&self, idle: Duration) -> Vec<(String, String)> {
        self.inner
            .values()
            .filter(|r| {
                r.is_live()
                    && r.op.act.kind == crate::protocol::operation::ActType::Export
                    && r.waiter_hash.is_some()
                    && r.last_waiter_poll.elapsed() >= idle
            })
            .map(|r| (r.id.clone(), r.vault_id.clone()))
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<&ApprovalRecord> {
        self.inner.get(id).filter(|r| !r.is_expired())
    }

    /// Raw lookup — ANY status, expiry IGNORED. Exists for exactly one
    /// caller: the batch-approve sibling rebuild (design/batch-approve.md
    /// §Daemon verify 3). Batch rows arrive and apply at independent times,
    /// so by row k the earlier siblings are already Approved/Consumed and a
    /// short-TTL sibling may have expired — a signed β is immutable and each
    /// sibling's own application is separately gated by its own pending
    /// check, so only a genuinely ABSENT record may fail the rebuild. Never
    /// use this for approval decisions.
    pub fn get_any(&self, id: &str) -> Option<&ApprovalRecord> {
        self.inner.get(id)
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

    /// Test seam: mutable record access (backdating clocks, etc.).
    #[cfg(test)]
    pub fn get_mut_for_test(&mut self, id: &str) -> Option<&mut ApprovalRecord> {
        self.inner.get_mut(id)
    }

    /// Drop expired and consumed records.
    pub fn cleanup(&mut self) {
        self.inner
            .retain(|_, r| !r.is_expired() && !matches!(r.status, ApprovalStatus::Consumed));
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
        assert!(matches!(
            s.get(&id).unwrap().status,
            ApprovalStatus::Pending
        ));
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
        s.reject(&id, "user rejected");
        assert!(s.consume(&id).is_none());
    }

    // ── intent chains (design/approvals-inbox.md D1) ────────────────────────

    fn use_op(path: &str, vault: &str) -> Operation {
        Operation {
            act: Act {
                kind: ActType::Use,
                target: "GITHUB_TOKEN".into(),
                scope: serde_json::json!({
                    "connection_id": "github",
                    "service": "github",
                    "host": "api.github.com",
                    "method": "GET",
                    "path": path,
                    "authorize_only": true,
                    "agent": "ag_test",
                    "level": "ask",
                    "window_s": 900,
                }),
            },
            bind: Bind {
                redeemer: vault.into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    fn pc(level: crate::core::policy::AccessLevel, ttl: u64) -> PolicyContext {
        PolicyContext {
            level,
            decided_by: crate::core::policy::DecidedBy::Rule {
                id: Some("r1".into()),
                label: None,
            },
            ttl_seconds: ttl,
            host: Some("api.github.com".into()),
        }
    }

    fn ask() -> PolicyContext {
        pc(crate::core::policy::AccessLevel::Ask, 900)
    }

    /// Pins the intent-key DEFINITION: tag directly concatenated (no
    /// separator) with the JCS of exactly {act, level, recipient, redeemer,
    /// ttl}. A drift in field set, naming or encoding breaks this vector.
    #[test]
    fn intent_key_fixture() {
        use sha2::{Digest, Sha256};
        let op = use_op("/user", "v1");
        let jcs = concat!(
            r#"{"act":{"scope":{"agent":"ag_test","authorize_only":true,"connection_id":"github","#,
            r#""host":"api.github.com","level":"ask","method":"GET","path":"/user","service":"github","#,
            r#""window_s":900},"target":"GITHUB_TOKEN","type":"use"},"level":"ask","recipient":null,"#,
            r#""redeemer":"v1","ttl":900}"#
        );
        let mut h = Sha256::new();
        h.update(b"safeclaw/v1/intent");
        h.update(jcs.as_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(intent_key(&op, &ask()), Some(expected));
    }

    #[test]
    fn intent_key_retries_collide_policy_and_request_separate() {
        use crate::core::policy::AccessLevel;
        let a = use_op("/user", "v1");
        // A retry differs only in `valid` (and `r`, which is not an input).
        let mut retry = use_op("/user", "v1");
        retry.valid = Valid::single_use(1_700_000_000, Some(1_700_000_300));
        assert_eq!(intent_key(&a, &ask()), intent_key(&retry, &ask()));
        assert!(intent_key(&a, &ask()).is_some());

        // Different policy level or ttl → different chain.
        assert_ne!(
            intent_key(&a, &ask()),
            intent_key(&a, &pc(AccessLevel::AskAlways, 900))
        );
        assert_ne!(
            intent_key(&a, &ask()),
            intent_key(&a, &pc(AccessLevel::Ask, 300))
        );
        // Different request or vault → different chain.
        assert_ne!(
            intent_key(&a, &ask()),
            intent_key(&use_op("/repos", "v1"), &ask())
        );
        assert_ne!(
            intent_key(&a, &ask()),
            intent_key(&use_op("/user", "v2"), &ask())
        );
        // Only `use` chains.
        assert_eq!(intent_key(&fake_op(), &ask()), None);
    }

    #[test]
    fn create_chained_supersedes_live_same_key_ops_display_only() {
        let mut s = ApprovalStore::new();
        let a = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "ra".into(),
            Some(ask()),
            None,
        );
        assert_eq!(a.retry_count, 1);
        assert!(a.supersedes.is_empty());

        let b = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rb".into(),
            Some(ask()),
            None,
        );
        assert_eq!(b.retry_count, 2);
        assert_eq!(b.supersedes, vec![a.id.clone()]);
        assert_eq!(
            s.get(&a.id).unwrap().superseded_by.as_deref(),
            Some(b.id.as_str())
        );

        // Path compression: C re-points BOTH A and B at itself.
        let c = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rc".into(),
            Some(ask()),
            None,
        );
        assert_eq!(c.retry_count, 3);
        let mut want = vec![a.id.clone(), b.id.clone()];
        want.sort();
        assert_eq!(c.supersedes, want);
        for id in [&a.id, &b.id] {
            assert_eq!(
                s.get(id).unwrap().superseded_by.as_deref(),
                Some(c.id.as_str())
            );
        }
        assert!(s.get(&c.id).unwrap().superseded_by.is_none());

        // Unrelated request / other vault / no policy context: no chain.
        let other = s.create_chained(
            "v1".into(),
            use_op("/repos", "v1"),
            "r".into(),
            Some(ask()),
            None,
        );
        assert!(other.supersedes.is_empty());
        let v2 = s.create_chained(
            "v2".into(),
            use_op("/user", "v2"),
            "r".into(),
            Some(ask()),
            None,
        );
        assert!(v2.supersedes.is_empty());
        let no_pc = s.create_chained("v1".into(), use_op("/user", "v1"), "r".into(), None, None);
        assert!(no_pc.supersedes.is_empty());
        assert_eq!(no_pc.retry_count, 1);

        // Superseded stays approvable (display state, not authority).
        assert!(matches!(
            s.get(&a.id).unwrap().status,
            ApprovalStatus::Pending
        ));
        assert!(s.approve(&a.id, None).is_some());
    }

    #[test]
    fn create_chained_skips_resolved_ops() {
        let mut s = ApprovalStore::new();
        let a = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "ra".into(),
            Some(ask()),
            None,
        );
        s.approve(&a.id, None);
        // A applied: the agent's later genuine second execution is a FRESH chain.
        let b = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rb".into(),
            Some(ask()),
            None,
        );
        assert!(b.supersedes.is_empty());
        assert_eq!(b.retry_count, 1);
        assert!(s.get(&a.id).unwrap().superseded_by.is_none());
    }

    #[test]
    fn approve_chain_satisfies_live_siblings_only() {
        let mut s = ApprovalStore::new();
        let a = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "ra".into(),
            Some(ask()),
            None,
        );
        let b = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rb".into(),
            Some(ask()),
            None,
        );
        let c = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rc".into(),
            Some(ask()),
            None,
        );
        let unrelated = s.create_chained(
            "v1".into(),
            use_op("/repos", "v1"),
            "r".into(),
            Some(ask()),
            None,
        );
        // An already-rejected sibling is not live: untouched.
        s.reject(&b.id, "user rejected");

        // Approving the SUPERSEDED op A applies it and resolves the chain.
        let (applied, sibs) = s.approve_chain(&a.id, None).unwrap();
        assert_eq!(applied.id, a.id);
        let ids: Vec<_> = sibs.iter().map(|x| x.id.clone()).collect();
        assert_eq!(ids, vec![c.id.clone()]);
        let rc = s.get(&c.id).unwrap();
        assert!(matches!(rc.status, ApprovalStatus::Approved));
        assert_eq!(rc.satisfied_by.as_deref(), Some(a.id.as_str()));
        assert!(rc.cached_value.is_none(), "a use sibling carries no value");
        assert!(s.get(&a.id).unwrap().satisfied_by.is_none());
        assert!(matches!(
            s.get(&b.id).unwrap().status,
            ApprovalStatus::Rejected { .. }
        ));
        assert!(matches!(
            s.get(&unrelated.id).unwrap().status,
            ApprovalStatus::Pending
        ));

        // A second grant for the chain finds nothing pending.
        assert!(s.approve_chain(&c.id, None).is_none());
    }

    #[test]
    fn reject_chain_propagates_only_user_rejections() {
        let mut s = ApprovalStore::new();
        let a = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "ra".into(),
            Some(ask()),
            None,
        );
        let b = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rb".into(),
            Some(ask()),
            None,
        );
        // An apply failure (propagate=false) is about THIS grant only.
        let (_, sibs) = s
            .reject_chain(&b.id, "approved, but applying it failed: x", false)
            .unwrap();
        assert!(sibs.is_empty());
        assert!(matches!(
            s.get(&a.id).unwrap().status,
            ApprovalStatus::Pending
        ));

        let c = s.create_chained(
            "v1".into(),
            use_op("/user", "v1"),
            "rc".into(),
            Some(ask()),
            None,
        );
        let (_, sibs) = s.reject_chain(&c.id, "user rejected", true).unwrap();
        assert_eq!(sibs.len(), 1);
        assert_eq!(sibs[0].id, a.id);
        match &s.get(&a.id).unwrap().status {
            ApprovalStatus::Rejected { reason } => assert_eq!(reason, "user rejected"),
            other => panic!("sibling must be rejected, got {:?}", other),
        }
    }

    #[test]
    fn waiter_secret_hash_match_and_idle_detection() {
        let mut s = ApprovalStore::new();
        let id = s.create("v1".into(), fake_op(), "r".into());
        assert!(!s.get(&id).unwrap().waiter_matches(Some("anything")));
        s.set_waiter(&id, "sekret");
        let rec = s.get(&id).unwrap();
        assert_eq!(rec.waiter_hash, Some(waiter_digest("sekret")));
        assert!(rec.waiter_matches(Some("sekret")));
        assert!(!rec.waiter_matches(Some("sekreT")));
        assert!(!rec.waiter_matches(None));

        assert!(s.abandoned_exports(Duration::from_secs(60)).is_empty());
        s.get_mut_for_test(&id).unwrap().last_waiter_poll =
            Instant::now() - Duration::from_secs(61);
        assert_eq!(
            s.abandoned_exports(Duration::from_secs(60)),
            vec![(id.clone(), "v1".to_string())]
        );
        // A poll with the secret refreshes liveness.
        s.touch_waiter(&id);
        assert!(s.abandoned_exports(Duration::from_secs(60)).is_empty());
        // Resolved exports are never reaped.
        s.get_mut_for_test(&id).unwrap().last_waiter_poll =
            Instant::now() - Duration::from_secs(61);
        s.approve(&id, Some("v".into()));
        assert!(s.abandoned_exports(Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn record_ttl_follows_op_valid_window() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // A bounded op: the record expires with the op, not at the default.
        let mut op = fake_op();
        op.valid = Valid::single_use(now, Some(now + 120));
        let mut s = ApprovalStore::new();
        let id = s.create("vault1".into(), op, "r".into());
        let rec = s.get(&id).unwrap();
        assert!(rec.ttl <= Duration::from_secs(120));
        assert!(rec.ttl >= Duration::from_secs(118)); // clock-tick slack
        assert!(rec.expires_at_unix <= now + 121);

        // No exp (fake_op default) keeps the default ceiling.
        let id2 = s.create("vault1".into(), fake_op(), "r".into());
        assert_eq!(s.get(&id2).unwrap().ttl, DEFAULT_TTL);

        // A user-widened window (aux.policy.timeout > default) passes
        // through — only the MAX_TTL ceiling clips. (Was: silently clipped
        // to DEFAULT_TTL — the grant page then promised a window the record
        // wouldn't honor.)
        let mut wide = fake_op();
        wide.valid = Valid::single_use(now, Some(now + 7200));
        let id3 = s.create("vault1".into(), wide, "r".into());
        let rec3 = s.get(&id3).unwrap();
        assert!(rec3.ttl > Duration::from_secs(7100));
        assert!(rec3.ttl <= Duration::from_secs(7200));
    }
}
