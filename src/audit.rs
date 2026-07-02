//! Per-vault audit log (PROTOCOL.md §5.3).
//!
//! Append-only SQLite at `<state>/vaults/<vid>/audit.db`. Records every
//! op lifecycle event — pending creation, terminal decision, cache-hit
//! auto-forward. Only operational metadata (service / method / path /
//! status / timestamps / credential_id); **no secret values, request
//! bodies, or response bodies** ever land on disk. That keeps the audit
//! file at the same trust level as a web-server access log — useful for
//! "what did my agent do" without needing SUDP-grade encryption.
//!
//! Per-vault DB (one file per vault) is the spec's isolation guarantee
//! (PROTOCOL.md §5.3 "跨 vault 永远隔离"). Connections cached lazily in
//! `AuditRegistry`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::{AppError, Result};
use crate::storage::VaultDir;

// ── Status vocabulary ────────────────────────────────────────────────────
//
// Six-state lifecycle (PROTOCOL.md §6.3). Five terminal, one transient.
//
//   pending   — ask-policy op awaiting user decision (transient)
//   allowed   — allow-policy auto-forwarded; no user gesture (terminal)
//   approved  — user approved a pending ask (terminal)
//   denied    — deny-policy auto-blocked; no user gesture (terminal)
//   rejected  — user rejected a pending ask (terminal)
//   cancelled — the REQUESTER withdrew its own pending op; no credential
//               accessed (terminal). Distinct from `rejected` (approver-side).
//   expired   — ask-policy op TTL elapsed without user action (terminal)
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_ALLOWED: &str = "allowed";
pub const STATUS_APPROVED: &str = "approved";
#[allow(dead_code)] // wired once policy auto-deny lands
pub const STATUS_DENIED: &str = "denied";
pub const STATUS_REJECTED: &str = "rejected";
/// Requester withdrew its own still-pending op (e.g. a `sc unlock` abandoned +
/// retried, the new op superseding the stale one). A NON-access outcome — no
/// credential or W_c is touched — so it is logged for transparency but never
/// reads as a security event.
pub const STATUS_CANCELLED: &str = "cancelled";
#[allow(dead_code)] // wired once op TTL sweep lands
pub const STATUS_EXPIRED: &str = "expired";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    decided_at      INTEGER,
    expires_at      INTEGER NOT NULL,
    status          TEXT NOT NULL,
    act_kind        TEXT NOT NULL,
    service         TEXT,
    method          TEXT,
    path            TEXT,
    target          TEXT,
    reason          TEXT,
    credential_id   TEXT,
    upstream_status INTEGER,
    -- De-daemon (DE_DAEMON.md §4): cloud audit-shipper outbox flag.
    -- 0 = not yet shipped to the cloud `audit_events` table; 1 = shipped.
    synced          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_approvals_status_created
    ON approvals(status, created_at DESC);
"#;

/// A single audit row. Mirrors the SQLite columns + the wire JSON shape
/// returned by `GET /v/{vid}/approvals`.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRow {
    pub id: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    pub expires_at: i64,
    pub status: String,
    pub act_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<i64>,
}

/// Derive an audit row from an `Operation` at the moment of op creation
/// (status = pending). Scope keys `service` / `method` / `path` come from
/// the broker's scope shape (set by `use_broker.rs`); other op types
/// just leave them None.
pub fn row_from_op(
    id: &str,
    op: &crate::protocol::operation::Operation,
    created_at: i64,
    expires_at: i64,
) -> ApprovalRow {
    let act_kind = crate::protocol::operation::discriminator(&op.act);
    let scope = &op.act.scope;
    let pick = |k: &str| {
        scope
            .get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    ApprovalRow {
        id: id.to_string(),
        created_at,
        decided_at: None,
        expires_at,
        status: STATUS_PENDING.into(),
        act_kind,
        service: pick("service"),
        method: pick("method"),
        path: pick("path"),
        target: if op.act.target.is_empty() {
            None
        } else {
            Some(op.act.target.clone())
        },
        reason: None,
        credential_id: None,
        upstream_status: None,
    }
}

pub struct AuditStore {
    conn: Mutex<Connection>,
}

impl AuditStore {
    fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Internal(format!("audit dir create: {}", e)))?;
        }
        let conn = Connection::open(db_path)
            .map_err(|e| AppError::Internal(format!("audit db open: {}", e)))?;
        // Reasonable defaults for a multi-threaded daemon: WAL = concurrent
        // readers don't block the writer; NORMAL sync = OS-buffered fsync
        // (we don't need stricter guarantees for an audit log).
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "synchronous", "NORMAL").ok();
        conn.execute_batch(SCHEMA)
            .map_err(|e| AppError::Internal(format!("audit schema init: {}", e)))?;
        // De-daemon: additive `synced` column for the cloud audit shipper.
        // An audit.db created before the shipper lacks it; the ALTER adds it.
        // On a fresh DB the column already exists (SCHEMA) and the
        // "duplicate column" error is intentionally ignored — idempotent.
        let _ = conn.execute(
            "ALTER TABLE approvals ADD COLUMN synced INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Outbox scan index — created here (not in SCHEMA) so it always runs
        // AFTER `synced` is guaranteed to exist on both fresh and migrated DBs.
        // Partial: indexes only the unshipped rows the shipper actually scans.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_approvals_unsynced
                 ON approvals(created_at) WHERE synced = 0;",
        )
        .map_err(|e| AppError::Internal(format!("audit unsynced index: {}", e)))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert a new row. Used both for `pending` initial create and for
    /// already-terminal entries like `allowed` (cache-hit).
    pub fn insert(&self, row: &ApprovalRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals
             (id, created_at, decided_at, expires_at, status, act_kind,
              service, method, path, target, reason, credential_id,
              upstream_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                row.id,
                row.created_at,
                row.decided_at,
                row.expires_at,
                row.status,
                row.act_kind,
                row.service,
                row.method,
                row.path,
                row.target,
                row.reason,
                row.credential_id,
                row.upstream_status,
            ],
        )
        .map_err(|e| AppError::Internal(format!("audit insert: {}", e)))?;
        Ok(())
    }

    /// F-22: Count pending rows for this vault. Used to enforce a per-vault
    /// cap on the number of concurrent pending ops so a rogue agent cannot
    /// fill the SQLite table unboundedly.
    pub fn count_pending(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE status = 'pending'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Internal(format!("audit count_pending: {}", e)))?;
        Ok(count)
    }

    /// Drop every row whose `created_at` is older than `cutoff` (unix
     /// seconds). Returns the number of deleted rows. Used for opportunistic
     /// retention cleanup — caller picks the cutoff based on the vault's
     /// `audit_retention_days` setting (None = keep forever).
    pub fn prune_older_than(&self, cutoff: i64) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute("DELETE FROM approvals WHERE created_at < ?1", params![cutoff])
            .map_err(|e| AppError::Internal(format!("audit prune: {}", e)))?;
        Ok(count as u64)
    }

    /// De-daemon outbox read (DE_DAEMON.md §4): terminal Use-op rows not yet
    /// shipped to the cloud `audit_events` table. Pending rows (transient) and
    /// control-plane ops (write/unlock/...) are out of v1 audit scope — only
    /// agent broker activity ships (a forward happened, or an ask was decided
    /// allowed/approved/denied/rejected/expired). Oldest-first so shipping
    /// preserves event order and the batch boundary is stable across ticks.
    pub fn list_unsynced(&self, limit: u32) -> Result<Vec<ApprovalRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, created_at, decided_at, expires_at, status, act_kind,
                        service, method, path, target, reason, credential_id,
                        upstream_status
                 FROM approvals
                 WHERE synced = 0 AND act_kind = 'use' AND status != 'pending'
                 ORDER BY created_at ASC
                 LIMIT ?1",
            )
            .map_err(|e| AppError::Internal(format!("audit unsynced prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(ApprovalRow {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    decided_at: row.get(2)?,
                    expires_at: row.get(3)?,
                    status: row.get(4)?,
                    act_kind: row.get(5)?,
                    service: row.get(6)?,
                    method: row.get(7)?,
                    path: row.get(8)?,
                    target: row.get(9)?,
                    reason: row.get(10)?,
                    credential_id: row.get(11)?,
                    upstream_status: row.get(12)?,
                })
            })
            .map_err(|e| AppError::Internal(format!("audit unsynced query: {}", e)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| AppError::Internal(format!("audit unsynced row: {}", e)))?);
        }
        Ok(out)
    }

    /// Mark shipped rows synced after the cloud `audit_events` upsert ACKs.
    /// Idempotent: re-marking an already-synced id is a no-op. At-least-once
    /// safe — a crash between ship and mark just re-ships (the backend upserts
    /// on `event_id`).
    pub fn mark_synced(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        for id in ids {
            conn.execute("UPDATE approvals SET synced = 1 WHERE id = ?1", params![id])
                .map_err(|e| AppError::Internal(format!("audit mark_synced: {}", e)))?;
        }
        Ok(())
    }

    /// Transition a pending row to a terminal status (approved | rejected
    /// | expired | denied). No-op if the row doesn't exist (e.g., audit
    /// was disabled when the pending was created).
    pub fn finalize(
        &self,
        id: &str,
        status: &str,
        decided_at: i64,
        credential_id: Option<&str>,
        reason: Option<&str>,
        upstream_status: Option<i64>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE approvals
             SET status=?1, decided_at=?2,
                 credential_id=COALESCE(?3, credential_id),
                 reason=COALESCE(?4, reason),
                 upstream_status=COALESCE(?5, upstream_status)
             WHERE id=?6",
            params![status, decided_at, credential_id, reason, upstream_status, id],
        )
        .map_err(|e| AppError::Internal(format!("audit finalize: {}", e)))?;
        Ok(())
    }

    /// Query rows. `status_filter = None` = all states. `since` = exclusive
    /// upper bound on `created_at` for pagination (omit on first page; set
    /// to the oldest seen `created_at` for the next page).
    pub fn list(
        &self,
        status_filter: Option<&[&str]>,
        service_filter: Option<&str>,
        since: Option<i64>,
        limit: u32,
    ) -> Result<Vec<ApprovalRow>> {
        let mut where_parts: Vec<String> = Vec::new();
        let mut bind: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(statuses) = status_filter {
            let ph: Vec<String> = (1..=statuses.len())
                .map(|i| format!("?{}", bind.len() + i))
                .collect();
            where_parts.push(format!("status IN ({})", ph.join(",")));
            for s in statuses {
                bind.push(rusqlite::types::Value::Text((*s).to_string()));
            }
        }
        if let Some(svc) = service_filter {
            where_parts.push(format!("service = ?{}", bind.len() + 1));
            bind.push(rusqlite::types::Value::Text(svc.to_string()));
        }
        if let Some(ts) = since {
            where_parts.push(format!("created_at < ?{}", bind.len() + 1));
            bind.push(rusqlite::types::Value::Integer(ts));
        }

        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", where_parts.join(" AND "))
        };
        let sql = format!(
            "SELECT id, created_at, decided_at, expires_at, status, act_kind,
                    service, method, path, target, reason, credential_id,
                    upstream_status
             FROM approvals{}
             ORDER BY created_at DESC
             LIMIT ?{}",
            where_clause,
            bind.len() + 1,
        );
        bind.push(rusqlite::types::Value::Integer(limit as i64));

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| AppError::Internal(format!("audit prepare: {}", e)))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind.iter()), |row| {
                Ok(ApprovalRow {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    decided_at: row.get(2)?,
                    expires_at: row.get(3)?,
                    status: row.get(4)?,
                    act_kind: row.get(5)?,
                    service: row.get(6)?,
                    method: row.get(7)?,
                    path: row.get(8)?,
                    target: row.get(9)?,
                    reason: row.get(10)?,
                    credential_id: row.get(11)?,
                    upstream_status: row.get(12)?,
                })
            })
            .map_err(|e| AppError::Internal(format!("audit query: {}", e)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| AppError::Internal(format!("audit row: {}", e)))?);
        }
        Ok(out)
    }

    /// Billable Use-op aggregate over `[since, until)`.
    ///
    /// **Billable** = `act_kind = 'use' AND status IN ('allowed', 'approved')`.
    /// - `allowed`: auto-passed by allow-level policy / cached secret — broker
    ///   forwarded an upstream request, charge it.
    /// - `approved`: user passkey-approved an ask-level op — broker forwarded
    ///   on approve, charge it.
    /// - `pending` / `denied` / `rejected` / `expired`: no forward happened,
    ///   don't charge.
    /// - Anything where `act_kind != 'use'` is control-plane (write/unlock/...)
    ///   — never billable.
    ///
    /// Time anchor: `COALESCE(decided_at, created_at)`. For `allowed` ops the
    /// decision is instantaneous (often unset), so `created_at` is the only
    /// time stamp available. For `approved` ops `decided_at` reflects when
    /// the forward actually fired.
    ///
    /// Returns `(total, by_service)`. Rows with `service IS NULL` are counted
    /// in `total` but skipped from `by_service`.
    pub fn aggregate_usage(
        &self,
        since: i64,
        until: i64,
    ) -> Result<(i64, std::collections::BTreeMap<String, i64>)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT service, COUNT(*) AS n
                 FROM approvals
                 WHERE act_kind = 'use'
                   AND status IN ('allowed', 'approved')
                   AND COALESCE(decided_at, created_at) >= ?1
                   AND COALESCE(decided_at, created_at) <  ?2
                 GROUP BY service",
            )
            .map_err(|e| AppError::Internal(format!("usage prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![since, until], |row| {
                let svc: Option<String> = row.get(0)?;
                let n: i64 = row.get(1)?;
                Ok((svc, n))
            })
            .map_err(|e| AppError::Internal(format!("usage query: {}", e)))?;
        let mut total: i64 = 0;
        let mut by_service: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
        for r in rows {
            let (svc, n) = r.map_err(|e| AppError::Internal(format!("usage row: {}", e)))?;
            total += n;
            if let Some(s) = svc {
                by_service.insert(s, n);
            }
        }
        Ok((total, by_service))
    }
}

/// Per-vault `AuditStore` cache. Lazy-init on first `for_vault` call —
/// no DB file exists until that vault's first op writes audit.

/// fd ceiling for simultaneously open SQLite connection handles.
/// Each WAL-mode SQLite connection uses ~3 fds; 2000 × 3 = 6000 fds,
/// well within Linux's default nofile=65536. This is a resource management
/// ceiling, not a DoS gate — the DoS gate is the vault-existence check in
/// `for_vault`. When the ceiling is hit, one cached handle is evicted (fd
/// closed, on-disk data untouched); the next access reopens the file.
const AUDIT_REGISTRY_CAP: usize = 2000;

pub struct AuditRegistry {
    vaults: VaultDir,
    stores: Mutex<HashMap<String, Arc<AuditStore>>>,
}

impl AuditRegistry {
    pub fn new(vaults: VaultDir) -> Self {
        Self {
            vaults,
            stores: Mutex::new(HashMap::new()),
        }
    }

    pub fn for_vault(&self, vault_id: &str) -> Result<Arc<AuditStore>> {
        {
            let stores = self.stores.lock().unwrap();
            if let Some(s) = stores.get(vault_id) {
                return Ok(s.clone());
            }
        }

        // Layer 1 — DoS gate: verify the vault exists before touching any fd.
        // Fake vault_ids have no directory on disk; without this check, open()
        // would call create_dir_all and allocate a real fd for a non-vault.
        let vault_dir = self.vaults.dir_for(vault_id)?;
        if !vault_dir.exists() {
            return Err(crate::error::AppError::NotFound);
        }

        // Open the SQLite connection outside the lock so a slow disk access
        // doesn't block concurrent requests to other vaults.
        let db_path = self.vaults.audit_path(vault_id)?;
        let store = Arc::new(AuditStore::open(&db_path)?);

        let mut stores = self.stores.lock().unwrap();
        // Race: another thread may have inserted while we were opening — keep theirs.
        if let Some(existing) = stores.get(vault_id) {
            return Ok(existing.clone());
        }

        // Layer 2 — fd ceiling: evict one handle when at capacity.
        // The evicted vault's SQLite fd is closed; its on-disk data is untouched.
        // The next request for that vault simply reopens the file.
        if stores.len() >= AUDIT_REGISTRY_CAP {
            if let Some(key) = stores.keys().next().cloned() {
                stores.remove(&key);
            }
        }

        stores.insert(vault_id.to_string(), store.clone());
        Ok(store)
    }

    /// Drop the cached `AuditStore` handle for a vault. Used during
    /// admin-driven vault deletion so the SQLite connection is closed
    /// before we `rm -rf` the directory it points at. Idempotent.
    pub fn forget(&self, vault_id: &str) {
        let mut stores = self.stores.lock().unwrap();
        stores.remove(vault_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, AuditStore) {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("audit.db");
        let s = AuditStore::open(&p).unwrap();
        (tmp, s)
    }

    fn row(id: &str, status: &str, created: i64) -> ApprovalRow {
        ApprovalRow {
            id: id.into(),
            created_at: created,
            decided_at: None,
            expires_at: created + 300,
            status: status.into(),
            act_kind: "use".into(),
            service: Some("inbox".into()),
            method: Some("POST".into()),
            path: Some("/".into()),
            target: Some("env.inbox_api_key".into()),
            reason: None,
            credential_id: None,
            upstream_status: None,
        }
    }

    #[test]
    fn insert_and_list_pending() {
        let (_tmp, s) = fresh_store();
        s.insert(&row("op1", STATUS_PENDING, 100)).unwrap();
        s.insert(&row("op2", STATUS_PENDING, 200)).unwrap();
        let pending = s.list(Some(&[STATUS_PENDING]), None, None, 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, "op2"); // newest first
    }

    #[test]
    fn finalize_pending_to_approved() {
        let (_tmp, s) = fresh_store();
        s.insert(&row("op1", STATUS_PENDING, 100)).unwrap();
        s.finalize("op1", STATUS_APPROVED, 150, Some("cred-xyz"), None, Some(200))
            .unwrap();
        let all = s.list(None, None, None, 10).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].status, STATUS_APPROVED);
        assert_eq!(all[0].decided_at, Some(150));
        assert_eq!(all[0].credential_id.as_deref(), Some("cred-xyz"));
        assert_eq!(all[0].upstream_status, Some(200));
    }

    #[test]
    fn insert_allowed_cache_hit_no_pending() {
        let (_tmp, s) = fresh_store();
        let mut r = row("op-allowed", STATUS_ALLOWED, 300);
        r.decided_at = Some(300);
        r.upstream_status = Some(200);
        s.insert(&r).unwrap();
        let allowed = s.list(Some(&[STATUS_ALLOWED]), None, None, 10).unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].decided_at, Some(300));
    }

    #[test]
    fn pagination_via_since() {
        let (_tmp, s) = fresh_store();
        for i in 1..=10 {
            s.insert(&row(&format!("op{}", i), STATUS_PENDING, i * 100))
                .unwrap();
        }
        let page1 = s.list(None, None, None, 3).unwrap();
        assert_eq!(page1.len(), 3);
        // oldest of page 1 = op8 (created_at=800); next page since=800.
        let page2 = s.list(None, None, Some(page1.last().unwrap().created_at), 3).unwrap();
        assert_eq!(page2.len(), 3);
        assert_eq!(page2[0].id, "op7");
    }

    #[test]
    fn aggregate_usage_counts_only_billable_use_ops() {
        let (_tmp, s) = fresh_store();

        // Billable: approved + allowed within window
        let mut approved = row("op1", STATUS_APPROVED, 100);
        approved.decided_at = Some(150);
        approved.service = Some("openai".into());
        s.insert(&approved).unwrap();

        let mut allowed = row("op2", STATUS_ALLOWED, 200);
        allowed.decided_at = Some(200);
        allowed.service = Some("openai".into());
        s.insert(&allowed).unwrap();

        let mut gmail = row("op3", STATUS_APPROVED, 300);
        gmail.decided_at = Some(305);
        gmail.service = Some("gmail".into());
        s.insert(&gmail).unwrap();

        // Non-billable: pending / rejected / expired / denied
        s.insert(&row("op-pending", STATUS_PENDING, 400)).unwrap();
        let mut rejected = row("op-rej", STATUS_REJECTED, 410);
        rejected.decided_at = Some(420);
        s.insert(&rejected).unwrap();
        let mut expired = row("op-exp", STATUS_EXPIRED, 430);
        expired.decided_at = Some(440);
        s.insert(&expired).unwrap();

        // Non-billable: control-plane op (act_kind != 'use')
        let mut write = row("op-write", STATUS_APPROVED, 500);
        write.decided_at = Some(510);
        write.act_kind = "write".into();
        write.service = None;
        s.insert(&write).unwrap();

        // Out-of-window approved Use
        let mut outside = row("op-old", STATUS_APPROVED, 50);
        outside.decided_at = Some(60);
        outside.service = Some("openai".into());
        s.insert(&outside).unwrap();

        let (total, by_svc) = s.aggregate_usage(100, 400).unwrap();
        assert_eq!(total, 3, "expected 3 billable ops in [100, 400)");
        assert_eq!(by_svc.get("openai").copied(), Some(2));
        assert_eq!(by_svc.get("gmail").copied(), Some(1));
        assert!(by_svc.get("write").is_none(), "write op must not appear");
    }

    #[test]
    fn aggregate_usage_uses_created_at_when_decided_at_null() {
        let (_tmp, s) = fresh_store();
        // status='allowed' may legitimately have decided_at = NULL — make sure
        // the COALESCE fallback to created_at still puts the row in-window.
        let mut allowed = row("op1", STATUS_ALLOWED, 250);
        allowed.decided_at = None;
        s.insert(&allowed).unwrap();
        let (total, _) = s.aggregate_usage(200, 300).unwrap();
        assert_eq!(total, 1);
        let (zero, _) = s.aggregate_usage(300, 400).unwrap();
        assert_eq!(zero, 0);
    }

    #[test]
    fn filter_by_service() {
        let (_tmp, s) = fresh_store();
        let mut a = row("op1", STATUS_ALLOWED, 100);
        a.service = Some("github".into());
        let mut b = row("op2", STATUS_ALLOWED, 200);
        b.service = Some("openai".into());
        s.insert(&a).unwrap();
        s.insert(&b).unwrap();
        let gh = s.list(None, Some("github"), None, 10).unwrap();
        assert_eq!(gh.len(), 1);
        assert_eq!(gh[0].id, "op1");
    }

    #[test]
    fn unsynced_outbox_lifecycle() {
        let (_tmp, s) = fresh_store();

        // Two terminal Use rows — shippable.
        let mut allowed = row("op1", STATUS_ALLOWED, 100);
        allowed.decided_at = Some(100);
        s.insert(&allowed).unwrap();
        let mut approved = row("op2", STATUS_APPROVED, 200);
        approved.decided_at = Some(210);
        s.insert(&approved).unwrap();
        // Pending = transient, NOT shipped.
        s.insert(&row("op-pending", STATUS_PENDING, 300)).unwrap();
        // Control-plane op (act_kind != 'use') = NOT shipped.
        let mut write = row("op-write", STATUS_APPROVED, 400);
        write.act_kind = "write".into();
        s.insert(&write).unwrap();

        let un = s.list_unsynced(100).unwrap();
        assert_eq!(un.len(), 2, "only terminal Use rows ship");
        assert_eq!(un[0].id, "op1", "oldest-first");
        assert_eq!(un[1].id, "op2");

        // Marking synced removes a row from the outbox.
        s.mark_synced(&["op1".to_string()]).unwrap();
        let un2 = s.list_unsynced(100).unwrap();
        assert_eq!(un2.len(), 1);
        assert_eq!(un2[0].id, "op2");

        // Re-marking is idempotent (empty + already-synced ids are no-ops).
        s.mark_synced(&[]).unwrap();
        s.mark_synced(&["op1".to_string(), "op2".to_string()]).unwrap();
        assert!(s.list_unsynced(100).unwrap().is_empty());

        // A pending row that finalizes to a terminal Use status becomes shippable.
        s.finalize("op-pending", STATUS_APPROVED, 350, None, None, Some(200))
            .unwrap();
        let un3 = s.list_unsynced(100).unwrap();
        assert_eq!(un3.len(), 1);
        assert_eq!(un3[0].id, "op-pending");
    }
}
