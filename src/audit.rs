//! Per-tenant audit log (PROTOCOL.md §5.3).
//!
//! Append-only SQLite at `<state>/tenants/<vid>/audit.db`. Records every
//! op lifecycle event — pending creation, terminal decision, cache-hit
//! auto-forward. Only operational metadata (service / method / path /
//! status / timestamps / credential_id); **no secret values, request
//! bodies, or response bodies** ever land on disk. That keeps the audit
//! file at the same trust level as a web-server access log — useful for
//! "what did my agent do" without needing SUDP-grade encryption.
//!
//! Per-tenant DB (one file per vault) is the spec's isolation guarantee
//! (PROTOCOL.md §5.3 "跨 tenant 永远隔离"). Connections cached lazily in
//! `AuditRegistry`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::{AppError, Result};
use crate::storage::TenantDir;

// ── Status vocabulary ────────────────────────────────────────────────────
//
// Six-state lifecycle (PROTOCOL.md §6.3). Five terminal, one transient.
//
//   pending   — ask-policy op awaiting user decision (transient)
//   allowed   — allow-policy auto-forwarded; no user gesture (terminal)
//   approved  — user approved a pending ask (terminal)
//   denied    — deny-policy auto-blocked; no user gesture (terminal)
//   rejected  — user rejected a pending ask (terminal)
//   expired   — ask-policy op TTL elapsed without user action (terminal)
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_ALLOWED: &str = "allowed";
pub const STATUS_APPROVED: &str = "approved";
#[allow(dead_code)] // wired once policy auto-deny lands
pub const STATUS_DENIED: &str = "denied";
pub const STATUS_REJECTED: &str = "rejected";
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
    upstream_status INTEGER
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
}

/// Per-tenant `AuditStore` cache. Lazy-init on first `for_tenant` call —
/// no DB file exists until that tenant's first op writes audit.
pub struct AuditRegistry {
    tenants: TenantDir,
    stores: Mutex<HashMap<String, Arc<AuditStore>>>,
}

impl AuditRegistry {
    pub fn new(tenants: TenantDir) -> Self {
        Self {
            tenants,
            stores: Mutex::new(HashMap::new()),
        }
    }

    pub fn for_tenant(&self, tenant_id: &str) -> Result<Arc<AuditStore>> {
        {
            let stores = self.stores.lock().unwrap();
            if let Some(s) = stores.get(tenant_id) {
                return Ok(s.clone());
            }
        }
        // Open outside the lock so a slow disk doesn't block other tenants.
        let db_path = self.tenants.audit_path(tenant_id)?;
        let store = Arc::new(AuditStore::open(&db_path)?);
        let mut stores = self.stores.lock().unwrap();
        // Race: another thread may have inserted in the meantime — keep theirs.
        if let Some(existing) = stores.get(tenant_id) {
            return Ok(existing.clone());
        }
        stores.insert(tenant_id.to_string(), store.clone());
        Ok(store)
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
}
