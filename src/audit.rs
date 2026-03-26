/// SQLite-backed audit log and approval record store.
/// Audit logs contain ZERO sensitive metadata — only service/method/path/decision.
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

// ── Record Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: String,
    pub service: String,
    pub method: String,
    pub path: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
}

// ── AuditLog ───────────────────────────────────────────────────────────────────

pub struct AuditLog {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
        service         TEXT    NOT NULL,
        method          TEXT    NOT NULL,
        path            TEXT    NOT NULL,
        level           TEXT    NOT NULL,
        decision        TEXT    NOT NULL,
        duration_ms     INTEGER,
        upstream_status INTEGER,
        approval_id     TEXT
    );
    CREATE TABLE IF NOT EXISTS approvals (
        id          TEXT PRIMARY KEY,
        service     TEXT NOT NULL,
        method      TEXT NOT NULL,
        path        TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'pending',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at  TEXT NOT NULL,
        decided_at  TEXT
    );
";

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record a proxied request in the audit log.
    /// NOTE: path is logged as-is; callers must ensure it contains no sensitive values.
    pub fn log_request(
        &self,
        service: &str,
        method: &str,
        path: &str,
        level: &str,
        decision: &str,
        duration_ms: Option<i64>,
        upstream_status: Option<u16>,
        approval_id: Option<&str>,
    ) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO audit_log \
             (service, method, path, level, decision, duration_ms, upstream_status, approval_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                service,
                method,
                path,
                level,
                decision,
                duration_ms,
                upstream_status.map(|s| s as i64),
                approval_id,
            ],
        );
    }

    /// Insert a new pending approval record.
    pub fn create_approval(
        &self,
        id: &str,
        service: &str,
        method: &str,
        path: &str,
        expires_at: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals (id, service, method, path, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, service, method, path, expires_at],
        )?;
        Ok(())
    }

    /// Update approval status (and set decided_at to now).
    pub fn update_approval(&self, id: &str, status: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE approvals SET status = ?1, decided_at = datetime('now') WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    /// Fetch a single approval by ID.
    pub fn get_approval(&self, id: &str) -> Result<Option<ApprovalRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, service, method, path, status, created_at, expires_at, decided_at \
             FROM approvals WHERE id = ?1",
        )?;
        match stmt.query_row(params![id], row_to_approval) {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// List all approvals with status = 'pending'.
    pub fn list_pending_approvals(&self) -> Result<Vec<ApprovalRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, service, method, path, status, created_at, expires_at, decided_at \
             FROM approvals WHERE status = 'pending' ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![], row_to_approval)?;
        rows.collect()
    }
}

fn row_to_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRecord> {
    Ok(ApprovalRecord {
        id: row.get(0)?,
        service: row.get(1)?,
        method: row.get(2)?,
        path: row.get(3)?,
        status: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        decided_at: row.get(7)?,
    })
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> AuditLog {
        AuditLog::open_in_memory().expect("in-memory audit log failed")
    }

    #[test]
    fn log_request_does_not_panic() {
        let log = open();
        log.log_request("svc", "GET", "/foo", "standard", "allowed", Some(42), Some(200), None);
    }

    #[test]
    fn approval_lifecycle() {
        let log = open();
        let id = "test-id-1";
        log.create_approval(id, "svc", "POST", "/api", "2099-01-01 00:00:00")
            .expect("create failed");

        let rec = log.get_approval(id).expect("get failed").expect("not found");
        assert_eq!(rec.status, "pending");
        assert_eq!(rec.service, "svc");

        log.update_approval(id, "approved").expect("update failed");
        let rec2 = log.get_approval(id).expect("get failed").expect("not found");
        assert_eq!(rec2.status, "approved");
        assert!(rec2.decided_at.is_some());
    }

    #[test]
    fn list_pending_only_returns_pending() {
        let log = open();
        log.create_approval("a", "s1", "GET", "/1", "2099-01-01 00:00:00").unwrap();
        log.create_approval("b", "s2", "POST", "/2", "2099-01-01 00:00:00").unwrap();
        log.update_approval("b", "approved").unwrap();

        let pending = log.list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "a");
    }
}
