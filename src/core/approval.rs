/// Approval manager: holds pending approval requests for the async 202 flow.
///
/// Flow:
///   1. Proxy creates approval via `create_approval()` → returns id, immediately 202 to agent
///   2. Agent polls  GET /approve/{id}  (proxy port) until status != pending
///   3. Human confirm/reject via console (passkey) → `confirm()` / `reject()`
///   4. First poll after confirm → execute upstream → cache → clear approved_auth
///   5. Subsequent polls → return cached response (idempotent)
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::HeaderMap;
use hyper::body::Bytes;

use super::audit::AuditLog;

// ── Status ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

// ── Cached upstream response (stored after first execute) ──────────────────────

pub struct CachedResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
}

// ── In-memory pending approval ─────────────────────────────────────────────────

pub struct PendingApproval {
    pub id: String,
    pub service: String,
    pub method: String,
    /// Route path after service prefix stripped (e.g. "/v1/messages").
    pub path: String,
    /// Full original URI path (e.g. "/anthropic/v1/messages?q=1") — for replay.
    pub uri_path: String,
    /// Upstream base URL — stored at create time; valid even if vault locks later.
    pub upstream: String,
    /// Request headers (hop-by-hop + auth stripped) — for replay.
    pub req_headers: HeaderMap,
    /// Full request body — for replay.
    pub req_body: Bytes,
    pub created_at: Instant,
    pub expires_at: Instant,
    /// Sanitised details (no secrets) — served by POST /approve/:id/details (passkey).
    pub details: Option<serde_json::Value>,
    pub approval_status: ApprovalStatus,
    /// Set by `confirm()`; consumed (cleared) after first upstream execute.
    pub approved_auth: Option<serde_json::Value>,
    /// True once `take_auth_for_execute` has been called; prevents double-execute.
    pub auth_executing: bool,
    /// Set after first execute; returned on subsequent polls (idempotent).
    pub cached_response: Option<CachedResponse>,
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

    /// Create a new pending approval. Returns the approval id (caller returns 202 immediately).
    #[allow(clippy::too_many_arguments)]
    pub fn create_approval(
        &self,
        service: String,
        method: String,
        path: String,
        uri_path: String,
        upstream: String,
        req_headers: HeaderMap,
        req_body: Bytes,
        timeout_secs: u64,
        details: Option<serde_json::Value>,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Instant::now();
        let expires_at = now + std::time::Duration::from_secs(timeout_secs);

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
                uri_path,
                upstream,
                req_headers,
                req_body,
                created_at: now,
                expires_at,
                details,
                approval_status: ApprovalStatus::Pending,
                approved_auth: None,
                auth_executing: false,
                cached_response: None,
            },
        );

        id
    }

    /// Mark an approval as confirmed (human pressed approve).
    /// Does NOT remove from map — agent still needs to poll.
    /// Returns `true` if found and was still pending.
    pub fn confirm(&self, id: &str, auth_json: Option<serde_json::Value>) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(approval) = pending.get_mut(id) {
            if approval.approval_status == ApprovalStatus::Pending {
                approval.approval_status = ApprovalStatus::Approved;
                approval.approved_auth = auth_json;
                let _ = self.audit.update_approval(id, "approved");
                return true;
            }
        }
        false
    }

    /// Mark an approval as rejected (human pressed reject).
    /// Does NOT remove from map — agent still needs to poll.
    /// Returns `true` if found and was still pending.
    pub fn reject(&self, id: &str) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(approval) = pending.get_mut(id) {
            if approval.approval_status == ApprovalStatus::Pending {
                approval.approval_status = ApprovalStatus::Rejected;
                let _ = self.audit.update_approval(id, "rejected");
                return true;
            }
        }
        false
    }

    /// Called by TTL cleanup task. Marks as expired — does NOT remove from map.
    /// Agent can still poll and receive {status:"expired"} (consistent with reject behavior).
    pub fn expire(&self, id: &str) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(approval) = pending.get_mut(id) {
            if approval.approval_status == ApprovalStatus::Pending {
                approval.approval_status = ApprovalStatus::Expired;
                let _ = self.audit.update_approval(id, "expired");
            }
        }
    }

    /// For poll handler: take the approved_auth to execute upstream.
    /// Returns `Some(auth_json)` if approved and not yet executed.
    /// Returns `None` if not in approved+unexecuted state.
    ///
    /// The inner `Option<serde_json::Value>` is the auth config (None = standard service).
    pub fn take_auth_for_execute(&self, id: &str) -> Option<Option<serde_json::Value>> {
        let mut pending = self.pending.lock().unwrap();
        if let Some(approval) = pending.get_mut(id) {
            if approval.approval_status == ApprovalStatus::Approved
                && !approval.auth_executing
                && approval.cached_response.is_none()
            {
                approval.auth_executing = true;
                return Some(approval.approved_auth.take());
            }
        }
        None
    }

    /// Store the cached upstream response after execution; clears approved_auth.
    pub fn set_cached_response(&self, id: &str, cached: CachedResponse) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(approval) = pending.get_mut(id) {
            approval.cached_response = Some(cached);
            approval.approved_auth = None; // security: don't retain auth after use
        }
    }

    /// Snapshot for the poll handler. Returns None if id not found.
    pub fn get_snapshot(&self, id: &str) -> Option<ApprovalSnapshot> {
        let pending = self.pending.lock().unwrap();
        pending.get(id).map(|a| ApprovalSnapshot {
            status: a.approval_status.clone(),
            service: a.service.clone(),
            method: a.method.clone(),
            uri_path: a.uri_path.clone(),
            upstream: a.upstream.clone(),
            req_headers: a.req_headers.clone(),
            req_body: a.req_body.clone(),
            expires_at: a.expires_at,
            cached_response: a.cached_response.as_ref().map(|r| CachedResponseSnapshot {
                status: r.status,
                headers: r.headers.clone(),
                body: r.body.clone(),
            }),
        })
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

// ── Snapshot types (lock-free copies for handlers) ────────────────────────────

pub struct ApprovalSnapshot {
    pub status: ApprovalStatus,
    pub service: String,
    pub method: String,
    pub uri_path: String,
    pub upstream: String,
    pub req_headers: HeaderMap,
    pub req_body: Bytes,
    pub expires_at: Instant,
    pub cached_response: Option<CachedResponseSnapshot>,
}

pub struct CachedResponseSnapshot {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
}
