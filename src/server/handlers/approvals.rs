//! `GET /v/{vid}/approvals` — list audit rows for a vault.
//!
//! Single endpoint, status filter handles both present (pending) and past
//! (allowed / approved / denied / rejected / expired). Frontend uses this
//! on page-load to seed the Pending card + Recent Activity card; live
//! updates come from `/v/{vid}/events` SSE.
//!
//! Returns `{ entries: ApprovalRow[], next_since: number | null }`.
//! Pagination: pass the oldest seen `created_at` back as `?since=` to get
//! the next page (results are ORDER BY created_at DESC, exclusive upper).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::{
    STATUS_ALLOWED, STATUS_APPROVED, STATUS_DENIED, STATUS_EXPIRED, STATUS_PENDING,
    STATUS_REJECTED,
};
use crate::error::Result;
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 500;

const TERMINAL_STATUSES: &[&str] = &[
    STATUS_ALLOWED,
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_REJECTED,
    STATUS_EXPIRED,
];

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// "pending" | "past" | "all" (default: "all").
    #[serde(default)]
    pub status: Option<String>,
    /// Service id filter (e.g. "github"). Default: all services.
    #[serde(default)]
    pub service: Option<String>,
    /// Exclusive upper bound on `created_at` for pagination.
    #[serde(default)]
    pub since: Option<i64>,
    /// Default 100, max 500.
    #[serde(default)]
    pub limit: Option<u32>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;

    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT).max(1);
    let status_filter: Option<&[&str]> = match q.status.as_deref() {
        Some("pending") => Some(&[STATUS_PENDING]),
        Some("past") => Some(TERMINAL_STATUSES),
        Some("all") | None => None,
        Some(other) => Some(match other {
            STATUS_PENDING => &[STATUS_PENDING],
            STATUS_ALLOWED => &[STATUS_ALLOWED],
            STATUS_APPROVED => &[STATUS_APPROVED],
            STATUS_DENIED => &[STATUS_DENIED],
            STATUS_REJECTED => &[STATUS_REJECTED],
            STATUS_EXPIRED => &[STATUS_EXPIRED],
            _ => return Ok(Json(json!({ "entries": [], "next_since": null }))),
        }),
    };

    // No vault audit DB yet = vault never had any op = empty list.
    let store = match state.audits.for_vault(&vault_id) {
        Ok(s) => s,
        Err(_) => return Ok(Json(json!({ "entries": [], "next_since": null }))),
    };

    // Opportunistic retention prune. Only runs when the vault is currently
    // unlocked (the only state in which the daemon knows the user's
    // `audit_retention_days` setting) AND the user has actually set a
    // value (None = keep forever). Best-effort: a prune failure is logged
    // but doesn't block the list response.
    if let Some(days) = state.audit_retention_days(&vault_id) {
        let days = days.max(1) as i64;
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            - days * 86_400;
        match store.prune_older_than(cutoff) {
            Ok(n) if n > 0 => {
                tracing::info!(vault = %vault_id, deleted = n, "audit prune");
            }
            Err(e) => {
                tracing::warn!(vault = %vault_id, "audit prune failed: {}", e);
            }
            _ => {}
        }
    }

    // F-21: reject over-long service filter to prevent unbounded DB params.
    if let Some(ref s) = q.service {
        if s.len() > 64 {
            return Err(crate::error::AppError::BadRequest(
                "service filter too long (max 64 chars)".into(),
            ));
        }
    }

    let entries = store.list(status_filter, q.service.as_deref(), q.since, limit)?;
    // Next-page cursor: the oldest row's created_at, only if we returned a
    // full page (otherwise we know the caller has seen everything).
    let next_since = if entries.len() as u32 == limit {
        entries.last().map(|r| r.created_at)
    } else {
        None
    };

    Ok(Json(json!({
        "entries": entries,
        "next_since": next_since,
    })))
}
