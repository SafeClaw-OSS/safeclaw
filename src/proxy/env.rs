//! `env` virtual service handler — agent-facing key/value secret access.
//! Renamed from `safeclaw-vault` (the legacy demo name).
//!
//! Flow per `safeclaw-protocol/PRO_API_DESIGN.md` §2.4:
//!
//! ```text
//! agent → POST /env/<key>     (with X-Safeclaw-Tenant + Idempotency-Key)
//!     ├─ no pending approval → daemon creates one → 202 { approval_id, approve_url, poll_url }
//!     └─ pending approval already approved → 200 { value }
//! agent → GET /env/<key>/poll?approval_id=<id>
//!     └─ returns same shape as /approve/{id} (status + value if approved)
//! ```
//!
//! For demo v0 we keep the contract minimal: every call without a query
//! `approval_id=<id>` creates a fresh approval. Idempotency tracking is
//! deferred until v0.1.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::approval::ApprovalStatus;
use crate::error::{AppError, Result};
use crate::protocol::operation::{Act, Operation, Valid};
use crate::server::tenant_extractor::TenantId;
use crate::state::AppState;

const ENV_NAMESPACE_PREFIX: &str = "env";

#[derive(Debug, Deserialize)]
pub struct PollQuery {
    pub approval_id: Option<String>,
}

/// `* /env/{key}` — create approval (or return cached value).
pub async fn handle(
    State(state): State<Arc<AppState>>,
    tenant: TenantId,
    Path(key): Path<String>,
    Query(q): Query<PollQuery>,
) -> Result<(StatusCode, Json<Value>)> {
    validate_key(&key)?;

    // If the caller already has an approval_id, treat as a poll.
    if let Some(approval_id) = q.approval_id.as_deref() {
        return poll_inner(&state, approval_id).await;
    }

    let TenantId(tenant_id) = tenant.clone();
    let path = format!("{}.{}", ENV_NAMESPACE_PREFIX, key);
    let op = Operation {
        act: Act::Reveal { path: path.clone() },
        valid: Valid {
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            exp: None,
        },
    };

    let approval_id = {
        let mut store = state.approvals.lock().unwrap();
        store.create(tenant_id, op)
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending_approval",
            "approval_id": approval_id,
            "approve_url": format!("/approve/{}", approval_id),
            "poll_url": format!("/env/{}/poll?approval_id={}", key, approval_id),
        })),
    ))
}

/// `GET /env/{key}/poll?approval_id=<id>` — agent-friendly poll.
pub async fn poll(
    State(state): State<Arc<AppState>>,
    Path(_key): Path<String>,
    Query(q): Query<PollQuery>,
) -> Result<(StatusCode, Json<Value>)> {
    let id = q
        .approval_id
        .ok_or_else(|| AppError::BadRequest("missing approval_id query param".into()))?;
    poll_inner(&state, &id).await
}

async fn poll_inner(state: &Arc<AppState>, approval_id: &str) -> Result<(StatusCode, Json<Value>)> {
    let mut store = state.approvals.lock().unwrap();
    let rec = store
        .get(approval_id)
        .ok_or(AppError::NotFound)?
        .clone();
    match &rec.status {
        ApprovalStatus::Pending => Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "status": "pending", "approval_id": approval_id })),
        )),
        ApprovalStatus::Approved => {
            let value = store
                .consume(approval_id)
                .ok_or_else(|| AppError::Internal("approved but no cached value".into()))?;
            Ok((
                StatusCode::OK,
                Json(json!({ "status": "ok", "value": value })),
            ))
        }
        ApprovalStatus::Rejected { reason } => Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "status": "rejected", "reason": reason })),
        )),
        ApprovalStatus::Consumed => Ok((
            StatusCode::GONE,
            Json(json!({ "status": "consumed" })),
        )),
    }
}

fn validate_key(k: &str) -> Result<()> {
    if k.is_empty() || k.len() > 64 {
        return Err(AppError::BadRequest("invalid key".into()));
    }
    if !k
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest("key has illegal chars".into()));
    }
    Ok(())
}
