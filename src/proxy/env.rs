//! `POST /v/{vid}/export/{key}` — R-side sugar for Export-class operations.
//!
//! Compiles `(vid, key)` into a sudp `Operation { act: Export, target: <key> }`
//! and creates a pending approval via the shared op-creation helper. Returns
//! `{ op_id, r, expires_at }` — same shape as `POST /v/{vid}/op`. R then polls
//! `GET /op/{op_id}` until U approves. In v3 the target is the bare item
//! name (no `env.` prefix); resolution goes through the v3 store_order.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
use crate::server::handlers::op::validate_vault_id;
use crate::state::{ApprovalEvent, AppState};

pub async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Path((vault_id, key)): Path<(String, String)>,
) -> Result<(StatusCode, Json<Value>)> {
    validate_vault_id(&vault_id)?;
    validate_key(&key)?;

    let target = key.clone();
    let op = Operation {
        act: Act {
            kind: ActType::Export,
            target,
            scope: serde_json::Value::Null,
        },
        bind: Bind {
            redeemer: vault_id.clone(),
            recipient: None,
        },
        valid: Valid::single_use(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            None,
        ),
    };

    let ip: IpAddr = addr.ip();
    let r = {
        let mut store = state.challenges.lock().unwrap();
        store.issue(ip).ok_or(AppError::TooManyRequests)?
    };
    let (op_id, expires_at) = {
        let mut store = state.approvals.lock().unwrap();
        let id = store.create(vault_id.clone(), op.clone(), r.clone());
        let exp = store.get(&id).map(|r| r.expires_at_unix).unwrap_or(0);
        (id, exp)
    };

    state.emit_event(ApprovalEvent {
        vault_id: vault_id,
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending_approval",
            "op_id": op_id,
            "r": r,
            "expires_at": expires_at,
            "approve_url": format!("/op/{}", op_id),
            "poll_url": format!("/op/{}", op_id),
        })),
    ))
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
