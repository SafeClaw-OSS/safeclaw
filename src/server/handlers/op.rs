//! `POST /v/{vid}/op` — R-side operation creation.
//!
//! Body: a canonical sudp `Operation`. The custodian stores it as a pending
//! approval, issues a fresh challenge `r`, and returns `{ op_id, r, expires_at }`.
//! U later authorizes via `POST /op/{op_id}/approve` (binding β computed over r).
//!
//! All flows route through here — R-driven (Use/Export) AND U-direct
//! (Enroll/Write/console-Export). The two-RTT shape is uniform.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::audit;
use crate::error::{AppError, Result};
use crate::protocol::operation::{ActType, Operation};
use crate::state::{ApprovalEvent, AppState};

pub async fn create(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Path(vault_id): Path<String>,
    Json(op): Json<Operation>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;
    // Locked-state gate (H3 / PROTOCOL.md §6.3): when the vault is Locked,
    // only the unlock ceremony (and first-time Enroll, which auto-unlocks)
    // is admissible. Everything else gets a canned 409 so the caller knows
    // to drive a `Custom("vault-unlock")` op first.
    let is_lifecycle_bypass = matches!(&op.act.kind, ActType::Enroll)
        || matches!(&op.act.kind, ActType::Custom(name) if name == "vault-unlock");
    if !is_lifecycle_bypass && state.is_vault_locked(&vault_id) {
        return Err(AppError::Conflict("vault locked — unlock first".into()));
    }
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

    // Persist a `pending` audit row so `GET /v/{vid}/approvals?status=pending`
    // can return current pendings on page load (in-memory ApprovalStore is
    // process-bound). Best-effort — audit failure must NOT block op creation.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_tenant(&vault_id) {
        let row = audit::row_from_op(&op_id, &op, now, expires_at as i64);
        if let Err(e) = store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        tenant_id: vault_id,
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok(Json(json!({
        "op_id": op_id,
        "r": r,
        "expires_at": expires_at,
    })))
}

pub fn validate_vault_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 {
        return Err(AppError::BadRequest("invalid vault_id".into()));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest("vault_id has illegal chars".into()));
    }
    Ok(())
}
