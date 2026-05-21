//! `/approve/{id}` family — approval workflow.
//!
//! - `GET /approve/{id}`: poll endpoint (agent or browser checks status)
//! - `POST /approve/{id}/details`: returns `render(o)` plus structured op summary
//! - `POST /approve/{id}/confirm`: body = a Grant. Validates and executes the
//!   approved act; caches plaintext result for the agent.
//! - `POST /approve/{id}/reject`: marks rejected.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::approval::ApprovalStatus;
use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{as_export_path, discriminator, ActType};
use crate::protocol::{render_operation, validate_grant, Grant};
use crate::server::handlers::metadata::decrypt_vault_targets;
use crate::server::tenant_extractor::TenantId;
use crate::state::AppState;
use crate::storage::sealed_vault::{find_pubkey, read as read_vault};

pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let store = state.approvals.lock().unwrap();
    let rec = store.get(&id).ok_or(AppError::NotFound)?;
    let body = match &rec.status {
        ApprovalStatus::Pending => json!({ "status": "pending" }),
        ApprovalStatus::Approved => {
            // For the agent's polling: include the cached value (will be marked
            // consumed when /proxy returns it). To avoid leaking on direct
            // GET we only return value if Bearer-equivalent (which the daemon
            // can't check without trust headers). For toy v0 we expose it here.
            json!({ "status": "approved", "value": rec.cached_value })
        }
        ApprovalStatus::Rejected { reason } => {
            json!({ "status": "rejected", "reason": reason })
        }
        ApprovalStatus::Consumed => json!({ "status": "consumed" }),
    };
    Ok(Json(body))
}

pub async fn details(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let store = state.approvals.lock().unwrap();
    let rec = store.get(&id).ok_or(AppError::NotFound)?;
    let act_kind = discriminator(&rec.op.act);
    let display = render_operation(&rec.op);
    let path = match &rec.op.act.kind {
        ActType::Export => Some(rec.op.act.target.clone()),
        _ => None,
    };
    let op_json = serde_json::to_value(&rec.op)?;
    Ok(Json(json!({
        "id": rec.id,
        "status": match &rec.status {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Rejected { .. } => "rejected",
            ApprovalStatus::Consumed => "consumed",
        },
        "act": act_kind,
        "path": path,
        "display": display,
        "op": op_json,
    })))
}

pub async fn confirm(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(grant): Json<Grant>,
) -> Result<Json<Value>> {
    // 1. Look up approval (also gives us tenant_id and the canonical op).
    let (tenant_id, approval_op) = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get(&id).ok_or(AppError::NotFound)?;
        if !matches!(rec.status, ApprovalStatus::Pending) {
            return Err(AppError::Conflict("approval not pending".into()));
        }
        (rec.tenant_id.clone(), rec.op.clone())
    };

    // 2. Sanity: the grant's operation must equal the approval's pending op.
    let canonical_grant_op = serde_json::to_value(&grant.o)?;
    let canonical_approval_op = serde_json::to_value(&approval_op)?;
    if canonical_grant_op != canonical_approval_op {
        return Err(AppError::BadRequest(
            "grant.o does not match the pending approval's operation".into(),
        ));
    }

    // 3. Validate the grant (passkey assertion + binding + freshness).
    let vault_path = state.tenants.vault_path(&tenant_id)?;
    let vault = read_vault(&vault_path)?
        .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        find_pubkey(&vault, cred_id_b64)
    };

    let validated = {
        let mut chs = state.challenges.lock().unwrap();
        validate_grant(
            &grant,
            &mut chs,
            &state.config.origin,
            &state.config.rp_id,
            lookup_credential,
        )?
    };

    // 4. Execute the act. v0 only supports Export (reveal) via approval.
    let cached_value = match &validated.op.act.kind {
        ActType::Export => {
            let path = as_export_path(&validated.op)?;
            let targets = decrypt_vault_targets(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            )?;
            // Targets are flat `{ name: b64(bytes) }`. Lookup the path and
            // decode back to a UTF-8 string for legacy display.
            let v_b64 = targets
                .get(path)
                .and_then(|x| x.as_str())
                .ok_or(AppError::NotFound)?;
            let raw = STANDARD
                .decode(v_b64)
                .map_err(|_| AppError::Internal("target value not base64".into()))?;
            let s = String::from_utf8(raw)
                .map_err(|_| AppError::Internal("target value not utf8".into()))?;
            Some(s)
        }
        _ => None,
    };

    let mut store = state.approvals.lock().unwrap();
    let rec = store.approve(&id, cached_value).ok_or_else(|| {
        AppError::Conflict("approval no longer pending after validation".into())
    })?;
    Ok(Json(json!({
        "ok": true,
        "id": rec.id,
        "status": "approved",
    })))
}

pub async fn reject(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let mut store = state.approvals.lock().unwrap();
    let rec = store
        .reject(&id, "user denied")
        .ok_or(AppError::NotFound)?;
    Ok(Json(json!({ "ok": true, "id": rec.id, "status": "rejected" })))
}

// Placeholder for future use: tenant header is currently ignored on these
// endpoints because the approval id already binds to a tenant. We could
// optionally enforce equality between header tenant and rec.tenant_id.
#[allow(dead_code)]
fn _enforce_tenant(rec_tenant: &str, header: TenantId) -> Result<()> {
    if rec_tenant != header.0 {
        return Err(AppError::Forbidden("tenant mismatch".into()));
    }
    Ok(())
}
