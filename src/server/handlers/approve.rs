//! `/op/{op_id}` family — op lifecycle (poll, approve, reject).
//!
//! - `GET  /op/{op_id}`            — poll: status + cached value + render(o)
//! - `POST /op/{op_id}/approve`    — U submits grant G; T validates, dispatches act
//! - `POST /op/{op_id}/reject`     — U denies
//!
//! All act kinds (Enroll, Write, Export, Use) flow through `approve_op`; the
//! act-specific dispatch is inlined per the SUDP protocol.

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
use crate::protocol::operation::{
    as_enroll_credential, as_export_path, as_write_patch, discriminator, ActType,
};
use crate::protocol::{render_operation, validate_grant, Grant};
use crate::server::handlers::metadata::decrypt_vault_targets;
use crate::state::{ApprovalEvent, AppState};
use crate::storage::sealed_vault::{
    build_initial, find_pubkey, read as read_vault, replace_after_write, write_atomic,
};

/// `GET /op/{op_id}` — unified poll + details.
///
/// Returns the canonical op, render string, status, expires_at, and (when
/// approved-and-not-yet-consumed) the cached `value`.
pub async fn get_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<Value>> {
    let store = state.approvals.lock().unwrap();
    let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
    let act_kind = discriminator(&rec.op.act);
    let display = render_operation(&rec.op);
    let path = match &rec.op.act.kind {
        ActType::Export => Some(rec.op.act.target.clone()),
        _ => None,
    };
    let op_json = serde_json::to_value(&rec.op)?;
    let (status, value) = match &rec.status {
        ApprovalStatus::Pending => ("pending", None),
        ApprovalStatus::Approved => ("approved", rec.cached_value.clone()),
        ApprovalStatus::Rejected { .. } => ("rejected", None),
        ApprovalStatus::Consumed => ("consumed", None),
    };
    Ok(Json(json!({
        "op_id": rec.id,
        "r": rec.r,
        "status": status,
        "act": act_kind,
        "path": path,
        "display": display,
        "op": op_json,
        "value": value,
        "expires_at": rec.expires_at_unix,
    })))
}

/// `POST /op/{op_id}/approve` — U submits the signed grant. T validates and
/// dispatches the act (Enroll / Write / Export / Use).
pub async fn approve_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    Json(grant): Json<Grant>,
) -> Result<Json<Value>> {
    // 1. Look up the pending op.
    let (vault_id, approval_op) = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
        if !matches!(rec.status, ApprovalStatus::Pending) {
            return Err(AppError::Conflict("op not pending".into()));
        }
        (rec.tenant_id.clone(), rec.op.clone())
    };

    // 2. grant.o must equal the stored op (canonical equality).
    let canonical_grant_op = serde_json::to_value(&grant.o)?;
    let canonical_stored_op = serde_json::to_value(&approval_op)?;
    if canonical_grant_op != canonical_stored_op {
        return Err(AppError::BadRequest(
            "grant.o does not match the stored op".into(),
        ));
    }

    // 3. Resolve credential pubkey lookup.
    //
    // For Enroll, the credential is brand-new (not in vault yet) — pubkey is
    // taken from the op's scope. For Write/Export/Use, the credential must be
    // already enrolled — look it up in the existing vault.
    let vault_path = state.tenants.vault_path(&vault_id)?;
    let existing_vault = read_vault(&vault_path)?;
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        existing_vault.as_ref().and_then(|v| find_pubkey(v, cred_id_b64))
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

    // 4. Act dispatch — same logic that previously lived in grant.rs.
    let (response, cached_value) = match &validated.op.act.kind {
        ActType::Enroll => {
            let credential = as_enroll_credential(&validated.op)?;
            if existing_vault.is_some() {
                return Err(AppError::Conflict(
                    "vault already initialized for this vault_id".into(),
                ));
            }
            let payload = grant.setup_payload.as_ref().ok_or_else(|| {
                AppError::BadRequest("enroll grant missing setup_payload".into())
            })?;
            let cid_bytes = STANDARD
                .decode(&credential.credential_id)
                .map_err(|_| AppError::BadRequest("credential_id not base64".into()))?;
            let prf_salt = STANDARD
                .decode(&credential.prf_salt)
                .map_err(|_| AppError::BadRequest("prf_salt not base64".into()))?;
            let wrapped_key = STANDARD
                .decode(&payload.wrapped_key)
                .map_err(|_| AppError::BadRequest("wrapped_key not base64".into()))?;
            let ciphertext = STANDARD
                .decode(&payload.ciphertext)
                .map_err(|_| AppError::BadRequest("ciphertext not base64".into()))?;
            let vault = build_initial(
                cid_bytes,
                credential.public_key_x,
                credential.public_key_y,
                credential.device_name,
                prf_salt,
                wrapped_key,
                ciphertext,
            )?;
            state.tenants.ensure_dir(&vault_id)?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(vault = %vault_id, "vault enroll complete");
            (
                json!({ "ok": true, "vault_id": vault_id, "act": "enroll" }),
                None,
            )
        }
        ActType::Write => {
            let patch = as_write_patch(&validated.op)?;
            let mut vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let new_prf_salt = STANDARD
                .decode(&patch.prf_salt_next)
                .map_err(|_| AppError::BadRequest("prf_salt_next not base64".into()))?;
            let new_wrapped_key = STANDARD
                .decode(&patch.wrapped_key)
                .map_err(|_| AppError::BadRequest("wrapped_key not base64".into()))?;
            let new_ciphertext = STANDARD
                .decode(&patch.ciphertext)
                .map_err(|_| AppError::BadRequest("ciphertext not base64".into()))?;
            replace_after_write(
                &mut vault,
                &grant.credential_id,
                new_prf_salt,
                new_wrapped_key,
                new_ciphertext,
            )?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(vault = %vault_id, "vault write applied");
            (json!({ "ok": true, "act": "write" }), None)
        }
        ActType::Export => {
            let path = as_export_path(&validated.op)?;
            let vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let targets = decrypt_vault_targets(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            )?;

            // Editor reveal-all: when target = "env" (or empty), surface every
            // `env.*` target with its plaintext UTF-8 value (legacy editor
            // contract). Per-target Export goes through the else branch.
            if path == "env" || path.is_empty() {
                let mut all = serde_json::Map::new();
                if let Some(obj) = targets.as_object() {
                    for (k, v) in obj {
                        let b64 = match v.as_str() {
                            Some(s) => s,
                            None => continue,
                        };
                        let raw = STANDARD.decode(b64).map_err(|_| {
                            AppError::Internal("target value not base64".into())
                        })?;
                        let s = String::from_utf8(raw).map_err(|_| {
                            AppError::Internal("target value not utf8".into())
                        })?;
                        let key = k.strip_prefix("env.").unwrap_or(k).to_string();
                        all.insert(key, serde_json::Value::String(s));
                    }
                }
                let resp = json!({
                    "ok": true, "act": "export", "path": path,
                    "value": serde_json::Value::Object(all),
                });
                let cached = Some(resp["value"].to_string());
                (resp, cached)
            } else {
                let v_b64 = targets
                    .get(path)
                    .and_then(|x| x.as_str())
                    .ok_or(AppError::NotFound)?;
                let raw = STANDARD
                    .decode(v_b64)
                    .map_err(|_| AppError::Internal("target value not base64".into()))?;
                let value = String::from_utf8(raw)
                    .map_err(|_| AppError::Internal("target value not utf8".into()))?;
                (
                    json!({ "ok": true, "act": "export", "path": path, "value": value.clone() }),
                    Some(value),
                )
            }
        }
        ActType::Use => {
            let vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let response = crate::server::broker::execute_use_forward(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            )
            .await?;
            let body = serde_json::to_string(&response)?;
            (
                json!({ "ok": true, "act": "use", "response": serde_json::from_str::<Value>(&body).unwrap_or(Value::Null) }),
                Some(body),
            )
        }
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported act kind: {:?}",
                other
            )));
        }
    };

    // 5. Mark approved + emit event.
    let (rec_id, rec_vault_id, response_preview) = {
        let mut store = state.approvals.lock().unwrap();
        let rec = store.approve(&op_id, cached_value.clone()).ok_or_else(|| {
            AppError::Conflict("op no longer pending after validation".into())
        })?;
        let preview = match &validated.op.act.kind {
            ActType::Use => cached_value
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok()),
            _ => None,
        };
        (rec.id.clone(), rec.tenant_id.clone(), preview)
    };

    state.emit_event(ApprovalEvent {
        tenant_id: rec_vault_id,
        approval_id: rec_id,
        kind: "approved".into(),
        op_summary: None,
        response_preview,
        reason: None,
    });

    Ok(Json(response))
}

pub async fn reject_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<Value>> {
    let (rec_id, rec_vault_id) = {
        let mut store = state.approvals.lock().unwrap();
        let rec = store
            .reject(&op_id, "user denied")
            .ok_or(AppError::NotFound)?;
        (rec.id.clone(), rec.tenant_id.clone())
    };

    state.emit_event(ApprovalEvent {
        tenant_id: rec_vault_id,
        approval_id: rec_id.clone(),
        kind: "rejected".into(),
        op_summary: None,
        response_preview: None,
        reason: Some("user denied".into()),
    });

    Ok(Json(json!({ "ok": true, "op_id": rec_id, "status": "rejected" })))
}
