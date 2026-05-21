//! `POST /grant` — main act dispatch.
//!
//! Enroll and Write are handled inline. Export returns the secret bytes
//! directly (used by user-driven console flows). For the agent-driven Export
//! flow, see `proxy::env` which creates an approval and dispatches via
//! `/approve/{id}/confirm`.

use std::sync::Arc;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{
    as_enroll_credential, as_export_path, as_write_patch, ActType,
};
use crate::protocol::{validate_grant, Grant};
use crate::server::handlers::metadata::decrypt_vault_targets;
use crate::server::tenant_extractor::TenantId;
use crate::state::AppState;
use crate::storage::sealed_vault::{
    build_initial, find_pubkey, read as read_vault, replace_after_write, write_atomic,
};

pub async fn grant(
    State(state): State<Arc<AppState>>,
    tenant: TenantId,
    Json(grant_body): Json<Grant>,
) -> Result<Json<Value>> {
    let TenantId(tenant_id) = tenant;
    dispatch_grant(&state, &tenant_id, &grant_body).await
}

pub async fn dispatch_grant(
    state: &Arc<AppState>,
    tenant_id: &str,
    grant: &Grant,
) -> Result<Json<Value>> {
    let vault_path = state.tenants.vault_path(tenant_id)?;
    let existing_vault = read_vault(&vault_path)?;

    // For non-Enroll ops, look up the credential pubkey from the existing
    // vault's Registry. For Enroll, the pubkey comes from the operation scope.
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        existing_vault.as_ref().and_then(|v| find_pubkey(v, cred_id_b64))
    };

    let validated = {
        let mut chs = state.challenges.lock().unwrap();
        validate_grant(
            grant,
            &mut chs,
            &state.config.origin,
            &state.config.rp_id,
            lookup_credential,
        )?
    };

    match &validated.op.act.kind {
        ActType::Enroll => {
            let credential = as_enroll_credential(&validated.op)?;
            if existing_vault.is_some() {
                return Err(AppError::Conflict(
                    "vault already initialized for this tenant".into(),
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
            state.tenants.ensure_dir(tenant_id)?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(tenant = %tenant_id, "vault enroll complete");
            Ok(Json(
                json!({ "ok": true, "tenant_id": tenant_id, "act": "enroll" }),
            ))
        }
        ActType::Write => {
            let patch = as_write_patch(&validated.op)?;
            let mut vault = existing_vault
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
            tracing::info!(tenant = %tenant_id, "vault write applied");
            Ok(Json(json!({ "ok": true, "act": "write" })))
        }
        ActType::Export => {
            let path = as_export_path(&validated.op)?;
            let vault = existing_vault
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let targets = decrypt_vault_targets(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            )?;
            let value = lookup_path(&targets, path)
                .ok_or_else(|| AppError::NotFound)?;
            Ok(Json(
                json!({ "ok": true, "act": "export", "path": path, "value": value }),
            ))
        }
        other => Err(AppError::BadRequest(format!(
            "unsupported act kind: {:?}",
            other
        ))),
    }
}

/// Walk a dot-separated path like `env.api_key` and return the value.
///
/// Post-storage-migration: ProtectedState.targets is FLAT (keys like
/// `"env.api_key"` directly, no nesting). So a path with no dots looks up
/// once; a path with dots walks the flat map first, then falls back to the
/// nested-JSON walk for transitional payloads.
fn lookup_path(root: &Value, path: &str) -> Option<Value> {
    // Try flat lookup first (post-migration shape).
    if let Some(v) = root.get(path) {
        return Some(v.clone());
    }
    // Fallback: legacy nested walk.
    let mut cur = root;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_path_flat() {
        let v = serde_json::json!({ "env.api_key": "sk-abc" });
        assert_eq!(
            lookup_path(&v, "env.api_key"),
            Some(serde_json::Value::String("sk-abc".into()))
        );
    }

    #[test]
    fn lookup_path_nested_fallback() {
        let v = serde_json::json!({ "env": { "api_key": "sk-abc" } });
        assert_eq!(
            lookup_path(&v, "env.api_key"),
            Some(serde_json::Value::String("sk-abc".into()))
        );
    }

    #[test]
    fn lookup_path_missing() {
        let v = serde_json::json!({ "env.api_key": "sk" });
        assert_eq!(lookup_path(&v, "env.missing"), None);
    }
}
