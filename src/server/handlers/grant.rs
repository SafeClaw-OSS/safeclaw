//! `POST /grant` — main act dispatch.
//!
//! Setup and Write are handled inline. Reveal returns `{ value }` directly
//! (used by the user-driven flow in the toy console).
//! For the agent-driven reveal flow, see `proxy::safeclaw_vault` which creates
//! an approval and dispatches the reveal via `/approve/{id}/confirm`.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::Act;
use crate::protocol::{validate_grant, Grant};
use crate::server::handlers::metadata::decrypt_vault_map;
use crate::server::tenant_extractor::TenantId;
use crate::state::AppState;
use crate::storage::sealed_vault::SealedCredential;
use crate::storage::SealedVault;

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
    let existing_vault = SealedVault::read(&vault_path)?;

    // For non-setup ops, look up the credential from the existing vault.
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        existing_vault
            .as_ref()
            .and_then(|v| v.find_credential(cred_id_b64).map(|c| c.passkey_entry()))
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

    match &validated.op.act {
        Act::Setup {
            credential,
            wrapped_dek,
            body,
        } => {
            if existing_vault.is_some() {
                return Err(AppError::Conflict(
                    "vault already initialized for this tenant".into(),
                ));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let sealed_cred = SealedCredential {
                credential_id: credential.credential_id.clone(),
                x: credential.public_key_x.clone(),
                y: credential.public_key_y.clone(),
                device_name: credential.device_name.clone(),
                created_at: now,
                prf_salt: credential.prf_salt.clone(),
                wrapped_dek: wrapped_dek.clone(),
            };
            let vault = SealedVault::empty(sealed_cred, body.clone());
            state.tenants.ensure_dir(tenant_id)?;
            vault.write_atomic(&vault_path)?;
            tracing::info!(tenant = %tenant_id, "vault setup complete");
            Ok(Json(
                json!({ "ok": true, "tenant_id": tenant_id, "act": "setup" }),
            ))
        }
        Act::Write { patch } => {
            let mut vault = existing_vault
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            vault.replace_credential_after_write(
                &grant.credential_id,
                &patch.prf_salt_next,
                &patch.wrapped_dek,
                &patch.body,
            )?;
            vault.write_atomic(&vault_path)?;
            tracing::info!(tenant = %tenant_id, "vault write applied");
            Ok(Json(json!({ "ok": true, "act": "write" })))
        }
        Act::Reveal { path } => {
            let vault = existing_vault
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let kv = decrypt_vault_map(
                &validated.user_key,
                &grant.credential_id,
                &validated.credential_id_bytes,
                &vault,
            )?;
            let value = lookup_path(&kv, path)
                .ok_or_else(|| AppError::NotFound)?;
            Ok(Json(
                json!({ "ok": true, "act": "reveal", "path": path, "value": value }),
            ))
        }
    }
}

/// Walk a dot-separated path like `services.toy.api_key` and return the value.
fn lookup_path(root: &Value, path: &str) -> Option<Value> {
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
    fn lookup_path_works() {
        let v = serde_json::json!({
            "services": { "toy": { "api_key": "sk-abc" } }
        });
        assert_eq!(
            lookup_path(&v, "services.toy.api_key"),
            Some(serde_json::Value::String("sk-abc".into()))
        );
        assert_eq!(lookup_path(&v, "services.toy.missing"), None);
    }
}
