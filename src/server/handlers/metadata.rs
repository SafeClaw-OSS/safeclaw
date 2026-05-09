//! Read-only metadata endpoints (no passkey required).
//!
//! - `GET /metadata/passkeys`: list registered credentials' public metadata
//! - `GET /metadata/keys`: list vault key names (NOT values) — used by skill.md generator

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::error::Result;
use crate::server::tenant_extractor::TenantId;
use crate::state::AppState;
use crate::storage::sealed_vault::{open_body, unwrap_dek};

#[derive(Debug, Serialize)]
pub struct PasskeyMeta {
    pub credential_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    /// Base64 of the credential's prf_salt — needed by the client for PRF eval.
    pub prf_salt: String,
}

pub async fn passkeys(
    State(state): State<Arc<AppState>>,
    tenant: TenantId,
) -> Result<Json<serde_json::Value>> {
    let TenantId(tenant_id) = tenant;
    let vault_path = state.tenants.vault_path(&tenant_id)?;
    let Some(vault) = crate::storage::SealedVault::read(&vault_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "passkeys": [] })));
    };
    let metas: Vec<PasskeyMeta> = vault
        .credentials
        .iter()
        .map(|c| PasskeyMeta {
            credential_id: c.credential_id.clone(),
            device_name: c.device_name.clone(),
            created_at: c.created_at,
            prf_salt: c.prf_salt.clone(),
        })
        .collect();
    Ok(Json(json!({ "vault_exists": true, "passkeys": metas })))
}

/// `GET /metadata/keys` — return the list of K names visible inside the
/// `env.*` namespace WITHOUT revealing values.
///
/// Demo v0: requires the user to have already supplied a `user_key` query param
/// (which would be sensitive). For now, we return only what's possible without
/// any decryption: the credential metadata. Full K-list disclosure happens
/// during /grant{type=write} responses (frontend gets back its own ciphertext).
///
/// Future: replace with a passkey-authenticated read endpoint.
pub async fn vault_keys(
    State(state): State<Arc<AppState>>,
    tenant: TenantId,
) -> Result<Json<Value>> {
    let TenantId(tenant_id) = tenant;
    let vault_path = state.tenants.vault_path(&tenant_id)?;
    let Some(vault) = crate::storage::SealedVault::read(&vault_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "keys": [] })));
    };
    // We can't decrypt without user_key. Just report metadata.
    Ok(Json(json!({
        "vault_exists": true,
        "version": vault.version,
        "credential_count": vault.credentials.len(),
        "note": "Listing key names requires a passkey-signed grant; use POST /grant.",
    })))
}

/// Helper: decrypt vault and return a JSON map of {key: value}. Used by act
/// dispatchers in `grant.rs` and `approve.rs`. Lives here to keep storage
/// concerns localized.
pub fn decrypt_vault_map(
    user_key: &[u8],
    credential_id_b64: &str,
    credential_id_bytes: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<serde_json::Value> {
    let cred = vault
        .find_credential(credential_id_b64)
        .ok_or_else(|| crate::error::AppError::Unauthorized("unknown credential".into()))?;
    let dek = unwrap_dek(user_key, cred, credential_id_bytes)?;
    let body = open_body(&dek, &vault.body)?;
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| crate::error::AppError::Internal(format!("vault body parse: {}", e)))?;
    Ok(parsed)
}
