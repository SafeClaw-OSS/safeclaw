//! Read-only metadata endpoints (no passkey required).
//!
//! - `GET /metadata/passkeys`: list registered credentials' public metadata
//! - `GET /metadata/keys`: list vault credential count (key NAMES require
//!   a passkey-signed Export grant via /grant)

use std::sync::Arc;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use sudp::grant::{GrantOpt, RedeemedGrant, WrappingKey};
use sudp::passkey::WebAuthn;
use sudp::primitives::StdPrimitives;

use crate::error::Result;
use crate::protocol::Operation;
use crate::server::tenant_extractor::TenantId;
use crate::state::AppState;
use crate::storage::sealed_vault::find_pubkey;

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
    let Some(vault) = crate::storage::sealed_vault::read(&vault_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "passkeys": [] })));
    };
    let metas: Vec<PasskeyMeta> = vault
        .credentials
        .iter()
        .map(|c| {
            let cid_b64 = STANDARD.encode(&c.credential_id);
            let pk = find_pubkey(&vault, &cid_b64);
            PasskeyMeta {
                credential_id: cid_b64,
                device_name: pk.as_ref().map(|p| p.device_name.clone()).unwrap_or_default(),
                created_at: 0, // sudp Registry doesn't track this; future: aux side-store.
                prf_salt: STANDARD.encode(&c.prf_salt),
            }
        })
        .collect();
    Ok(Json(json!({ "vault_exists": true, "passkeys": metas })))
}

/// `GET /metadata/keys` — surface vault existence + version without
/// touching plaintext. Listing actual target names requires a passkey-signed
/// Export grant via `/grant`.
pub async fn vault_keys(
    State(state): State<Arc<AppState>>,
    tenant: TenantId,
) -> Result<Json<Value>> {
    let TenantId(tenant_id) = tenant;
    let vault_path = state.tenants.vault_path(&tenant_id)?;
    let Some(vault) = crate::storage::sealed_vault::read(&vault_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "keys": [] })));
    };
    Ok(Json(json!({
        "vault_exists": true,
        "version": vault.version,
        "credential_count": vault.credentials.len(),
        "note": "Listing key names requires a passkey-signed Export grant; use POST /grant.",
    })))
}

/// Decrypt vault and return the `ProtectedState.targets` map as JSON (key →
/// base64 of secret bytes). Used by act dispatchers in `grant.rs` and
/// `approve.rs` for Export-class operations.
///
/// Internally constructs a `sudp::RedeemedGrant` from the safeclaw
/// `ValidatedGrant` data and calls `sudp::phases::consumption::open` to
/// recover `M`.
pub fn decrypt_vault_targets(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<serde_json::Value> {
    let redeemed = RedeemedGrant {
        o: op.clone(),
        credential_id: credential_id_bytes.to_vec(),
        wrapping_key: WrappingKey::from_bytes(wrapping_key.to_vec()),
        opt: GrantOpt::default(),
    };
    let opened = sudp::phases::consumption::open::<StdPrimitives>(&redeemed, vault)
        .map_err(|e| crate::error::AppError::Unauthorized(format!("vault open: {}", e)))?;

    // Convert ProtectedState.targets (BTreeMap<String, TargetValue>) to a
    // JSON map of `{ name: base64(bytes) }` for legacy callers that walk by
    // dotted path. Future: callers should consume `opened.m` directly.
    let mut out = serde_json::Map::new();
    for (k, v) in opened.m.targets.iter() {
        out.insert(k.clone(), serde_json::Value::String(STANDARD.encode(v.as_bytes())));
    }
    let _ = redeemed_zeroize_marker(); // touch to keep import alive
    Ok(serde_json::Value::Object(out))
}

// Tiny helper to keep WebAuthn import path obvious (used elsewhere via
// SealedState registry typing); not actually invoked.
fn redeemed_zeroize_marker() -> std::marker::PhantomData<WebAuthn> {
    std::marker::PhantomData
}
