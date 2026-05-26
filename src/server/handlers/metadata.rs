//! Vault-scoped and custodian-level read-only endpoints.
//!
//! - `GET /v/{vid}/passkeys` — list this vault's enrolled credentials (public metadata only)
//! - `GET /c/pubkey`         — custodian's HPKE public key (bootstrap for outer envelope)
//!
//! Listing actual target names still requires a passkey-signed Export op via
//! `POST /v/{vid}/op` + `POST /op/{op_id}/approve`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use sudp::grant::{GrantOpt, RedeemedGrant, WrappingKey};
use sudp::passkey::WebAuthn;
use sudp::primitives::StdPrimitives;

use crate::error::{AppError, Result};
use crate::protocol::Operation;
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;
use crate::storage::plaintext::VaultPlaintextView;
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
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    validate_vault_id(&vault_id)?;
    let vault_path = state.tenants.vault_path(&vault_id)?;
    let Some(vault) = crate::storage::sealed_vault::read(&vault_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "passkeys": [] })));
    };
    let metas: Vec<PasskeyMeta> = vault
        .credentials
        .iter()
        .map(|c| {
            // Emit credential_id as base64url-no-pad. credentialId is the one
            // sudp field that crosses the WebAuthn boundary (W3C spec specifies
            // base64url here) and that appears in URL paths on the pro-backend.
            // Everything else (prf_salt, wrapped_key, ciphertext, signatures…)
            // stays strict-STANDARD — those don't have the same cross-system
            // / URL-safety pressure.
            let cid_b64 = URL_SAFE_NO_PAD.encode(&c.credential_id);
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

/// `GET /c/pubkey` — custodian-level HPKE public key.
///
/// Placeholder: HPKE outer-envelope is not yet implemented (M1 in
/// protocol-md-review). Returns `{ hpke_supported: false }` so clients can
/// detect non-support and fall back to TLS-only confidentiality.
pub async fn pubkey(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "hpke_supported": false,
        "note": "HPKE outer envelope (sc_pk) not yet implemented; see PROTOCOL.md M1.",
    }))
}

/// Decrypt vault and return a parsed v3 view of the plaintext. Used by
/// `approve.rs` for Export/Use act dispatch and by the unlock-bootstrap
/// path. Hard-fails on `version != 3` (callers should treat this as
/// "user must re-enroll under the new binary").
pub fn decrypt_vault_view(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<VaultPlaintextView> {
    let redeemed = RedeemedGrant {
        o: op.clone(),
        credential_id: credential_id_bytes.to_vec(),
        wrapping_key: WrappingKey::from_bytes(wrapping_key.to_vec()),
        opt: GrantOpt::default(),
    };
    let opened = sudp::phases::consumption::open::<StdPrimitives>(&redeemed, vault)
        .map_err(|e| AppError::Unauthorized(format!("vault open: {}", e)))?;
    let view = VaultPlaintextView::from_protected_state(&opened.m)?;
    let _ = redeemed_zeroize_marker();
    Ok(view)
}

fn redeemed_zeroize_marker() -> std::marker::PhantomData<WebAuthn> {
    std::marker::PhantomData
}
