//! Vault-scoped and custodian-level read-only endpoints.
//!
//! - `GET /v/{vid}/passkeys` — list this vault's enrolled credentials (public metadata only)
//! - `GET /pubkey`           — custodian's HPKE public key (bootstrap for outer envelope)
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
    let vault_path = state.vaults.vault_path(&vault_id)?;
    let Some(vault) = crate::storage::sealed_vault::read(&vault_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "passkeys": [] })));
    };
    // F-24: prf_salt exposure mitigation.
    //
    // Protocol constraint: prf_salt IS required by the client to run WebAuthn
    // PRF and derive W_c for the vault-unlock ceremony — the ceremony begins
    // from the Locked state. Suppressing prf_salt universally when locked
    // would therefore break unlock. The correct long-term fix is a session-
    // token gate on this endpoint so only the authenticated vault owner can
    // retrieve the salt.
    //
    // For now we add a tracing event when the vault is locked so operators can
    // see unauthenticated probes in their logs, and include a TODO so this is
    // not forgotten.
    //
    // TODO: Add a lightweight session-token requirement to this endpoint so
    // prf_salt is only returned to the authenticated vault owner (F-24).
    if state.is_vault_locked(&vault_id) {
        tracing::debug!(vault = %vault_id, "GET /passkeys while vault locked — prf_salt returned; TODO: gate on session token (F-24)");
    }
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
    // Pending-passkey deposits (Stage 1 done, awaiting Stage 2 Enroll).
    // list() opportunistically GC-sweeps expired files — that's the only
    // place we know the daemon is actively serving this vault. Failure to
    // list isn't fatal: pending list just renders empty.
    let pending: Vec<Value> = crate::storage::pending_passkey::list(&state.vaults, &vault_id)
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.public_metadata())
        .collect();
    Ok(Json(json!({
        "vault_exists": true,
        "passkeys": metas,
        "pending_passkeys": pending,
    })))
}

/// `GET /pubkey` — daemon HPKE outer-envelope public key (PROTOCOL.md §4.2.1 M1).
///
/// Returns the daemon's static `sc_pk` plus the suite identifier so clients
/// can pick the matching HPKE implementation. Currently used by the
/// pending-passkey deposit flow (cross-device add-passkey); future use:
/// `[HPKE: MUST]` grant submissions.
///
/// `sc_pk_fingerprint` lets remote clients OOB-verify the key on first pin
/// (per PROTOCOL.md §4.2.2 trust establishment).
pub async fn pubkey(State(state): State<Arc<AppState>>) -> Json<Value> {
    use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
    use sha2::{Digest, Sha256};
    let pk_bytes = state.sc.pk_bytes();
    let fp = Sha256::digest(&pk_bytes);
    Json(json!({
        "hpke_supported": true,
        "kem": "x25519-hkdf-sha256",
        "kdf": "hkdf-sha256",
        "aead": "chacha20-poly1305",
        "sc_pk": URL_SAFE_NO_PAD.encode(&pk_bytes),
        "sc_pk_fingerprint": STANDARD.encode(fp),
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
