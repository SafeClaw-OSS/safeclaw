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
    /// P-256 public key X coordinate (base64). Used by --reuse to skip create().
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_x: Option<String>,
    /// P-256 public key Y coordinate (base64). Used by --reuse to skip create().
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_y: Option<String>,
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
                public_key_x: pk.as_ref().map(|p| p.x.clone()),
                public_key_y: pk.as_ref().map(|p| p.y.clone()),
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

/// `POST /v/{vid}/sync` — on-demand cloud pull + complete-pending-connect
/// (backs `sc sync`). No passkey: it only advances already-sealed state (the
/// pull is device-key-authed; the connect re-seal uses the retained K and
/// no-ops if the vault is locked). The vault id is validated; the rest is
/// handled inside `sync::sync_vault_now`.
pub async fn sync_now(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Json<Value> {
    if let Err(e) = validate_vault_id(&vault_id) {
        return Json(json!({ "ok": false, "error": e.to_string() }));
    }
    match crate::sync::sync_vault_now(&state, &vault_id).await {
        Ok(pulled) => Json(json!({ "ok": true, "pulled": pulled })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
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

/// Like [`decrypt_vault_view`] but also returns the unwrapped state key `K`
/// (zeroized on drop) so the caller can RETAIN it for the unlocked session.
/// Used by the unlock + write paths so a later cloud-sync pull can refresh the
/// cache with `K` instead of forcing another passkey ([`decrypt_vault_view_with_key`]).
pub fn decrypt_vault_view_keep_key(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<(VaultPlaintextView, zeroize::Zeroizing<Vec<u8>>)> {
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
    Ok((view, opened.k))
}

/// Decrypt the vault's body ciphertext with a RETAINED state key `K` — no
/// grant, no passkey. The body is sealed under `K` with AAD `DS_SEAL ‖ ver`,
/// independent of any credential, so a held `K` opens it directly. Returns
/// `Unauthorized` if `K` can't open it (e.g. the writer rotated `K`), which
/// callers treat as graceful "lock+unlock to see new state". Used by the
/// cloud-sync refresh after a runtime pull. Reconstructs `seal_ad` from sudp's
/// public `DS_SEAL` (sudp's own `seal_ad` is crate-private).
pub fn decrypt_vault_view_with_key(
    k: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<VaultPlaintextView> {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    use sudp::state::ProtectedState;

    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&vault.version.to_be_bytes());

    let m_bytes = ChaCha20Poly1305::open(k, &vault.ciphertext, &ad)
        .map_err(|e| AppError::Unauthorized(format!("vault open (retained key): {}", e)))?;
    let m = ProtectedState::from_canonical(&m_bytes)
        .map_err(|e| AppError::Internal(format!("protected-state parse: {}", e)))?;
    VaultPlaintextView::from_protected_state(&m)
}

fn redeemed_zeroize_marker() -> std::marker::PhantomData<WebAuthn> {
    std::marker::PhantomData
}

/// Open the vault body to the RAW [`sudp::state::ProtectedState`] with a
/// RETAINED state key `K` — no grant, no passkey. Unlike
/// [`decrypt_vault_view_with_key`] (which projects to a read-only
/// `VaultPlaintextView`), this returns the full mutable `ProtectedState` so a
/// caller can edit `targets` and re-seal it with [`reseal_body_with_key`]
/// while preserving `peers`/`aux` byte-for-byte. Used by the OAuth-connect
/// processor (CONNECTIONS_AND_AUTH.md §4a), which writes
/// `<conn>_refresh_token` into the open vault and deletes the pending item —
/// the daemon's own connect-completion, no approval op (it holds `K` while
/// unlocked; an agent can't forge a Google login + a passkey-sealed code).
pub fn open_protected_state_with_key(
    k: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<sudp::state::ProtectedState> {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    use sudp::state::ProtectedState;

    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&vault.version.to_be_bytes());

    let m_bytes = ChaCha20Poly1305::open(k, &vault.ciphertext, &ad)
        .map_err(|e| AppError::Unauthorized(format!("vault open (retained key): {}", e)))?;
    ProtectedState::from_canonical(&m_bytes)
        .map_err(|e| AppError::Internal(format!("protected-state parse: {}", e)))
}

/// Re-seal a (possibly mutated) [`sudp::state::ProtectedState`] under the same
/// retained `K` and write the new body ciphertext into `vault.ciphertext`,
/// leaving `registry`/`credentials`/`wrapped_key` untouched (the body is
/// sealed under `K` with AAD `DS_SEAL ‖ ver`, independent of any credential —
/// see [`decrypt_vault_view_with_key`]). The caller persists the updated
/// `vault` via `write_atomic`. Companion to [`open_protected_state_with_key`].
pub fn reseal_body_with_key(
    k: &[u8],
    vault: &mut crate::storage::SealedVault,
    m: &sudp::state::ProtectedState,
) -> Result<()> {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};

    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&vault.version.to_be_bytes());

    let canonical = m
        .to_canonical()
        .map_err(|e| AppError::Internal(format!("protected-state canonicalize: {}", e)))?;
    let ciphertext = ChaCha20Poly1305::seal(k, &canonical[..], &ad)
        .map_err(|e| AppError::Internal(format!("vault re-seal: {}", e)))?;
    vault.ciphertext = ciphertext;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::plaintext::VaultAux;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    use sudp::state::{ProtectedState, CURRENT_VERSION};

    /// The retained-K refresh path: a vault's body is K-sealed with AAD
    /// `DS_SEAL ‖ ver`, independent of any credential, so a held `K` opens it
    /// with NO grant/passkey. This builds a real v3 ProtectedState, seals it
    /// under K exactly as the vault does, and asserts `decrypt_vault_view_with_key`
    /// recovers the target with the right K and rejects a wrong K (the graceful
    /// "rotated K → lock+unlock" path). Guards the seal_ad reconstruction.
    #[test]
    fn retained_key_opens_body_without_credential() {
        let k = vec![9u8; 32];
        let version: u16 = CURRENT_VERSION;

        let mut ps = ProtectedState::new();
        ps.aux = serde_json::to_value(VaultAux::initial()).unwrap();
        ps.put_target("openai_key", b"sk-test-123".to_vec());
        let canonical = ps.to_canonical().unwrap();

        let mut ad = Vec::new();
        ad.extend_from_slice(DS_SEAL);
        ad.extend_from_slice(&version.to_be_bytes());
        let ciphertext = ChaCha20Poly1305::seal(&k, &canonical[..], &ad).unwrap();

        // Empty registry/credentials — the body opens independent of any cred.
        let vault: crate::storage::SealedVault = serde_json::from_value(serde_json::json!({
            "version": version,
            "registry": {},
            "credentials": [],
            "ciphertext": STANDARD.encode(&ciphertext),
        }))
        .unwrap();

        let view = decrypt_vault_view_with_key(&k, &vault).expect("retained-K open");
        assert_eq!(
            view.native_secrets.get("openai_key").map(|v| v.as_slice()),
            Some(b"sk-test-123".as_ref())
        );

        // Wrong K (the rotated-K case) → AEAD open fails → Err (graceful).
        assert!(decrypt_vault_view_with_key(&vec![1u8; 32], &vault).is_err());
    }
}
