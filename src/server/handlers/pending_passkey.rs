//! `POST /v/{vid}/pending-passkeys` — Stage 1 of the cross-device
//! add-passkey flow. See `storage::pending_passkey` for the lifecycle
//! and Stage 2 (the existing `Enroll(target="passkeys")` handler).
//!
//! ## What the body is
//!
//! ```json
//! {
//!   "credential_id": "<base64url-no-pad>",
//!   "x": "<base64 P-256 x coord, 32B>",
//!   "y": "<base64 P-256 y coord, 32B>",
//!   "prf_salt": "<base64 32B>",
//!   "device_name": "Mac · quiet-willow",
//!   "enc": "<base64url-no-pad HPKE encapsulated key, 32B X25519>",
//!   "ct":  "<base64url-no-pad HPKE ciphertext, sealed user_key_initial + tag>",
//!   "assertion": {
//!     "authenticatorData": "<base64>",
//!     "clientDataJSON": "<base64>",
//!     "signature": "<base64>",
//!     "credentialId": "<base64url, same as outer>"
//!   }
//! }
//! ```
//!
//! ## Authn: self-assertion bound to payload hash
//!
//! Anyone with network access can hit this endpoint, so we need
//! cryptographic proof that the uploader controls the credential they
//! claim. We do this by having the client sign — with the **new**
//! credential it just created — a WebAuthn assertion whose
//! `clientDataJSON.challenge` equals `SHA-256(canonical(payload\\assertion))`.
//!
//! The daemon recomputes the same hash from the request body, runs the
//! standard `verify_assertion`, and confirms the signing key is
//! `(x, y)`. This binds the assertion to the **entire** payload — Mallory
//! can't swap fields (cid, sealed user_key, etc.) and still produce a
//! valid signature.
//!
//! ## What we DON'T enforce here
//!
//! - Stage 2 (Enroll(target="passkeys")) is what authorizes actually
//!   joining the vault. Stage 1 just stages opaque material. So we
//!   accept any well-formed self-attested deposit; the Stage 2 user
//!   reviews the device_name in the approval UI and decides.
//! - The HPKE ciphertext is NOT decrypted here. It stays opaque until
//!   Stage 2 consumption.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto::canonical::canonicalize;
use crate::error::{AppError, Result};
use crate::passkey::webauthn::{verify_assertion, AssertionData};
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;
use crate::storage::pending_passkey::{put, PendingPasskey, PENDING_PASSKEY_TTL_SECS};

#[derive(Debug, Deserialize)]
pub struct PendingPasskeyRequest {
    pub credential_id: String,
    pub x: String,
    pub y: String,
    pub prf_salt: String,
    pub device_name: String,
    pub enc: String,
    pub ct: String,
    pub assertion: AssertionData,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(body): Json<PendingPasskeyRequest>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;

    // 1. Length sanity. WebAuthn credentialIds are bounded; the rest
    //    are fixed-size after b64 decode but checking length early
    //    rejects obviously malformed payloads before the crypto work.
    if body.credential_id.is_empty() || body.credential_id.len() > 1024 {
        return Err(AppError::BadRequest("credential_id length out of range".into()));
    }
    if body.device_name.len() > 128 {
        return Err(AppError::BadRequest("device_name too long (max 128)".into()));
    }

    // 2. Recompute the payload hash that the client should have signed.
    //    Canonical JSON over everything except `assertion` itself
    //    (you can't sign over your own signature). Field set must match
    //    what the client signs — see frontend lib/passkey-vault-primitive.ts.
    let payload_for_hash = json!({
        "credential_id": body.credential_id,
        "x": body.x,
        "y": body.y,
        "prf_salt": body.prf_salt,
        "device_name": body.device_name,
        "enc": body.enc,
        "ct": body.ct,
    });
    let canonical_bytes = canonicalize(&payload_for_hash);
    let payload_hash: [u8; 32] = {
        let d = Sha256::digest(&canonical_bytes);
        d.into()
    };

    // 3. Verify the assertion against the claimed (x, y). If it verifies,
    //    the uploader provably controls the credential they're depositing.
    verify_assertion(
        &body.assertion,
        &body.x,
        &body.y,
        &state.config.origin,
        &state.config.rp_id,
        &payload_hash,
    )?;

    // 4. Store. TTL clock starts now.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pending = PendingPasskey {
        credential_id: body.credential_id.clone(),
        x: body.x,
        y: body.y,
        prf_salt: body.prf_salt,
        device_name: body.device_name,
        enc: body.enc,
        ct: body.ct,
        created_at: now,
    };
    put(&state.vaults, &vault_id, &pending)?;

    tracing::info!(
        vault = %vault_id,
        cred = %body.credential_id,
        "pending-passkey deposited"
    );

    Ok(Json(json!({
        "ok": true,
        "credential_id": body.credential_id,
        "ttl_seconds": PENDING_PASSKEY_TTL_SECS,
    })))
}
