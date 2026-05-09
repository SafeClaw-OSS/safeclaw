//! WebAuthn assertion verification for SafeClaw v1.
//!
//! Full verification checks (WebAuthn L3 §7.2):
//!   1. Decode `authenticatorData`, `clientDataJSON`, `signature` from base64.
//!   2. Parse clientDataJSON and check `type == "webauthn.get"`.
//!   3. Check `clientDataJSON.origin` equals expected origin (constant-time).
//!   4. **Check `clientDataJSON.challenge` equals the expected binding** .
//!   5. Check `authenticatorData.rpIdHash == SHA-256(rpId)`.
//!   6. Check the User Present (UP) flag.
//!   7. Parse DER signature to raw r||s (64B).
//!   8. Verify ECDSA-P-256 over `authenticatorData || SHA-256(clientDataJSON)`.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::binding::constant_time_eq;
use crate::crypto::keys::public_key_from_xy;
use crate::error::{AppError, Result};

/// Assertion data as sent by the browser client.
///
/// All base64 fields are **standard** base64 (with padding). The `credential_id`
/// field is optional and used only for defensive sanity checks.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AssertionData {
    #[serde(rename = "credentialId", default, alias = "credential_id")]
    pub credential_id: Option<String>,
    #[serde(rename = "authenticatorData", alias = "authenticator_data")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON", alias = "client_data_json")]
    pub client_data_json: String,
    pub signature: String,
}

/// Expected assertion type. For `navigator.credentials.get` this is always `webauthn.get`.
/// For `navigator.credentials.create` (setup / add passkey), it is `webauthn.create`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AssertionKind {
    Get,
    Create,
}

impl AssertionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssertionKind::Get => "webauthn.get",
            AssertionKind::Create => "webauthn.create",
        }
    }
}

/// Verify a WebAuthn assertion with channel binding.
///
/// Arguments:
/// - `assertion`: the parsed assertion fields (standard base64).
/// - `x_b64`, `y_b64`: the credential's public key coordinates, standard base64.
/// - `expected_origin`: the configured origin to compare against `clientDataJSON.origin`.
/// - `rp_id`: the WebAuthn relying party ID (hostname only).
/// - `expected_challenge`: the 32-byte binding hash the client should have used as
///   the WebAuthn challenge. On success, `clientDataJSON.challenge` (after base64url
///   decode) must equal this.
/// - `kind`: the expected `clientDataJSON.type` value.
///
/// Returns `Ok(())` if the assertion is fully valid. Any failure returns an
/// `AppError::Unauthorized`. Error messages do not distinguish which individual
/// check failed, to avoid timing side channels.
pub fn verify_assertion(
    assertion: &AssertionData,
    x_b64: &str,
    y_b64: &str,
    expected_origin: &str,
    rp_id: &str,
    expected_challenge: &[u8; 32],
    kind: AssertionKind,
) -> Result<()> {
    // 1. Decode fields.
    let auth_data = STANDARD
        .decode(&assertion.authenticator_data)
        .map_err(|_| AppError::Unauthorized("bad authenticatorData".into()))?;
    let client_data_json = STANDARD
        .decode(&assertion.client_data_json)
        .map_err(|_| AppError::Unauthorized("bad clientDataJSON".into()))?;
    let sig_der = STANDARD
        .decode(&assertion.signature)
        .map_err(|_| AppError::Unauthorized("bad signature".into()))?;

    // 2. Parse clientDataJSON and check type.
    let client_obj: serde_json::Value = serde_json::from_slice(&client_data_json)
        .map_err(|_| AppError::Unauthorized("clientDataJSON not JSON".into()))?;

    let cd_type = client_obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("clientDataJSON missing type".into()))?;
    if cd_type != kind.as_str() {
        return Err(AppError::Unauthorized(format!(
            "clientDataJSON.type is not {}",
            kind.as_str()
        )));
    }

    // 3. Origin.
    let origin = client_obj
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("clientDataJSON missing origin".into()))?;
    if !constant_time_eq(origin.as_bytes(), expected_origin.as_bytes()) {
        return Err(AppError::Unauthorized(format!(
            "origin mismatch: expected {}, got {}",
            expected_origin, origin
        )));
    }

    // 4. Challenge (channel binding check).
    let challenge_b64u = client_obj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("clientDataJSON missing challenge".into()))?;
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge_b64u)
        .map_err(|_| AppError::Unauthorized("challenge not base64url".into()))?;
    if challenge_bytes.len() != 32 {
        return Err(AppError::Unauthorized(format!(
            "challenge wrong length: {} (expected 32)",
            challenge_bytes.len()
        )));
    }
    if !constant_time_eq(&challenge_bytes, expected_challenge) {
        return Err(AppError::Unauthorized("channel binding mismatch".into()));
    }

    // 5. rpIdHash.
    if auth_data.len() < 37 {
        return Err(AppError::Unauthorized("authenticatorData too short".into()));
    }
    let expected_rp_id_hash = Sha256::digest(rp_id.as_bytes());
    if !constant_time_eq(&auth_data[..32], expected_rp_id_hash.as_slice()) {
        return Err(AppError::Unauthorized("rpIdHash mismatch".into()));
    }

    // 6. UP flag.
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(AppError::Unauthorized("User Present flag not set".into()));
    }

    // 7 & 8. Verify signature.
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_data_hash);

    let x_bytes = STANDARD
        .decode(x_b64)
        .map_err(|_| AppError::Unauthorized("bad passkey x".into()))?;
    let y_bytes = STANDARD
        .decode(y_b64)
        .map_err(|_| AppError::Unauthorized("bad passkey y".into()))?;
    let pk = public_key_from_xy(&x_bytes, &y_bytes)?;
    let vk = VerifyingKey::from(&pk);

    let raw_sig = der_to_raw_rs(&sig_der)?;
    let sig = Signature::try_from(raw_sig.as_slice())
        .map_err(|_| AppError::Unauthorized("invalid signature format".into()))?;

    vk.verify(&signed, &sig)
        .map_err(|_| AppError::Unauthorized("signature verification failed".into()))
}

/// Parse a DER-encoded ECDSA signature to raw `r||s` (64 bytes).
fn der_to_raw_rs(der: &[u8]) -> Result<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(AppError::Unauthorized("bad DER: SEQUENCE".into()));
    }
    let seq_len = der[1] as usize;
    if seq_len + 2 > der.len() {
        return Err(AppError::Unauthorized("bad DER: length".into()));
    }
    let mut offset = 2usize;

    if der[offset] != 0x02 {
        return Err(AppError::Unauthorized("bad DER: r tag".into()));
    }
    let r_len = der[offset + 1] as usize;
    if offset + 2 + r_len > der.len() {
        return Err(AppError::Unauthorized("bad DER: r overflow".into()));
    }
    let r = &der[offset + 2..offset + 2 + r_len];
    offset += 2 + r_len;

    if offset >= der.len() || der[offset] != 0x02 {
        return Err(AppError::Unauthorized("bad DER: s tag".into()));
    }
    let s_len = der[offset + 1] as usize;
    if offset + 2 + s_len > der.len() {
        return Err(AppError::Unauthorized("bad DER: s overflow".into()));
    }
    let s = &der[offset + 2..offset + 2 + s_len];

    let mut out = [0u8; 64];
    let r_take = r.len().min(32);
    let r_src_start = r.len() - r_take;
    let r_dst_start = 32 - r_take;
    out[r_dst_start..32].copy_from_slice(&r[r_src_start..]);

    let s_take = s.len().min(32);
    let s_src_start = s.len() - s_take;
    let s_dst_start = 32 + (32 - s_take);
    out[s_dst_start..64].copy_from_slice(&s[s_src_start..]);

    Ok(out)
}
