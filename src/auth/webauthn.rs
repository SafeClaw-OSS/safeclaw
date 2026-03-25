/// WebAuthn assertion verification for P-256 ECDSA.
///
/// Protocol:
///   1. Decode authenticatorData, clientDataJSON, signature from base64
///   2. Check clientDataJSON.type === "webauthn.get"
///   3. Check clientDataJSON.origin matches expected origin
///   4. Check rpIdHash (first 32 bytes of authenticatorData) = SHA-256(rpId)
///   5. Check UP flag (bit 0 of byte 32 in authenticatorData)
///   6. Parse DER signature to raw r||s (64 bytes)
///   7. Verify P-256 ECDSA over SHA-256(authenticatorData || SHA-256(clientDataJSON))
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use serde::Deserialize;

use crate::crypto::keys::public_key_from_xy;
use crate::error::{AppError, Result};

/// Assertion data as sent by the browser client (all fields are standard base64)
#[derive(Debug, Deserialize, Clone)]
pub struct AssertionData {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String, // base64
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64
    pub signature: String, // base64 (DER-encoded ECDSA signature)
}

/// Parse DER-encoded ECDSA signature to raw r||s (64 bytes).
///
/// DER format: 30 <seq_len> 02 <r_len> <r> 02 <s_len> <s>
/// r and s may have a leading 0x00 byte for sign encoding — strip it.
fn der_to_raw_rs(der: &[u8]) -> Result<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(AppError::Unauthorized("Invalid DER signature: bad SEQUENCE header".into()));
    }
    let seq_len = der[1] as usize;
    if seq_len + 2 > der.len() {
        return Err(AppError::Unauthorized("Invalid DER signature: length mismatch".into()));
    }

    let mut offset = 2usize;

    // Parse r
    if der[offset] != 0x02 {
        return Err(AppError::Unauthorized("Invalid DER signature: expected INTEGER tag for r".into()));
    }
    let r_len = der[offset + 1] as usize;
    if offset + 2 + r_len > der.len() {
        return Err(AppError::Unauthorized("Invalid DER signature: r overflows buffer".into()));
    }
    let r = &der[offset + 2..offset + 2 + r_len];
    offset += 2 + r_len;

    // Parse s
    if offset >= der.len() || der[offset] != 0x02 {
        return Err(AppError::Unauthorized("Invalid DER signature: expected INTEGER tag for s".into()));
    }
    let s_len = der[offset + 1] as usize;
    if offset + 2 + s_len > der.len() {
        return Err(AppError::Unauthorized("Invalid DER signature: s overflows buffer".into()));
    }
    let s = &der[offset + 2..offset + 2 + s_len];

    // Right-align r and s into 32-byte arrays (strip leading zeros, pad on left)
    let mut result = [0u8; 64];
    let r_take = r.len().min(32);
    let r_src_start = r.len() - r_take;
    let r_dst_start = 32 - r_take;
    result[r_dst_start..32].copy_from_slice(&r[r_src_start..]);

    let s_take = s.len().min(32);
    let s_src_start = s.len() - s_take;
    let s_dst_start = 32 + (32 - s_take);
    result[s_dst_start..64].copy_from_slice(&s[s_src_start..]);

    Ok(result)
}

/// Verify a WebAuthn assertion.
///
/// `x` and `y` are the passkey public key coordinates as standard base64.
/// Returns Ok(()) if valid, Err if invalid.
pub fn verify_assertion(
    assertion: &AssertionData,
    x_b64: &str,
    y_b64: &str,
    expected_origin: &str,
    rp_id: &str,
) -> Result<()> {
    // Decode fields
    let auth_data = STANDARD
        .decode(&assertion.authenticator_data)
        .map_err(|e| AppError::Unauthorized(format!("Bad authenticatorData: {}", e)))?;
    let client_data_json = STANDARD
        .decode(&assertion.client_data_json)
        .map_err(|e| AppError::Unauthorized(format!("Bad clientDataJSON: {}", e)))?;
    let sig_der = STANDARD
        .decode(&assertion.signature)
        .map_err(|e| AppError::Unauthorized(format!("Bad signature: {}", e)))?;

    // Parse clientDataJSON
    let client_obj: serde_json::Value = serde_json::from_slice(&client_data_json)
        .map_err(|_| AppError::Unauthorized("clientDataJSON is not valid JSON".into()))?;

    // Check type
    if client_obj.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(AppError::Unauthorized(
            "clientDataJSON.type is not 'webauthn.get'".into(),
        ));
    }

    // Check origin
    let origin = client_obj
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Missing origin in clientDataJSON".into()))?;
    if origin != expected_origin {
        return Err(AppError::Unauthorized(format!(
            "Origin mismatch: expected {}, got {}",
            expected_origin, origin
        )));
    }

    // Check rpIdHash (first 32 bytes of authenticatorData)
    if auth_data.len() < 37 {
        return Err(AppError::Unauthorized("authenticatorData too short".into()));
    }
    let expected_rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let actual_rp_id_hash = &auth_data[..32];
    if expected_rp_id_hash.as_slice() != actual_rp_id_hash {
        return Err(AppError::Unauthorized("rpIdHash mismatch".into()));
    }

    // Check UP (User Present) flag — bit 0 of flags byte at offset 32
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(AppError::Unauthorized("User Present flag not set".into()));
    }

    // Build signed data: authenticatorData || SHA-256(clientDataJSON)
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    // Parse passkey public key (x, y are standard base64 in passkeys.json)
    let x_bytes = STANDARD
        .decode(x_b64)
        .map_err(|e| AppError::Unauthorized(format!("Bad passkey x coordinate: {}", e)))?;
    let y_bytes = STANDARD
        .decode(y_b64)
        .map_err(|e| AppError::Unauthorized(format!("Bad passkey y coordinate: {}", e)))?;

    let pk = public_key_from_xy(&x_bytes, &y_bytes)?;
    let vk = VerifyingKey::from(&pk);

    // Parse DER signature to raw r||s
    let raw_sig = der_to_raw_rs(&sig_der)?;

    // Verify ECDSA-P256 signature (p256::ecdsa::VerifyingKey::verify hashes with SHA-256)
    let sig = Signature::try_from(raw_sig.as_slice())
        .map_err(|e| AppError::Unauthorized(format!("Invalid signature format: {}", e)))?;

    vk.verify(&signed_data, &sig)
        .map_err(|_| AppError::Unauthorized("Signature verification failed".into()))
}
