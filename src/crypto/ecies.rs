/// E2E encryption/decryption using P-256 ECDH + HKDF-SHA256 + AES-256-GCM.
///
/// Wire format: JSON { epk: JWK, iv: base64 (standard), ct: base64 (standard) }
/// The JSON bytes are what's actually encrypted/decrypted.
///
/// Decryption side (server):
///   1. Parse JSON wire format
///   2. Import ephemeral public key from JWK
///   3. ECDH(server_sk, epk) → shared_secret
///   4. HKDF-SHA256(salt=zeros(32), info="safeclaw-e2e") → aes_key
///   5. AES-256-GCM decrypt(aes_key, iv, ct) → plaintext
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdh::diffie_hellman;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::aes::aes_decrypt;
use crate::crypto::kdf::derive_e2e_key;
use crate::crypto::keys::{jwk_pk_to_public_key, secret_key_from_bytes, JwkPublicKey};
use crate::error::{AppError, Result};

/// Wire format for E2E encrypted payload
#[derive(Debug, Serialize, Deserialize)]
pub struct E2eWire {
    pub epk: EpkJwk,
    pub iv: String,  // standard base64
    pub ct: String,  // standard base64 (ciphertext + 16-byte GCM tag)
}

/// Ephemeral public key in JWK format (as sent by WebCrypto)
#[derive(Debug, Serialize, Deserialize)]
pub struct EpkJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,   // base64url, no padding
    pub y: String,   // base64url, no padding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
}

/// Decrypt an E2E-encrypted payload using the server's VM private key.
///
/// `wire_bytes` is the JSON wire format (not base64-encoded, already decoded).
pub fn e2e_decrypt(wire_bytes: &[u8], sk_d: &[u8; 32]) -> Result<Vec<u8>> {
    // Parse wire JSON
    let wire: E2eWire = serde_json::from_slice(wire_bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid E2E wire format: {}", e)))?;

    // Decode iv and ct from standard base64
    let iv = STANDARD
        .decode(&wire.iv)
        .map_err(|e| AppError::BadRequest(format!("Invalid E2E iv: {}", e)))?;
    let ct = STANDARD
        .decode(&wire.ct)
        .map_err(|e| AppError::BadRequest(format!("Invalid E2E ct: {}", e)))?;

    if iv.len() != 12 {
        return Err(AppError::BadRequest(format!(
            "E2E iv must be 12 bytes, got {}",
            iv.len()
        )));
    }

    // Import ephemeral public key from JWK
    let epk_jwk_pub = JwkPublicKey {
        kty: wire.epk.kty.clone(),
        crv: wire.epk.crv.clone(),
        x: wire.epk.x.clone(),
        y: wire.epk.y.clone(),
        key_ops: None,
        ext: None,
    };
    let epk = jwk_pk_to_public_key(&epk_jwk_pub)?;

    // ECDH: server_sk × epk → shared_secret
    let server_sk = secret_key_from_bytes(sk_d)?;
    let nz_scalar = server_sk.to_nonzero_scalar();
    let shared_secret = diffie_hellman(&nz_scalar, epk.as_affine());

    // HKDF: derive AES key from shared secret
    let mut aes_key = derive_e2e_key(shared_secret.raw_secret_bytes().as_slice())?;

    // Build sealed = iv || ct (aes_decrypt expects this format)
    let mut sealed = Vec::with_capacity(12 + ct.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ct);

    // AES-256-GCM decrypt
    let plaintext = aes_decrypt(&aes_key, &sealed)
        .map_err(|_| AppError::Unauthorized("E2E decryption failed".into()))?;

    aes_key.zeroize();
    Ok(plaintext)
}
