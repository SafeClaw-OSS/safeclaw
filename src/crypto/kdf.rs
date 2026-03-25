use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{AppError, Result};

/// HKDF-SHA256(ikm=user_key, salt=sk_d, info="safeclaw-kek-v1") → 32-byte KEK
pub fn derive_kek(user_key: &[u8], sk_d: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(sk_d), user_key);
    let mut okm = [0u8; 32];
    hkdf.expand(b"safeclaw-kek-v1", &mut okm)
        .map_err(|e| AppError::Internal(format!("HKDF expand (KEK) failed: {}", e)))?;
    Ok(okm)
}

/// HKDF-SHA256(ikm=shared_secret, salt=zeros(32), info="safeclaw-e2e") → 32-byte AES key
///
/// Note: Zero salt is acceptable because the ephemeral key pair provides per-message
/// uniqueness — HKDF-Expand still produces a fresh key for each encryption.
pub fn derive_e2e_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_secret);
    let mut okm = [0u8; 32];
    hkdf.expand(b"safeclaw-e2e", &mut okm)
        .map_err(|e| AppError::Internal(format!("HKDF expand (E2E) failed: {}", e)))?;
    Ok(okm)
}

/// HKDF-SHA256(ikm=user_key, salt=nonce, info="safeclaw-response-v1") → 32-byte response key
pub fn derive_response_key(user_key: &[u8], nonce: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), user_key);
    let mut okm = [0u8; 32];
    hkdf.expand(b"safeclaw-response-v1", &mut okm)
        .map_err(|e| AppError::Internal(format!("HKDF expand (response) failed: {}", e)))?;
    Ok(okm)
}
