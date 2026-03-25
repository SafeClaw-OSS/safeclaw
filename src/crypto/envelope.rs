/// DEK/KEK envelope encryption.
///
/// - DEK (Data Encryption Key): random 32 bytes, encrypts vault.enc
/// - KEK (Key Encryption Key): derived per-passkey via HKDF, wraps DEK
///
/// Wrapped DEK file format: iv(12) || encrypted_dek+tag (same as AES-GCM sealed format)
use rand::{rngs::OsRng, RngCore};

use crate::crypto::aes::{aes_decrypt, aes_encrypt};
use crate::error::Result;

/// Generate a random 32-byte DEK
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Wrap (encrypt) a DEK with the KEK using AES-256-GCM.
/// Returns iv(12) || ciphertext+tag
pub fn wrap_dek(dek: &[u8; 32], kek: &[u8; 32]) -> Result<Vec<u8>> {
    aes_encrypt(kek, dek)
}

/// Unwrap (decrypt) a wrapped DEK using the KEK.
/// Input: iv(12) || ciphertext+tag
pub fn unwrap_dek(wrapped: &[u8], kek: &[u8; 32]) -> Result<[u8; 32]> {
    let plaintext = aes_decrypt(kek, wrapped)
        .map_err(|_| crate::error::AppError::Unauthorized("DEK unwrap failed — wrong key?".into()))?;
    if plaintext.len() != 32 {
        return Err(crate::error::AppError::Internal(
            format!("Unwrapped DEK is {} bytes (expected 32)", plaintext.len())
        ));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

/// Encrypt vault contents with DEK
pub fn encrypt_vault(dek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    aes_encrypt(dek, plaintext)
}

/// Decrypt vault contents with DEK
pub fn decrypt_vault(dek: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    aes_decrypt(dek, sealed)
}
