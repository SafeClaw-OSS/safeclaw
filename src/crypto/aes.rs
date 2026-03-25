use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{AppError, Result};

const IV_LEN: usize = 12;

/// Encrypt plaintext with AES-256-GCM.
/// Wire format: iv(12) || ciphertext+tag
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&iv);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Internal(format!("AES-GCM encrypt failed: {}", e)))?;

    let mut result = Vec::with_capacity(IV_LEN + ct.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ct);
    Ok(result)
}

/// Decrypt sealed data with AES-256-GCM.
/// Input format: iv(12) || ciphertext+tag
pub fn aes_decrypt(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < IV_LEN {
        return Err(AppError::BadRequest("Sealed data too short".into()));
    }
    let iv = &sealed[..IV_LEN];
    let ct = &sealed[IV_LEN..];

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ct)
        .map_err(|_| AppError::Unauthorized("Decryption failed".into()))
}

/// Encrypt with a zeroizable key
pub fn aes_encrypt_zeroize(key: &mut [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let result = aes_encrypt(key, plaintext);
    key.zeroize();
    result
}

/// Decrypt with a zeroizable key
pub fn aes_decrypt_zeroize(key: &mut [u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    let result = aes_decrypt(key, sealed);
    key.zeroize();
    result
}
