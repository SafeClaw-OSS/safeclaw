//! XChaCha20-Poly1305 AEAD for v2.
//!
//! All v2 symmetric encryption (wrapped DEKs, vault.enc, files/*.enc, response seals)
//! uses XChaCha20-Poly1305 (24-byte nonce, 16-byte tag).
//!
//! Wire format is always `nonce(24) || ciphertext || tag(16)`, except that on-disk file
//! formats carry their own headers (magic/version/nonce) before the ciphertext.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{AppError, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Generate a fresh 24-byte XChaCha20 nonce.
pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Encrypt with XChaCha20-Poly1305 using a caller-supplied nonce and AAD.
/// Returns `ciphertext || tag`.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| AppError::Internal(format!("XChaCha20-Poly1305 encrypt: {}", e)))
}

/// Decrypt with XChaCha20-Poly1305 using a caller-supplied nonce and AAD.
/// Input is `ciphertext || tag`.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| AppError::Unauthorized("AEAD authentication failed".into()))
}

/// Convenience: encrypt with a fresh nonce. Returns `nonce || ciphertext || tag`.
/// Use this when the caller does not need to control the nonce separately.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = fresh_nonce();
    let mut ct = encrypt(key, &nonce, plaintext, aad)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.append(&mut ct);
    Ok(out)
}

/// Convenience: decrypt a `nonce || ciphertext || tag` blob.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::BadRequest("sealed blob too short".into()));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ct = &sealed[NONCE_LEN..];
    decrypt(key, &nonce, ct, aad)
}

/// Allocate a zeroizing `Vec<u8>` of the given capacity.
pub fn zeroizing_buf(cap: usize) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(Vec::with_capacity(cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let msg = b"hello safeclaw v1";
        let aad = b"safeclaw/v1/test";
        let sealed = seal(&key, msg, aad).unwrap();
        let out = open(&key, &sealed, aad).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x42u8; 32];
        let msg = b"hello";
        let sealed = seal(&key, msg, b"aad-a").unwrap();
        assert!(open(&key, &sealed, b"aad-b").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = [0x01u8; 32];
        let mut k2 = [0x01u8; 32];
        k2[0] = 0x02;
        let sealed = seal(&k1, b"hello", b"aad").unwrap();
        assert!(open(&k2, &sealed, b"aad").is_err());
    }

    #[test]
    fn tamper_fails() {
        let key = [0xAAu8; 32];
        let mut sealed = seal(&key, b"hello", b"aad").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&key, &sealed, b"aad").is_err());
    }

    #[test]
    fn fresh_nonces_differ() {
        let n1 = fresh_nonce();
        let n2 = fresh_nonce();
        assert_ne!(n1, n2);
    }
}
