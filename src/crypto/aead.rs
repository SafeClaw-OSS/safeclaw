//! XChaCha20-Poly1305 AEAD — thin adapter over `sudp::primitives::ChaCha20Poly1305`.
//!
//! Wire format `nonce(24) ‖ ciphertext ‖ tag(16)` matches sudp's `seal`/`open`
//! contract exactly; we just bridge the error type (sudp::Error → AppError) and
//! preserve fixed-size array argument shapes for existing call sites.

use sudp::primitives::{Aead as SudpAead, ChaCha20Poly1305 as SudpCipher};

use crate::error::{AppError, Result};

pub const KEY_LEN: usize = <SudpCipher as SudpAead>::KEY_LEN; // 32
pub const NONCE_LEN: usize = <SudpCipher as SudpAead>::NONCE_LEN; // 24
pub const TAG_LEN: usize = <SudpCipher as SudpAead>::TAG_LEN; // 16

/// Generate a fresh 24-byte XChaCha20 nonce.
pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    let v = SudpCipher::fresh_nonce();
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&v);
    out
}

/// Encrypt with XChaCha20-Poly1305. Returns `ciphertext ‖ tag`.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    SudpCipher::encrypt(key, nonce, plaintext, aad)
        .map_err(|e| AppError::Internal(format!("XChaCha20-Poly1305 encrypt: {}", e)))
}

/// Decrypt with XChaCha20-Poly1305. Input is `ciphertext ‖ tag`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    SudpCipher::decrypt(key, nonce, ciphertext, aad)
        .map_err(|_| AppError::Unauthorized("AEAD authentication failed".into()))
}

/// One-shot seal with fresh nonce. Returns `nonce ‖ ciphertext ‖ tag`.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    SudpCipher::seal(key, plaintext, aad)
        .map_err(|e| AppError::Internal(format!("AEAD seal: {}", e)))
}

/// One-shot open of `nonce ‖ ciphertext ‖ tag`.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    SudpCipher::open(key, sealed, aad)
        .map_err(|e| match e {
            sudp::Error::SealDecryptionFailed => {
                AppError::Unauthorized("AEAD authentication failed".into())
            }
            sudp::Error::Malformed(msg) => AppError::BadRequest(msg.to_string()),
            other => AppError::Internal(format!("AEAD open: {}", other)),
        })
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
        let sealed = seal(&key, b"hello", b"aad-a").unwrap();
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
