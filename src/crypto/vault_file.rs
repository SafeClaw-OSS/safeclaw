//! `vault.enc` v1 file format.
//!
//! Layout (see `docs/PROTOCOL.md` §6.2):
//!
//! ```text
//! [ "SCV2" | u16 ver | u16 reserved | [u8; 24] aead_nonce | ciphertext || tag ]
//! ```
//!
//! The plaintext is UTF-8 encoded JSON. The AEAD associated data is:
//!
//! ```text
//! aad = "safeclaw/v1/vault\x00" || u16_be(version) || aead_nonce
//! ```

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::crypto::aead::{self, KEY_LEN, NONCE_LEN};
use crate::error::{AppError, Result};

const MAGIC: &[u8; 4] = b"SCV1";
const VERSION: u16 = 0x0001;
const HEADER_LEN: usize = 4 + 2 + 2 + NONCE_LEN; // 32

const VAULT_AAD_PREFIX: &[u8] = b"safeclaw/v1/vault\x00";

fn build_aad(version: u16, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VAULT_AAD_PREFIX.len() + 2 + NONCE_LEN);
    aad.extend_from_slice(VAULT_AAD_PREFIX);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad
}

/// Check whether the given bytes appear to be a valid vault file.
pub fn is_valid_version(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == MAGIC
}

/// Encrypt the vault plaintext JSON bytes, producing a complete vault.enc payload.
pub fn encrypt_vault(dek: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = aead::fresh_nonce();
    let aad = build_aad(VERSION, &nonce);
    let ct = aead::encrypt(dek, &nonce, plaintext, &aad)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&[0u8, 0u8]); // reserved
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a vault.enc payload back to its JSON plaintext bytes.
pub fn decrypt_vault(dek: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < HEADER_LEN {
        return Err(AppError::BadRequest("vault.enc too short".into()));
    }
    if &sealed[..4] != MAGIC {
        return Err(AppError::BadRequest(
            "vault.enc has wrong magic (not a valid file)".into(),
        ));
    }
    let version = u16::from_be_bytes([sealed[4], sealed[5]]);
    if version != VERSION {
        return Err(AppError::BadRequest(format!(
            "vault.enc: unsupported version 0x{:04x}",
            version
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[8..8 + NONCE_LEN]);
    let ct = &sealed[HEADER_LEN..];
    let aad = build_aad(version, &nonce);
    aead::decrypt(dek, &nonce, ct, &aad)
}

/// Write `vault.enc` atomically to disk at the given path.
pub fn save_atomic(path: &Path, dek: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<()> {
    let sealed = encrypt_vault(dek, plaintext)?;
    let tmp = path.with_extension("enc.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| AppError::Internal(format!("open tmp: {}", e)))?;
        f.write_all(&sealed)
            .map_err(|e| AppError::Internal(format!("write tmp: {}", e)))?;
        f.sync_all()
            .map_err(|e| AppError::Internal(format!("fsync tmp: {}", e)))?;
    }
    fs::rename(&tmp, path)
        .map_err(|e| AppError::Internal(format!("rename tmp: {}", e)))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

// ─── files/*.enc v1 format ───────────────────────────────────────────────────

const FILE_MAGIC: &[u8; 4] = b"SCF1";
const FILE_AAD_PREFIX: &[u8] = b"safeclaw/v1/file\x00";
const FILE_HEADER_LEN: usize = 4 + 2 + 2 + NONCE_LEN;

fn file_aad(version: u16, nonce: &[u8; NONCE_LEN], file_uuid: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_AAD_PREFIX.len() + 2 + NONCE_LEN + file_uuid.len());
    aad.extend_from_slice(FILE_AAD_PREFIX);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(file_uuid.as_bytes());
    aad
}

/// Encrypt a file under its per-file random DEK. Returns the complete file
/// payload (magic + header + ciphertext).
pub fn encrypt_file(file_key: &[u8; KEY_LEN], file_uuid: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = aead::fresh_nonce();
    let aad = file_aad(VERSION, &nonce, file_uuid);
    let ct = aead::encrypt(file_key, &nonce, plaintext, &aad)?;
    let mut out = Vec::with_capacity(FILE_HEADER_LEN + ct.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&[0u8, 0u8]);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a file payload.
pub fn decrypt_file(file_key: &[u8; KEY_LEN], file_uuid: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < FILE_HEADER_LEN {
        return Err(AppError::BadRequest("file too short".into()));
    }
    if &sealed[..4] != FILE_MAGIC {
        return Err(AppError::BadRequest("file has wrong magic".into()));
    }
    let version = u16::from_be_bytes([sealed[4], sealed[5]]);
    if version != VERSION {
        return Err(AppError::BadRequest(format!(
            "file: unsupported version 0x{:04x}",
            version
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[8..8 + NONCE_LEN]);
    let ct = &sealed[FILE_HEADER_LEN..];
    let aad = file_aad(version, &nonce, file_uuid);
    aead::decrypt(file_key, &nonce, ct, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip() {
        let dek = [0x42u8; 32];
        let plain = br#"{"services":{"openai":{"key":"sk-xxx"}}}"#;
        let sealed = encrypt_vault(&dek, plain).unwrap();
        assert!(is_valid_version(&sealed));
        let out = decrypt_vault(&dek, &sealed).unwrap();
        assert_eq!(out.as_slice(), plain.as_slice());
    }

    #[test]
    fn vault_wrong_key_fails() {
        let dek = [0x42u8; 32];
        let mut other = [0x42u8; 32];
        other[0] = 0x43;
        let sealed = encrypt_vault(&dek, b"secret").unwrap();
        assert!(decrypt_vault(&other, &sealed).is_err());
    }

    #[test]
    fn vault_tamper_fails() {
        let dek = [0x42u8; 32];
        let mut sealed = encrypt_vault(&dek, b"secret data").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(decrypt_vault(&dek, &sealed).is_err());
    }

    #[test]
    fn file_roundtrip() {
        let k = [0x99u8; 32];
        let plain = b"file contents here, binary ok \x00\x01\x02";
        let sealed = encrypt_file(&k, "abc-uuid", plain).unwrap();
        let out = decrypt_file(&k, "abc-uuid", &sealed).unwrap();
        assert_eq!(out.as_slice(), plain.as_slice());
    }

    #[test]
    fn file_wrong_uuid_fails() {
        let k = [0x99u8; 32];
        let sealed = encrypt_file(&k, "a", b"x").unwrap();
        assert!(decrypt_file(&k, "b", &sealed).is_err());
    }
}
