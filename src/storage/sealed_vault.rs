//! SCSV (SafeClaw Sealed Vault) — toy v0 single-DEK simplification.
//!
//! On-disk format is a single JSON document. AEAD ciphertexts and salts are
//! base64. This trades a few bytes for transparency; production builds will
//! switch to a binary container with HPKE outer envelope.
//!
//! ```text
//! {
//!   "version": 1,
//!   "credentials": [
//!     {
//!       "credential_id": "...b64...",
//!       "x":             "...b64...",
//!       "y":             "...b64...",
//!       "device_name":   "Chrome (MacOS)",
//!       "created_at":    1746780000,
//!       "prf_salt":      "...b64 32B...",
//!       "wrapped_dek":   "...b64 nonce|ct|tag (XChaCha20-Poly1305)..."
//!     }
//!   ],
//!   "body": "...b64 nonce|ct|tag (XChaCha20-Poly1305 of canonical KV under DEK)..."
//! }
//! ```

use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::crypto::aead::{open as aead_open, seal as aead_seal};
use crate::crypto::kdf::{derive_kek, WRAP_VERSION};
use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;

pub const VAULT_VERSION: u16 = 1;

const WRAP_AAD: &[u8] = b"safeclaw/v1/wrap-dek";
const BODY_AAD: &[u8] = b"safeclaw/v1/vault-body";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedCredential {
    pub credential_id: String,
    pub x: String,
    pub y: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub created_at: u64,
    /// Base64 of 32B prf_salt.
    pub prf_salt: String,
    /// Base64 of nonce(24) || ciphertext || tag(16). DEK is 32B.
    pub wrapped_dek: String,
}

impl SealedCredential {
    pub fn passkey_entry(&self) -> PasskeyEntry {
        PasskeyEntry {
            x: self.x.clone(),
            y: self.y.clone(),
            device_name: self.device_name.clone(),
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedVault {
    pub version: u16,
    pub credentials: Vec<SealedCredential>,
    /// Base64 of nonce(24) || ciphertext || tag(16) of the canonical-KV body
    /// under the (single shared) DEK.
    pub body: String,
}

impl SealedVault {
    pub fn empty(credential: SealedCredential, body: String) -> Self {
        Self {
            version: VAULT_VERSION,
            credentials: vec![credential],
            body,
        }
    }

    pub fn find_credential(&self, credential_id_b64: &str) -> Option<&SealedCredential> {
        self.credentials
            .iter()
            .find(|c| c.credential_id == credential_id_b64)
    }

    pub fn replace_credential_after_write(
        &mut self,
        credential_id_b64: &str,
        new_prf_salt_b64: &str,
        new_wrapped_dek_b64: &str,
        new_body_b64: &str,
    ) -> Result<()> {
        let cred = self
            .credentials
            .iter_mut()
            .find(|c| c.credential_id == credential_id_b64)
            .ok_or_else(|| AppError::Unauthorized("unknown credential for write".into()))?;
        cred.prf_salt = new_prf_salt_b64.to_string();
        cred.wrapped_dek = new_wrapped_dek_b64.to_string();
        self.body = new_body_b64.to_string();
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let v: SealedVault = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("vault.dat parse: {}", e)))?;
        if v.version != VAULT_VERSION {
            return Err(AppError::Internal(format!(
                "vault.dat version mismatch: {} (expected {})",
                v.version, VAULT_VERSION
            )));
        }
        Ok(Some(v))
    }

    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        let tmp = path.with_extension("dat.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

// ── DEK helpers ────────────────────────────────────────────────────────────

/// Decrypt the wrapped DEK for a specific credential, given the PRF-derived
/// `user_key`.
pub fn unwrap_dek(
    user_key: &[u8],
    credential: &SealedCredential,
    credential_id_bytes: &[u8],
) -> Result<[u8; 32]> {
    let prf_salt = STANDARD
        .decode(&credential.prf_salt)
        .map_err(|_| AppError::Internal("prf_salt not base64".into()))?;
    if prf_salt.len() != 32 {
        return Err(AppError::Internal("prf_salt wrong length".into()));
    }
    let kek = derive_kek(user_key, &prf_salt, WRAP_VERSION, credential_id_bytes)?;

    let wrapped = STANDARD
        .decode(&credential.wrapped_dek)
        .map_err(|_| AppError::Internal("wrapped_dek not base64".into()))?;
    let plaintext = aead_open(&kek, &wrapped, WRAP_AAD)?;
    if plaintext.len() != 32 {
        return Err(AppError::Internal("DEK wrong length".into()));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

/// Wrap a freshly-generated DEK for a credential. Returns base64(nonce|ct|tag).
pub fn wrap_dek(
    user_key: &[u8],
    prf_salt: &[u8],
    credential_id_bytes: &[u8],
    dek: &[u8; 32],
) -> Result<String> {
    let kek = derive_kek(user_key, prf_salt, WRAP_VERSION, credential_id_bytes)?;
    let sealed = aead_seal(&kek, dek, WRAP_AAD)?;
    Ok(STANDARD.encode(sealed))
}

/// Decrypt the vault body to canonical KV bytes. Caller is responsible for
/// parsing and zeroizing.
pub fn open_body(dek: &[u8; 32], body_b64: &str) -> Result<Vec<u8>> {
    let sealed = STANDARD
        .decode(body_b64)
        .map_err(|_| AppError::Internal("body not base64".into()))?;
    aead_open(dek, &sealed, BODY_AAD)
}

/// Encrypt a body. Returns base64(nonce|ct|tag).
pub fn seal_body(dek: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let sealed = aead_seal(dek, plaintext, BODY_AAD)?;
    Ok(STANDARD.encode(sealed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_dek() {
        let user_key = [0x42u8; 32];
        let prf_salt = [0x11u8; 32];
        let cid = b"credential-bytes";
        let dek = [0x77u8; 32];
        let wrapped = wrap_dek(&user_key, &prf_salt, cid, &dek).unwrap();
        let cred = SealedCredential {
            credential_id: "AAAA".into(),
            x: "".into(),
            y: "".into(),
            device_name: "".into(),
            created_at: 0,
            prf_salt: STANDARD.encode(prf_salt),
            wrapped_dek: wrapped,
        };
        let unwrapped = unwrap_dek(&user_key, &cred, cid).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn roundtrip_body() {
        let dek = [0x77u8; 32];
        let plaintext = b"{\"a\":1}";
        let sealed = seal_body(&dek, plaintext).unwrap();
        let opened = open_body(&dek, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn vault_write_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let v = SealedVault::empty(
            SealedCredential {
                credential_id: "abc".into(),
                x: "x".into(),
                y: "y".into(),
                device_name: "test".into(),
                created_at: 1,
                prf_salt: STANDARD.encode([0u8; 32]),
                wrapped_dek: STANDARD.encode([0u8; 64]),
            },
            STANDARD.encode([0u8; 64]),
        );
        v.write_atomic(&path).unwrap();
        let loaded = SealedVault::read(&path).unwrap().unwrap();
        assert_eq!(loaded.version, VAULT_VERSION);
        assert_eq!(loaded.credentials.len(), 1);
    }
}
