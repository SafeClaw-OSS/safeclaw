//! `dek_wraps.bin` manifest: per-credential DEK wrapping entries.
//!
//! File layout (see `docs/PROTOCOL.md` §6.1):
//!
//! ```text
//! [ "SCW2" | u16 ver | u16 entry_count | Entry* ]
//! Entry:
//!   [ u16 entry_length | u16 cred_id_length | cred_id_bytes
//!     | [u8; 32] prf_salt | [u8; 24] aead_nonce
//!     | [u8; 48] wrapped (ct+tag) ]
//! ```

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use zeroize::Zeroize;

use crate::crypto::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{derive_kek, WRAP_VERSION};
use crate::error::{AppError, Result};

const MAGIC: &[u8; 4] = b"SCW1";
const VERSION: u16 = 0x0001;
const PRF_SALT_LEN: usize = 32;
const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN; // 32 + 16 = 48

const WRAP_AAD_PREFIX: &[u8] = b"safeclaw/v1/wrap\x00";

/// A single wrapping entry in the manifest.
#[derive(Clone)]
pub struct DekWrapEntry {
    pub credential_id: Vec<u8>,
    pub prf_salt: [u8; PRF_SALT_LEN],
    pub aead_nonce: [u8; NONCE_LEN],
    /// Ciphertext + 16-byte Poly1305 tag.
    pub wrapped: Vec<u8>,
}

impl std::fmt::Debug for DekWrapEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DekWrapEntry")
            .field("credential_id_len", &self.credential_id.len())
            .field("prf_salt_hash", &format!("{:x?}", &self.prf_salt[..4]))
            .field("aead_nonce_hash", &format!("{:x?}", &self.aead_nonce[..4]))
            .field("wrapped_len", &self.wrapped.len())
            .finish()
    }
}

/// The complete manifest, typically loaded and rewritten as a unit.
#[derive(Clone, Debug, Default)]
pub struct DekWrapManifest {
    pub entries: Vec<DekWrapEntry>,
}

impl DekWrapManifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find an entry by credential ID.
    pub fn find(&self, credential_id: &[u8]) -> Option<&DekWrapEntry> {
        self.entries.iter().find(|e| e.credential_id == credential_id)
    }

    /// Update (or insert) an entry by credential ID.
    pub fn upsert(&mut self, entry: DekWrapEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.credential_id == entry.credential_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Remove an entry by credential ID. Returns true if an entry was removed.
    pub fn remove(&mut self, credential_id: &[u8]) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.credential_id != credential_id);
        self.entries.len() != before
    }

    /// List all credential IDs present in the manifest, in file order.
    pub fn credential_ids(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(|e| e.credential_id.clone()).collect()
    }

    /// Serialize to the on-disk binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.entries.len() > u16::MAX as usize {
            return Err(AppError::Internal("too many wrapped entries".into()));
        }
        let mut out = Vec::with_capacity(8 + self.entries.len() * 128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for e in &self.entries {
            if e.credential_id.len() > u16::MAX as usize {
                return Err(AppError::Internal("credential_id too long".into()));
            }
            if e.wrapped.len() != WRAPPED_LEN {
                return Err(AppError::Internal(format!(
                    "wrapped length must be {}, got {}",
                    WRAPPED_LEN,
                    e.wrapped.len()
                )));
            }
            let cid_len = e.credential_id.len() as u16;
            // entry_length: 2 (this field) + 2 (cid_len field) + cid_len + 32 + 24 + 48
            let entry_len = 2 + 2 + cid_len as u32 + 32 + 24 + WRAPPED_LEN as u32;
            if entry_len > u16::MAX as u32 {
                return Err(AppError::Internal("entry too large".into()));
            }
            out.extend_from_slice(&(entry_len as u16).to_be_bytes());
            out.extend_from_slice(&cid_len.to_be_bytes());
            out.extend_from_slice(&e.credential_id);
            out.extend_from_slice(&e.prf_salt);
            out.extend_from_slice(&e.aead_nonce);
            out.extend_from_slice(&e.wrapped);
        }
        Ok(out)
    }

    /// Parse the on-disk binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 || &data[..4] != MAGIC {
            return Err(AppError::BadRequest(
                "dek_wraps.bin: bad magic (not a valid file)".into(),
            ));
        }
        let version = u16::from_be_bytes([data[4], data[5]]);
        if version != VERSION {
            return Err(AppError::BadRequest(format!(
                "dek_wraps.bin: unsupported version 0x{:04x}",
                version
            )));
        }
        let count = u16::from_be_bytes([data[6], data[7]]) as usize;
        let mut entries = Vec::with_capacity(count);
        let mut offset = 8;
        for _ in 0..count {
            if offset + 2 > data.len() {
                return Err(AppError::BadRequest("dek_wraps.bin: truncated entry".into()));
            }
            let entry_len =
                u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            if offset + entry_len > data.len() {
                return Err(AppError::BadRequest(
                    "dek_wraps.bin: entry overflows file".into(),
                ));
            }
            let entry_end = offset + entry_len;
            // [ u16 entry_length (already read)
            //   u16 cred_id_length
            //   cid bytes
            //   [u8; 32] prf_salt
            //   [u8; 24] aead_nonce
            //   wrapped ]
            if entry_len < 2 + 2 + 32 + 24 + WRAPPED_LEN {
                return Err(AppError::BadRequest("dek_wraps.bin: entry too small".into()));
            }
            let mut p = offset + 2;
            let cid_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            p += 2;
            if cid_len == 0 || p + cid_len > entry_end {
                return Err(AppError::BadRequest(
                    "dek_wraps.bin: bad credential_id length".into(),
                ));
            }
            let credential_id = data[p..p + cid_len].to_vec();
            p += cid_len;
            if p + 32 + 24 + WRAPPED_LEN != entry_end {
                return Err(AppError::BadRequest(
                    "dek_wraps.bin: entry size mismatch".into(),
                ));
            }
            let mut prf_salt = [0u8; 32];
            prf_salt.copy_from_slice(&data[p..p + 32]);
            p += 32;
            let mut aead_nonce = [0u8; NONCE_LEN];
            aead_nonce.copy_from_slice(&data[p..p + NONCE_LEN]);
            p += NONCE_LEN;
            let wrapped = data[p..p + WRAPPED_LEN].to_vec();
            entries.push(DekWrapEntry {
                credential_id,
                prf_salt,
                aead_nonce,
                wrapped,
            });
            offset = entry_end;
        }
        Ok(Self { entries })
    }

    /// Load from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let mut f = fs::File::open(path).map_err(|e| {
            AppError::Internal(format!("open dek_wraps.bin: {}", e))
        })?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .map_err(|e| AppError::Internal(format!("read dek_wraps.bin: {}", e)))?;
        Self::from_bytes(&data)
    }

    /// Write atomically to disk via `<path>.tmp` and rename.
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let bytes = self.to_bytes()?;
        let tmp = path.with_extension("bin.tmp");
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| AppError::Internal(format!("open tmp: {}", e)))?;
            f.write_all(&bytes)
                .map_err(|e| AppError::Internal(format!("write tmp: {}", e)))?;
            f.sync_all()
                .map_err(|e| AppError::Internal(format!("fsync tmp: {}", e)))?;
        }
        fs::rename(&tmp, path)
            .map_err(|e| AppError::Internal(format!("rename tmp: {}", e)))?;
        // fsync the parent directory so the rename is durable
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

/// Compute the AEAD AAD for wrapping/unwrapping a DEK for a specific credential.
///
/// `aad = "safeclaw/v1/wrap\x00" || u16_be(version) || credential_id`
pub fn wrap_aad(version: u16, credential_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_PREFIX.len() + 2 + credential_id.len());
    aad.extend_from_slice(WRAP_AAD_PREFIX);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(credential_id);
    aad
}

/// Wrap a DEK under the given credential's KEK.
///
/// Inputs:
/// - `dek`: 32-byte DEK plaintext
/// - `user_key`: 32-byte client-derived userKey for this credential
/// - `prf_salt`: 32-byte current PRF salt for this credential
/// - `credential_id`: raw credential ID bytes
///
/// Returns a `DekWrapEntry` with a fresh random `aead_nonce`.
pub fn wrap_dek_for_credential(
    dek: &[u8; KEY_LEN],
    user_key: &[u8; KEY_LEN],
    prf_salt: &[u8; PRF_SALT_LEN],
    credential_id: &[u8],
) -> Result<DekWrapEntry> {
    let mut kek = derive_kek(user_key, prf_salt, WRAP_VERSION, credential_id)?;
    let aead_nonce = aead::fresh_nonce();
    let aad = wrap_aad(WRAP_VERSION, credential_id);
    let wrapped = aead::encrypt(&kek, &aead_nonce, dek, &aad)?;
    kek.zeroize();
    Ok(DekWrapEntry {
        credential_id: credential_id.to_vec(),
        prf_salt: *prf_salt,
        aead_nonce,
        wrapped,
    })
}

/// Wrap a DEK using an already-derived KEK (used when rewrapping for peer
/// credentials during a write operation, where the KEK comes from peer_keks
/// in the vault plaintext rather than from a freshly derived userKey).
pub fn wrap_dek_with_kek(
    dek: &[u8; KEY_LEN],
    kek: &[u8; KEY_LEN],
    prf_salt: &[u8; PRF_SALT_LEN],
    credential_id: &[u8],
) -> Result<DekWrapEntry> {
    let aead_nonce = aead::fresh_nonce();
    let aad = wrap_aad(WRAP_VERSION, credential_id);
    let wrapped = aead::encrypt(kek, &aead_nonce, dek, &aad)?;
    Ok(DekWrapEntry {
        credential_id: credential_id.to_vec(),
        prf_salt: *prf_salt,
        aead_nonce,
        wrapped,
    })
}

/// Unwrap a DEK from a `DekWrapEntry` given the userKey for that credential.
pub fn unwrap_dek(
    entry: &DekWrapEntry,
    user_key: &[u8; KEY_LEN],
) -> Result<[u8; KEY_LEN]> {
    let mut kek = derive_kek(
        user_key,
        &entry.prf_salt,
        WRAP_VERSION,
        &entry.credential_id,
    )?;
    let aad = wrap_aad(WRAP_VERSION, &entry.credential_id);
    let plain = aead::decrypt(&kek, &entry.aead_nonce, &entry.wrapped, &aad)?;
    kek.zeroize();
    if plain.len() != KEY_LEN {
        return Err(AppError::Internal(format!(
            "unwrapped DEK has wrong length: {}",
            plain.len()
        )));
    }
    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&plain);
    let mut plain = plain;
    plain.zeroize();
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_manifest_bytes() {
        let mut m = DekWrapManifest::new();
        m.entries.push(DekWrapEntry {
            credential_id: b"cred-A".to_vec(),
            prf_salt: [0x11u8; 32],
            aead_nonce: [0x22u8; NONCE_LEN],
            wrapped: vec![0x33u8; WRAPPED_LEN],
        });
        m.entries.push(DekWrapEntry {
            credential_id: b"cred-BB".to_vec(),
            prf_salt: [0xAAu8; 32],
            aead_nonce: [0xBBu8; NONCE_LEN],
            wrapped: vec![0xCCu8; WRAPPED_LEN],
        });
        let bytes = m.to_bytes().unwrap();
        let m2 = DekWrapManifest::from_bytes(&bytes).unwrap();
        assert_eq!(m2.entries.len(), 2);
        assert_eq!(m2.entries[0].credential_id, b"cred-A");
        assert_eq!(m2.entries[1].credential_id, b"cred-BB");
        assert_eq!(m2.entries[0].prf_salt, [0x11u8; 32]);
        assert_eq!(m2.entries[1].wrapped, vec![0xCCu8; WRAPPED_LEN]);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let dek = [0xDEu8; 32];
        let user_key = [0xAAu8; 32];
        let prf_salt = [0x55u8; 32];
        let cid = b"credential-id-abc";
        let entry = wrap_dek_for_credential(&dek, &user_key, &prf_salt, cid).unwrap();
        let recovered = unwrap_dek(&entry, &user_key).unwrap();
        assert_eq!(recovered, dek);
    }

    #[test]
    fn wrong_user_key_fails_unwrap() {
        let dek = [0xDEu8; 32];
        let user_key = [0xAAu8; 32];
        let other_key = [0xBBu8; 32];
        let prf_salt = [0x55u8; 32];
        let cid = b"cred";
        let entry = wrap_dek_for_credential(&dek, &user_key, &prf_salt, cid).unwrap();
        assert!(unwrap_dek(&entry, &other_key).is_err());
    }

    #[test]
    fn reject_bad_magic() {
        let data = b"NOPEmagicbytes".to_vec();
        assert!(DekWrapManifest::from_bytes(&data).is_err());
    }

    #[test]
    fn upsert_updates_existing() {
        let mut m = DekWrapManifest::new();
        m.entries.push(DekWrapEntry {
            credential_id: b"cred".to_vec(),
            prf_salt: [1u8; 32],
            aead_nonce: [1u8; NONCE_LEN],
            wrapped: vec![1u8; WRAPPED_LEN],
        });
        m.upsert(DekWrapEntry {
            credential_id: b"cred".to_vec(),
            prf_salt: [2u8; 32],
            aead_nonce: [2u8; NONCE_LEN],
            wrapped: vec![2u8; WRAPPED_LEN],
        });
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].prf_salt, [2u8; 32]);
    }
}
