//! Sealed-vault on-disk format = [`sudp::state::SealedState`].
//!
//! As of Phase 3b.M (2026-05-21), safeclaw uses sudp's canonical state shape
//! for vault.dat: `{ version, registry, credentials, ciphertext }` where
//! - `registry` keys credential_id → opaque public-key JSON (WebAuthn x/y/
//!   device_name)
//! - `credentials[i]` carries `cid, prf_salt, wrapped_key` (= `K̂_c` =
//!   AEAD-wrap of K under W_c with AAD `DS_WRAP ‖ cid ‖ ver_be`)
//! - `ciphertext` = AEAD-seal of canonical(ProtectedState) under K with AAD
//!   `DS_SEAL ‖ ver_be`
//!
//! The client does the sealing — safeclaw daemon never sees `K` (the state
//! key) or `M` (ProtectedState) in plaintext at setup time. The client sends
//! the already-sealed bytes; the daemon just rehouses them into a SealedState
//! file. At grant redemption (export / use / write) the client transmits `W_c`
//! over the confidential TLS leg; the daemon momentarily unwraps and acts on
//! `M`, then drops `K` and any decrypted target bytes.

use std::path::Path;

use sudp::passkey::WebAuthn;
use sudp::state::{Registry, SealedCredential, SealedState, CURRENT_VERSION};

use crate::error::{AppError, Result};
use crate::protocol::operation::decode_credential_id;
use crate::passkey::PasskeyEntry;

/// On-disk vault is exactly the sudp sealed-state JSON.
pub type SealedVault = SealedState;

/// File suffix for atomic-replace writes.
const TMP_EXT: &str = "dat.tmp";

/// Read the vault file. Returns `None` if it doesn't exist.
pub fn read(path: &Path) -> Result<Option<SealedVault>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let v: SealedVault = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("vault.dat parse: {}", e)))?;
    if v.version != CURRENT_VERSION {
        return Err(AppError::Internal(format!(
            "vault.dat version mismatch: {} (expected {})",
            v.version, CURRENT_VERSION
        )));
    }
    Ok(Some(v))
}

/// Atomically write vault.dat.
pub fn write_atomic(path: &Path, vault: &SealedVault) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(vault)?;
    let tmp = path.with_extension(TMP_EXT);
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Look up a credential's WebAuthn public key from the registry.
///
/// Returns a safeclaw-side [`PasskeyEntry`] so existing call sites that fetch
/// `(x, y, device_name)` for binding verification don't need to know the
/// sudp Registry shape.
pub fn find_pubkey(vault: &SealedVault, credential_id_b64: &str) -> Option<PasskeyEntry> {
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    let pk = vault.registry.get::<WebAuthn>(&cid_bytes).ok().flatten()?;
    Some(PasskeyEntry {
        x: pk.x,
        y: pk.y,
        device_name: pk.device_name,
        created_at: 0, // sudp Registry doesn't track this; lossy.
    })
}

/// Find a credential entry by base64 id. Returns None if absent.
pub fn find_credential<'a>(
    vault: &'a SealedVault,
    credential_id_b64: &str,
) -> Option<&'a SealedCredential> {
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    vault.find_credential(&cid_bytes)
}

/// Build a fresh single-credential vault for first-time setup.
///
/// All sealing is performed by the client; the daemon receives the already-
/// sealed bytes (`wrapped_key`, `ciphertext`) and just assembles the file.
pub fn build_initial(
    credential_id: Vec<u8>,
    public_key_x_b64: String,
    public_key_y_b64: String,
    device_name: String,
    prf_salt: Vec<u8>,
    wrapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<SealedVault> {
    let mut registry = Registry::new();
    let pk = sudp::passkey::WebAuthnPublicKey {
        x: public_key_x_b64,
        y: public_key_y_b64,
        device_name,
    };
    registry
        .insert::<WebAuthn>(&credential_id, &pk)
        .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
    let sealed_cred = SealedCredential {
        credential_id,
        prf_salt,
        wrapped_key,
    };
    Ok(SealedState {
        version: CURRENT_VERSION,
        registry,
        credentials: vec![sealed_cred],
        ciphertext,
    })
}

/// Rotate the acting credential's `(prf_salt, wrapped_key)` after a Write and
/// replace the body ciphertext. Used by the write handler.
pub fn replace_after_write(
    vault: &mut SealedVault,
    credential_id_b64: &str,
    new_prf_salt: Vec<u8>,
    new_wrapped_key: Vec<u8>,
    new_ciphertext: Vec<u8>,
) -> Result<()> {
    let cid_bytes = decode_credential_id(credential_id_b64)?;
    let cred = vault
        .credentials
        .iter_mut()
        .find(|c| c.credential_id == cid_bytes)
        .ok_or_else(|| AppError::Unauthorized("unknown credential for write".into()))?;
    cred.prf_salt = new_prf_salt;
    cred.wrapped_key = new_wrapped_key;
    vault.ciphertext = new_ciphertext;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vault_write_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let v = build_initial(
            b"cred-bytes".to_vec(),
            "x_b64".into(),
            "y_b64".into(),
            "Test Device".into(),
            vec![0u8; 32],
            vec![0u8; 48],
            vec![0u8; 64],
        )
        .unwrap();
        write_atomic(&path, &v).unwrap();
        let loaded = read(&path).unwrap().unwrap();
        assert_eq!(loaded.version, CURRENT_VERSION);
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(loaded.credentials[0].credential_id, b"cred-bytes");
        let pk = find_pubkey(&v, &STANDARD.encode(b"cred-bytes")).unwrap();
        assert_eq!(pk.x, "x_b64");
        assert_eq!(pk.device_name, "Test Device");
    }
}
