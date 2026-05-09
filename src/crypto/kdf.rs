//! HKDF-SHA-256 key derivation.
//!
//! ```text
//! userKey = HKDF(ikm=rawPRF, salt=0,        info="safeclaw/v1/userkey\0" ‖ credentialId)        [client]
//! KEK     = HKDF(ikm=userKey, salt=prf_salt, info="safeclaw/v1/kek\0" ‖ u16_be(ver) ‖ credentialId)
//! ```

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{AppError, Result};

const KEK_INFO_PREFIX: &[u8] = b"safeclaw/v1/kek\x00";
const USERKEY_INFO_PREFIX: &[u8] = b"safeclaw/v1/userkey\x00";

/// Current wrap version used in KEK and AEAD AAD domain separation.
pub const WRAP_VERSION: u16 = 0x0001;

/// Derive the per-credential userKey from raw PRF output.
///
/// The client derives userKey in JavaScript before sending; this helper exists
/// for tests and reference implementations.
pub fn derive_user_key(raw_prf: &[u8], credential_id: &[u8]) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(USERKEY_INFO_PREFIX.len() + credential_id.len());
    info.extend_from_slice(USERKEY_INFO_PREFIX);
    info.extend_from_slice(credential_id);
    let hkdf = Hkdf::<Sha256>::new(None, raw_prf);
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|e| AppError::Internal(format!("HKDF expand (userkey): {}", e)))?;
    Ok(out)
}

/// Derive the KEK for wrapping a DEK under the given credential.
pub fn derive_kek(
    user_key: &[u8],
    prf_salt: &[u8],
    wrap_version: u16,
    credential_id: &[u8],
) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(KEK_INFO_PREFIX.len() + 2 + credential_id.len());
    info.extend_from_slice(KEK_INFO_PREFIX);
    info.extend_from_slice(&wrap_version.to_be_bytes());
    info.extend_from_slice(credential_id);

    let hkdf = Hkdf::<Sha256>::new(Some(prf_salt), user_key);
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|e| AppError::Internal(format!("HKDF expand (kek): {}", e)))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kek_is_deterministic() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let cid = b"credential_id_bytes";
        let k1 = derive_kek(&uk, &salt, WRAP_VERSION, cid).unwrap();
        let k2 = derive_kek(&uk, &salt, WRAP_VERSION, cid).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn kek_changes_with_salt() {
        let uk = [0x42u8; 32];
        let cid = b"cid";
        let k1 = derive_kek(&uk, &[0x11u8; 32], WRAP_VERSION, cid).unwrap();
        let k2 = derive_kek(&uk, &[0x22u8; 32], WRAP_VERSION, cid).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn kek_changes_with_credential_id() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let k1 = derive_kek(&uk, &salt, WRAP_VERSION, b"cred1").unwrap();
        let k2 = derive_kek(&uk, &salt, WRAP_VERSION, b"cred2").unwrap();
        assert_ne!(k1, k2);
    }
}
