//! HKDF-SHA-256 — thin adapter over `sudp::primitives::HkdfSha256`.
//!
//! ```text
//! userKey      = HKDF(ikm=rawPRF, salt=∅,         info="safeclaw/v1/userkey\0" ‖ credentialId)
//! wrappingKey  = HKDF(ikm=userKey, salt=prf_salt, info=DS_WRAP ‖ credentialId ‖ ver_be)
//! ```
//!
//! `wrappingKey` is `W_c` in the SUDP paper (§5.5 II.2). It's the per-credential
//! key that wraps the state key `K = sudp::SealedState.ciphertext`-encryption-
//! key. SUDP leaves the client-side derivation of `W_c` to deployments;
//! safeclaw picks HKDF with `DS_WRAP` as the info prefix so the label matches
//! the AEAD AAD that the wrap step itself uses.

use sudp::primitives::{domain::DS_WRAP, HkdfSha256, Kdf as _};

use crate::error::{AppError, Result};

const USERKEY_INFO_PREFIX: &[u8] = b"safeclaw/v1/userkey\x00";

/// Current wrap version used in the WrapBinding AAD.
pub const WRAP_VERSION: u16 = 0x0001;

/// Derive the per-credential `userKey` (= `y_c` in SUDP) from raw PRF output.
///
/// The client derives `userKey` in JavaScript and then derives `wrappingKey`
/// from it; this helper exists for tests and reference parity.
pub fn derive_user_key(raw_prf: &[u8], credential_id: &[u8]) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(USERKEY_INFO_PREFIX.len() + credential_id.len());
    info.extend_from_slice(USERKEY_INFO_PREFIX);
    info.extend_from_slice(credential_id);
    HkdfSha256::derive_32(raw_prf, &[], &info)
        .map_err(|e| AppError::Internal(format!("HKDF expand (userkey): {}", e)))
}

/// Derive the per-credential wrapping key `W_c` from `userKey`.
///
/// `info = DS_WRAP ‖ credential_id ‖ ver_be`. Matches the AAD layout that
/// `sudp::primitives::WrapBinding::to_canonical_ad()` produces, modulo the
/// fact that this is *KDF info* (driving HKDF expand) and not *AEAD AD*.
/// Using the same label structure keeps the deployment story tidy.
pub fn derive_wrapping_key(
    user_key: &[u8],
    prf_salt: &[u8],
    credential_id: &[u8],
    wrap_version: u16,
) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(DS_WRAP.len() + credential_id.len() + 2);
    info.extend_from_slice(DS_WRAP);
    info.extend_from_slice(credential_id);
    info.extend_from_slice(&wrap_version.to_be_bytes());
    HkdfSha256::derive_32(user_key, prf_salt, &info)
        .map_err(|e| AppError::Internal(format!("HKDF expand (wrap): {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_key_is_deterministic() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let cid = b"credential_id_bytes";
        let k1 = derive_wrapping_key(&uk, &salt, cid, WRAP_VERSION).unwrap();
        let k2 = derive_wrapping_key(&uk, &salt, cid, WRAP_VERSION).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn wrapping_key_changes_with_salt() {
        let uk = [0x42u8; 32];
        let cid = b"cid";
        let k1 = derive_wrapping_key(&uk, &[0x11u8; 32], cid, WRAP_VERSION).unwrap();
        let k2 = derive_wrapping_key(&uk, &[0x22u8; 32], cid, WRAP_VERSION).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn wrapping_key_changes_with_credential_id() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let k1 = derive_wrapping_key(&uk, &salt, b"cred1", WRAP_VERSION).unwrap();
        let k2 = derive_wrapping_key(&uk, &salt, b"cred2", WRAP_VERSION).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn wrapping_key_changes_with_version() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let cid = b"cid";
        let k1 = derive_wrapping_key(&uk, &salt, cid, 1).unwrap();
        let k2 = derive_wrapping_key(&uk, &salt, cid, 2).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn userkey_smoke() {
        let prf = [0x42u8; 32];
        let cid = b"cred-id";
        let uk = derive_user_key(&prf, cid).unwrap();
        assert_eq!(uk.len(), 32);
    }
}
