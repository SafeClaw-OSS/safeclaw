//! HKDF-SHA-256 key derivation for SafeClaw v1.
//!
//! v1 uses the following derivation chain (see `docs/PROTOCOL.md` §5):
//!
//! ```text
//! userKey       = HKDF(ikm=rawPRF, salt=0,         info="safeclaw/v1/userkey\0" || credentialId)       [client]
//! KEK           = HKDF(ikm=userKey, salt=prf_salt,  info="safeclaw/v1/kek\0" || u16_be(ver) || credentialId)
//! responseSeal  = HKDF(ikm=userKey, salt=prf_salt,  info="safeclaw/v1/response_seal\0" || credentialId)
//! ```
//!
//! The `prf_salt` parameter is the salt stored in the credential's entry in
//! `dek_wraps.bin`; it rotates on every write by the acting credential.
//!
//! The response-seal key provides defense-in-depth for read responses: the
//! server encrypts the JSON response body so that an attacker who only
//! observes responses (but not requests containing `user_key`) cannot read
//! vault contents. Note: this is **not** true E2E against a proxy operator
//! who sees both requests and responses — that requires an ECDH session
//! layer (see `docs/PROTOCOL.md` Future Work).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{AppError, Result};

const KEK_INFO_PREFIX: &[u8] = b"safeclaw/v1/kek\x00";
const USERKEY_INFO_PREFIX: &[u8] = b"safeclaw/v1/userkey\x00";
const RESPONSE_SEAL_INFO_PREFIX: &[u8] = b"safeclaw/v1/response_seal\x00";
const OFFLINE_TRANSPORT_INFO: &[u8] = b"safeclaw/v1/offline-transport";

/// Current wrap version used in KEK and AEAD AAD domain separation.
pub const WRAP_VERSION: u16 = 0x0001;

/// Derive the per-credential userKey from raw PRF output.
///
/// This function is primarily a specification anchor; the client derives
/// userKey in JavaScript before sending to the server. The server calls it
/// only when it needs to reproduce the derivation (e.g., during migration).
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
///
/// `user_key` is the 32-byte client-derived PRF-based key.
/// `prf_salt` is the 32-byte salt currently stored in this credential's
/// `dek_wraps.bin` entry.
/// `wrap_version` is the protocol version (currently `WRAP_VERSION`).
/// `credential_id` is the WebAuthn credential ID bytes.
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

/// Derive the response-seal key for encrypting read responses.
///
/// This provides defense-in-depth: an attacker who only observes responses
/// (but not request bodies containing `user_key`) cannot decrypt vault data.
/// Note: a proxy operator who sees both directions can derive this key from
/// the request body. True E2E against an operator requires an ECDH session
/// layer (see `docs/PROTOCOL.md` Future Work).
pub fn derive_response_seal_key(
    user_key: &[u8],
    prf_salt: &[u8],
    credential_id: &[u8],
) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(RESPONSE_SEAL_INFO_PREFIX.len() + credential_id.len());
    info.extend_from_slice(RESPONSE_SEAL_INFO_PREFIX);
    info.extend_from_slice(credential_id);

    let hkdf = Hkdf::<Sha256>::new(Some(prf_salt), user_key);
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|e| AppError::Internal(format!("HKDF expand (response_seal): {}", e)))?;
    Ok(out)
}

/// Derive the transport key for the offline unlock handshake from a shared
/// ECDH secret.
pub fn derive_offline_transport_key(
    shared_secret: &[u8],
    session_id: &[u8],
) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(session_id), shared_secret);
    let mut out = [0u8; 32];
    hkdf.expand(OFFLINE_TRANSPORT_INFO, &mut out)
        .map_err(|e| AppError::Internal(format!("HKDF expand (offline): {}", e)))?;
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

    #[test]
    fn kek_changes_with_version() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let cid = b"cred";
        let k1 = derive_kek(&uk, &salt, 0x0002, cid).unwrap();
        let k2 = derive_kek(&uk, &salt, 0x0003, cid).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn offline_transport_key_differs_from_kek() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let kek = derive_kek(&uk, &salt, WRAP_VERSION, b"cred").unwrap();
        let tk = derive_offline_transport_key(&uk, &salt).unwrap();
        assert_ne!(kek, tk);
    }

    #[test]
    fn response_seal_key_differs_from_kek() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let cid = b"cred";
        let kek = derive_kek(&uk, &salt, WRAP_VERSION, cid).unwrap();
        let rsk = derive_response_seal_key(&uk, &salt, cid).unwrap();
        assert_ne!(kek, rsk);
    }

    #[test]
    fn response_seal_key_is_deterministic() {
        let uk = [0x42u8; 32];
        let salt = [0x11u8; 32];
        let cid = b"cred";
        let k1 = derive_response_seal_key(&uk, &salt, cid).unwrap();
        let k2 = derive_response_seal_key(&uk, &salt, cid).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn response_seal_key_changes_with_salt() {
        let uk = [0x42u8; 32];
        let cid = b"cred";
        let k1 = derive_response_seal_key(&uk, &[0x11u8; 32], cid).unwrap();
        let k2 = derive_response_seal_key(&uk, &[0x22u8; 32], cid).unwrap();
        assert_ne!(k1, k2);
    }
}
