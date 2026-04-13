//! SafeClaw v1 cryptographic protocol primitives.
//!
//! See `docs/PROTOCOL.md` for the full specification.
//!
//! Module layout:
//! - `aead`: XChaCha20-Poly1305 wrapper used for all AEAD operations.
//! - `kdf`: HKDF-SHA-256 derivations (userKey, KEK, response key, offline transport).
//! - `canonical`: RFC 8785 JCS subset for channel binding.
//! - `binding`: channel binding hash computation.
//! - `wrapped_deks`: on-disk `wrapped_deks.bin` manifest format.
//! - `vault_file`: on-disk `vault.enc` and `files/*.enc` formats.
//! - `keys`: P-256 key handling for WebAuthn assertion verification and
//!   offline-unlock ECDH.
//! - `zeroize`: best-effort recursive zeroization of `serde_json::Value`.

pub mod aead;
pub mod binding;
pub mod canonical;
pub mod kdf;
pub mod keys;
pub mod vault_file;
pub mod dek_wraps;
pub mod zeroize;

// ── Re-exports ──────────────────────────────────────────────────────────────

pub use aead::{decrypt as aead_decrypt, encrypt as aead_encrypt, open as aead_open, seal as aead_seal};
pub use binding::{
    binding_for_request, compute_binding, compute_request_hash, constant_time_eq,
    DOMAIN_IDENTITY, DOMAIN_OFFLINE, DOMAIN_SETUP, DOMAIN_SETUP_OVERWRITE, DOMAIN_STANDARD,
};
pub use canonical::{canonicalize, canonicalize_body};
pub use kdf::{
    derive_kek, derive_offline_transport_key, derive_response_seal_key, derive_user_key,
    WRAP_VERSION,
};
pub use keys::jwk_sk_d_bytes;
pub use vault_file::{decrypt_file, decrypt_vault, encrypt_file, encrypt_vault, is_valid_version, save_atomic as save_vault_atomic};
pub use dek_wraps::{
    unwrap_dek, wrap_aad, wrap_dek_for_credential, wrap_dek_with_kek, DekWrapManifest,
    DekWrapEntry,
};

use rand::{rngs::OsRng, RngCore};

/// Generate a random 32-byte DEK.
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Generate a random 32-byte prf_salt for rotation.
pub fn fresh_prf_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random 32-byte file DEK.
pub fn fresh_file_key() -> [u8; 32] {
    generate_dek()
}
