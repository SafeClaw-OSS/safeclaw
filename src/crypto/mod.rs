pub mod aes;
pub mod ecies;
pub mod envelope;
pub mod kdf;
pub mod keys;
pub mod zeroize;

// Re-export commonly used items
pub use aes::{aes_decrypt, aes_encrypt};
pub use envelope::{decrypt_vault, encrypt_vault, generate_dek, unwrap_dek, wrap_dek};
pub use kdf::{derive_kek, derive_response_key};
pub use keys::jwk_sk_d_bytes;
