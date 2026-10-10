//! SafeClaw cryptographic primitives.

pub mod admission;
pub mod aead;
pub mod batch;
pub mod binding;
pub mod canonical;
pub mod envelope;
pub mod keys;
pub mod ledger;
pub mod vault_key;
pub mod zeroize;

#[cfg(test)]
mod trust_reset_vectors;

pub use aead::{
    decrypt as aead_decrypt, encrypt as aead_encrypt, open as aead_open, seal as aead_seal,
};
pub use binding::{
    binding_for_op, binding_for_request, compute_binding, compute_request_hash, constant_time_eq,
    DOMAIN_SETUP, DOMAIN_STANDARD,
};
pub use canonical::{canonicalize, canonicalize_body};
