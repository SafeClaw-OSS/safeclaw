//! Vault file storage.
//!
//! - `sealed_vault`: the per-vault local store (verified member record + sealed
//!   item records).
//! - `item`: the per-item seal / address primitives.
//! - `plaintext`: decrypted vault shape (v3 stores+items per
//!   `design/stores-and-items.md`).
//! - `vault_dir`: state-dir layout helpers (vaults/<id>/…).

pub mod item;
pub mod plaintext;
pub mod sealed_vault;
pub mod vault_dir;

pub use vault_dir::VaultDir;
