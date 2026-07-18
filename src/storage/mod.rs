//! Vault file storage.
//!
//! - `sealed_vault`: thin wrapper around `sudp::state::SealedState` for
//!   on-disk vault.dat (Phase 3b.M, 2026-05-21).
//! - `plaintext`: decrypted vault shape (v3 stores+items per
//!   `design/stores-and-items.md`).
//! - `vault_dir`: state-dir layout helpers (vaults/<id>/vault.dat).

pub mod item;
pub mod pending_passkey;
pub mod plaintext;
pub mod sealed_vault;
pub mod vault_dir;

pub use sealed_vault::SealedVault;
pub use sudp::state::SealedCredential;
pub use vault_dir::VaultDir;
