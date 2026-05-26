//! Vault file storage.
//!
//! - `sealed_vault`: thin wrapper around `sudp::state::SealedState` for
//!   on-disk vault.dat (Phase 3b.M, 2026-05-21).
//! - `plaintext`: decrypted vault shape (v3 stores+items per
//!   `docs/STORES_AND_ITEMS.md`).
//! - `tenant_dir`: state-dir layout helpers (tenants/<id>/vault.dat).

pub mod pending_passkey;
pub mod plaintext;
pub mod sealed_vault;
pub mod tenant_dir;

pub use sealed_vault::SealedVault;
pub use sudp::state::SealedCredential;
pub use tenant_dir::TenantDir;
