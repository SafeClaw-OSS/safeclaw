//! Vault file storage.
//!
//! - `sealed_vault`: the SCSV file format (single-DEK simplified for v0).
//! - `tenant_dir`: state-dir layout helpers (tenants/<id>/vault.dat).

pub mod sealed_vault;
pub mod tenant_dir;

pub use sealed_vault::{SealedCredential, SealedVault};
pub use tenant_dir::TenantDir;
