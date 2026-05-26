//! State directory layout helpers.
//!
//! ```text
//! <state-dir>/
//! └── vaults/
//!     └── <vault_id>/
//!         └── vault.dat
//! ```

use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

#[derive(Debug, Clone)]
pub struct VaultDir {
    pub root: PathBuf,
}

impl VaultDir {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("vaults"),
        }
    }

    fn validate_id(id: &str) -> Result<()> {
        if id.is_empty() || id.len() > 128 {
            return Err(AppError::BadRequest("invalid vault_id length".into()));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AppError::BadRequest("vault_id has illegal chars".into()));
        }
        Ok(())
    }

    pub fn dir_for(&self, vault_id: &str) -> Result<PathBuf> {
        Self::validate_id(vault_id)?;
        Ok(self.root.join(vault_id))
    }

    pub fn vault_path(&self, vault_id: &str) -> Result<PathBuf> {
        Ok(self.dir_for(vault_id)?.join("vault.dat"))
    }

    pub fn audit_path(&self, vault_id: &str) -> Result<PathBuf> {
        Ok(self.dir_for(vault_id)?.join("audit.db"))
    }

    /// `vaults/{vid}/pending-passkeys/` — transient store for cross-device
    /// add-passkey deposits, one file per pending credential id. Files are
    /// deleted on Stage 2 consumption or by TTL sweep (1h).
    pub fn pending_passkeys_dir(&self, vault_id: &str) -> Result<PathBuf> {
        Ok(self.dir_for(vault_id)?.join("pending-passkeys"))
    }

    pub fn ensure_dir(&self, vault_id: &str) -> Result<PathBuf> {
        let d = self.dir_for(vault_id)?;
        std::fs::create_dir_all(&d)?;
        Ok(d)
    }

    /// Recursively delete the vault's directory (vault.dat + any files/
    /// blobs alongside). Idempotent: no error if the directory is already
    /// missing. Caller is responsible for any in-memory state cleanup
    /// (e.g. flushing the vault_states cache).
    pub fn remove(&self, vault_id: &str) -> Result<()> {
        let d = self.dir_for(vault_id)?;
        if d.exists() {
            std::fs::remove_dir_all(&d)?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<String>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_string());
                }
            }
        }
        Ok(out)
    }
}
