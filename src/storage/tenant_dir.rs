//! State directory layout helpers.
//!
//! ```text
//! <state-dir>/
//! └── tenants/
//!     └── <tenant_id>/
//!         └── vault.dat
//! ```

use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

#[derive(Debug, Clone)]
pub struct TenantDir {
    pub root: PathBuf,
}

impl TenantDir {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("tenants"),
        }
    }

    fn validate_id(id: &str) -> Result<()> {
        if id.is_empty() || id.len() > 128 {
            return Err(AppError::BadRequest("invalid tenant_id length".into()));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AppError::BadRequest("tenant_id has illegal chars".into()));
        }
        Ok(())
    }

    pub fn dir_for(&self, tenant_id: &str) -> Result<PathBuf> {
        Self::validate_id(tenant_id)?;
        Ok(self.root.join(tenant_id))
    }

    pub fn vault_path(&self, tenant_id: &str) -> Result<PathBuf> {
        Ok(self.dir_for(tenant_id)?.join("vault.dat"))
    }

    pub fn ensure_dir(&self, tenant_id: &str) -> Result<PathBuf> {
        let d = self.dir_for(tenant_id)?;
        std::fs::create_dir_all(&d)?;
        Ok(d)
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
