//! `Operation` — the canonical U↔T contract that the user's passkey signs over.

use serde::{Deserialize, Serialize};

/// Validity window. `iat`/`exp` are unix seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Valid {
    pub iat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

impl Valid {
    /// Reject if `exp` is set and current time exceeds it. Also reject if `iat`
    /// is grossly skewed (>5min in the future).
    pub fn check_now(&self) -> crate::error::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if self.iat > now + 300 {
            return Err(crate::error::AppError::BadRequest("iat in future".into()));
        }
        if let Some(exp) = self.exp {
            if exp < now {
                return Err(crate::error::AppError::BadRequest("operation expired".into()));
            }
        }
        Ok(())
    }
}

/// New credential payload — used in `setup` and (future) `enroll` acts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCredential {
    /// Base64-encoded credential ID.
    pub credential_id: String,
    /// Base64 P-256 X coordinate (32B raw).
    pub public_key_x: String,
    /// Base64 P-256 Y coordinate (32B raw).
    pub public_key_y: String,
    /// Base64 prf_salt (32B raw) — used to derive KEK.
    pub prf_salt: String,
    #[serde(default)]
    pub device_name: String,
}

/// Write patch — for v0 toy this is a full replace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritePatch {
    /// Base64 of new sealed body (XChaCha20-Poly1305 of canonical KV under DEK).
    pub body: String,
    /// Base64 of new wrapped DEK (XChaCha20-Poly1305 under KEK derived from
    /// `user_key` + `prf_salt_next`). Required if `prf_salt_next` is set.
    pub wrapped_dek: String,
    /// Base64 of next prf_salt (32B raw). On every write we rotate the salt to
    /// keep KEK forward-secure relative to the previous wrap.
    pub prf_salt_next: String,
}

/// Act — what the operation does. `type` discriminator on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Act {
    /// First-time vault creation. Body carries the new credential, an initial
    /// wrapped DEK, and an initial sealed body.
    Setup {
        credential: NewCredential,
        /// Base64 of wrapped DEK (XChaCha20-Poly1305 under KEK derived from
        /// `user_key` + `credential.prf_salt`).
        wrapped_dek: String,
        /// Base64 of initial sealed body (XChaCha20-Poly1305 under DEK).
        body: String,
    },
    /// Replace the sealed body and rotate prf_salt + wrapped DEK.
    Write {
        #[serde(flatten)]
        patch: WritePatch,
    },
    /// Decrypt a single key from the vault and return its plaintext value.
    /// The path is dot-separated, e.g. `services.toy.api_key`.
    Reveal {
        path: String,
    },
}

impl Act {
    pub fn discriminator(&self) -> &'static str {
        match self {
            Act::Setup { .. } => "setup",
            Act::Write { .. } => "write",
            Act::Reveal { .. } => "reveal",
        }
    }
}

/// Operation — the U↔T contract. Bind is dropped from v0 toy (no policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub act: Act,
    pub valid: Valid,
}
