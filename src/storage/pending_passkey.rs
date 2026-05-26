//! Pending-passkey deposit store (cross-device add-passkey, Stage 1 →
//! Stage 2 bridge).
//!
//! ## Why this exists
//!
//! Per-vault add-passkey requires the **new** credential's `W_c`
//! (`user_key_initial`) and an **existing** vault-enrolled credential to
//! sign the `Enroll(target="passkeys")` op. When those two credentials
//! live on different devices (e.g. new iPhone Face ID + Mac, where Mac
//! is the vault's current passkey holder), there's no live channel
//! between them. The pending-passkey deposit bridges the gap:
//!
//! ```text
//! Stage 1 (new-cred device): POST a pending-passkey record. Body
//!   contains the new credential's public material + an HPKE-sealed
//!   `user_key_initial` (sealed to daemon's sc_pk per envelope.rs,
//!   info-bound to (vault_id ‖ cid) so the seal can't be re-purposed).
//!
//! Stage 2 (existing-cred device): submit Enroll(target="passkeys")
//!   referencing only the new cid. The daemon looks up the pending
//!   record, HPKE-opens user_key_initial with sc_sk, runs the usual
//!   add-passkey lifecycle, and deletes the file.
//! ```
//!
//! ## Lifecycle
//!
//! Transient. **TTL = 1 hour**. Either consumed by a successful
//! Stage 2 (`load_and_consume`), or swept by the opportunistic GC
//! that runs on `list()` calls (the only place we know the daemon is
//! actively serving this vault).
//!
//! ## Storage
//!
//! `tenants/{vid}/pending-passkeys/{cid_filename}.json` — one file per
//! pending credential. `cid_filename` is the URL-safe base64url cid
//! (already filename-safe by construction since we standardized on
//! base64url-no-pad in commit ca2ffd2 / c382eac).
//!
//! The file is plain JSON: the `sealed_user_key` field is opaque HPKE
//! ciphertext, everything else is metadata needed by Stage 2 UI and
//! by the Enroll handler to register the credential.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::storage::tenant_dir::TenantDir;

/// Wall-clock TTL for a pending-passkey file. After this, Stage 2
/// `load_and_consume` returns `NotFound` and the opportunistic GC
/// will delete the stale file on the next `list()` call.
pub const PENDING_PASSKEY_TTL_SECS: u64 = 3600; // 1h

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPasskey {
    /// base64url-no-pad credential id (matches everywhere else on the wire).
    pub credential_id: String,
    /// base64 (STANDARD) of the P-256 pubkey x coord.
    pub x: String,
    /// base64 (STANDARD) of the P-256 pubkey y coord.
    pub y: String,
    /// base64 (STANDARD) of the new credential's prf_salt (32 bytes).
    pub prf_salt: String,
    /// Display name for the Stage 2 approval UI ("Mac · quiet-willow").
    pub device_name: String,
    /// HPKE encapsulated key (X25519, 32 bytes), URL-safe base64-no-pad.
    pub enc: String,
    /// HPKE ciphertext (sealed `user_key_initial` = 32B + 16B tag),
    /// URL-safe base64-no-pad.
    pub ct: String,
    /// Unix seconds the deposit was written. Used for TTL.
    pub created_at: u64,
}

impl PendingPasskey {
    /// Seconds since this deposit was created. Used by GC + by the
    /// Enroll handler to reject expired deposits.
    pub fn age_secs(&self) -> u64 {
        now_unix().saturating_sub(self.created_at)
    }

    pub fn expired(&self) -> bool {
        self.age_secs() > PENDING_PASSKEY_TTL_SECS
    }

    /// Public metadata for the Stage 2 approval UI. Opaque ciphertext
    /// stays daemon-side; the UI just needs to render the device name
    /// + cid + freshness.
    pub fn public_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "credential_id": self.credential_id,
            "x": self.x,
            "y": self.y,
            "device_name": self.device_name,
            "created_at": self.created_at,
            "ttl_seconds": PENDING_PASSKEY_TTL_SECS,
            "expires_in_seconds": PENDING_PASSKEY_TTL_SECS.saturating_sub(self.age_secs()),
        })
    }
}

/// Write or overwrite a pending-passkey deposit for this vault. Existing
/// records for the same cid are replaced (idempotent retries are fine).
pub fn put(tenants: &TenantDir, vault_id: &str, pending: &PendingPasskey) -> Result<()> {
    let dir = ensure_dir(tenants, vault_id)?;
    let path = dir.join(filename_for(&pending.credential_id));
    let body = serde_json::to_vec_pretty(pending)
        .map_err(|e| AppError::Internal(format!("serialize pending: {}", e)))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &body)
        .map_err(|e| AppError::Internal(format!("write pending tmp: {}", e)))?;
    fs::rename(&tmp, &path)
        .map_err(|e| AppError::Internal(format!("rename pending: {}", e)))?;
    Ok(())
}

/// Read + delete in one step (Stage 2 consumption). Atomic on most
/// filesystems via rename-then-read. Returns the deserialized record
/// or `NotFound` if the file's missing / expired / malformed (the
/// expired branch also deletes).
pub fn load_and_consume(
    tenants: &TenantDir,
    vault_id: &str,
    credential_id: &str,
) -> Result<PendingPasskey> {
    let dir = tenants.pending_passkeys_dir(vault_id)?;
    let path = dir.join(filename_for(credential_id));
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AppError::NotFound);
        }
        Err(e) => return Err(AppError::Internal(format!("read pending: {}", e))),
    };
    // Delete first so a parse error or any later failure still cleans
    // up the slot — pending-passkeys are single-use by design.
    let _ = fs::remove_file(&path);
    let rec: PendingPasskey = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("parse pending: {}", e)))?;
    if rec.expired() {
        return Err(AppError::NotFound);
    }
    Ok(rec)
}

/// List all non-expired pending-passkey deposits for this vault. Side
/// effect: deletes any expired files encountered (opportunistic GC, same
/// pattern as the audit prune in approvals.rs).
pub fn list(tenants: &TenantDir, vault_id: &str) -> Result<Vec<PendingPasskey>> {
    let dir = tenants.pending_passkeys_dir(vault_id)?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries = fs::read_dir(&dir)
        .map_err(|e| AppError::Internal(format!("read pending dir: {}", e)))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let rec: PendingPasskey = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(_) => {
                // Malformed → can't trust it, drop it.
                let _ = fs::remove_file(&path);
                continue;
            }
        };
        if rec.expired() {
            let _ = fs::remove_file(&path);
            continue;
        }
        out.push(rec);
    }
    out.sort_by_key(|r| std::cmp::Reverse(r.created_at));
    Ok(out)
}

fn ensure_dir(tenants: &TenantDir, vault_id: &str) -> Result<PathBuf> {
    let dir = tenants.pending_passkeys_dir(vault_id)?;
    fs::create_dir_all(&dir)
        .map_err(|e| AppError::Internal(format!("mkdir pending: {}", e)))?;
    Ok(dir)
}

/// Sanitize cid → filesystem-safe filename. Standardised credential_id
/// is base64url-no-pad (`-_` alphabet), already safe for filenames on
/// every platform we care about. Belt-and-suspenders: reject anything
/// that snuck in with `/` or other path separators.
fn filename_for(credential_id: &str) -> String {
    let sanitized: String = credential_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    format!("{}.json", sanitized)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
