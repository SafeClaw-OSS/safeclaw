//! WebAuthn assertion verification primitives.

pub mod challenge;
pub mod webauthn;

use serde::{Deserialize, Serialize};

/// Persisted credential metadata (used inside SealedVault).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyEntry {
    /// Base64 of the credential's P-256 X coordinate (32B).
    pub x: String,
    /// Base64 of the credential's P-256 Y coordinate (32B).
    pub y: String,
    #[serde(rename = "deviceName", default, alias = "device_name")]
    pub device_name: String,
    #[serde(rename = "createdAt", default, alias = "created_at")]
    pub created_at: u64,
}
