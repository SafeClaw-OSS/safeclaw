//! Cloud sealed-blob sync (Slice 3).
//!
//! The daemon is a thin pull/push client over the pro-backend's blind blob
//! store (`/v/{vid}/blob`, Supabase Storage behind it). On startup it pulls
//! the active vault's `SealedState` blob and writes it to the local
//! `vault.dat`, so a freshly-paired device can serve a vault that was sealed
//! in the browser. Cloud is the source of truth (1Password model); the pull
//! is version-gated (`?since=<local>`) so an already-current local copy is
//! left untouched and a web edit shows up on the next daemon (re)start.
//!
//! The cloud never decrypts: the blob is passkey-sealed (W_c is not in it).
//! Auth is the daemon's device-key (`~/.safeclaw/device-key`, a `sc_device_`
//! token), distinct from the agent→daemon broker api-key.
//!
//! Best-effort by design: any failure logs and leaves local state untouched
//! — a local-only daemon (no `cloud_backend` configured) just skips this and
//! serves whatever `vault.dat` is on disk. See [[project_slice3_design]].

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::active;
use crate::storage::sealed_vault::{self, SealedVault};

/// Read the persisted device-key (`~/.safeclaw/device-key`, written by
/// `sc login`). Returns None when the device hasn't been paired.
fn device_key() -> Option<String> {
    let home = dirs::home_dir()?;
    let raw = std::fs::read_to_string(home.join(".safeclaw").join("device-key")).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Sidecar next to a vault's `vault.dat` recording the last-pulled blob
/// version, so `?since=` can short-circuit an unchanged cloud copy.
fn version_sidecar(state_dir: &Path, vault: &str) -> PathBuf {
    state_dir.join("vaults").join(vault).join(".blob_version")
}

fn read_local_version(state_dir: &Path, vault: &str) -> u64 {
    std::fs::read_to_string(version_sidecar(state_dir, vault))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Pull the active vault's sealed blob from the cloud and write `vault.dat`
/// if the cloud copy is newer than the local one. Never returns Err — a
/// failed or unconfigured sync must not stop the daemon from serving.
pub async fn pull_on_start(state_dir: &Path) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("cloud sync: no CLI config ({}); skipping pull", e);
            return;
        }
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        tracing::debug!("cloud sync: no cloud_backend configured; local-only daemon");
        return;
    };
    let Some(vault) = cfg.vault.as_deref().filter(|s| !s.is_empty()) else {
        tracing::debug!("cloud sync: no active vault; skipping pull");
        return;
    };
    let Some(dk) = device_key() else {
        tracing::debug!("cloud sync: no device-key (unpaired); skipping pull");
        return;
    };
    match pull(state_dir, cloud, vault, &dk).await {
        Ok(Some(version)) => {
            tracing::info!(vault = %vault, version, "cloud sync: pulled vault.dat from cloud");
        }
        Ok(None) => {
            tracing::debug!(vault = %vault, "cloud sync: local vault.dat already current");
        }
        Err(e) => {
            tracing::warn!(vault = %vault, "cloud sync pull failed (serving local state): {}", e);
        }
    }
}

/// Returns `Ok(Some(version))` when a newer blob was written, `Ok(None)` when
/// local was already current (or the cloud has no blob yet).
async fn pull(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<Option<u64>, String> {
    let local_ver = read_local_version(state_dir, vault);
    let url = format!(
        "{}/v/{}/blob?since={}",
        cloud.trim_end_matches('/'),
        vault,
        local_ver
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;

    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(None), // no blob in the cloud yet (not sealed on web)
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("cloud blob GET HTTP {}", other)),
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse blob response: {}", e))?;

    // `{ unchanged: true }` — the cheap freshness probe said local is current.
    if body
        .get("unchanged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let blob = body
        .get("blob")
        .ok_or_else(|| "blob missing in cloud response".to_string())?;

    // Validate it parses as a SealedVault BEFORE touching disk — never
    // persist garbage over a working vault.dat.
    let sealed: SealedVault = serde_json::from_value(blob.clone())
        .map_err(|e| format!("cloud blob is not a valid SealedState: {}", e))?;

    let vault_path = state_dir.join("vaults").join(vault).join("vault.dat");
    sealed_vault::write_atomic(&vault_path, &sealed)
        .map_err(|e| format!("write vault.dat: {}", e))?;

    // Record the version so the next start can `?since=` short-circuit.
    if let Err(e) = std::fs::write(version_sidecar(state_dir, vault), version.to_string()) {
        tracing::warn!(vault = %vault, "cloud sync: wrote vault.dat but failed to record version: {}", e);
    }

    Ok(Some(version))
}
