//! CLI-side config (`~/.safeclaw/config.toml`).
//!
//! Tracks the active `(custodian, vault)` pair plus a list of all
//! vaults the user has used on this machine. Vaults are addressed via
//! `SAFECLAW_VAULT_URL` (= custodian root + vault id baked into the
//! path); the CLI splits/joins as needed.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct CliConfig {
    #[serde(default)]
    pub custodian: Option<String>,
    #[serde(default)]
    pub vault: Option<String>,
    /// History of vaults this CLI has used. `sc vault ls` displays
    /// these; new entries get added by `sc vault use` and `sc vault
    /// create`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_vaults: Vec<KnownVault>,
    /// Cloud pro-backend origin for sealed-blob sync (Slice 3). Set by
    /// `sc login`; the daemon pulls `{cloud_backend}/v/{vault}/blob` on
    /// start. Distinct from `custodian`, which after login points at the
    /// LOCAL daemon the agent talks to. See [[project_slice3_design]].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_backend: Option<String>,
    /// Persistent user preferences. Set via `sc config set <key> <value>`.
    /// Resolution chain for any setting: flag > env > this > built-in
    /// default.
    #[serde(default, skip_serializing_if = "Settings::is_empty")]
    pub settings: Settings,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// Localhost callback port for browser-gesture commands (`unlock`,
    /// `vault create`, etc.). The CLI binds this to receive WebAuthn
    /// redirects. Useful with SSH `-L` forwarding when the browser
    /// lives on a different machine than the daemon. Env override:
    /// `SAFECLAW_CB_PORT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cb_port: Option<u16>,
}

impl Settings {
    fn is_empty(&self) -> bool {
        self.cb_port.is_none()
    }
}

/// Resolve the effective `cb_port`: flag override wins, otherwise read
/// the persisted setting. (Env is handled by clap's `env = ...` and is
/// already folded into the flag value.)
pub fn settings_cb_port() -> Option<u16> {
    load().ok().and_then(|c| c.settings.cb_port)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KnownVault {
    pub custodian: String,
    pub vault: String,
}

pub fn config_path() -> Result<PathBuf, String> {
    let base = dirs::home_dir().ok_or_else(|| "no home dir".to_string())?;
    Ok(base.join(".safeclaw").join("config.toml"))
}

pub fn load() -> Result<CliConfig, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let text = String::from_utf8(bytes).map_err(|_| "config.toml not utf8".to_string())?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {}", path.display(), e))
}

pub fn save(cfg: &CliConfig) -> Result<PathBuf, String> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    let body = toml::to_string_pretty(cfg)
        .map_err(|e| format!("serialize config: {}", e))?;
    let tmp = path.with_extension("toml.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| format!("create {}: {}", tmp.display(), e))?;
        f.write_all(body.as_bytes())
            .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    }
    fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), path.display(), e))?;
    Ok(path)
}

/// Remove a vault from known_vaults. If it was active, clears active.
/// Returns true if something was removed.
pub fn forget(custodian: &str, vault: &str) -> Result<bool, String> {
    let mut cfg = load().unwrap_or_default();
    let before = cfg.known_vaults.len();
    cfg.known_vaults.retain(|kv| !(kv.custodian == custodian && kv.vault == vault));
    if cfg.known_vaults.len() == before {
        return Ok(false);
    }
    if cfg.custodian.as_deref() == Some(custodian) && cfg.vault.as_deref() == Some(vault) {
        cfg.custodian = None;
        cfg.vault = None;
    }
    save(&cfg)?;
    Ok(true)
}

/// Set the active vault and dedupe-add to known_vaults.
pub fn put_active(custodian: &str, vault: &str) -> Result<PathBuf, String> {
    let mut cfg = load().unwrap_or_default();
    let new = KnownVault { custodian: custodian.to_string(), vault: vault.to_string() };
    if !cfg.known_vaults.contains(&new) {
        cfg.known_vaults.push(new);
    }
    cfg.custodian = Some(custodian.to_string());
    cfg.vault = Some(vault.to_string());
    save(&cfg)
}

/// Set the active vault to a LOCAL daemon custodian AND record the cloud
/// pro-backend for sealed-blob sync. Used by `sc login`: the agent talks to
/// the local daemon (`custodian`), while the daemon syncs against the cloud
/// (`cloud_backend`). Dedupe-adds to known_vaults like `put_active`.
pub fn put_active_with_cloud(
    custodian: &str,
    vault: &str,
    cloud_backend: &str,
) -> Result<PathBuf, String> {
    let mut cfg = load().unwrap_or_default();
    let new = KnownVault { custodian: custodian.to_string(), vault: vault.to_string() };
    if !cfg.known_vaults.contains(&new) {
        cfg.known_vaults.push(new);
    }
    cfg.custodian = Some(custodian.to_string());
    cfg.vault = Some(vault.to_string());
    cfg.cloud_backend = Some(cloud_backend.to_string());
    save(&cfg)
}

/// Split a combined URL like `http://host:port/v/<vid>` into
/// `(root, vid)`. Returns None if the URL doesn't carry `/v/<vid>`.
pub fn split_vault_url(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim_end_matches('/');
    let (root, tail) = trimmed.rsplit_once("/v/")?;
    if tail.is_empty() || tail.contains('/') {
        return None;
    }
    Some((root.to_string(), tail.to_string()))
}

pub fn join_vault_url(custodian: &str, vault: &str) -> String {
    format!("{}/v/{}", custodian.trim_end_matches('/'), vault)
}

/// Resolve the active `(daemon_url, vault)` pair for short-lived CLI commands.
/// The daemon URL comes from `$SAFECLAW_VAULT_URL` (or the active config),
/// defaulting via config — point the agent/CLI at another device's daemon by
/// setting `$SAFECLAW_VAULT_URL`. `vault_override` (the `--vault` flag) only
/// reselects the vault id on that daemon. Precedence: $SAFECLAW_VAULT_URL >
/// config; `--vault` overrides just the vault id.
pub fn resolve_active(vault_override: Option<&str>) -> Result<(String, String), String> {
    let (env_custodian, env_vault) = match std::env::var("SAFECLAW_VAULT_URL") {
        Ok(url) if !url.is_empty() => split_vault_url(&url)
            .map(|(c, v)| (Some(c), Some(v)))
            .unwrap_or((None, None)),
        _ => (None, None),
    };
    let cfg = load()?;
    let custodian = env_custodian
        .or(cfg.custodian.clone())
        .ok_or_else(|| {
            "no vault selected — run `safeclaw vault use` or set $SAFECLAW_VAULT_URL".to_string()
        })?;
    let vault = vault_override
        .map(str::to_string)
        .or(env_vault)
        .or(cfg.vault.clone())
        .ok_or_else(|| {
            "no vault selected — run `safeclaw vault use` or set $SAFECLAW_VAULT_URL".to_string()
        })?;
    Ok((custodian, vault))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_vault_url_basic() {
        assert_eq!(
            split_vault_url("http://localhost:23294/v/abc"),
            Some(("http://localhost:23294".to_string(), "abc".to_string()))
        );
    }

    #[test]
    fn split_vault_url_no_vid_returns_none() {
        assert_eq!(split_vault_url("http://localhost:23294"), None);
        assert_eq!(split_vault_url("http://localhost:23294/v/"), None);
    }
}
