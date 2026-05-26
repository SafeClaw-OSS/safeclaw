//! CLI-side profile config (`~/.config/safeclaw/config.toml`).
//!
//! The CLI persists per-profile `(daemon, vault)` pairs here so users don't
//! type `--daemon URL --vault VID` on every command. The api key (for SaaS)
//! lives only in `$SAFECLAW_API_KEY` — never on disk.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Default profile name used when `SAFECLAW_PROFILE` is unset.
pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct ProfileConfig {
    /// Name of the profile to use when no `--profile` flag is given. Falls
    /// back to `"default"` if absent.
    #[serde(default)]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: std::collections::BTreeMap<String, Profile>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub daemon: String,
    pub vault: String,
}

/// Path to `~/.config/safeclaw/config.toml` (or whatever the platform conf
/// dir resolves to). Returns an error if the platform has no config dir.
pub fn config_path() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "no platform config dir".to_string())?;
    Ok(base.join("safeclaw").join("config.toml"))
}

/// Load `config.toml` if present; returns an empty config if not.
pub fn load() -> Result<ProfileConfig, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(ProfileConfig::default());
    }
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let text = String::from_utf8(bytes).map_err(|_| "config.toml not utf8".to_string())?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {}", path.display(), e))
}

/// Atomically write the entire config back. Creates parent dirs as needed.
pub fn save(cfg: &ProfileConfig) -> Result<PathBuf, String> {
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

/// Upsert a single profile and persist.
pub fn put_profile(name: &str, profile: Profile) -> Result<PathBuf, String> {
    let mut cfg = load()?;
    cfg.profiles.insert(name.to_string(), profile);
    if cfg.default_profile.is_none() {
        cfg.default_profile = Some(name.to_string());
    }
    save(&cfg)
}

/// Resolve the active `(daemon, vault)` pair for short-lived CLI commands.
/// Explicit `--daemon` / `--vault` flags always win; otherwise the named
/// profile (default: `$SAFECLAW_PROFILE` env, then `config.default_profile`,
/// then `"default"`) is loaded.
pub fn resolve_active(
    daemon_override: Option<&str>,
    vault_override: Option<&str>,
    profile_override: Option<&str>,
) -> Result<(String, String), String> {
    if let (Some(d), Some(v)) = (daemon_override, vault_override) {
        return Ok((d.to_string(), v.to_string()));
    }
    let cfg = load()?;
    let profile_name = profile_override
        .map(str::to_string)
        .or_else(|| cfg.default_profile.clone())
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let p = cfg.profiles.get(&profile_name).ok_or_else(|| {
        format!(
            "profile '{}' not found in config — run `safeclaw login` first",
            profile_name
        )
    })?;
    Ok((
        daemon_override
            .map(str::to_string)
            .unwrap_or_else(|| p.daemon.clone()),
        vault_override
            .map(str::to_string)
            .unwrap_or_else(|| p.vault.clone()),
    ))
}
