//! CLI-side config (`~/.config/safeclaw/config.toml`).
//!
//! Stores a single active `(custodian, vault)` pair so short-lived CLI
//! commands don't have to retype `--custodian URL --vault VID` every
//! call. The api key (SaaS users) lives in `$SAFECLAW_API_KEY` only,
//! never on disk.
//!
//! Schema (2026-05-27, per [[architecture-final-2026-05-27]]):
//!
//! ```toml
//! custodian = "http://localhost:23294"
//! vault     = "abc-def-..."
//! ```
//!
//! Multi-profile `[profiles.NAME]` was dropped in favour of "switch with
//! `--custodian` / `--vault` flags, or override `SAFECLAW_VAULT_URL` env
//! per shell." The agent skill itself reads `SAFECLAW_VAULT_URL`
//! exclusively (vault id baked into the URL); the CLI accepts both
//! shapes — `SAFECLAW_VAULT_URL` for one-shot all-in-one override,
//! `SAFECLAW_CUSTODIAN` for daemon-only override.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct CliConfig {
    /// Custodian (daemon) base URL, no trailing slash and no `/v/<vid>`
    /// suffix. e.g. `http://localhost:23294` or
    /// `https://api.safeclaw.pro`.
    #[serde(default)]
    pub custodian: Option<String>,
    /// Active vault id. Required for any vault-scoped command.
    #[serde(default)]
    pub vault: Option<String>,
}

/// Path to `~/.config/safeclaw/config.toml` (or the platform-specific
/// equivalent). Errors only if the platform has no config dir at all.
pub fn config_path() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "no platform config dir".to_string())?;
    Ok(base.join("safeclaw").join("config.toml"))
}

/// Load `config.toml` if present; returns an empty config if not.
///
/// Unknown fields (e.g. the legacy `[profiles.X]` tables from pre-
/// 2026-05-27 configs) are silently ignored — old configs deserialize
/// to defaults and the user just re-runs `safeclaw login`.
pub fn load() -> Result<CliConfig, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let text = String::from_utf8(bytes).map_err(|_| "config.toml not utf8".to_string())?;
    // serde + toml ignores unknown fields by default, so legacy
    // `[profiles.X]` tables from pre-2026-05-27 configs don't trip
    // parsing — they just don't show up on `CliConfig`. The user
    // re-runs `safeclaw login` to populate the new flat fields.
    toml::from_str(&text).map_err(|e| format!("parse {}: {}", path.display(), e))
}

/// Atomically write the entire config back. Creates parent dirs as needed.
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

/// Replace the active config and persist.
pub fn put_active(custodian: &str, vault: &str) -> Result<PathBuf, String> {
    save(&CliConfig {
        custodian: Some(custodian.to_string()),
        vault: Some(vault.to_string()),
    })
}

/// Split a combined URL like `http://host:port/v/<vid>` into
/// `(root, vid)`. Returns None if the URL doesn't carry `/v/<vid>`.
fn split_vault_url(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim_end_matches('/');
    let (root, tail) = trimmed.rsplit_once("/v/")?;
    if tail.is_empty() || tail.contains('/') {
        return None;
    }
    Some((root.to_string(), tail.to_string()))
}

/// Resolve the active `(custodian, vault)` pair for short-lived CLI
/// commands. Precedence (highest first):
///
/// 1. Explicit `--custodian` / `--vault` flag overrides.
/// 2. `SAFECLAW_VAULT_URL` env (split into root + vid).
/// 3. `SAFECLAW_CUSTODIAN` / `SAFECLAW_VAULT` env (handled upstream via
///    clap `env = "..."` on each flag; arrives as Some at this point).
/// 4. The active `~/.config/safeclaw/config.toml`.
pub fn resolve_active(
    custodian_override: Option<&str>,
    vault_override: Option<&str>,
) -> Result<(String, String), String> {
    if let (Some(c), Some(v)) = (custodian_override, vault_override) {
        return Ok((c.to_string(), v.to_string()));
    }
    let (env_custodian, env_vault) = match std::env::var("SAFECLAW_VAULT_URL") {
        Ok(url) if !url.is_empty() => split_vault_url(&url)
            .map(|(c, v)| (Some(c), Some(v)))
            .unwrap_or((None, None)),
        _ => (None, None),
    };
    let cfg = load()?;
    let custodian = custodian_override
        .map(str::to_string)
        .or(env_custodian)
        .or(cfg.custodian.clone())
        .ok_or_else(|| {
            "no custodian configured — run `safeclaw login` or set \
                $SAFECLAW_VAULT_URL"
                .to_string()
        })?;
    let vault = vault_override
        .map(str::to_string)
        .or(env_vault)
        .or(cfg.vault.clone())
        .ok_or_else(|| {
            "no vault configured — run `safeclaw login` or set \
                $SAFECLAW_VAULT_URL"
                .to_string()
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
        assert_eq!(
            split_vault_url("https://api.safeclaw.pro/v/abc-def-123/"),
            Some(("https://api.safeclaw.pro".to_string(), "abc-def-123".to_string()))
        );
    }

    #[test]
    fn split_vault_url_no_vid_returns_none() {
        assert_eq!(split_vault_url("http://localhost:23294"), None);
        assert_eq!(split_vault_url("http://localhost:23294/v/"), None);
        assert_eq!(split_vault_url("http://localhost:23294/v/abc/extra"), None);
    }
}
