//! CLI-side config (`~/.safeclaw/config.toml`).
//!
//! Tracks the active `(daemon, vault)` pair plus a list of all vaults the user
//! has used on this machine. `daemon` is the local SafeClaw daemon URL the
//! human's `sc` talks to (after `sc login` it's the loopback daemon, not the
//! cloud). Vaults are addressed via `SAFECLAW_VAULT_URL` (= daemon root + vault
//! id baked into the path); the CLI splits/joins as needed.
//!
//! On-disk field name: `daemon`. Configs written by an older build used
//! `custodian`; `#[serde(alias = "custodian")]` keeps those loading (pre-launch
//! is wipe+re-enroll, so the alias is belt-and-suspenders, not a migration).

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct CliConfig {
    /// The local daemon URL the human's `sc` talks to (loopback after login).
    #[serde(default, alias = "custodian")]
    pub daemon: Option<String>,
    #[serde(default)]
    pub vault: Option<String>,
    /// History of vaults this CLI has used. `sc vault ls` displays
    /// these; new entries get added by `sc vault use` and `sc vault
    /// create`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_vaults: Vec<KnownVault>,
    /// Cloud pro-backend origin for sealed-blob sync (Slice 3) AND the
    /// op-relay (web approval). Set by `sc login`; the daemon pulls
    /// `{cloud_backend}/v/{vault}/blob` and registers pending ops at
    /// `{cloud_backend}/v/{vault}/op/relay/*`. Distinct from `daemon`,
    /// which after login points at the LOCAL daemon the agent talks to.
    /// See [[project_slice3_design]].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_backend: Option<String>,
    /// Cloud FRONTEND origin (where the human taps their passkey: the web
    /// approval page at `{frontend_origin}/grant/{op_id}`). Returned by the
    /// pair-token exchange as `console_url`. Distinct from `cloud_backend`
    /// (the API host, typically `api.<frontend>`). Set by `sc login`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_origin: Option<String>,
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
    /// The daemon URL this vault lives behind. (On-disk alias: `custodian`.)
    #[serde(alias = "custodian")]
    pub daemon: String,
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
    cfg.known_vaults.retain(|kv| !(kv.daemon == custodian && kv.vault == vault));
    if cfg.known_vaults.len() == before {
        return Ok(false);
    }
    if cfg.daemon.as_deref() == Some(custodian) && cfg.vault.as_deref() == Some(vault) {
        cfg.daemon = None;
        cfg.vault = None;
    }
    save(&cfg)?;
    Ok(true)
}

/// Remove a vault from `known_vaults` by **vault id alone** (any custodian),
/// and clear the active selection if it pointed at that vault. Used by the
/// cloud-sync delete-propagation path, which only knows the vid (a tombstone
/// carries no custodian). Returns true if anything was removed. Idempotent: a
/// vault not present is `Ok(false)`, never an error. Load → retain != vault →
/// save (atomic via the tmp-rename in `save`).
pub fn forget_vault(vault: &str) -> Result<bool, String> {
    let mut cfg = load().unwrap_or_default();
    let before = cfg.known_vaults.len();
    cfg.known_vaults.retain(|kv| kv.vault != vault);
    let removed_known = cfg.known_vaults.len() != before;
    let cleared_active = cfg.vault.as_deref() == Some(vault);
    if cleared_active {
        cfg.daemon = None;
        cfg.vault = None;
    }
    if !removed_known && !cleared_active {
        return Ok(false);
    }
    save(&cfg)?;
    Ok(true)
}

/// Set the active vault and dedupe-add to known_vaults.
pub fn put_active(daemon: &str, vault: &str) -> Result<PathBuf, String> {
    let mut cfg = load().unwrap_or_default();
    let new = KnownVault { daemon: daemon.to_string(), vault: vault.to_string() };
    if !cfg.known_vaults.contains(&new) {
        cfg.known_vaults.push(new);
    }
    cfg.daemon = Some(daemon.to_string());
    cfg.vault = Some(vault.to_string());
    save(&cfg)
}

/// Set the active vault to a LOCAL daemon URL AND record the cloud pro-backend
/// for sealed-blob sync. Used by `sc login`: the agent talks to the local
/// `daemon`, while the daemon syncs against the cloud (`cloud_backend`).
/// Dedupe-adds to known_vaults like `put_active`.
pub fn put_active_with_cloud(
    daemon: &str,
    vault: &str,
    cloud_backend: &str,
    frontend_origin: Option<&str>,
) -> Result<PathBuf, String> {
    let mut cfg = load().unwrap_or_default();
    let new = KnownVault { daemon: daemon.to_string(), vault: vault.to_string() };
    if !cfg.known_vaults.contains(&new) {
        cfg.known_vaults.push(new);
    }
    cfg.daemon = Some(daemon.to_string());
    cfg.vault = Some(vault.to_string());
    cfg.cloud_backend = Some(cloud_backend.to_string());
    cfg.frontend_origin = frontend_origin
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());
    save(&cfg)
}

/// Resolve the cloud FRONTEND origin (for the human web-approval link
/// `{origin}/grant/{op_id}`). Prefers the `console_url` persisted at login;
/// falls back to deriving it from `cloud_backend` by dropping a leading
/// `api.` label (the deployment convention is `api.<frontend>`). Returns
/// `None` for a local-only / self-host daemon (no cloud pairing).
pub fn frontend_origin() -> Option<String> {
    let cfg = load().ok()?;
    if let Some(fo) = cfg.frontend_origin.as_deref().filter(|s| !s.is_empty()) {
        return Some(fo.trim_end_matches('/').to_string());
    }
    let backend = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty())?;
    Some(derive_frontend_from_backend(backend))
}

/// Human web-approval link for an op. When the daemon is cloud-paired this is
/// the absolute cloud page `{frontend_origin}/grant/{op_id}` — the only
/// approval surface a remote user can actually reach (the daemon is
/// zero-inbound localhost). For a local-only / self-host daemon it's the
/// relative `/op/{op_id}` page the daemon serves itself. Single source of
/// truth for both the broker's `approve_url` and the CLI's remote-approve arm.
pub fn grant_url(op_id: &str) -> String {
    match frontend_origin() {
        Some(origin) => format!("{}/grant/{}", origin, op_id),
        None => format!("/op/{}", op_id),
    }
}

/// `https://api.dev.safeclaw.pro` → `https://dev.safeclaw.pro`. Only strips a
/// leading `api.` on the host; everything else (scheme, port, path) is kept.
/// A backend host without an `api.` prefix is returned unchanged (self-host
/// where frontend == backend).
fn derive_frontend_from_backend(backend: &str) -> String {
    let trimmed = backend.trim_end_matches('/');
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s, r),
        None => return trimmed.to_string(),
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let host_port = host_port.strip_prefix("api.").unwrap_or(host_port);
    match path {
        Some(p) => format!("{}://{}/{}", scheme, host_port, p),
        None => format!("{}://{}", scheme, host_port),
    }
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

pub fn join_vault_url(daemon: &str, vault: &str) -> String {
    format!("{}/v/{}", daemon.trim_end_matches('/'), vault)
}

/// Resolve the active `(daemon_url, vault)` pair for short-lived CLI commands —
/// the `(daemon, vault)` the **human's** `sc` command operates on.
/// Source = `config.toml` (set by `sc login` / `sc vault use`) + the explicit
/// `--vault` flag (`vault_override`, which reselects just the vault id).
///
/// We deliberately do NOT read `$SAFECLAW_VAULT_URL` here. That env var is the
/// AGENT's broker endpoint (the install-prompt persists it for the agent
/// process). A human's `sc` command must never inherit the agent's vault
/// choice — if it did, a stale agent env would hijack the human's commands
/// (it did: a real unlock bug). The rule we keep:
///   env          = process config (daemon-serve params, the agent's broker URL)
///   active vault = user state → config.toml
pub fn resolve_active(vault_override: Option<&str>) -> Result<(String, String), String> {
    let cfg = load()?;
    let daemon = cfg.daemon.clone().ok_or_else(|| {
        "no vault selected — run `sc login` or `sc vault use`".to_string()
    })?;
    let vault = vault_override
        .map(str::to_string)
        .or(cfg.vault.clone())
        .ok_or_else(|| "no vault selected — run `sc login` or `sc vault use`".to_string())?;
    Ok((daemon, vault))
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

    #[test]
    fn derive_frontend_strips_api_label() {
        assert_eq!(
            derive_frontend_from_backend("https://api.dev.safeclaw.pro"),
            "https://dev.safeclaw.pro"
        );
        assert_eq!(
            derive_frontend_from_backend("https://api.safeclaw.pro/"),
            "https://safeclaw.pro"
        );
        // No api. prefix (self-host) → unchanged.
        assert_eq!(
            derive_frontend_from_backend("http://localhost:8787"),
            "http://localhost:8787"
        );
        // Only the leading label is stripped; a path is preserved.
        assert_eq!(
            derive_frontend_from_backend("https://api.example.com/base"),
            "https://example.com/base"
        );
    }
}
