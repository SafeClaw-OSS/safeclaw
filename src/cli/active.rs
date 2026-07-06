//! CLI-side config (`~/.safeclaw/config.toml`) + the single derivation point
//! for every daemon URL the CLI uses.
//!
//! The DEVICE atoms live here: `daemon` (the daemon the human's `sc` talks to)
//! and `vault` (the durable default), plus cloud pairing coordinates. URLs are
//! DERIVED from the atoms, never stored (AGENT_SURFACE design wave: atoms are
//! truth, `_url`s are projections):
//!
//! - control root  = daemon host + `CONTROL_PORT` (ceremony/write plane)
//! - API-face root = daemon host + `PROXY_PORT`   (the agent's `DAEMON_URL`)
//!
//! THE self-consistency invariant: both planes derive from ONE daemon-host
//! value. When `$SAFECLAW_DAEMON_URL` is set (an agent's env snapshot), its
//! host wins — an agent's shelled `sc` then targets the SAME daemon the
//! agent's own HTTP does, by construction; the two faces cannot split.
//!
//! On-disk field name: `daemon`. Configs written by an older build used
//! `custodian`; `#[serde(alias = "custodian")]` keeps those loading (pre-launch
//! is wipe+re-enroll, so the alias is belt-and-suspenders, not a migration).
//! The vault-history catalog lives in its own file
//! (`~/.safeclaw/known_vaults.toml`, ssh known_hosts-style — append-growing,
//! harmless to delete), separate from the active selection.

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
    /// LEGACY location of the vault-history catalog — now lives in
    /// `~/.safeclaw/known_vaults.toml` (see [`known_vaults`]). Still read (and
    /// merged) so pre-split configs keep working; the first catalog WRITE
    /// migrates entries over and clears this field.
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

// ── known-vaults catalog (own file, design wave §E) ─────────────────────────

pub fn known_vaults_path() -> Result<PathBuf, String> {
    let base = dirs::home_dir().ok_or_else(|| "no home dir".to_string())?;
    Ok(base.join(".safeclaw").join("known_vaults.toml"))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KnownVaultsFile {
    #[serde(default)]
    vaults: Vec<KnownVault>,
}

/// Every vault this machine has used: the catalog file, plus any entries still
/// in the legacy `config.toml` field (pre-split configs). File order first;
/// the next catalog WRITE migrates the legacy entries over.
pub fn known_vaults() -> Vec<KnownVault> {
    let mut list = read_known_file();
    if let Ok(cfg) = load() {
        for kv in cfg.known_vaults {
            if !list.contains(&kv) {
                list.push(kv);
            }
        }
    }
    list
}

fn read_known_file() -> Vec<KnownVault> {
    let Ok(path) = known_vaults_path() else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    toml::from_str::<KnownVaultsFile>(&text)
        .map(|f| f.vaults)
        .unwrap_or_default()
}

/// Rewrite the catalog with `mutate` applied to the MERGED view (file + legacy
/// config field). Atomic tmp-rename write; completes the migration by clearing
/// the legacy field afterwards.
fn update_known_vaults<F: FnOnce(&mut Vec<KnownVault>)>(mutate: F) -> Result<(), String> {
    let mut list = known_vaults();
    mutate(&mut list);
    let path = known_vaults_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    let body = toml::to_string_pretty(&KnownVaultsFile { vaults: list })
        .map_err(|e| format!("serialize known_vaults: {}", e))?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, body).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), path.display(), e))?;
    if let Ok(mut cfg) = load() {
        if !cfg.known_vaults.is_empty() {
            cfg.known_vaults.clear();
            let _ = save(&cfg);
        }
    }
    Ok(())
}

/// Wipe the catalog (logout).
pub fn clear_known_vaults() -> Result<(), String> {
    update_known_vaults(|l| l.clear())
}

/// Dedupe-append one vault to the catalog.
fn remember_vault(daemon: &str, vault: &str) -> Result<(), String> {
    let new = KnownVault { daemon: daemon.to_string(), vault: vault.to_string() };
    if known_vaults().contains(&new) {
        return Ok(());
    }
    update_known_vaults(move |l| {
        if !l.contains(&new) {
            l.push(new);
        }
    })
}

/// Remove a vault from the catalog. If it was active, clears active.
/// Returns true if something was removed.
pub fn forget(custodian: &str, vault: &str) -> Result<bool, String> {
    if !known_vaults()
        .iter()
        .any(|kv| kv.daemon == custodian && kv.vault == vault)
    {
        return Ok(false);
    }
    update_known_vaults(|l| l.retain(|kv| !(kv.daemon == custodian && kv.vault == vault)))?;
    let mut cfg = load().unwrap_or_default();
    if cfg.daemon.as_deref() == Some(custodian) && cfg.vault.as_deref() == Some(vault) {
        cfg.daemon = None;
        cfg.vault = None;
        save(&cfg)?;
    }
    Ok(true)
}

/// Remove a vault from the catalog by **vault id alone** (any custodian), and
/// clear the active selection if it pointed at that vault. Used by the
/// cloud-sync delete-propagation path, which only knows the vid (a tombstone
/// carries no custodian). Idempotent: a vault not present is `Ok(false)`,
/// never an error.
pub fn forget_vault(vault: &str) -> Result<bool, String> {
    let removed_known = known_vaults().iter().any(|kv| kv.vault == vault);
    if removed_known {
        update_known_vaults(|l| l.retain(|kv| kv.vault != vault))?;
    }
    let mut cfg = load().unwrap_or_default();
    let cleared_active = cfg.vault.as_deref() == Some(vault);
    if cleared_active {
        cfg.daemon = None;
        cfg.vault = None;
        save(&cfg)?;
    }
    Ok(removed_known || cleared_active)
}

/// Set the active vault and dedupe-add it to the catalog.
pub fn put_active(daemon: &str, vault: &str) -> Result<PathBuf, String> {
    remember_vault(daemon, vault)?;
    let mut cfg = load().unwrap_or_default();
    cfg.daemon = Some(daemon.to_string());
    cfg.vault = Some(vault.to_string());
    save(&cfg)
}

/// Set the active vault to a LOCAL daemon URL AND record the cloud pro-backend
/// for sealed-blob sync. Used by `sc login`: the agent talks to the local
/// `daemon`, while the daemon syncs against the cloud (`cloud_backend`).
/// Dedupe-adds to the catalog like `put_active`.
pub fn put_active_with_cloud(
    daemon: &str,
    vault: &str,
    cloud_backend: &str,
    frontend_origin: Option<&str>,
) -> Result<PathBuf, String> {
    remember_vault(daemon, vault)?;
    let mut cfg = load().unwrap_or_default();
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

// ── Atom derivation (design wave §C/§D) ─────────────────────────────────────

/// `scheme://host` of a URL — port and path stripped, `[::1]`-style bracketed
/// hosts kept whole. `None` when there's no `scheme://` or no host.
fn scheme_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if let Some(r) = host_port.strip_prefix('[') {
        format!("[{}]", r.split_once(']')?.0)
    } else {
        host_port.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        return None;
    }
    Some(format!("{}://{}", scheme, host))
}

fn env_daemon_host() -> Option<String> {
    std::env::var("SAFECLAW_DAEMON_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|u| scheme_host(&u))
}

/// The DEVICE's daemon-host atom (`scheme://host`): config's `daemon` with its
/// port stripped, else loopback. This is what the device-side projections
/// (`sc env`, the `sc agent add` minter) derive from — deliberately NOT the
/// process env: a tool that re-read its own output would freeze stale values.
pub fn device_daemon_host(cfg: &CliConfig) -> String {
    cfg.daemon
        .as_deref()
        .and_then(scheme_host)
        .unwrap_or_else(|| "http://127.0.0.1".to_string())
}

/// The control root (`scheme://host:CONTROL_PORT`) every ceremony/write `sc`
/// call targets. Env-first: `$SAFECLAW_DAEMON_URL`'s HOST wins when set (the
/// invariant — shelled `sc` and the agent's own HTTP share one daemon); else
/// config's `daemon` VERBATIM (it may carry a hand-edited custom control
/// port); else the loopback default. The env value carries the PROXY port,
/// never the control port, so the control port comes from the constant — a
/// remote daemon on a non-default control port would need a config edit
/// (that deployment doesn't exist yet).
pub fn control_root(cfg: &CliConfig) -> String {
    control_root_with(env_daemon_host(), cfg)
}

fn control_root_with(env_host: Option<String>, cfg: &CliConfig) -> String {
    if let Some(h) = env_host {
        return format!("{}:{}", h, crate::config::CONTROL_PORT);
    }
    cfg.daemon
        .clone()
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", crate::config::CONTROL_PORT))
}

/// The API-face root (`scheme://host:PROXY_PORT`) — the value an agent holds
/// as `SAFECLAW_DAEMON_URL`. Env verbatim when set (the agent's snapshot,
/// custom port included); else derived from the device atom.
pub fn api_face_root(cfg: &CliConfig) -> String {
    let env_url = std::env::var("SAFECLAW_DAEMON_URL").ok().filter(|s| !s.is_empty());
    api_face_root_with(env_url, cfg)
}

fn api_face_root_with(env_url: Option<String>, cfg: &CliConfig) -> String {
    match env_url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => format!("{}:{}", device_daemon_host(cfg), crate::config::PROXY_PORT),
    }
}

/// The device-default vault (config default, else the single known vault) —
/// the chain WITHOUT the env pin, for projections that mint fresh env output
/// (`sc env`, `sc agent add`): reading the pin there would freeze a stale pin
/// into new output.
pub fn device_default_vault(cfg: &CliConfig) -> Option<String> {
    cfg.vault.clone().or_else(single_known_vault)
}

/// Resolve the active `(control_root, vault)` pair every short-lived `sc`
/// command routes through — the single choke point (AGENT_SURFACE §5).
///
/// - **control root:** see [`control_root`] — the env `DAEMON_URL` HOST wins
///   (the single-host invariant), else config, else the loopback default.
/// - **vault precedence:** `--vault flag > $SAFECLAW_VAULT_ID (env pin) >
///   config default > single-vault auto-select`. The env pin is what makes an
///   agent's shelled-out `sc` target the SAME vault its own HTTP does — env
///   overrides file for the VARYING axis, exactly like `AWS_PROFILE`. A fresh
///   shell (no pin) still follows config + `sc vault use`.
pub fn resolve_active(vault_override: Option<&str>) -> Result<(String, String), String> {
    let cfg = load()?;
    let daemon = control_root(&cfg);
    let vault = vault_override
        .map(str::to_string)
        .or_else(|| std::env::var("SAFECLAW_VAULT_ID").ok().filter(|s| !s.is_empty()))
        .or_else(|| device_default_vault(&cfg))
        .ok_or_else(|| "no vault selected — run `sc login` or `sc vault use`".to_string())?;
    Ok((daemon, vault))
}

/// Single-vault auto-select (§5): exactly one known vault defaults to it, so a
/// fresh shell needs no `sc vault use` and the agent/human vault can't diverge
/// in the common single-vault case. `None` for zero or many.
fn single_known_vault() -> Option<String> {
    let mut it = known_vaults().into_iter().map(|kv| kv.vault);
    match (it.next(), it.next()) {
        (Some(v), None) => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_vault_url_basic() {
        assert_eq!(
            split_vault_url("http://localhost:23295/v/abc"),
            Some(("http://localhost:23295".to_string(), "abc".to_string()))
        );
    }

    #[test]
    fn split_vault_url_no_vid_returns_none() {
        assert_eq!(split_vault_url("http://localhost:23295"), None);
        assert_eq!(split_vault_url("http://localhost:23295/v/"), None);
    }

    #[test]
    fn scheme_host_strips_port_and_path() {
        assert_eq!(scheme_host("http://127.0.0.1:23294"), Some("http://127.0.0.1".into()));
        assert_eq!(
            scheme_host("https://box.example.com:23294/x/y"),
            Some("https://box.example.com".into())
        );
        assert_eq!(scheme_host("http://[::1]:23294"), Some("http://[::1]".into()));
        assert_eq!(scheme_host("no-scheme"), None);
        assert_eq!(scheme_host("http://"), None);
    }

    #[test]
    fn control_root_env_host_wins_config_verbatim_else_default() {
        let cfg = CliConfig {
            daemon: Some("http://127.0.0.1:9999".into()), // hand-edited custom control port
            ..Default::default()
        };
        // Env host set (an agent's shell): its HOST + the control-port constant —
        // the single-host invariant (proxy face and control face share a daemon).
        assert_eq!(
            control_root_with(Some("https://box.example.com".into()), &cfg),
            format!("https://box.example.com:{}", crate::config::CONTROL_PORT)
        );
        // No env: config's control root VERBATIM (custom port preserved).
        assert_eq!(control_root_with(None, &cfg), "http://127.0.0.1:9999");
        // Bare machine: loopback default.
        assert_eq!(
            control_root_with(None, &CliConfig::default()),
            format!("http://127.0.0.1:{}", crate::config::CONTROL_PORT)
        );
    }

    #[test]
    fn api_face_root_env_verbatim_else_derived() {
        let cfg = CliConfig {
            daemon: Some("http://box.example.com:23295".into()),
            ..Default::default()
        };
        // The agent's snapshot wins untouched (custom proxy port included).
        assert_eq!(
            api_face_root_with(Some("http://box.example.com:9999/".into()), &cfg),
            "http://box.example.com:9999"
        );
        // Derived: device daemon HOST + the proxy-port constant.
        assert_eq!(
            api_face_root_with(None, &cfg),
            format!("http://box.example.com:{}", crate::config::PROXY_PORT)
        );
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
