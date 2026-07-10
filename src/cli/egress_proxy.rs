//! Device-level EGRESS proxy: the upstream HTTP proxy the daemon (and this CLI)
//! use to reach the outside internet — OAuth code/refresh exchanges, the resident
//! MITM proxy's forward hop, and `sc upgrade`'s GitHub fetch.
//!
//! WHY this exists separate from the child-facing proxy (`proxy_env`): the
//! macOS launchd agent (and the systemd unit) do NOT inherit the operator's
//! shell `HTTPS_PROXY`, and both unit generators whitelist only `SAFECLAW_*`, so
//! a `$HTTPS_PROXY` set in a terminal never reaches the long-running daemon.
//! Agents behind a corporate/on-demand proxy therefore couldn't complete a Gmail
//! connect (the daemon-side token exchange hit Google directly and timed out).
//!
//! Model (deliberately the standard one — Docker/systemd/git all do this): the
//! proxy is CONFIGURED at the device level, persisted in a file, and applied to
//! the process env at startup BEFORE any HTTP client is built (reqwest honours
//! `*_PROXY` natively, so one env shaping covers every client). `sc proxy set`
//! writes it + bounces the daemon; changing it is a service-config change, not a
//! per-request knob. An explicit shell `HTTPS_PROXY` still WINS (env > config),
//! so this only fills the gap, never overrides an operator who set it directly.
//!
//! The custodian (cloud control plane) is pinned into `NO_PROXY` so a proxy that
//! can reach the wider internet but NOT the SafeClaw backend doesn't break the
//! cloud sync that was working over a direct route.

use crate::config::default_state_dir;

/// Persisted egress-proxy URL location: `<state_dir>/egress-proxy` (one line, the
/// URL). Absent/empty = no configured egress proxy.
pub fn path() -> std::path::PathBuf {
    default_state_dir().join("egress-proxy")
}

/// The configured egress-proxy URL, or `None` when unset. Trims whitespace and
/// treats an empty file as unset.
pub fn load() -> Option<String> {
    let s = std::fs::read_to_string(path()).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Persist `url` as the device egress proxy (0600 — it may carry proxy
/// userinfo). Overwrites any prior value.
pub fn store(url: &str) -> Result<(), String> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    }
    std::fs::write(&p, format!("{}\n", url.trim()))
        .map_err(|e| format!("write {}: {}", p.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Remove the configured egress proxy (no-op if already absent).
pub fn clear() -> Result<(), String> {
    match std::fs::remove_file(path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {}", path().display(), e)),
    }
}

/// Apply the configured egress proxy to THIS process's environment before any
/// HTTP client is built. No-op when nothing is configured. Called at startup for
/// every `sc` invocation (daemon + CLI) so `serve`'s clients and `sc upgrade`'s
/// GitHub fetch both honour it. An already-set `HTTPS_PROXY` in the real env
/// takes precedence and is left untouched (env > config).
pub fn apply_to_env() {
    let Some(url) = load() else { return };
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // Only fill the slot the operator didn't already set in their shell.
        if std::env::var_os(key).map(|v| v.is_empty()).unwrap_or(true) {
            std::env::set_var(key, &url);
        }
    }
    // Keep the cloud control plane on its (working) direct route: pin the
    // custodian host into NO_PROXY so a Google-only proxy can't sink cloud sync.
    let mut extra: Vec<String> = Vec::new();
    if let Ok(cfg) = crate::cli::active::load() {
        if let Some(host) = cfg
            .cloud_backend
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(host_of)
        {
            extra.push(host);
        }
    }
    if !extra.is_empty() {
        for key in ["NO_PROXY", "no_proxy"] {
            let merged = merge_hosts(&std::env::var(key).unwrap_or_default(), &extra);
            std::env::set_var(key, merged);
        }
    }
}

/// Extract the bare host from a `scheme://host[:port]/path` URL (no scheme, port,
/// path, or userinfo) — the shape a `NO_PROXY` entry matches on.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Drop any userinfo, then the port.
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port);
    (!host.is_empty()).then(|| host.to_string())
}

/// Append `extra` hosts to a comma-separated NO_PROXY value, preserving existing
/// entries/order and skipping case-insensitive duplicates. Pure (testable).
fn merge_hosts(current: &str, extra: &[String]) -> String {
    let mut hosts: Vec<String> = current
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for h in extra {
        if !hosts.iter().any(|e| e.eq_ignore_ascii_case(h)) {
            hosts.push(h.clone());
        }
    }
    hosts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_scheme_port_path_userinfo() {
        assert_eq!(
            host_of("https://api.safeclaw.pro").as_deref(),
            Some("api.safeclaw.pro")
        );
        assert_eq!(
            host_of("https://api.safeclaw.pro/").as_deref(),
            Some("api.safeclaw.pro")
        );
        assert_eq!(
            host_of("https://api.safeclaw.pro:8443/v/x/blob").as_deref(),
            Some("api.safeclaw.pro")
        );
        assert_eq!(
            host_of("http://u:p@box.example.com:9999").as_deref(),
            Some("box.example.com")
        );
        assert_eq!(host_of("").as_deref(), None);
    }

    #[test]
    fn merge_hosts_appends_missing_case_insensitive() {
        assert_eq!(
            merge_hosts("", &["api.safeclaw.pro".into()]),
            "api.safeclaw.pro"
        );
        assert_eq!(
            merge_hosts("localhost,127.0.0.1", &["api.safeclaw.pro".into()]),
            "localhost,127.0.0.1,api.safeclaw.pro"
        );
        // Idempotent: already-present (any case) not duplicated.
        assert_eq!(
            merge_hosts("localhost,API.safeclaw.pro", &["api.safeclaw.pro".into()]),
            "localhost,API.safeclaw.pro"
        );
    }
}
