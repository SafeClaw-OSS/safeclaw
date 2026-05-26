//! `safeclaw status` — daemon reachability + version probe.
//!
//! Read-only, no passkey ceremony, no vault context. Hits the daemon's
//! `GET /c/health` and pretty-prints the result. Daemon URL is resolved
//! from (in order): `--daemon` flag, `$SAFECLAW_DAEMON`, the active
//! profile in `~/.config/safeclaw/config.toml`, then `127.0.0.1:23294`.
//! Exit code is non-zero on transport / parse failure so shell scripts
//! can gate on it.

use crate::cli::profile::load as load_profiles;
use crate::config::StatusArgs;

const LOCAL_DEFAULT: &str = "http://127.0.0.1:23294";

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let daemon = resolve_daemon(args.daemon.as_deref(), args.profile.as_deref())?;
    let url = format!("{}/c/health", daemon.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach daemon at {}: {}", daemon, e))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse response: {}", e))?;

    // Expected shape: {"ok": true, "name": "safeclaw", "version": "...", "vault_count": N}
    if !status.is_success() {
        return Err(format!(
            "daemon returned HTTP {}: {}",
            status,
            body
        ));
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    let vaults = body.get("vault_count").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("safeclaw — daemon ok");
    println!("  url:     {}", daemon);
    println!("  name:    {}", name);
    println!("  version: {}", version);
    println!("  vaults:  {}", vaults);
    Ok(())
}

fn resolve_daemon(
    daemon_override: Option<&str>,
    profile_override: Option<&str>,
) -> Result<String, String> {
    if let Some(d) = daemon_override {
        return Ok(d.to_string());
    }
    // Try the active profile.
    if let Ok(cfg) = load_profiles() {
        let pname = profile_override
            .map(str::to_string)
            .or_else(|| cfg.default_profile.clone());
        if let Some(name) = pname {
            if let Some(p) = cfg.profiles.get(&name) {
                return Ok(p.daemon.clone());
            }
        }
    }
    Ok(LOCAL_DEFAULT.to_string())
}
