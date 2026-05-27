//! `safeclaw status` — custodian reachability + version probe.
//!
//! Read-only, no passkey ceremony, no vault context. Hits the custodian's
//! `GET /c/health` and pretty-prints the result. Custodian URL is resolved
//! from (in order): `--custodian` flag, `$SAFECLAW_DAEMON`, the active
//! profile in `~/.config/safeclaw/config.toml`, then `127.0.0.1:23294`.
//! Exit code is non-zero on transport / parse failure so shell scripts
//! can gate on it.

use crate::cli::profile::load as load_profiles;
use crate::config::StatusArgs;

const LOCAL_DEFAULT: &str = "http://127.0.0.1:23294";

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let custodian = resolve_daemon(args.custodian.as_deref(), args.profile.as_deref())?;
    let url = format!("{}/c/health", custodian.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach custodian at {}: {}", custodian, e))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse response: {}", e))?;

    // Expected shape: {"ok": true, "version": "...", "vault_count": N}
    if !status.is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            status,
            body
        ));
    }
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    let vaults = body.get("vault_count").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("safeclaw — custodian ok");
    println!("  url:     {}", custodian);
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
                return Ok(p.custodian.clone());
            }
        }
    }
    Ok(LOCAL_DEFAULT.to_string())
}
