//! `safeclaw status` — custodian reachability + version probe.
//!
//! Read-only, no passkey ceremony, no vault context. Hits the custodian's
//! `GET /health` and pretty-prints the result. Custodian URL is resolved
//! from (in order): `--custodian` flag, `$SAFECLAW_CUSTODIAN`,
//! `$SAFECLAW_VAULT_URL` (parsed for root), the active config in
//! `~/.safeclaw/config.toml`, then `localhost:23294`. Exit code is
//! non-zero on transport / parse failure so shell scripts can gate on it.

use crate::cli::active::load as load_config;
use crate::config::StatusArgs;

const LOCAL_DEFAULT: &str = "http://localhost:23294";

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let custodian = resolve_custodian(args.custodian.as_deref())?;
    let url = format!("{}/health", custodian.trim_end_matches('/'));
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

fn resolve_custodian(custodian_override: Option<&str>) -> Result<String, String> {
    if let Some(d) = custodian_override {
        return Ok(d.to_string());
    }
    // SAFECLAW_VAULT_URL carries (custodian_root)/v/<vid>; strip the suffix.
    if let Ok(url) = std::env::var("SAFECLAW_VAULT_URL") {
        if let Some((root, _)) = url.trim_end_matches('/').rsplit_once("/v/") {
            return Ok(root.to_string());
        }
    }
    // Active config file
    if let Ok(cfg) = load_config() {
        if let Some(c) = cfg.custodian {
            return Ok(c);
        }
    }
    Ok(LOCAL_DEFAULT.to_string())
}
