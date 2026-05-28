//! `safeclaw login` — save the active `(custodian, vault)` to the CLI
//! config.
//!
//! Config-only. Does NOT enroll a passkey or unlock the vault — those are
//! per-operation passkey ceremonies. Login's job is just to make later
//! commands ergonomic (`safeclaw status` instead of
//! `safeclaw status --custodian https://...`).

use crate::cli::active::put_active;
use crate::config::LoginArgs;

pub async fn run(args: LoginArgs) -> Result<(), String> {
    let custodian = args.custodian.trim_end_matches('/').to_string();
    let vault = args.vault.trim().to_string();
    if vault.is_empty() {
        return Err("--vault cannot be empty".into());
    }

    if !args.no_probe {
        probe_daemon(&custodian).await?;
    }

    let path = put_active(&custodian, &vault)?;

    println!("safeclaw — config saved");
    println!("  config:    {}", path.display());
    println!("  custodian: {}", custodian);
    println!("  vault:     {}", vault);
    println!();
    println!("Run `eval \"$(safeclaw env)\"` in your shell to export");
    println!("$SAFECLAW_VAULT_URL for agents that read the env directly.");
    if std::env::var("SAFECLAW_API_KEY").is_err() && custodian.starts_with("https://") {
        println!();
        println!("note: SaaS custodians require $SAFECLAW_API_KEY in your shell env.");
        println!("      (the api key is never written to config.toml).");
    }
    Ok(())
}

/// Hit `/health` to confirm the custodian is reachable + responding. Bails
/// with a clear error message — don't write config pointing at a dead URL
/// silently.
async fn probe_daemon(custodian: &str) -> Result<(), String> {
    let url = format!("{}/health", custodian);
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
    if !status.is_success() {
        return Err(format!("custodian at {} returned HTTP {}", custodian, status));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse health response: {}", e))?;
    let version = body
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    println!("safeclaw — custodian ok ({})", version);
    Ok(())
}
