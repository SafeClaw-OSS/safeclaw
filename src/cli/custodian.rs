//! `safeclaw custodian ...` — read-only info about the daemon hosting
//! the active vault. No passkey gestures here.

use crate::cli::active::resolve_active;
use crate::config::{CommonArgs, CustodianSubcommand};

pub async fn run(sub: CustodianSubcommand) -> Result<(), String> {
    match sub {
        CustodianSubcommand::Status(a) => status(a).await,
        CustodianSubcommand::Pubkey(a) => fetch_print(a, "/pubkey").await,
        CustodianSubcommand::Menu(a) => fetch_print(a, "/menu").await,
    }
}

async fn status(args: CommonArgs) -> Result<(), String> {
    let custodian = resolve_custodian(args.custodian.as_deref())?;
    let url = format!("{}/health", custodian.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client.get(&url).send().await
        .map_err(|e| format!("reach custodian at {}: {}", custodian, e))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("parse response: {}", e))?;
    if !status.is_success() {
        return Err(format!("custodian returned HTTP {}: {}", status, body));
    }
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    let vaults = body.get("vault_count").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("custodian: {}", custodian);
    println!("  status:  ok");
    println!("  version: {}", version);
    println!("  vaults:  {}", vaults);
    Ok(())
}

async fn fetch_print(args: CommonArgs, path: &str) -> Result<(), String> {
    let custodian = resolve_custodian(args.custodian.as_deref())?;
    let url = format!("{}{}", custodian.trim_end_matches('/'), path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client.get(&url).send().await
        .map_err(|e| format!("reach custodian: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("parse: {}", e))?;
    println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
    Ok(())
}

fn resolve_custodian(custodian_override: Option<&str>) -> Result<String, String> {
    if let Some(c) = custodian_override {
        return Ok(c.to_string());
    }
    // Reuse vault resolver; ignore vault, take custodian half.
    if let Ok((c, _)) = resolve_active(None, None) {
        return Ok(c);
    }
    Ok("http://localhost:23294".to_string())
}
