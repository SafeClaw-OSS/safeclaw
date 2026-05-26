//! `safeclaw login` — save a `(daemon, vault)` pair to the CLI's profile
//! config.
//!
//! This is config-only. It does NOT enroll a passkey or unlock the vault —
//! those are per-operation passkey ceremonies. Login's job is just to make
//! later commands ergonomic (`safeclaw status` instead of
//! `safeclaw status --daemon https://...`).

use crate::cli::profile::{put_profile, Profile};
use crate::config::LoginArgs;

pub async fn run(args: LoginArgs) -> Result<(), String> {
    let daemon = args.daemon.trim_end_matches('/').to_string();
    let vault = args.vault.trim().to_string();
    if vault.is_empty() {
        return Err("--vault cannot be empty".into());
    }

    if !args.no_probe {
        probe_daemon(&daemon).await?;
    }

    let path = put_profile(
        &args.profile,
        Profile {
            daemon: daemon.clone(),
            vault: vault.clone(),
        },
    )?;

    println!("safeclaw — profile '{}' saved", args.profile);
    println!("  config:  {}", path.display());
    println!("  daemon:  {}", daemon);
    println!("  vault:   {}", vault);
    if std::env::var("SAFECLAW_API_KEY").is_err() {
        println!();
        println!("note: for SaaS daemons, set $SAFECLAW_API_KEY in your shell env.");
        println!("      (the api key is never written to config.toml).");
    }
    Ok(())
}

/// Hit `/c/health` to confirm the daemon is reachable + responding. Bails
/// with a clear error message — don't write a profile pointing at a dead
/// URL silently.
async fn probe_daemon(daemon: &str) -> Result<(), String> {
    let url = format!("{}/c/health", daemon);
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
    if !status.is_success() {
        return Err(format!("daemon at {} returned HTTP {}", daemon, status));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse health response: {}", e))?;
    let version = body
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    println!("safeclaw — daemon ok ({})", version);
    Ok(())
}
