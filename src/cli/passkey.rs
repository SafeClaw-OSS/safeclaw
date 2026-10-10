//! `sc passkey ls` — the passkeys that can approve for the active vault: your
//! account's ledger-admitted passkeys. Passkeys are added, renamed and revoked
//! in the console (a ledger write needs a passkey and the account's UIK), so
//! `ls` is the only subcommand.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::resolve_active;
use crate::config::PasskeySubcommand;

pub async fn run(sub: PasskeySubcommand, json: bool) -> Result<(), String> {
    match sub {
        PasskeySubcommand::Ls(_a) => run_ls(json).await,
    }
}

#[derive(Debug, Deserialize)]
struct PasskeysBody {
    #[serde(default)]
    vault_exists: bool,
    #[serde(default = "yes")]
    record: bool,
    #[serde(default)]
    passkeys: Vec<PasskeyMeta>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct PasskeyMeta {
    credential_id: String,
    #[serde(default, rename = "deviceName", alias = "device_name")]
    device_name: Option<String>,
}

async fn run_ls(json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault)
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach custodian: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: PasskeysBody = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    if json {
        let arr: Vec<serde_json::Value> = body
            .passkeys
            .iter()
            .map(|p| {
                serde_json::json!({
                    "credential_id": p.credential_id,
                    "device_name": p.device_name,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if !body.vault_exists {
        println!(
            "(vault {} is not on this machine yet — run `sc sync`)",
            vault
        );
        return Ok(());
    }
    if !body.record {
        println!(
            "(vault {} needs an upgrade before it can be used — upgrade this vault in the console)",
            vault
        );
        return Ok(());
    }
    if body.passkeys.is_empty() {
        println!("(no passkeys yet — add one in the console)");
        return Ok(());
    }
    let id_w = body
        .passkeys
        .iter()
        .map(|p| p.credential_id.len())
        .max()
        .unwrap_or(0)
        .clamp(8, 32);
    println!("  {:<iw$}  NAME", "CREDENTIAL_ID", iw = id_w);
    for p in &body.passkeys {
        let id_display = if p.credential_id.len() > id_w {
            format!("{}…", &p.credential_id[..id_w.saturating_sub(1)])
        } else {
            p.credential_id.clone()
        };
        println!(
            "  {:<iw$}  {}",
            id_display,
            p.device_name.as_deref().unwrap_or("(unnamed)"),
            iw = id_w
        );
    }
    Ok(())
}
