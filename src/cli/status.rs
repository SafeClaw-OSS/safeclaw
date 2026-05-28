//! `safeclaw status` — current vault status.
//!
//! Vault-centric: shows which vault the CLI is managing right now,
//! whether it's locked/unlocked, and how many keys it has. For
//! custodian-level info use `sc custodian status`.

use crate::cli::active::{join_vault_url, load as load_config};
use crate::config::StatusArgs;

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let cfg = load_config()?;
    let custodian = args.custodian.as_deref()
        .map(String::from)
        .or_else(|| cfg.custodian.clone());
    let vault = cfg.vault.clone();

    match (custodian.as_deref(), vault.as_deref()) {
        (Some(c), Some(v)) => print_vault_status(c, v).await,
        _ => {
            println!("safeclaw — no active vault");
            println!("  hint: `safeclaw vault use` to select one, or");
            println!("        `safeclaw vault create` to make a new one");
            Ok(())
        }
    }
}

async fn print_vault_status(custodian: &str, vault: &str) -> Result<(), String> {
    let url = join_vault_url(custodian, vault);
    println!("active vault");
    println!("  url:    {}", url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;

    // Vault existence + passkey count via /v/{vid}/passkeys
    let pk_url = format!("{}/v/{}/passkeys", custodian.trim_end_matches('/'), urlencoding::encode(vault));
    match client.get(&pk_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                let exists = body.get("vault_exists").and_then(|v| v.as_bool()).unwrap_or(false);
                let passkeys = body.get("passkeys").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                if !exists {
                    println!("  state:  not enrolled (run `safeclaw vault create`)");
                    return Ok(());
                }
                println!("  passkeys: {}", passkeys);
            }
        }
        _ => {
            println!("  state:  unreachable (is the daemon running?)");
            return Ok(());
        }
    }

    // Try keys-known (only works when unlocked)
    let kk_url = format!("{}/v/{}/keys-known", custodian.trim_end_matches('/'), urlencoding::encode(vault));
    match client.get(&kk_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                let n = body.get("native_keys").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                println!("  state:    unlocked");
                println!("  secrets:  {}", n);
            }
        }
        Ok(resp) if resp.status().as_u16() == 409 => {
            println!("  state:    locked (run `safeclaw unlock`)");
        }
        _ => {
            println!("  state:    unknown");
        }
    }
    Ok(())
}
