//! `safeclaw status` / `safeclaw vault status` — current vault status.

use crate::cli::active::{join_vault_url, load as load_config};
use crate::config::StatusArgs;

#[derive(Debug)]
pub struct VaultStatus {
    pub url: String,
    pub state: VaultState,
}

#[derive(Debug, PartialEq)]
pub enum VaultState {
    /// Daemon unreachable.
    Unreachable,
    /// Vault id doesn't exist on the custodian.
    NotFound,
    /// Vault locked. Passkey count from /passkeys.
    Locked { passkeys: usize },
    /// Vault unlocked. Passkey + native-secret counts.
    Unlocked { passkeys: usize, secrets: usize },
}

/// Cheap probe: does a local safeclaw daemon answer on the default port?
/// Used to specialize "no daemon" vs "no vault" hints. ~400ms timeout.
pub async fn local_daemon_up() -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(400))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client.get("http://localhost:23294/c/health").send().await
        .map(|r| r.status().is_success()).unwrap_or(false)
}

pub async fn fetch_status(custodian: &str, vault: &str) -> VaultStatus {
    let url = join_vault_url(custodian, vault);
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(_) => return VaultStatus { url, state: VaultState::Unreachable },
    };

    let pk_url = format!("{}/v/{}/passkeys", custodian.trim_end_matches('/'), urlencoding::encode(vault));
    let pk_resp = match client.get(&pk_url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return VaultStatus { url, state: VaultState::Unreachable },
    };
    let pk_body: serde_json::Value = match pk_resp.json().await {
        Ok(b) => b,
        Err(_) => return VaultStatus { url, state: VaultState::Unreachable },
    };
    let exists = pk_body.get("vault_exists").and_then(|v| v.as_bool()).unwrap_or(false);
    if !exists {
        return VaultStatus { url, state: VaultState::NotFound };
    }
    let passkeys = pk_body.get("passkeys").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

    let kk_url = format!("{}/v/{}/keys-known", custodian.trim_end_matches('/'), urlencoding::encode(vault));
    match client.get(&kk_url).send().await {
        Ok(r) if r.status().is_success() => {
            let n = r.json::<serde_json::Value>().await.ok()
                .and_then(|b| b.get("native_keys").and_then(|v| v.as_array()).map(|a| a.len()))
                .unwrap_or(0);
            VaultStatus { url, state: VaultState::Unlocked { passkeys, secrets: n } }
        }
        Ok(r) if r.status().as_u16() == 409 => {
            VaultStatus { url, state: VaultState::Locked { passkeys } }
        }
        _ => VaultStatus { url, state: VaultState::Locked { passkeys } },
    }
}

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let cfg = load_config()?;
    let custodian = args.custodian.as_deref()
        .map(String::from)
        .or_else(|| cfg.custodian.clone());
    let vault = cfg.vault.clone();

    match (custodian.as_deref(), vault.as_deref()) {
        (Some(c), Some(v)) => {
            let s = fetch_status(c, v).await;
            print_status(&s);
            Ok(())
        }
        _ => {
            let up = local_daemon_up().await;
            println!("safeclaw — no active vault");
            if up {
                println!("  hint: `safeclaw vault use` to select one, or");
                println!("        `safeclaw vault create` to make a new one");
            } else {
                println!("  hint: no local daemon on :23294 — start one with `safeclaw serve`,");
                println!("        then `safeclaw vault create` for your first vault");
            }
            Ok(())
        }
    }
}

pub fn print_status(s: &VaultStatus) {
    println!("active vault");
    println!("  url:   {}", s.url);
    match &s.state {
        VaultState::Unreachable => {
            if s.url.contains("//localhost") || s.url.contains("//127.0.0.1") {
                println!("  state: unreachable — start daemon with `safeclaw serve`");
            } else {
                println!("  state: unreachable (is the daemon running?)");
            }
        }
        VaultState::NotFound => {
            println!("  state: not found (run `safeclaw vault create`, or pick a different URL with `safeclaw vault use`)");
        }
        VaultState::Locked { passkeys } => {
            println!("  state: locked (run `safeclaw unlock`)");
            println!("  passkeys: {}", passkeys);
        }
        VaultState::Unlocked { passkeys, secrets } => {
            println!("  state: unlocked");
            println!("  passkeys: {}", passkeys);
            println!("  secrets:  {}", secrets);
        }
    }
}
