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

/// Snapshot of the local daemon: is it up, and (if so) how many vaults
/// does it know about? Lets us give precise post-`sc start` guidance
/// like "daemon is up with 0 vaults — run `sc vault create`". ~400ms.
pub struct LocalDaemon {
    pub up: bool,
    pub version: Option<String>,
    pub vault_count: Option<u64>,
}

pub async fn probe_local_daemon() -> LocalDaemon {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(400))
        .build()
    {
        Ok(c) => c,
        Err(_) => return LocalDaemon { up: false, version: None, vault_count: None },
    };
    let resp = match client.get("http://localhost:23294/health").send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return LocalDaemon { up: false, version: None, vault_count: None },
    };
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let version = body.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
    let vault_count = body.get("vault_count").and_then(|v| v.as_u64());
    LocalDaemon { up: true, version, vault_count }
}

/// Shorthand for callers that only care about reachability.
pub async fn local_daemon_up() -> bool {
    probe_local_daemon().await.up
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

    let kk_url = format!("{}/v/{}/secret-keys", custodian.trim_end_matches('/'), urlencoding::encode(vault));
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
    let _ = &args; // no per-command override flag; daemon URL comes from config
    let cfg = load_config()?;

    // ── Daemon ──────────────────────────────────────────────────────────
    let d = probe_local_daemon().await;
    println!("daemon");
    if d.up {
        println!("  state:   running");
        if let Some(v) = &d.version {
            println!("  version: {}", v);
        }
        if let Some(n) = d.vault_count {
            println!("  vaults:  {}", n);
        }
    } else {
        println!("  state:   not running — bring it up with `sc up`");
    }
    println!();

    // ── Active vault ────────────────────────────────────────────────────
    match (cfg.daemon.as_deref(), cfg.vault.as_deref()) {
        (Some(c), Some(v)) => {
            let s = fetch_status(c, v).await;
            print_status(&s);
        }
        _ => {
            println!("active vault");
            println!("  state: none selected");
            if d.vault_count == Some(0) {
                println!("  hint:  no vaults yet — seal one on the web, then `sc login`");
            } else if cfg.known_vaults.is_empty() {
                println!("  hint:  pick one with `sc vault use`, or `sc vault create`");
            } else {
                println!("  hint:  pick one with `sc vault use` (`sc vault ls` to list)");
            }
        }
    }
    Ok(())
}

pub fn print_status(s: &VaultStatus) {
    println!("active vault");
    println!("  url:   {}", s.url);
    match &s.state {
        VaultState::Unreachable => {
            if s.url.contains("//localhost") || s.url.contains("//127.0.0.1") {
                println!("  state: unreachable — bring the daemon up with `sc up`");
            } else {
                println!("  state: unreachable (is the daemon running?)");
            }
        }
        VaultState::NotFound => {
            println!("  state: not found (run `sc vault create`, or pick a different URL with `sc vault use`)");
        }
        VaultState::Locked { passkeys } => {
            println!("  state: locked (run `sc up` to unlock)");
            println!("  passkeys: {}", passkeys);
        }
        VaultState::Unlocked { passkeys, secrets } => {
            println!("  state: unlocked");
            println!("  passkeys: {}", passkeys);
            println!("  secrets:  {}", secrets);
        }
    }
}
