//! `safeclaw status` / `safeclaw vault status` — current vault status.

use crate::cli::active::{join_vault_url, load as load_config};
use crate::cli::discovery::{self, ConnRow};
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

pub async fn probe_local_daemon(control_root: &str) -> LocalDaemon {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(400))
        .build()
    {
        Ok(c) => c,
        Err(_) => return LocalDaemon { up: false, version: None, vault_count: None },
    };
    let health_url = format!("{}/health", control_root.trim_end_matches('/'));
    let resp = match client.get(&health_url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return LocalDaemon { up: false, version: None, vault_count: None },
    };
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let version = body.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
    let vault_count = body.get("vault_count").and_then(|v| v.as_u64());
    LocalDaemon { up: true, version, vault_count }
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
    let cfg = load_config()?;
    // ONE control root for the probe and every fetch below — derived env-first
    // (an agent's shelled `sc status` reports the agent's own daemon).
    let control = crate::cli::active::control_root(&cfg);
    let d = probe_local_daemon(&control).await;

    // Vault resolution mirrors `resolve_active` (§5): `--vault` isn't a status
    // arg, so it's env-pin > config default. Surface BOTH so a shell pinned to a
    // different vault than the device default is legible (no coined verdict — the
    // facts). Routing DETECTION is gone (§9): the broker is opt-in, the agent
    // routes explicitly with `sc run`, so there's no "am I routed?" to report.
    let env_pin = std::env::var("SAFECLAW_VAULT_ID").ok().filter(|s| !s.is_empty());
    let config_default = cfg.vault.clone();
    let active_vault = env_pin.clone().or_else(|| config_default.clone());

    let vault = match active_vault.as_deref() {
        Some(v) => Some(fetch_status(&control, v).await),
        None => None,
    };
    let conns: Vec<ConnRow> = match active_vault.as_deref() {
        Some(v) => discovery::connections(&control, v).await.unwrap_or_default(),
        None => Vec::new(),
    };

    if args.json {
        print_json(&d, &vault, &conns, env_pin.as_deref(), config_default.as_deref());
        return Ok(());
    }

    // ── Daemon ──────────────────────────────────────────────────────────
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
    match &vault {
        Some(s) => print_status(s),
        None => {
            println!("active vault");
            println!("  state: none selected");
            if d.vault_count == Some(0) {
                println!("  hint:  no vaults yet — seal one on the web, then `sc login`");
            } else if crate::cli::active::known_vaults().is_empty() {
                println!("  hint:  pick one with `sc vault use`, or `sc vault create`");
            } else {
                println!("  hint:  pick one with `sc vault use` (`sc vault ls` to list)");
            }
        }
    }
    // Pin-vs-config (§5): flag a shell pinned to a different vault than the device
    // default so a surprising `sc` target is legible.
    if let (Some(pin), Some(def)) = (env_pin.as_deref(), config_default.as_deref()) {
        if pin != def {
            println!("  note:  this shell is pinned to {} via $SAFECLAW_VAULT_ID; the device default is {}", pin, def);
            println!("         unset SAFECLAW_VAULT_ID (or re-run `eval \"$(sc env)\"`) to follow the default");
        }
    }
    println!();

    // ── Connections (what the agent can use) ────────────────────────────
    println!("connections");
    if conns.is_empty() {
        println!("  (none — add one with `sc connect <name> --host <domain>`, or in the console)");
    } else {
        for c in &conns {
            println!("  {}", c.name);
            if !c.hosts.is_empty() {
                println!("    hosts:    {}", c.hosts.join(", "));
            }
            for ph in &c.phantoms {
                println!("    phantom:  {}", ph);
            }
        }
    }
    Ok(())
}

fn print_json(
    d: &LocalDaemon,
    vault: &Option<VaultStatus>,
    conns: &[ConnRow],
    env_pin: Option<&str>,
    config_default: Option<&str>,
) {
    let vault_json = vault.as_ref().map(|s| {
        let (state, passkeys, secrets) = match &s.state {
            VaultState::Unreachable => ("unreachable", None, None),
            VaultState::NotFound => ("not_found", None, None),
            VaultState::Locked { passkeys } => ("locked", Some(*passkeys), None),
            VaultState::Unlocked { passkeys, secrets } => ("unlocked", Some(*passkeys), Some(*secrets)),
        };
        serde_json::json!({
            "url": s.url,
            "state": state,
            "passkeys": passkeys,
            "secrets": secrets,
        })
    });
    let conns_json: Vec<serde_json::Value> = conns
        .iter()
        .map(|c| serde_json::json!({ "name": c.name, "hosts": c.hosts, "phantoms": c.phantoms }))
        .collect();
    let mismatch = matches!((env_pin, config_default), (Some(p), Some(c)) if p != c);
    let out = serde_json::json!({
        "daemon": { "up": d.up, "version": d.version, "vaults": d.vault_count },
        "vault": vault_json,
        // §5: the active vault + WHERE it came from (env pin vs device default),
        // so a mismatch is machine-detectable. No routing block — the broker is
        // opt-in (§9), so there's no "routed" state to report.
        "vault_selection": {
            "env_pin": env_pin,
            "config_default": config_default,
            "mismatch": mismatch,
        },
        "connections": conns_json,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()));
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
