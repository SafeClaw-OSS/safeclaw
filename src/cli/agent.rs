//! `sc agent` — manage this account's agent api-keys.
//!
//! agent ≡ api-key (1:1, account-level). Each agent gets its own `sc_agent_`
//! key; the cloud stores only its hash; the key works on ANY of the account's
//! paired devices (the daemon syncs the hash-set + validates locally). Auth is
//! this device's device-key (account-scoped), so `sc agent` works on any
//! paired machine. See [[project_vault_agent_architecture_2026_06_25]].

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::load as load_config;
use crate::config::{AgentAddArgs, AgentRmArgs, AgentSubcommand};

pub async fn run(sub: AgentSubcommand) -> Result<(), String> {
    match sub {
        AgentSubcommand::Add(a) => add(a).await,
        AgentSubcommand::Ls => ls().await,
        AgentSubcommand::Rm(a) => rm(a).await,
    }
}

/// Resolve (cloud backend, device-key) — both come from `sc login`.
fn cloud_and_key() -> Result<(String, String), String> {
    let cfg = load_config().map_err(|e| format!("read config: {}", e))?;
    let cloud = cfg
        .cloud_backend
        .filter(|s| !s.is_empty())
        .ok_or("this device isn't paired — run `sc login <pair-token>` first")?;
    let key = crate::sync::device_key()
        .ok_or("no device-key — run `sc login <pair-token>` first")?;
    Ok((cloud.trim_end_matches('/').to_string(), key))
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))
}

#[derive(Deserialize)]
struct CreateResp {
    token: String,
}

#[derive(Deserialize)]
struct ListResp {
    keys: Vec<ListKey>,
}

#[derive(Deserialize)]
struct ListKey {
    id: String,
    prefix: String,
    label: Option<String>,
    last_used_at: Option<String>,
}

async fn add(args: AgentAddArgs) -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let resp = client()?
        .post(format!("{}/api/vault/agents", cloud))
        .bearer_auth(&key)
        .json(&serde_json::json!({ "label": args.name, "tier": "agent" }))
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    if !resp.status().is_success() {
        return Err(format!("create agent key failed: HTTP {}", resp.status()));
    }
    let r: CreateResp = resp.json().await.map_err(|e| format!("parse response: {}", e))?;
    // Token to STDOUT (so `KEY=$(sc agent add x)` works); guidance to STDERR.
    println!("{}", r.token);
    eprintln!(
        "\nAgent '{}' created. This key is shown ONCE — set it in the agent's env:\n  \
         SAFECLAW_API_KEY={}\n  SAFECLAW_VAULT_URL=$(sc env | grep VAULT_URL | cut -d= -f2-)\n\
         It works on any of your paired devices. Revoke: `sc agent rm {}`.",
        args.name, r.token, args.name
    );
    Ok(())
}

async fn fetch_agents(cloud: &str, key: &str) -> Result<Vec<ListKey>, String> {
    // `/api/vault/agents` is already tier-scoped server-side (agent|demo);
    // device-keys live under `/api/vault/devices`.
    let resp = client()?
        .get(format!("{}/api/vault/agents", cloud))
        .bearer_auth(key)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    if !resp.status().is_success() {
        return Err(format!("list agents failed: HTTP {}", resp.status()));
    }
    let r: ListResp = resp.json().await.map_err(|e| format!("parse response: {}", e))?;
    Ok(r.keys)
}

async fn ls() -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let agents = fetch_agents(&cloud, &key).await?;
    if agents.is_empty() {
        println!("(no agents yet — `sc agent add <name>`)");
        return Ok(());
    }
    for k in &agents {
        let label = k.label.clone().unwrap_or_else(|| "(unnamed)".into());
        let last = k.last_used_at.clone().unwrap_or_else(|| "never".into());
        println!("{:<28} {}…  last-used {}", label, k.prefix, last);
    }
    Ok(())
}

async fn rm(args: AgentRmArgs) -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let agents = fetch_agents(&cloud, &key).await?;
    let matches: Vec<&ListKey> = agents
        .iter()
        .filter(|k| {
            k.label.as_deref() == Some(args.name.as_str())
                || k.id == args.name
                || k.prefix == args.name
        })
        .collect();
    let id = match matches.as_slice() {
        [k] => k.id.clone(),
        [] => return Err(format!("no agent named '{}' (see `sc agent ls`)", args.name)),
        _ => {
            return Err(format!(
                "'{}' matches multiple agents — remove by id or prefix (`sc agent ls`)",
                args.name
            ))
        }
    };
    let resp = client()?
        .delete(format!("{}/api/vault/agents/{}", cloud, id))
        .bearer_auth(&key)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    if !resp.status().is_success() {
        return Err(format!("revoke failed: HTTP {}", resp.status()));
    }
    eprintln!(
        "Revoked agent '{}'. It stops working on every device after that device's next sync.",
        args.name
    );
    Ok(())
}
