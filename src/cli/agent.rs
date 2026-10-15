//! `sc agent` — manage this account's agent api-keys.
//!
//! agent ≡ api-key (1:1, account-level). Each agent gets its own `sc_agent_`
//! key; the cloud stores only its hash; the key works on ANY of the account's
//! paired devices (the daemon syncs the hash-set + validates locally). Auth is
//! this device's device-key (account-scoped), so `sc agent` works on any
//! paired machine. As of the identity wave each agent ALSO mints an AIK keypair
//! (hop-A PoP identity) here; the api-key stays as the dual-auth legacy path.
//! See [[project_vault_agent_architecture_2026_06_25]].

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::load as load_config;
use crate::config::{AgentAddArgs, AgentRmArgs, AgentSubcommand};
use crate::device_auth::DikRequestExt;

pub async fn run(sub: AgentSubcommand, json: bool) -> Result<(), String> {
    match sub {
        AgentSubcommand::Add(a) => add(a).await,
        AgentSubcommand::Ls => ls(json).await,
        AgentSubcommand::Rm(a) => rm(a).await,
    }
}

/// Resolve (cloud backend, device-key) — both come from `sc login`.
fn cloud_and_key() -> Result<(String, String), String> {
    let cfg = load_config().map_err(|e| format!("read config: {}", e))?;
    let cloud = cfg
        .cloud_backend
        .filter(|s| !s.is_empty())
        .ok_or("this device isn't paired — run `sc login` first")?;
    let key = crate::sync::device_key().ok_or("no device-key — run `sc login` first")?;
    Ok((cloud.trim_end_matches('/').to_string(), key))
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))
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
    // Requires a paired device: the cloud backend to run the admission ceremony
    // against comes from `sc login`. (The ceremony's authorize/poll are
    // unauthenticated — the device_code + AIK PoP are the auth — so the
    // device-key itself isn't sent; requiring pairing is the "this machine
    // belongs to the account" precondition.)
    let (cloud, _key) = cloud_and_key()?;
    let cfg = load_config().unwrap_or_default();
    let broker_url = format!(
        "{}:{}",
        crate::cli::active::device_daemon_host(&cfg),
        crate::config::PROXY_PORT
    );

    // ── Mint this agent's AIK (possession-proven identity; identity wave §2) ──
    // Ed25519 keypair, self-certifying `ag_…` id. The private SEED never leaves
    // this disk (0600) and never enters the agent's env — only the PUBLIC key is
    // sent to the cloud. hop-A verifies the AIK per-CONNECT via a
    // Proxy-Authorization PoP token (DPoP-style), NOT mTLS. Persisted only AFTER
    // the owner approves admission, so a declined/expired ceremony leaves no
    // orphan identity file.
    let (seed, ag_id) = crate::identity_file::mint(crate::identity::IdKind::Agent);
    let (aik, _) = crate::identity_file::resolve(crate::identity::IdKind::Agent, &seed);
    let identity_path = crate::identity_file::agent_identity_path(&args.name)?;

    // ── §14 agent admission = the same /pair ceremony as a device (C2) ──────
    // Adding an agent to the account is an OWNER decision: the PAKE short code,
    // approved in the browser, with principal='agent'. The admit must be signed
    // by the account this machine is paired to (its pinned owner UIK): an agent
    // acts as that one account.
    let pinned = crate::cli::active::account_uik_pub()
        .ok_or("this machine's pairing predates verified pairing: run `sc login` first")?;
    let origin = crate::cli::active::console_origin()
        .ok_or("this machine isn't paired to SafeClaw yet: run `sc login` first")?;
    let client = client()?;
    let paired = crate::cli::pair_flow::pair(
        &client,
        &crate::cli::pair_flow::PairRequest {
            principal: "agent",
            name: &args.name,
            principal_id: &ag_id,
            signer: &aik,
            sc_pk: None,
            cloud: &cloud,
            origin: &origin,
            restart: "sc agent add",
        },
    )
    .await?;
    if paired.uik_pub != pinned {
        return Err(format!(
            "the agent was approved by another account ({}) than the one this machine is \
             paired to; it was not set up. Approve it signed in as the paired account.",
            paired.uik_id
        ));
    }

    // Admitted — NOW persist the AIK identity file (0600).
    crate::identity_file::write(&identity_path, crate::identity::IdKind::Agent, &seed)?;

    // ── Mint-time projection (CREDENTIAL_BROKER.md §14): this IS the minter ─
    // The agent's env is now just TWO non-secret lines: the daemon's API face and
    // the AIK identity PATH (a path, not a secret). Auth is the AIK's per-CONNECT
    // proof-of-possession, minted by `sc run`'s transport shim — NO api-key is
    // emitted (it was legacy dual-auth cruft the shim stripped anyway). So there's
    // no secret to guard: this output can be shown, and appended to the agent's env
    // file directly. The daemon still holds an account-roster row for this AIK.
    println!("SAFECLAW_BROKER_URL={}", broker_url);
    println!(
        "SAFECLAW_AGENT_IDENTITY={}",
        env_value(&identity_path.display().to_string())
    );

    let rm_name = if args.name.contains(char::is_whitespace) {
        format!("'{}'", args.name)
    } else {
        args.name.clone()
    };
    eprintln!(
        "\nAgent '{}' authorized. Its SafeClaw env (two non-secret lines: the broker URL \
         and its identity-file path) went to stdout. Append them to the env file your \
         framework loads. It can reach any vault you turn it on for in that vault's \
         Agent access page. Works on any paired device; revoke: `sc agent rm {}`.",
        args.name, rm_name
    );
    Ok(())
}

async fn fetch_agents(cloud: &str, key: &str) -> Result<Vec<ListKey>, String> {
    // `/api/vault/agents` is already tier-scoped server-side (agent|demo);
    // device-keys live under `/api/vault/devices`.
    let url = format!("{}/api/vault/agents", cloud);
    let resp = client()?
        .get(&url)
        .bearer_auth(key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&cloud, &e))?;
    if !resp.status().is_success() {
        return Err(format!("list agents failed: HTTP {}", resp.status()));
    }
    let r: ListResp = resp
        .json()
        .await
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(r.keys)
}

async fn ls(json: bool) -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let agents = fetch_agents(&cloud, &key).await?;
    if json {
        // Machine-readable mirror of the human list: one object per agent.
        let arr: Vec<serde_json::Value> = agents
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id": k.id,
                    "prefix": k.prefix,
                    "label": k.label,
                    "last_used_at": k.last_used_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if agents.is_empty() {
        println!("(no agents yet, `sc agent add <name>`)");
        return Ok(());
    }
    for k in &agents {
        let label = k.label.clone().unwrap_or_else(|| "(unnamed)".into());
        let last = k.last_used_at.clone().unwrap_or_else(|| "never".into());
        println!("{:<28} {}…  last-used {}", label, k.prefix, last);
    }
    Ok(())
}

/// `sc agent rm`: revoking an agent is an owner-signed ledger revoke, signed in
/// the console (this machine holds no owner key). Print the page; every device
/// refuses the agent at its next ledger pull.
async fn rm(args: AgentRmArgs) -> Result<(), String> {
    let url = crate::cli::vault::console_page("/account/access")?;
    eprintln!(
        "Remove the agent '{}' in the SafeClaw console (it asks for your passkey):",
        args.name
    );
    eprintln!("  {}", url);
    eprintln!("Every device stops serving it within two minutes of the removal.");
    Ok(())
}

/// A dotenv value that also survives `set -a; . file`: bare when it is only path-safe
/// characters, else single-quoted (dotenv parsers strip the quotes). A home directory
/// with a space is the usual case.
fn env_value(v: &str) -> String {
    if !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | ':' | '+'))
    {
        v.to_string()
    } else {
        format!("'{}'", v.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod env_value_tests {
    #[test]
    fn a_path_with_a_space_is_quoted_once() {
        assert_eq!(
            super::env_value("/home/a/.safeclaw/agents/claude/identity"),
            "/home/a/.safeclaw/agents/claude/identity"
        );
        assert_eq!(super::env_value("/Users/Jo Lee/x"), "'/Users/Jo Lee/x'");
        assert_eq!(super::env_value("/it's"), "'/it'\\''s'");
    }
}
