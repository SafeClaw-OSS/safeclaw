//! `safeclaw unlock` / `safeclaw lock` — build the lifecycle op and hand it to
//! the shared approval driver (`cli::approve`), which picks the remote (cloud
//! web-approval) or local (on-box ceremony) arm. No bespoke passkey logic here
//! — every approval flows through the one code path.

use serde_json::json;
use std::io::IsTerminal;

use crate::cli::active::resolve_active;
use crate::cli::approve::{approve_op, ApproveOpts};
use crate::cli::status::VaultState;
use crate::cli::webauthn::now_unix;
use crate::config::UnlockArgs;

pub async fn run_unlock(args: UnlockArgs) -> Result<(), String> {
    drive("vault-unlock", "Unlock", args).await
}
pub async fn run_lock(args: UnlockArgs) -> Result<(), String> {
    drive("vault-lock", "Lock", args).await
}

async fn drive(custom_op: &str, verb: &str, args: UnlockArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let name = crate::cli::active::known_vaults()
        .into_iter()
        .find(|k| k.vault == vault)
        .and_then(|k| k.label)
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| "the vault".to_string());
    let label = format!("{} {}", verb, name);
    let label = label.as_str();

    // Already in the asked-for state: say so instead of minting an approval, so
    // re-running after an approval (what `sc op wait` says to do) ends here.
    let state = crate::cli::status::fetch_status(&custodian, &vault).await.state;
    let done = match (custom_op, &state) {
        ("vault-unlock", VaultState::Unlocked { .. }) => Some("unlocked"),
        ("vault-lock", VaultState::Locked { .. }) => Some("locked"),
        _ => None,
    };
    if let Some(done) = done {
        println!("{} is {}.", upper_first(&name), done);
        return Ok(());
    }

    let op = json!({
        "act": { "type": { "custom": custom_op }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });

    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
        return_after_remote_link: true,
    };
    approve_op(&custodian, &vault, &op, label, &opts).await?;

    if crate::cli::active::frontend_origin().is_some()
        && (!std::io::stdin().is_terminal() || !std::io::stderr().is_terminal())
    {
        return Ok(());
    }

    let done = if custom_op == "vault-unlock" { "unlocked" } else { "locked" };
    println!("{} is {}.", upper_first(&name), done);
    Ok(())
}

fn upper_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
