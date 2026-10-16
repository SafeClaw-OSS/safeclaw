//! `safeclaw vault ...` — vault lifecycle ops.

use serde_json::json;
use std::io::{self, Write as _};

use crate::cli::active::{
    forget as forget_vault, join_vault_url, known_vaults, load as load_config, put_active,
    resolve_active, split_vault_url,
};
use crate::cli::status::{fetch_status, print_status, VaultState};
use crate::cli::webauthn::*;
use crate::config::{
    VaultCreateArgs, VaultDeleteArgs, VaultForgetArgs, VaultSubcommand, VaultUseArgs,
};

// Port must equal `config::CONTROL_PORT` (the daemon's control/API plane).
const LOCAL_CUSTODIAN: &str = "http://localhost:23293";
const LOCAL_VAULT_ID: &str = "default";

/// True if the custodian URL points at this machine. Used to specialize
/// "daemon down" hints — a remote daemon being unreachable is a network
/// problem; a local one almost always means `safeclaw c start` isn't running.
fn is_localhost(custodian: &str) -> bool {
    let after_scheme = custodian
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub async fn run(sub: VaultSubcommand, json: bool) -> Result<(), String> {
    match sub {
        VaultSubcommand::Status(_a) => crate::cli::status::run(json).await,
        VaultSubcommand::Ls(_a) => run_ls(json).await,
        VaultSubcommand::Use(a) => run_use(a).await,
        VaultSubcommand::Forget(a) => run_forget(a).await,
        VaultSubcommand::Create(a) => run_create(a).await,
        VaultSubcommand::Rm(a) => run_rm(a).await,
        VaultSubcommand::Unlock(a) => crate::cli::unlock::run_unlock(a).await,
        VaultSubcommand::Lock(a) => crate::cli::unlock::run_lock(a).await,
    }
}

async fn run_ls(json: bool) -> Result<(), String> {
    let cfg = load_config()?;
    let known = known_vaults();
    let active = (cfg.daemon.as_deref(), cfg.vault.as_deref());
    if json {
        let rows: Vec<serde_json::Value> = known
            .iter()
            .map(|kv| {
                json!({
                    "url": join_vault_url(&kv.daemon, &kv.vault),
                    "daemon": kv.daemon,
                    "vault": kv.vault,
                    "label": kv.label,
                    "kind": kv.kind,
                    "default": active == (Some(kv.daemon.as_str()), Some(kv.vault.as_str())),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        );
        return Ok(());
    }
    if known.is_empty() {
        println!("(no vaults yet; `safeclaw vault create` or `safeclaw vault use`)");
        return Ok(());
    }
    for (i, kv) in known.iter().enumerate() {
        let marker = if active == (Some(&kv.daemon), Some(&kv.vault)) {
            "*"
        } else {
            " "
        };
        // Lead with the human name + kind so an agent told "the team vault" can
        // pick the right one; the id trails as the canonical, copyable handle.
        let name = kv.label.as_deref().unwrap_or("(unnamed)");
        let kind = kv.kind.as_deref().unwrap_or("?");
        println!("  {} {}) {} ({})  {}", marker, i + 1, name, kind, kv.vault);
    }
    Ok(())
}

/// Parse a `url_or_idx` arg into (custodian, vault). Accepts:
/// - SAFECLAW_VAULT_URL (`<custodian>/v/<id>`)
/// - numeric index (1-based) into the known_vaults list
fn resolve_url_or_idx(arg: &str) -> Result<(String, String), String> {
    if let Ok(idx) = arg.parse::<usize>() {
        let known = known_vaults();
        if idx < 1 || idx > known.len() {
            return Err(format!("index {} out of range [1-{}]", idx, known.len()));
        }
        let kv = &known[idx - 1];
        return Ok((kv.daemon.clone(), kv.vault.clone()));
    }
    if let Some(pair) = split_vault_url(arg) {
        return Ok(pair);
    }
    // Otherwise resolve it as a vault TOKEN — id, unique id-prefix, or exact name
    // (case-insensitive) — via the same git/docker/kubectl resolver `--vault`
    // uses, so `sc vault use` and `sc run --vault` accept identical handles
    // (including a quoted name). Ambiguity fails loud with candidates; a name
    // with spaces just needs quoting.
    let cfg = load_config().unwrap_or_default();
    crate::cli::active::resolve_vault_token(arg, &cfg)
}

async fn run_use(args: VaultUseArgs) -> Result<(), String> {
    let (custodian, vault) = if args.local {
        (LOCAL_CUSTODIAN.to_string(), LOCAL_VAULT_ID.to_string())
    } else if let Some(arg) = args.url_or_idx {
        resolve_url_or_idx(&arg)?
    } else {
        let url = interactive_pick(OnEmpty::UseLocalDefault)?
            .expect("UseLocalDefault never returns None");
        split_vault_url(&url).ok_or_else(|| format!("not a valid SAFECLAW_VAULT_URL: {}", url))?
    };

    // Probe before saving. If the vault doesn't exist on the custodian,
    // refuse — bad active state would silently confuse later commands.
    // (Daemon unreachable is OK — accept and warn; user might be offline.)
    let s = fetch_status(&custodian, &vault).await;
    match s.state {
        VaultState::NotFound => {
            return Err(format!(
                "vault not found on custodian: {}\n  run `safeclaw vault create` to make a new one, or pick a different URL",
                join_vault_url(&custodian, &vault)
            ));
        }
        VaultState::Unreachable => {
            if is_localhost(&custodian) {
                eprintln!(
                    "warning: no local daemon at {}. Start one with `safeclaw c start`",
                    custodian
                );
                eprintln!(
                    "  (saving anyway; `safeclaw status` will recheck once the daemon is up)"
                );
            } else {
                eprintln!("warning: couldn't reach custodian; saving anyway");
            }
        }
        _ => {}
    }
    put_active(&custodian, &vault).map_err(|e| format!("save config: {}", e))?;
    print_status(&s);
    // Pin-aware (design/vault-addressing.md): a shell that carries a launch pin
    // keeps targeting it — say so here, at the moment of the switch, instead of
    // letting the very next `sc ls` contradict the header above.
    if let Ok(pin) = std::env::var("SAFECLAW_VAULT_ID") {
        if !pin.is_empty() && pin != vault {
            eprintln!(
                "note: this shell is pinned to {} via $SAFECLAW_VAULT_ID, so `sc` here still targets it;",
                pin
            );
            eprintln!(
                "      the new default applies everywhere else; `unset SAFECLAW_VAULT_ID` to follow it here"
            );
        }
    }
    Ok(())
}

async fn run_forget(args: VaultForgetArgs) -> Result<(), String> {
    let (custodian, vault) = if let Some(arg) = args.url_or_idx {
        resolve_url_or_idx(&arg)?
    } else {
        if known_vaults().is_empty() {
            return Err("no vaults in known list. Nothing to forget".into());
        }
        let url = interactive_pick(OnEmpty::Abort)?.ok_or("cancelled")?;
        split_vault_url(&url).ok_or_else(|| format!("not a valid SAFECLAW_VAULT_URL: {}", url))?
    };
    let removed = forget_vault(&custodian, &vault)?;
    if !removed {
        return Err(format!(
            "vault not in known list: {}",
            join_vault_url(&custodian, &vault)
        ));
    }
    println!("forgot: {}", join_vault_url(&custodian, &vault));
    Ok(())
}

/// What `interactive_pick` does when the user just hits Enter.
enum OnEmpty {
    /// Return the local-default URL (`use` semantics).
    UseLocalDefault,
    /// Return `Ok(None)` so the caller can treat it as a cancel
    /// (`forget` semantics).
    Abort,
}

fn interactive_pick(on_empty: OnEmpty) -> Result<Option<String>, String> {
    let cfg = load_config().unwrap_or_default();
    let known = known_vaults();
    let active = (cfg.daemon.as_deref(), cfg.vault.as_deref());
    let has_known = !known.is_empty();
    if has_known {
        eprintln!("Known vaults:");
        for (i, kv) in known.iter().enumerate() {
            let marker = if active == (Some(&kv.daemon), Some(&kv.vault)) {
                " (active)"
            } else {
                ""
            };
            eprintln!(
                "  {}) {}{}",
                i + 1,
                join_vault_url(&kv.daemon, &kv.vault),
                marker
            );
        }
        eprintln!();
    }
    // Prompt shape depends on what input is actually meaningful here:
    // - has_known controls whether "index" is offered
    // - on_empty controls what Enter does
    let prompt = match (has_known, &on_empty) {
        (true, OnEmpty::UseLocalDefault) => {
            "Pick: index, SAFECLAW_VAULT_URL, or Enter for local default: "
        }
        (true, OnEmpty::Abort) => "Pick: index or SAFECLAW_VAULT_URL (Enter to cancel): ",
        (false, OnEmpty::UseLocalDefault) => {
            "Paste a SAFECLAW_VAULT_URL, or press Enter for local default: "
        }
        (false, OnEmpty::Abort) => "Paste a SAFECLAW_VAULT_URL (Enter to cancel): ",
    };
    eprint!("{}", prompt);
    io::stderr().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        return match on_empty {
            OnEmpty::UseLocalDefault => Ok(Some(join_vault_url(LOCAL_CUSTODIAN, LOCAL_VAULT_ID))),
            OnEmpty::Abort => Ok(None),
        };
    }
    if let Ok(idx) = trimmed.parse::<usize>() {
        if idx < 1 || idx > known.len() {
            return Err(format!("index {} out of range [1-{}]", idx, known.len()));
        }
        let kv = &known[idx - 1];
        return Ok(Some(join_vault_url(&kv.daemon, &kv.vault)));
    }
    Ok(Some(trimmed.to_string()))
}

/// `sc vault create`: vaults are created in the SafeClaw console, where the
/// identity key lives (it never reaches this daemon). Print the link; the new
/// vault syncs to this machine on its own once created.
async fn run_create(_args: VaultCreateArgs) -> Result<(), String> {
    let url = console_page("/vaults?new=vault")?;
    eprintln!("Create the vault in the SafeClaw console:");
    eprintln!("  {}", url);
    eprintln!("This machine picks it up automatically once it exists.");
    Ok(())
}

/// An absolute console page link (`{console origin}{path}`) for this machine's
/// pairing. Vault creation and passkey enrollment happen there.
pub(crate) fn console_page(path: &str) -> Result<String, String> {
    let origin = crate::cli::active::console_origin()
        .ok_or("this machine isn't paired to SafeClaw yet: run `sc login` first")?;
    Ok(format!("{}{}", origin.trim_end_matches('/'), path))
}

async fn run_rm(args: VaultDeleteArgs) -> Result<(), String> {
    if !args.yes {
        return Err("destructive; pass -y/--yes to confirm vault deletion".into());
    }
    let (custodian, _) = resolve_active(Some(args.vault.as_str()))?;
    let vault = args.vault.trim().to_string();
    if vault.is_empty() {
        return Err("vault id cannot be empty".into());
    }

    if atty_isatty_stdin() {
        eprint!("Type vault id `{}` to confirm permanent deletion: ", vault);
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        if buf.trim() != vault {
            return Err("confirmation mismatch. Aborted".into());
        }
    }

    // Delete is approval-only (the daemon wipes the vault from the grant's
    // W_c) — same shape as unlock/lock, so it goes through the ONE shared
    // approval path: cloud /grant link when paired, local ceremony for
    // self-host. No bespoke gesture here.
    let op = json!({
        "act": { "type": { "custom": "vault-delete" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = crate::cli::approve::ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
        return_after_remote_link: false,
    };
    crate::cli::approve::approve_op(
        &custodian,
        &vault,
        &op,
        "Delete vault (irreversible)",
        &opts,
    )
    .await?;
    eprintln!("safeclaw vault rm: ok (vault {} wiped)", vault);
    Ok(())
}

fn atty_isatty_stdin() -> bool {
    unsafe { libc_isatty(0) != 0 }
}

#[link(name = "c")]
extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}
