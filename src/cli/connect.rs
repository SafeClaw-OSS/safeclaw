//! `sc connect <name>` — create a raw connection (secret(s) + host anchor) in
//! one unlock+write cycle. The CLI twin of the console's custom-connection form.
//!
//! Interactive (TTY): prompt host(s) → secret KEY(s) with hidden values.
//! Non-interactive: `--host <domain>` (repeatable) + `--secret KEY=VALUE`
//! (repeatable) and/or `--use-existing KEY`. Reachable via `__sc__<name>__`.
//!
//! Storage contract (matches the daemon's raw reverse-index): a NEW secret
//! `KEY` is stored at `<name>:<KEY>`; `--use-existing KEY` claims an already
//! stored BARE secret whose name lowercases to `<name>` (the single-secret
//! promote case). One injectable secret ⇒ the short phantom `__sc__<name>__`;
//! several ⇒ `__sc__<name>__<key>__`.

use std::io::IsTerminal;
use std::io::Write as _;

use crate::cli::active::resolve_active;
use crate::cli::conn::{insert_raw_connection, valid_conn_id, valid_role, validate_raw_host};
use crate::cli::secret::{do_unlock, seal_and_submit_write};
use crate::cli::webauthn::fetch_passkey_meta;
use crate::config::ConnectArgs;

pub async fn run(args: ConnectArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    let name = args.name.clone();
    if !valid_conn_id(&name) {
        return Err(format!(
            "connection name '{}' must be [a-z0-9_], start alphanumeric, and contain no '__'",
            name
        ));
    }

    // ── hosts ────────────────────────────────────────────────────────────────
    let hosts = if !args.host.is_empty() {
        args.host.clone()
    } else if std::io::stdin().is_terminal() {
        prompt_hosts(&name)?
    } else {
        return Err(
            "a connection needs at least one host — pass `--host <domain>` (repeatable)".into(),
        );
    };
    for h in &hosts {
        validate_raw_host(h)?;
    }

    // ── secrets ──────────────────────────────────────────────────────────────
    let gathered = gather_secrets(&name, &args.secret, &args.use_existing)?;
    if gathered.new_values.is_empty() && gathered.existing.is_empty() {
        return Err(
            "a connection needs at least one secret — `--secret KEY=VALUE` or `--use-existing KEY`".into(),
        );
    }

    eprintln!("safeclaw connect {} — two passkey gestures (unlock + write)", name);
    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, mut aux, user_key) =
        do_unlock(&custodian, &vault, &meta, args.no_browser, args.timeout, args.cb_port).await?;
    let mut new_kv = kv;

    // New secrets are namespaced `<name>:<ROLE>`.
    for (role, val) in &gathered.new_values {
        new_kv.insert(format!("{}:{}", name, role), val.clone());
    }
    // --use-existing: the stored bare key must lowercase to the conn name.
    for existing in &gathered.existing {
        if !new_kv.contains_key(existing) {
            return Err(format!("--use-existing {}: no such secret in the vault", existing));
        }
        if existing.to_ascii_lowercase() != name {
            return Err(format!(
                "--use-existing {} can only back a connection named '{}' — use `--secret {}=<value>` to add it under '{}' instead",
                existing,
                existing.to_ascii_lowercase(),
                existing,
                name
            ));
        }
        // Already present as a bare key equal to the conn name — nothing to write.
    }

    insert_raw_connection(&mut aux, &name, &hosts);
    seal_and_submit_write(&custodian, &vault, &meta, &user_key, &new_kv, &aux, args.no_browser, args.timeout, args.cb_port).await?;

    report(&name, &hosts, &gathered);
    Ok(())
}

struct Gathered {
    /// New secrets to write: `(ROLE, value)`.
    new_values: Vec<(String, String)>,
    /// Existing bare secret names to claim.
    existing: Vec<String>,
}

fn gather_secrets(name: &str, secret_flags: &[String], use_existing: &[String]) -> Result<Gathered, String> {
    let mut new_values: Vec<(String, String)> = Vec::new();
    let existing: Vec<String> = use_existing.to_vec();

    if !secret_flags.is_empty() {
        for s in secret_flags {
            if let Some((k, v)) = s.split_once('=') {
                let role = k.trim();
                if !valid_role(role) {
                    return Err(format!("secret KEY '{}' isn't a valid env key ([A-Za-z0-9_])", role));
                }
                new_values.push((role.to_string(), v.to_string()));
            } else if std::io::stdin().is_terminal() {
                let role = s.trim();
                if !valid_role(role) {
                    return Err(format!("secret KEY '{}' isn't a valid env key ([A-Za-z0-9_])", role));
                }
                let val = rpassword::prompt_password(format!("Value for {} (hidden): ", role))
                    .map_err(|e| format!("read value: {}", e))?;
                if val.is_empty() {
                    return Err(format!("value for '{}' cannot be empty", role));
                }
                new_values.push((role.to_string(), val));
            } else {
                return Err(format!(
                    "--secret {}: provide a value as `--secret {}=<value>` (non-interactive)",
                    s, s
                ));
            }
        }
    } else if existing.is_empty() {
        // Fully interactive: loop prompting role names + hidden values.
        if !std::io::stdin().is_terminal() {
            return Err(
                "no secrets given — `--secret KEY=VALUE` (repeatable) or `--use-existing KEY`".into(),
            );
        }
        loop {
            let role = prompt_line(&format!("secret KEY for '{}' (blank to finish): ", name))?;
            let role = role.trim();
            if role.is_empty() {
                break;
            }
            if !valid_role(role) {
                eprintln!("  '{}' isn't a valid env key ([A-Za-z0-9_]); try again", role);
                continue;
            }
            let val = rpassword::prompt_password(format!("Value for {} (hidden): ", role))
                .map_err(|e| format!("read value: {}", e))?;
            if val.is_empty() {
                eprintln!("  value cannot be empty; try again");
                continue;
            }
            new_values.push((role.to_string(), val));
        }
    }

    // Duplicate role guard (case-insensitive — roles become phantom segments).
    let mut seen = std::collections::HashSet::new();
    for (role, _) in &new_values {
        if !seen.insert(role.to_ascii_lowercase()) {
            return Err(format!("duplicate secret KEY '{}'", role));
        }
    }
    Ok(Gathered { new_values, existing })
}

fn prompt_hosts(name: &str) -> Result<Vec<String>, String> {
    eprintln!("Connection '{}' needs at least one egress host (the API's exact domain).", name);
    let mut hosts = Vec::new();
    loop {
        let prompt = if hosts.is_empty() {
            "Host (e.g. api.example.com): ".to_string()
        } else {
            "Another host (blank to finish): ".to_string()
        };
        let h = prompt_line(&prompt)?;
        let h = h.trim();
        if h.is_empty() {
            if hosts.is_empty() {
                eprintln!("  at least one host is required");
                continue;
            }
            break;
        }
        hosts.push(h.to_string());
    }
    Ok(hosts)
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read input: {}", e))?;
    Ok(line)
}

fn report(name: &str, hosts: &[String], g: &Gathered) {
    let injectable = g.new_values.len() + g.existing.len();
    eprintln!("safeclaw connect — '{}' → {}", name, hosts.join(", "));
    if injectable == 1 {
        eprintln!("  phantom: __sc__{}__", name);
    } else {
        for (role, _) in &g.new_values {
            eprintln!("  phantom: __sc__{}__{}__", name, role.to_ascii_lowercase());
        }
    }
}
