//! `sc connection add <id>` (hidden alias `sc connect`) — create a connection in
//! ONE approval. The CLI superset of `sc set --host` (the raw single-secret
//! shorthand).
//!
//! Every secret SLOT is filled from one of two sources, two flags of the same
//! shape (the flag names the source):
//!   - `--from-literal SLOT=VALUE` — a NEW value, written to the vault on
//!     approval (the value rides the local deposit, never the op);
//!   - `--from-secret SLOT=KEY` — a secret ALREADY in the vault, bound by KEY
//!     (no plaintext anywhere).
//!
//! Two shapes (§9):
//!   - RAW (default): `--host <domain>` (repeatable). A raw connection's SLOT is
//!     the vault KEY itself, so `--from-secret KEY` is its short form. Anchors
//!     its own hosts; stores new values at their BARE uppercase KEY (the vault
//!     is a flat env namespace). Reachable via `__sc__<name>__` (sole) or
//!     `__sc__<name>__<role>__` (several).
//!   - SERVICE-backed: `--service <id>` binds a catalog service — its hosts and
//!     declared secret roles. SLOT is a role (case-insensitive), and
//!     `--from-secret` needs the `ROLE=KEY` form. Every role must be filled: a
//!     role named by neither flag is prompted for (hidden) on a terminal and is
//!     an error off one. `--host` is optional and only PINS an exact FQDN
//!     inside the service's `*.suffix` wildcards. A new value is stored at a
//!     BARE uppercase key (§3): the role's own name for the default connection,
//!     the suggested `<ROLE>_<QUALIFIER>` for a named one; the role → KEY
//!     binding is recorded in the connection's `keys` map.
//!
//! An agent may run this to PROPOSE a connection; nothing is written until the
//! vault owner approves with a passkey. The daemon stamps the approval card
//! (every bound key, new vs existing, every destination host, other
//! connections sharing a key) into the signed op and checks it again at apply.
//!
//! Secret KEYs written here are canonical UPPERCASE (§1); a lowercase literal
//! slot is auto-converted. Connection ids are lowercase.

use std::io::IsTerminal;
use std::io::Write as _;

use serde_json::{json, Value};

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, deposit_values, ApproveOpts};
use crate::cli::conn::{slugify_conn_id, valid_role, validate_raw_host};
use crate::cli::webauthn::now_unix;
use crate::config::{ConnectArgs, ConnectionHostArgs, ConnectionRmArgs};
use crate::service::ServiceRegistry;
use crate::storage::plaintext::suggested_secret_key;

pub async fn run(mut args: ConnectArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;

    // Resolve the connection id: slugify a provided handle, or (no id given) run
    // the TTY wizard — which prompts the id and may also pick a `--service`.
    let name = resolve_conn_id(&mut args)?;

    match args.service.clone() {
        Some(service) => run_service_backed(&custodian, &vault, &name, &service, &args).await,
        None => run_raw(&custodian, &vault, &name, &args).await,
    }
}

/// Turn the optional `<id>` arg into a concrete, phantom-safe connection id.
/// Provided handle → slugified (echoing the result when it changed). Omitted →
/// wizard on a terminal (prompt the id, then optionally a catalog service);
/// hard error off a terminal.
fn resolve_conn_id(args: &mut ConnectArgs) -> Result<String, String> {
    if let Some(raw) = args.name.clone() {
        let id = slugify_conn_id(&raw);
        if id.is_empty() {
            return Err(format!(
                "'{}' has no usable id characters — choose a handle with letters or digits",
                raw
            ));
        }
        if id != raw {
            eprintln!("safeclaw connect — using id '{}' (from '{}')", id, raw);
        }
        return Ok(id);
    }

    if !std::io::stdin().is_terminal() {
        return Err(
            "provide a connection id: `sc connection add <id> --host <domain> --from-literal KEY=VALUE` (or `--service <id>`)".into(),
        );
    }

    // Wizard step 1 — the id.
    let id = loop {
        let raw = prompt_line("Connection id (a short handle you choose, e.g. work_gmail): ")?;
        let raw = raw.trim();
        if raw.is_empty() {
            eprintln!("  an id is required");
            continue;
        }
        let id = slugify_conn_id(raw);
        if id.is_empty() {
            eprintln!(
                "  '{}' has no usable id characters; use letters/digits",
                raw
            );
            continue;
        }
        if id != raw {
            eprintln!("  → id '{}'", id);
        }
        break id;
    };

    // Wizard step 2 — optionally back it with a catalog service (skip if the
    // caller already passed `--service`). Blank = a raw connection.
    if args.service.is_none() {
        let svc = prompt_line(
            "Back with a catalog service? id from `sc registry`, or blank for a raw connection: ",
        )?;
        let svc = svc.trim();
        if !svc.is_empty() {
            args.service = Some(svc.to_string());
        }
    }
    Ok(id)
}

// ── ls ───────────────────────────────────────────────────────────────────────

/// `sc connection ls` — the agent-usable connection projection (the same rows
/// `sc status` prints), optionally as JSON.
pub async fn run_ls(json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let conns = crate::cli::discovery::connections(&custodian, &vault).await?;

    if json {
        let arr: Vec<Value> = conns
            .iter()
            .map(|c| serde_json::json!({ "id": c.name, "hosts": c.hosts, "phantoms": c.phantoms, "setup": c.setup }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&Value::Array(arr)).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }

    if conns.is_empty() {
        println!(
            "no connections; add one with `sc connection add <id> --host <domain> --from-literal KEY=VALUE`"
        );
        return Ok(());
    }
    // Names and hosts derive from service definitions (untrusted text).
    use crate::util::terminal_safe;
    for c in &conns {
        println!("{}", terminal_safe(&c.name));
        if !c.hosts.is_empty() {
            println!("  hosts:    {}", terminal_safe(&c.hosts.join(", ")));
        }
        for ph in &c.phantoms {
            println!("  phantom:  {}", terminal_safe(ph));
        }
    }
    Ok(())
}

// ── rm ───────────────────────────────────────────────────────────────────────

/// `sc connection rm <id>` — drop a connection record and the secret(s) ONLY
/// it references, the inverse of `add` and the CLI twin of the console's
/// removal. Shared-pool semantics (CONNECTION_SCHEMA.md §3): a key another
/// connection still references is always kept (printed with its claimants);
/// `--keep-secrets` keeps everything (unreference only). Two passkey gestures
/// (unlock + write); confirms first unless `--yes`.
/// `sc connection add-host <id> <host>` — the SELF-SERVICE host widen: an agent
/// (or a human) proposes adding a host to an existing connection's anchor, the
/// vault owner approves with a passkey, and the host is added DURABLY. Mints the
/// SAME `widen-host` op the proxy's one-tap widen uses (approve.rs dispatch), so
/// reactive and proactive widening share one code path + one consent card. The
/// host may be an exact FQDN or a leftmost `*.domain` wildcard.
pub async fn run_add_host(args: ConnectionHostArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let id = slugify_conn_id(&args.id);
    if id.is_empty() {
        return Err(format!("'{}' is not a valid connection id", args.id));
    }
    let host = args.host.trim().to_string();
    validate_raw_host(&host)?;

    let op = json!({
        "act": {
            "type": { "custom": "widen-host" },
            "target": "",
            "scope": { "connection_id": id, "host": host }
        },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Add host {} to connection {}", host, id),
        &opts,
    )
    .await?;
    let _ = act_result(&body);
    println!("host '{}' added to connection '{}'", host, id);
    Ok(())
}

/// `sc connection rm-host <id> <host>` — the inverse of `add-host`: propose
/// REMOVING a host from a connection's anchor (tighten access). Same passkey
/// approval; mints the `narrow-host` op the dispatch removes durably. Idempotent
/// — a host not on the anchor reports nothing removed (no error).
pub async fn run_rm_host(args: ConnectionHostArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let id = slugify_conn_id(&args.id);
    if id.is_empty() {
        return Err(format!("'{}' is not a valid connection id", args.id));
    }
    let host = args.host.trim().to_string();
    if host.is_empty() {
        return Err("host cannot be empty".into());
    }

    let op = json!({
        "act": {
            "type": { "custom": "narrow-host" },
            "target": "",
            "scope": { "connection_id": id, "host": host }
        },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Remove host {} from connection {}", host, id),
        &opts,
    )
    .await?;
    let removed = act_result(&body)
        .get("removed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if removed {
        println!("host '{}' removed from connection '{}'", host, id);
    } else {
        println!(
            "host '{}' was not on connection '{}' (nothing to remove)",
            host, id
        );
    }
    Ok(())
}

pub async fn run_rm(args: ConnectionRmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let id = slugify_conn_id(&args.id);
    if id.is_empty() {
        return Err(format!("'{}' is not a valid connection id", args.id));
    }

    // Anti-fat-finger confirm BEFORE the gesture (the grant page also names the
    // op). The cascade detail — which secrets get deleted — is reported AFTER,
    // computed daemon-side under the open vault. The connection id rides the op
    // (public); no secret value ever does. Off a terminal, require `--yes`.
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(format!(
                "refusing to remove connection '{}' without confirmation — pass `--yes` (non-interactive)",
                id
            ));
        }
        let ans = prompt_line(&format!(
            "Remove connection '{}'{}? [y/N]: ",
            id,
            if args.keep_secrets {
                " (keeping its secrets)"
            } else {
                " and the secret(s) it wrote that nothing else uses"
            },
        ))?;
        if !matches!(ans.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("aborted");
            return Ok(());
        }
    }

    let op = json!({
        "act": { "type": { "custom": "connection-rm" }, "target": id, "scope": { "keep_secrets": args.keep_secrets } },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Remove connection {}", id),
        &opts,
    )
    .await?;

    let result = act_result(&body);
    let strs = |field: &str| -> Vec<String> {
        result
            .get(field)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let removed_secrets = strs("removed_secrets");
    if removed_secrets.is_empty() {
        println!("connection '{}' removed", id);
    } else {
        println!(
            "connection '{}' removed (+{} secret(s): {})",
            id,
            removed_secrets.len(),
            removed_secrets.join(", ")
        );
    }
    if args.keep_secrets {
        eprintln!("  secrets kept (record removed only)");
    }
    // kept_secrets: [[key, [referencing_conn, …]], …]
    if let Some(kept) = result.get("kept_secrets").and_then(|v| v.as_array()) {
        for entry in kept {
            let Some(pair) = entry.as_array() else {
                continue;
            };
            let key = pair.first().and_then(|v| v.as_str()).unwrap_or("?");
            let by = pair
                .get(1)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            eprintln!("  kept: {} (still referenced by {})", key, by);
        }
    }
    for key in strs("kept_referenced") {
        eprintln!(
            "  kept: {} (it was already in the vault when this connection was added; this connection did not write it)",
            key
        );
    }
    for key in strs("kept_untracked") {
        eprintln!(
            "  kept: {} (this connection was added before SafeClaw recorded which secrets a connection writes, so the key may predate it; `sc secret rm {}` deletes it)",
            key, key
        );
    }
    Ok(())
}

// ── raw connection ───────────────────────────────────────────────────────────

async fn run_raw(
    custodian: &str,
    vault: &str,
    name: &str,
    args: &ConnectArgs,
) -> Result<(), String> {
    // Hosts: anchor our own exact FQDNs.
    let hosts = if !args.host.is_empty() {
        args.host.clone()
    } else if std::io::stdin().is_terminal() {
        prompt_hosts(name)?
    } else {
        return Err(
            "a raw connection needs at least one host — pass `--host <domain>` (repeatable), or `--service <id>` to bind a catalog service".into(),
        );
    };
    for h in &hosts {
        validate_raw_host(h)?;
    }

    // Slots: a raw connection's SLOT is its vault KEY. New values are stored at
    // their BARE uppercase KEY (§2 — the vault is a flat env namespace; two
    // connections referencing the same KEY share it).
    let gathered = gather_raw_slots(
        name,
        &args.from_literal,
        &args.from_secret,
        std::io::stdin().is_terminal(),
    )?;
    if gathered.new_values.is_empty() && gathered.existing.is_empty() {
        return Err(
            "a raw connection needs at least one secret: `--from-literal KEY=VALUE` (a new value) or `--from-secret KEY` (a secret already in the vault)"
                .into(),
        );
    }

    // `secret_keys` = every KEY the connection binds (new + existing); the
    // daemon verifies each `--from-secret` KEY actually exists.
    let mut secret_keys: Vec<String> = gathered
        .new_values
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    secret_keys.extend(gathered.existing.iter().cloned());
    dedup_exact(&mut secret_keys);
    print_proposal(
        name,
        gathered
            .new_values
            .iter()
            .map(|(k, _)| (k.clone(), k.clone(), true))
            .chain(
                gathered
                    .existing
                    .iter()
                    .map(|k| (k.clone(), k.clone(), false)),
            ),
        &[],
    );

    // New VALUES go to the local daemon deposit; the op carries only the
    // salted digest (the op JSON travels to the cloud grant page — §values).
    let mut scope = json!({ "hosts": hosts, "secrets": secret_keys });
    if !gathered.new_values.is_empty() {
        let values: std::collections::BTreeMap<String, String> =
            gathered.new_values.iter().cloned().collect();
        scope["values_digest"] = json!(deposit_values(custodian, vault, &values).await?);
    }
    let op = json!({
        "act": { "type": { "custom": "connection-add" }, "target": name, "scope": scope },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(
        custodian,
        vault,
        &op,
        &format!("Add connection {}", name),
        &opts,
    )
    .await?;

    report_phantoms(name, &hosts, &secret_keys);
    Ok(())
}

// ── service-backed connection ────────────────────────────────────────────────

async fn run_service_backed(
    custodian: &str,
    vault: &str,
    name: &str,
    service: &str,
    args: &ConnectArgs,
) -> Result<(), String> {
    // Resolve the service from the compiled catalog (built-ins). A per-vault
    // custom service (aux.services) is connected via the console, not here.
    let reg = ServiceRegistry::load();
    let def = reg.get(service).ok_or_else(|| {
        format!(
            "unknown service '{}' — see `sc registry`; per-vault custom services are connected in the console",
            service
        )
    })?;
    let service_hosts = def.service.hosts.clone();
    let service_secrets = def.service.secrets.clone();
    // Auxiliary pointer to where the token is minted (display-only).
    if let Some(url) = def.service.secret_url.as_deref() {
        eprintln!("  Get a token: {}", crate::util::terminal_safe(url));
    }

    // `--host` on a service-backed connect only PINS a host inside the service's
    // declared set: each pin must match an exact host or fall within a `*.suffix`
    // wildcard. `None` (no pin) derives the service's exact hosts at runtime.
    let pins: Option<Vec<String>> = if args.host.is_empty() {
        None
    } else {
        for h in &args.host {
            validate_raw_host(h)?;
            let ok = service_hosts
                .iter()
                .any(|e| crate::core::host::wildcard_matches(e, h));
            if !ok {
                return Err(format!(
                    "host '{}' is not within service '{}' hosts ({}) — a --service pin must be ⊆ the service's hosts",
                    h,
                    service,
                    service_hosts.join(", ")
                ));
            }
        }
        Some(args.host.clone())
    };

    // Every declared role is a slot, filled from a new value or a secret
    // already in the vault. Only the service's primary credential role (its
    // mint input, else its first declared secret) is required; the rest are
    // optional and may stay unfilled.
    let required: Vec<String> = def
        .env_role()
        .and_then(|r| {
            service_secrets
                .iter()
                .find(|s| s.eq_ignore_ascii_case(&r))
                .cloned()
        })
        .into_iter()
        .collect();
    let filled = fill_service_slots(
        service,
        &service_secrets,
        &required,
        &args.from_literal,
        &args.from_secret,
        std::io::stdin().is_terminal(),
    )?;

    // A NEW value is stored at a BARE uppercase KEY (§3): the role's own
    // mainstream name for the default connection (`name == service`), or the
    // suggested `<ROLE>_<QUALIFIER>` for a named one. An existing secret is
    // bound by its KEY as typed (the daemon folds a native key's case).
    let mut bindings: Vec<(String, String, bool)> = Vec::new(); // (role, KEY, new?)
    let mut unfilled: Vec<String> = Vec::new();
    let mut values = std::collections::BTreeMap::new();
    for (role, source) in filled {
        match source {
            Some(Filled::Value(v)) => {
                let key = suggested_secret_key(name, service, &role);
                values.insert(key.clone(), v);
                bindings.push((role, key, true));
            }
            Some(Filled::Secret(key)) => bindings.push((role, key, false)),
            None => unfilled.push(role),
        }
    }
    // The connection's `keys` map: a named connection records every role's
    // KEY; the default connection keeps the identity binding for its new
    // values and records only roles bound to a differently named secret.
    let keys: Vec<(String, String)> = bindings
        .iter()
        .filter(|(role, key, new)| name != service || (!*new && key != role))
        .map(|(role, key, _)| (role.clone(), key.clone()))
        .collect();
    let mut bound_keys: Vec<String> = bindings.iter().map(|(_, k, _)| k.clone()).collect();
    dedup_exact(&mut bound_keys);
    print_proposal(name, bindings.iter().cloned(), &unfilled);

    // New VALUES go to the local daemon deposit; the op carries only the
    // salted digest plus the public shape (service, pins, key bindings).
    let mut scope = json!({ "service": service, "secrets": bound_keys });
    if let Some(p) = &pins {
        scope["hosts"] = json!(p);
    }
    if !keys.is_empty() {
        let map: serde_json::Map<String, Value> = keys
            .iter()
            .map(|(role, key)| (role.clone(), Value::String(key.clone())))
            .collect();
        scope["keys"] = Value::Object(map);
    }
    if !values.is_empty() {
        scope["values_digest"] = json!(deposit_values(custodian, vault, &values).await?);
    }
    let op = json!({
        "act": { "type": { "custom": "connection-add" }, "target": name, "scope": scope },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(
        custodian,
        vault,
        &op,
        &format!("Add connection {}", name),
        &opts,
    )
    .await?;

    // The service def is the SSoT for the advertised phantoms.
    let phantoms: Vec<String> = crate::core::host::phantoms_for(name, def)
        .into_values()
        .collect();
    let host_line = pins
        .as_ref()
        .map(|p| p.join(", "))
        .unwrap_or_else(|| service_hosts.join(", "));
    eprintln!(
        "safeclaw connect — '{}' → {} ({})",
        name, service, host_line
    );
    for ph in &phantoms {
        eprintln!("  phantom: {}", ph);
    }
    if phantoms.is_empty() {
        eprintln!("  (no injectable phantom yet: fill the service's secret with `--from-literal ROLE=VALUE` or `--from-secret ROLE=KEY`)");
    }
    Ok(())
}

// ── slot filling ─────────────────────────────────────────────────────────────

/// One `--from-literal` / `--from-secret` argument, split.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SlotArg {
    /// `--from-literal SLOT=VALUE`.
    Literal { slot: String, value: String },
    /// `--from-literal SLOT`: prompt for the value (hidden) on a terminal.
    Prompt { slot: String },
    /// `--from-secret SLOT=KEY`.
    Secret { slot: String, key: String },
    /// `--from-secret KEY` (raw connections only: the slot IS the key).
    SecretShort { key: String },
}

/// Split the two flags into slot arguments, checking only their shape.
fn parse_slot_args(
    from_literal: &[String],
    from_secret: &[String],
) -> Result<Vec<SlotArg>, String> {
    let mut out = Vec::new();
    for a in from_literal {
        match a.split_once('=') {
            Some((slot, value)) => {
                let slot = slot.trim();
                if slot.is_empty() {
                    return Err(format!(
                        "--from-literal '{}': SLOT is empty (expected SLOT=VALUE)",
                        a
                    ));
                }
                if value.is_empty() {
                    return Err(format!(
                        "--from-literal {}: the value is empty; pass `--from-literal {}=<value>`, or `--from-literal {}` on a terminal to type it hidden",
                        slot, slot, slot
                    ));
                }
                out.push(SlotArg::Literal {
                    slot: slot.to_string(),
                    value: value.to_string(),
                });
            }
            None => {
                let slot = a.trim();
                if slot.is_empty() {
                    return Err("--from-literal needs SLOT=VALUE".into());
                }
                out.push(SlotArg::Prompt {
                    slot: slot.to_string(),
                });
            }
        }
    }
    for a in from_secret {
        let (slot, key) = match a.split_once('=') {
            Some((slot, key)) => (Some(slot.trim()), key.trim()),
            None => (None, a.trim()),
        };
        if !crate::cli::conn::valid_secret_ref(key) {
            return Err(format!(
                "--from-secret '{}': '{}' is not a valid secret key (ASCII letters/digits/_/-, no '__')",
                a, key
            ));
        }
        match slot {
            Some("") => {
                return Err(format!(
                    "--from-secret '{}': SLOT is empty (expected SLOT=KEY)",
                    a
                ))
            }
            Some(slot) => out.push(SlotArg::Secret {
                slot: slot.to_string(),
                key: key.to_string(),
            }),
            None => out.push(SlotArg::SecretShort {
                key: key.to_string(),
            }),
        }
    }
    Ok(out)
}

/// Where a filled slot's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Filled {
    /// A new value to write.
    Value(String),
    /// An existing vault secret, by KEY as typed.
    Secret(String),
}

/// What a slot argument resolves to before prompting: a value, a prompt, or a
/// reference.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    Value(String),
    Prompt,
    Secret(String),
}

/// Record `slot → pending`, refusing a slot named twice (case-insensitively),
/// with the reason naming both flags when the sources differ.
fn claim_slot(
    seen: &mut Vec<(String, Pending)>,
    slot: String,
    pending: Pending,
) -> Result<(), String> {
    if let Some((_, prev)) = seen.iter().find(|(s, _)| s.eq_ignore_ascii_case(&slot)) {
        let both = matches!(prev, Pending::Secret(_)) != matches!(pending, Pending::Secret(_));
        return Err(if both {
            format!(
                "slot '{}' is filled by both --from-literal and --from-secret; use one",
                slot
            )
        } else {
            format!("slot '{}' is given twice", slot)
        });
    }
    seen.push((slot, pending));
    Ok(())
}

/// Hidden prompt for one slot's value (re-asks on an empty answer).
fn prompt_value(slot: &str) -> Result<String, String> {
    loop {
        let val = rpassword::prompt_password(format!("Value for {} (hidden): ", slot))
            .map_err(|e| format!("read value: {}", e))?;
        if !val.is_empty() {
            return Ok(val);
        }
        eprintln!("  value cannot be empty; try again");
    }
}

/// RAW slots: SLOT is the vault KEY. Returns new `(UPPERCASE KEY, value)`
/// pairs and existing KEYs as typed. No flags at all on a terminal runs the
/// interactive KEY + hidden-value loop.
#[derive(Debug)]
struct RawSlots {
    new_values: Vec<(String, String)>,
    existing: Vec<String>,
}

fn gather_raw_slots(
    name: &str,
    from_literal: &[String],
    from_secret: &[String],
    tty: bool,
) -> Result<RawSlots, String> {
    let args = parse_slot_args(from_literal, from_secret)?;
    let mut seen: Vec<(String, Pending)> = Vec::new();
    for a in args {
        match a {
            SlotArg::Literal { slot, value } => {
                claim_slot(&mut seen, upper_key(&slot)?, Pending::Value(value))?
            }
            SlotArg::Prompt { slot } => claim_slot(&mut seen, upper_key(&slot)?, Pending::Prompt)?,
            SlotArg::SecretShort { key } => {
                claim_slot(&mut seen, key.clone(), Pending::Secret(key))?
            }
            SlotArg::Secret { slot, key } => {
                if !slot.eq_ignore_ascii_case(&key) {
                    return Err(format!(
                        "--from-secret {}={}: a raw connection's slot is the key itself; use `--from-secret {}`",
                        slot, key, key
                    ));
                }
                claim_slot(&mut seen, key.clone(), Pending::Secret(key))?
            }
        }
    }

    let mut out = RawSlots {
        new_values: Vec::new(),
        existing: Vec::new(),
    };
    if seen.is_empty() && tty {
        // Fully interactive: loop prompting KEY names + hidden values.
        loop {
            let key = prompt_line(&format!("secret KEY for '{}' (blank to finish): ", name))?;
            let key = key.trim().to_ascii_uppercase();
            if key.is_empty() {
                break;
            }
            if !valid_role(&key) {
                eprintln!("  '{}' isn't a valid env key ([A-Z0-9_]); try again", key);
                continue;
            }
            if out.new_values.iter().any(|(k, _)| *k == key) {
                eprintln!("  '{}' already given; try again", key);
                continue;
            }
            let val = prompt_value(&key)?;
            out.new_values.push((key, val));
        }
        return Ok(out);
    }
    for (slot, pending) in seen {
        match pending {
            Pending::Value(v) => out.new_values.push((slot, v)),
            Pending::Secret(k) => out.existing.push(k),
            Pending::Prompt if tty => {
                let v = prompt_value(&slot)?;
                out.new_values.push((slot, v));
            }
            Pending::Prompt => {
                return Err(format!(
                    "--from-literal {}: provide the value as `--from-literal {}=<value>` (no terminal to prompt on)",
                    slot, slot
                ))
            }
        }
    }
    Ok(out)
}

/// A raw literal slot names the KEY to write: canonical UPPERCASE (§1).
fn upper_key(slot: &str) -> Result<String, String> {
    let key = slot.trim().to_ascii_uppercase();
    if !valid_role(&key) {
        return Err(format!(
            "secret KEY '{}' isn't a valid env key ([A-Z0-9_])",
            slot.trim()
        ));
    }
    Ok(key)
}

/// SERVICE slots: every declared role, in declaration order. A role named by
/// a flag is filled from it. A `required` role no flag names is prompted for
/// (hidden) on a terminal; off a terminal that is an error naming the missing
/// required roles and both ways to fill them. Any other role is optional: on
/// a terminal it is offered with a blank answer skipping it, and otherwise it
/// stays unfilled (`None`).
fn fill_service_slots(
    service: &str,
    roles: &[String],
    required: &[String],
    from_literal: &[String],
    from_secret: &[String],
    tty: bool,
) -> Result<Vec<(String, Option<Filled>)>, String> {
    let declared = |slot: &str| -> Result<String, String> {
        roles
            .iter()
            .find(|r| r.eq_ignore_ascii_case(slot))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "secret '{}' is not declared by service '{}' (its secrets: {})",
                    slot,
                    service,
                    if roles.is_empty() {
                        "none".into()
                    } else {
                        roles.join(", ")
                    }
                )
            })
    };
    let mut seen: Vec<(String, Pending)> = Vec::new();
    for a in parse_slot_args(from_literal, from_secret)? {
        match a {
            SlotArg::Literal { slot, value } => {
                claim_slot(&mut seen, declared(&slot)?, Pending::Value(value))?
            }
            SlotArg::Prompt { slot } => claim_slot(&mut seen, declared(&slot)?, Pending::Prompt)?,
            SlotArg::Secret { slot, key } => {
                claim_slot(&mut seen, declared(&slot)?, Pending::Secret(key))?
            }
            SlotArg::SecretShort { key } => {
                return Err(format!(
                    "--from-secret {}: with --service, name the slot it fills: `--from-secret ROLE={}` (roles of '{}': {}). A key name alone does not say which of the service's secrets it is.",
                    key,
                    key,
                    service,
                    if roles.is_empty() {
                        "none".into()
                    } else {
                        roles.join(", ")
                    }
                ))
            }
        }
    }

    let is_required = |r: &str| required.iter().any(|q| q.eq_ignore_ascii_case(r));
    let missing: Vec<&String> = roles
        .iter()
        .filter(|r| is_required(r) && !seen.iter().any(|(s, _)| s == *r))
        .collect();
    if !missing.is_empty() && !tty {
        let first = missing[0];
        return Err(format!(
            "service '{}' needs a value for: {}. Fill each slot with a new value (`--from-literal {}=<value>`) or with a secret already in the vault (`--from-secret {}=<KEY>`).",
            service,
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            first,
            first
        ));
    }

    let mut out = Vec::with_capacity(roles.len());
    for role in roles {
        let filled = match seen.iter().find(|(s, _)| s == role).map(|(_, p)| p.clone()) {
            Some(Pending::Value(v)) => Some(Filled::Value(v)),
            Some(Pending::Secret(k)) => Some(Filled::Secret(k)),
            // A bare `--from-literal ROLE`, or a required role no flag named:
            // hidden prompt (only reached on a terminal).
            Some(Pending::Prompt) => Some(Filled::Value(prompt_or_fail(role, tty)?)),
            None if is_required(role) => Some(Filled::Value(prompt_or_fail(role, tty)?)),
            // An optional role no flag named.
            None if tty => prompt_optional_value(role)?.map(Filled::Value),
            None => None,
        };
        out.push((role.clone(), filled));
    }
    Ok(out)
}

/// The hidden prompt for a slot that needs a value, or the error saying how to
/// pass it when there is no terminal to prompt on.
fn prompt_or_fail(role: &str, tty: bool) -> Result<String, String> {
    if !tty {
        return Err(format!(
            "--from-literal {}: provide the value as `--from-literal {}=<value>` (no terminal to prompt on)",
            role, role
        ));
    }
    prompt_value(role)
}

/// Hidden prompt for an optional slot; a blank answer leaves it unfilled.
fn prompt_optional_value(slot: &str) -> Result<Option<String>, String> {
    let val = rpassword::prompt_password(format!(
        "Value for {} (hidden, optional; blank to skip): ",
        slot
    ))
    .map_err(|e| format!("read value: {}", e))?;
    Ok(Some(val).filter(|v| !v.is_empty()))
}

/// Print what the request proposes, before the approval: every slot, its KEY,
/// and whether the value is new or an existing secret.
fn print_proposal(
    name: &str,
    bindings: impl Iterator<Item = (String, String, bool)>,
    unfilled: &[String],
) {
    eprintln!(
        "Proposing connection '{}' (nothing changes until it is approved):",
        name
    );
    for (slot, key, new) in bindings {
        let src = if new { "new value" } else { "existing secret" };
        if slot == key {
            eprintln!("  {}  ({})", key, src);
        } else {
            eprintln!("  {} ← {}  ({})", slot, key, src);
        }
    }
    for slot in unfilled {
        eprintln!("  {}  (optional, not set by this command)", slot);
    }
}

fn dedup_exact(keys: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    keys.retain(|k| seen.insert(k.clone()));
}

fn prompt_hosts(name: &str) -> Result<Vec<String>, String> {
    eprintln!(
        "Connection '{}' needs at least one egress host (the API's exact domain).",
        name
    );
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

pub(crate) fn prompt_line(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read input: {}", e))?;
    Ok(line)
}

/// Report the advertised phantom(s) for a raw connection: sole → short form,
/// several → role-qualified (matches the resolver's form-A grammar).
fn report_phantoms(name: &str, hosts: &[String], secret_keys: &[String]) {
    eprintln!("safeclaw connect — '{}' → {}", name, hosts.join(", "));
    let phantoms = crate::core::host::phantoms_for_raw(name, secret_keys);
    for ph in phantoms.values() {
        eprintln!("  phantom: {}", ph);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    fn roles() -> Vec<String> {
        v(&["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"])
    }

    #[test]
    fn parse_shapes() {
        let a = parse_slot_args(&v(&["K=a=b", "P"]), &v(&["R=OLD_KEY", "xh-gcp-test"])).unwrap();
        assert_eq!(
            a,
            vec![
                SlotArg::Literal {
                    slot: "K".into(),
                    value: "a=b".into()
                },
                SlotArg::Prompt { slot: "P".into() },
                SlotArg::Secret {
                    slot: "R".into(),
                    key: "OLD_KEY".into()
                },
                SlotArg::SecretShort {
                    key: "xh-gcp-test".into()
                },
            ]
        );
        assert!(parse_slot_args(&v(&["K="]), &[])
            .unwrap_err()
            .contains("value is empty"));
        assert!(parse_slot_args(&v(&["=x"]), &[])
            .unwrap_err()
            .contains("SLOT is empty"));
        assert!(parse_slot_args(&[], &v(&["R=a__b"]))
            .unwrap_err()
            .contains("not a valid secret key"));
        assert!(parse_slot_args(&[], &v(&["=K"]))
            .unwrap_err()
            .contains("SLOT is empty"));
    }

    fn required() -> Vec<String> {
        v(&["CLOUDFLARE_API_TOKEN"])
    }

    #[test]
    fn service_slots_mix_sources_case_insensitively() {
        let f = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &v(&["cloudflare_account_id=acc123"]),
            &v(&["Cloudflare_Api_Token=CF_TOKEN_WORK"]),
            false,
        )
        .unwrap();
        assert_eq!(
            f,
            vec![
                (
                    "CLOUDFLARE_API_TOKEN".into(),
                    Some(Filled::Secret("CF_TOKEN_WORK".into()))
                ),
                (
                    "CLOUDFLARE_ACCOUNT_ID".into(),
                    Some(Filled::Value("acc123".into()))
                ),
            ]
        );
        // A pure-reference service connection is fine (no "no secrets" refusal).
        let f = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &[],
            &v(&["CLOUDFLARE_API_TOKEN=A", "CLOUDFLARE_ACCOUNT_ID=B"]),
            false,
        )
        .unwrap();
        assert!(f.iter().all(|(_, s)| matches!(s, Some(Filled::Secret(_)))));
    }

    /// Only the primary credential role is required: the account id may stay
    /// unfilled off a terminal, from either flag's side.
    #[test]
    fn optional_service_roles_may_stay_unfilled() {
        for (lit, sec) in [
            (v(&["CLOUDFLARE_API_TOKEN=x"]), vec![]),
            (vec![], v(&["CLOUDFLARE_API_TOKEN=CF_TOKEN"])),
        ] {
            let f =
                fill_service_slots("cloudflare", &roles(), &required(), &lit, &sec, false).unwrap();
            assert!(f[0].1.is_some(), "{f:?}");
            assert_eq!(f[1], ("CLOUDFLARE_ACCOUNT_ID".to_string(), None));
        }
        // The optional role alone does not satisfy the required one.
        let e = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &v(&["CLOUDFLARE_ACCOUNT_ID=acc"]),
            &[],
            false,
        )
        .unwrap_err();
        assert!(
            e.contains("needs a value for: CLOUDFLARE_API_TOKEN."),
            "{e}"
        );
        // The required role is the service's primary credential (env_role):
        // the mint input for a minted service, else the first secret.
        let reg = ServiceRegistry::load();
        assert_eq!(
            reg.get("cloudflare").unwrap().env_role().as_deref(),
            Some("CLOUDFLARE_API_TOKEN")
        );
        assert_eq!(
            reg.get("openai_codex").unwrap().env_role().as_deref(),
            Some("OPENAI_CODEX_REFRESH_TOKEN")
        );
    }

    #[test]
    fn service_slot_errors() {
        // Undeclared role: same message shape as before, listing the roles.
        let e = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &v(&["NOPE=x"]),
            &[],
            false,
        )
        .unwrap_err();
        assert_eq!(
            e,
            "secret 'NOPE' is not declared by service 'cloudflare' (its secrets: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID)"
        );
        // Shorthand needs a slot with --service, and says why.
        let e = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &[],
            &v(&["CF_TOKEN"]),
            false,
        )
        .unwrap_err();
        assert!(e.contains("with --service, name the slot"), "{e}");
        assert!(e.contains("--from-secret ROLE=CF_TOKEN"), "{e}");
        // Both flags on one slot.
        let e = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &v(&["CLOUDFLARE_API_TOKEN=x"]),
            &v(&["cloudflare_api_token=K"]),
            false,
        )
        .unwrap_err();
        assert!(e.contains("both --from-literal and --from-secret"), "{e}");
        // Same flag twice.
        let e = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &v(&["CLOUDFLARE_API_TOKEN=x", "cloudflare_api_token=y"]),
            &[],
            false,
        )
        .unwrap_err();
        assert!(e.contains("given twice"), "{e}");
        // Unfilled REQUIRED roles off a terminal: listed, with both ways to
        // fill them.
        let e =
            fill_service_slots("cloudflare", &roles(), &required(), &[], &[], false).unwrap_err();
        assert!(e.contains("needs a value for: CLOUDFLARE_API_TOKEN"), "{e}");
        assert!(
            e.contains("--from-literal CLOUDFLARE_API_TOKEN=<value>"),
            "{e}"
        );
        assert!(
            e.contains("--from-secret CLOUDFLARE_API_TOKEN=<KEY>"),
            "{e}"
        );
        assert!(
            !e.contains("CLOUDFLARE_ACCOUNT_ID"),
            "optional roles are not listed: {e}"
        );
        // A bare --from-literal off a terminal can't prompt.
        let e = fill_service_slots(
            "cloudflare",
            &roles(),
            &required(),
            &v(&["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID=x"]),
            &[],
            false,
        )
        .unwrap_err();
        assert!(e.contains("no terminal to prompt on"), "{e}");
    }

    #[test]
    fn raw_slots_are_keys() {
        let r = gather_raw_slots(
            "myapi",
            &v(&["api_token=v1"]),
            &v(&["xh-gcp-test", "OLD_KEY=old_key"]),
            false,
        )
        .unwrap();
        assert_eq!(r.new_values, vec![("API_TOKEN".into(), "v1".into())]);
        assert_eq!(r.existing, v(&["xh-gcp-test", "old_key"]));
        // SLOT=KEY with a different slot is refused for raw: the slot IS the key.
        let e = gather_raw_slots("myapi", &[], &v(&["TOKEN=OTHER_KEY"]), false).unwrap_err();
        assert!(e.contains("use `--from-secret OTHER_KEY`"), "{e}");
        // Same KEY from both flags.
        let e =
            gather_raw_slots("myapi", &v(&["API_TOKEN=x"]), &v(&["api_token"]), false).unwrap_err();
        assert!(e.contains("both --from-literal and --from-secret"), "{e}");
        // Literal KEYs must be env keys.
        let e = gather_raw_slots("myapi", &v(&["bad-key=x"]), &[], false).unwrap_err();
        assert!(e.contains("isn't a valid env key"), "{e}");
        // No flags off a terminal: empty (the caller refuses with both flags named).
        let r = gather_raw_slots("myapi", &[], &[], false).unwrap();
        assert!(r.new_values.is_empty() && r.existing.is_empty());
    }
}
