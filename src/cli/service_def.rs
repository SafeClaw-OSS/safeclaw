//! `sc service validate <path>` — run the service-definition gate offline (no
//! daemon): the same `service::gate::admit` the daemon applies when it stores
//! and loads a definition, so authors can check a service.toml before
//! submitting it.
//!
//! Every human-readable line here that carries definition-derived text goes
//! through `util::terminal_safe` (the definition is untrusted input).

use serde_json::json;

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, ApproveOpts};
use crate::cli::webauthn::now_unix;
use crate::config::{ServiceAddArgs, ServiceLsArgs, ServiceRmArgs, ServiceValidateArgs};
use crate::service::ServiceDef;
use crate::util::terminal_safe;

/// Read `path` and admit it through the gate, printing every problem when it
/// is rejected.
fn admit_file(path: &std::path::Path) -> Result<(String, ServiceDef), String> {
    let shown = path.display().to_string();
    let toml_str = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", terminal_safe(&shown), e))?;
    match crate::service::gate::admit(None, &toml_str, None) {
        Ok(def) => Ok((toml_str, def)),
        Err(problems) => {
            eprintln!(
                "✗ {}: {} problem{}:",
                terminal_safe(&shown),
                problems.len(),
                if problems.len() == 1 { "" } else { "s" }
            );
            for p in &problems {
                eprintln!("  • {}", terminal_safe(p));
            }
            // Non-zero exit via the Err path (main prints + boxes it).
            Err(format!(
                "{}: service validation failed",
                terminal_safe(&shown)
            ))
        }
    }
}

/// Print the parts of `def`'s policy a vault does not apply (a vault
/// definition's policy can only tighten), one note each.
fn print_vault_notes(def: &ServiceDef) {
    let (_, notes) = def.clone().for_vault();
    if !notes.is_empty() {
        eprintln!("note: in a vault, part of this policy is not applied:");
        for n in &notes {
            eprintln!("  • {}", terminal_safe(n));
        }
    }
}

pub async fn run_validate(args: ServiceValidateArgs) -> Result<(), String> {
    let (_, def) = admit_file(&args.path)?;
    println!(
        "✓ {}: valid",
        terminal_safe(&args.path.display().to_string())
    );
    print_vault_notes(&def);
    Ok(())
}

/// `sc service add <file.toml>` — validate a v4 definition, then store it in the
/// active vault's `aux.services` (keyed by the service id) via a daemon-side
/// grant op. One passkey gesture; over SSH it surfaces the cloud grant link (no
/// browser tunnel, no local WebAuthn ceremony). The daemon re-validates + seals.
pub async fn run_add(args: ServiceAddArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // Offline fast-fail: the same gate the daemon re-runs on the grant.
    let (toml_str, def) = admit_file(&args.path)?;
    print_vault_notes(&def);
    let id = def.service.id.clone();

    let op = json!({
        "act": { "type": { "custom": "service-add" }, "target": "", "scope": { "toml": toml_str } },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Add service {}", id),
        &opts,
    )
    .await?;
    println!("service '{}' stored", terminal_safe(&id));
    Ok(())
}

/// `sc service ls` — list `aux.services` with each definition's validation
/// status + referencing connections. The daemon silently SKIPS an invalid
/// definition at unlock (its connections stay stuck "connecting"), and the
/// console only shows a definition through its connections — so a broken or
/// orphaned def is invisible everywhere but here. One passkey gesture (over SSH:
/// the cloud grant link).
pub async fn run_ls(args: ServiceLsArgs, json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let op = json!({
        "act": { "type": { "custom": "service-ls" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(&custodian, &vault, &op, "List services", &opts).await?;

    let services = act_result(&body)
        .get("services")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if json {
        // Machine-readable mirror: the daemon's per-definition rows verbatim
        // (id, valid, connections, problems), the same data the table renders.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Array(services))
                .unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if services.is_empty() {
        println!("(no custom service definitions in this vault)");
        return Ok(());
    }
    for s in &services {
        let id = terminal_safe(s.get("id").and_then(|v| v.as_str()).unwrap_or("?"));
        let valid = s.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        let conns = s
            .get("connections")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let conns = terminal_safe(&conns);
        let used = if conns.is_empty() {
            "no connections".to_string()
        } else {
            format!("connections: {}", conns)
        };
        if valid {
            println!("✓ {}: valid ({})", id, used);
        } else {
            println!("✗ {}: INVALID, the daemon skips it ({})", id, used);
            if let Some(problems) = s.get("problems").and_then(|v| v.as_array()) {
                for p in problems {
                    let Some(p) = p.as_str() else { continue };
                    let p = terminal_safe(p);
                    // A parse error spans lines; indent them under the bullet.
                    let mut lines = p.lines();
                    if let Some(first) = lines.next() {
                        println!("    • {}", first);
                    }
                    for l in lines {
                        println!("      {}", l);
                    }
                }
            }
        }
    }
    Ok(())
}

/// `sc service rm <id>` — delete a custom service definition from
/// `aux.services` via a daemon-side grant op. Connections referencing it are
/// kept (their stored secrets stay resolvable; only the service backing goes
/// away) and reported so we can warn. One passkey gesture (over SSH: the cloud
/// grant link).
pub async fn run_rm(args: ServiceRmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let op = json!({
        "act": { "type": { "custom": "service-rm" }, "target": args.id, "scope": null },
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
        &format!("Remove service {}", args.id),
        &opts,
    )
    .await?;

    let refs: Vec<String> = act_result(&body)
        .get("referencing_connections")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !refs.is_empty() {
        eprintln!(
            "note: connection{} still reference{} it: {}; stored secrets keep working, the service backing is gone",
            if refs.len() == 1 { "" } else { "s" },
            if refs.len() == 1 { "s" } else { "" },
            terminal_safe(&refs.join(", "))
        );
    }
    println!("service '{}' removed", terminal_safe(&args.id));
    Ok(())
}
