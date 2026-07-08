//! `sc service validate <path>` — run the static service-definition safety
//! validator offline (no daemon). Mirrors exactly what the console's custom-TOML
//! upload editor will enforce, so authors can check a service.toml before
//! submitting it.

use crate::cli::active::resolve_active;
use crate::cli::conn::{insert_custom_service, remove_custom_service};
use crate::cli::secret::{do_unlock, seal_and_submit_write};
use crate::cli::webauthn::fetch_passkey_meta;
use crate::config::{ServiceAddArgs, ServiceLsArgs, ServiceRmArgs, ServiceValidateArgs};
use crate::service::validate::validate_recipe;
use crate::service::ServiceDef;

pub async fn run_validate(args: ServiceValidateArgs) -> Result<(), String> {
    let path = &args.path;
    let toml_str = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

    match validate_recipe(&toml_str, args.first_party) {
        Ok(()) => {
            let mode = if args.first_party {
                " (first-party: exec allowed)"
            } else {
                ""
            };
            println!("✓ {} — valid{}", path.display(), mode);
            Ok(())
        }
        Err(problems) => {
            eprintln!(
                "✗ {} — {} problem{}:",
                path.display(),
                problems.len(),
                if problems.len() == 1 { "" } else { "s" }
            );
            for p in &problems {
                eprintln!("  • {}", p);
            }
            // Non-zero exit via the Err path (main prints + boxes it).
            Err(format!("{}: service validation failed", path.display()))
        }
    }
}

/// `sc service add <file.toml>` — validate a v4 definition, then store it in the
/// active vault's `aux.services` (keyed by the service id). The daemon
/// re-validates at unlock (v4 schema, no tool-named sections, never shadow a
/// built-in) before it can broker — this is the authoring gate.
pub async fn run_add(args: ServiceAddArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    let toml_str = std::fs::read_to_string(&args.path)
        .map_err(|e| format!("cannot read {}: {}", args.path.display(), e))?;

    // Full v4 schema check up front — the same validator the daemon re-runs
    // at unlock.
    if let Err(problems) = validate_recipe(&toml_str, false) {
        eprintln!(
            "✗ {} — {} problem{}:",
            args.path.display(),
            problems.len(),
            if problems.len() == 1 { "" } else { "s" }
        );
        for p in &problems {
            eprintln!("  • {}", p);
        }
        return Err(format!("{}: service validation failed", args.path.display()));
    }

    // The service id keys the aux.services map.
    let def: ServiceDef = toml::from_str(&toml_str).map_err(|e| format!("parse: {}", e))?;
    let id = def.service.id.clone();

    eprintln!("safeclaw service add {} — two passkey gestures (unlock + write)", id);
    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, mut aux, user_key) =
        do_unlock(&custodian, &vault, &meta, args.no_browser, args.timeout, args.cb_port).await?;

    insert_custom_service(&mut aux, &id, &toml_str);
    seal_and_submit_write(&custodian, &vault, &meta, &user_key, &kv, &aux, args.no_browser, args.timeout, args.cb_port).await?;
    eprintln!("safeclaw service add — '{}' stored (validated at unlock before it can broker)", id);
    Ok(())
}

/// The connection ids (from `aux.connections` and in-flight `aux.connecting`)
/// whose `service` field references `service_id`.
fn connections_referencing(aux: &serde_json::Value, service_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["connections", "connecting"] {
        let Some(map) = aux.get(key).and_then(|v| v.as_object()) else { continue };
        for (conn_id, entry) in map {
            if entry.get("service").and_then(|s| s.as_str()) == Some(service_id)
                && !out.contains(conn_id)
            {
                out.push(conn_id.clone());
            }
        }
    }
    out
}

/// `sc service ls` — list `aux.services` with each definition's validation
/// status. The daemon silently SKIPS an invalid definition at unlock (its
/// connections stay stuck "connecting"), and the console only shows a
/// definition through its connections — so a broken or orphaned def is
/// invisible everywhere but here. One passkey gesture (unlock, read-only).
pub async fn run_ls(args: ServiceLsArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    eprintln!("safeclaw service ls — one passkey gesture (unlock, read-only)");
    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (_kv, aux, _user_key) =
        do_unlock(&custodian, &vault, &meta, args.no_browser, args.timeout, args.cb_port).await?;

    let Some(svcs) = aux.get("services").and_then(|v| v.as_object()).filter(|m| !m.is_empty())
    else {
        println!("(no custom service definitions in this vault)");
        return Ok(());
    };

    for (id, src) in svcs {
        let Some(toml_src) = src.as_str() else {
            println!("✗ {} — not a TOML string (corrupt entry)", id);
            continue;
        };
        let conns = connections_referencing(&aux, id);
        let used = if conns.is_empty() {
            "no connections".to_string()
        } else {
            format!("connections: {}", conns.join(", "))
        };
        match validate_recipe(toml_src, false) {
            Ok(()) => println!("✓ {} — valid ({})", id, used),
            Err(problems) => {
                println!("✗ {} — INVALID, the daemon skips it ({})", id, used);
                for p in &problems {
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
/// `aux.services`. Connections referencing it are WARNED about but kept: their
/// stored secrets stay resolvable; only the service backing (catalog card,
/// OAuth wiring) goes away. Two passkey gestures (unlock + write).
pub async fn run_rm(args: ServiceRmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    eprintln!(
        "safeclaw service rm {} — two passkey gestures (unlock + write)",
        args.id
    );
    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, mut aux, user_key) =
        do_unlock(&custodian, &vault, &meta, args.no_browser, args.timeout, args.cb_port).await?;

    let refs = connections_referencing(&aux, &args.id);
    if !remove_custom_service(&mut aux, &args.id) {
        return Err(format!(
            "no custom service '{}' in this vault (see `sc service ls`)",
            args.id
        ));
    }
    if !refs.is_empty() {
        eprintln!(
            "warning: connection{} still reference{} it: {} — stored secrets keep working, the service backing is gone",
            if refs.len() == 1 { "" } else { "s" },
            if refs.len() == 1 { "s" } else { "" },
            refs.join(", ")
        );
    }
    seal_and_submit_write(&custodian, &vault, &meta, &user_key, &kv, &aux, args.no_browser, args.timeout, args.cb_port).await?;
    eprintln!("safeclaw service rm — '{}' deleted", args.id);
    Ok(())
}
