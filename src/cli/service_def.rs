//! `sc service validate <path>` — run the static service-definition safety
//! validator offline (no daemon). Mirrors exactly what the console's custom-TOML
//! upload editor will enforce, so authors can check a service.toml before
//! submitting it.

use crate::cli::active::resolve_active;
use crate::cli::conn::insert_custom_service;
use crate::cli::secret::{do_unlock, seal_and_submit_write};
use crate::cli::webauthn::fetch_passkey_meta;
use crate::config::{ServiceAddArgs, ServiceValidateArgs};
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
