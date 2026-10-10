//! `sc registry` (public service catalog, rendered OFFLINE from the
//! compiled-in services — no daemon needed). Daemon lifecycle (up / down /
//! restart / logs / serve) lives in `service` + `up`; vault/daemon status in
//! `status`.

/// `sc registry` — render the static service catalog from the compiled-in
/// services, no running daemon. This is the exact shape `GET /registry` serves;
/// CI runs `sc registry --json` to publish the catalog artifact the console
/// reads. Offline by construction (`ServiceRegistry::compiled_only()`).
pub fn registry(json: bool) -> Result<(), String> {
    let reg = crate::service::ServiceRegistry::compiled_only();
    // include_policy_rules = true: this catalog is the SSoT the CONSOLE reads
    // (CI publishes it as registry.json) and the policy panel needs each
    // service's per-action rules. The agent-facing `GET /registry` still omits
    // them by default (lean); only this published artifact opts in.
    let catalog = crate::server::handlers::registry::render_catalog(&reg, true, None, false)
        .map_err(|e| e.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&catalog).map_err(|e| e.to_string())?
        );
    } else {
        println!("{:<24} {:<30} TAGS", "ID", "NAME");
        for s in &catalog.services {
            println!("{:<24} {:<30} {}", s.id, s.name, s.tags.join(","));
        }
    }
    Ok(())
}
