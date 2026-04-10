/// Workspace file generation: safeclaw.md and AGENTS.md snippets.

/// Read a template file at runtime from `$SAFECLAW_DATA/templates/`.
/// Falls back to the compile-time embedded version if the file isn't found.
pub fn read_template(name: &str, fallback: &str) -> String {
    if let Ok(data) = std::env::var("SAFECLAW_DATA") {
        let path = format!("{}/templates/{}", data, name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            return content;
        }
    }
    fallback.to_string()
}

/// Load the service catalog from services/*/service.toml.
/// Returns the set of known service IDs and their display names.
fn load_catalog() -> Vec<(String, String)> {
    let registry = crate::service::ServiceRegistry::load();
    let mut out: Vec<(String, String)> = registry.all()
        .iter()
        .map(|(id, def)| (id.clone(), def.service.name.clone()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Generate safeclaw.md content describing all services and their proxy URLs.
///
/// When `locked` is true, auth/level details are omitted (only names shown).
/// `vault_data` should be the full vault JSON when unlocked, or a minimal
/// `{"services": {"name": null, ...}}` when locked.

pub fn generate_safeclaw_md(vault_data: &serde_json::Value, locked: bool, proxy_port: u16, console_url: &str) -> String {
    let template = read_template("safeclaw.md", include_str!("../../templates/safeclaw.md"));
    let proxy_base = format!("http://localhost:{}", proxy_port);

    // Collect connected service IDs
    let connected: std::collections::HashSet<String> = vault_data
        .get("services")
        .and_then(|s| s.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    // Build service table rows
    let registry = crate::service::ServiceRegistry::load();
    let mut rows = vec![
        "| Service | Upstream | Proxy URL | Auth | Approval |".to_string(),
        "|---------|----------|-----------|------|----------|".to_string(),
    ];
    if let Some(services) = vault_data.get("services").and_then(|s| s.as_object()) {
        for (name, svc) in services {
            // Skip services not callable by the agent (no [[upstream]] or [[api]])
            if !crate::service::is_proxy_service(svc) && !registry.is_agent_visible(name) {
                continue;
            }
            let proxy_url = format!("{}/{}/", proxy_base, name);
            let upstream = if locked || svc.is_null() { "-".to_string() } else {
                svc.get("upstream").and_then(|u| u.as_str())
                    .or_else(|| registry.get(name).and_then(|d| d.upstream_url()))
                    .unwrap_or("local").to_string()
            };
            let auth = if locked || svc.is_null() { "-".to_string() } else { auth_display(svc) };
            let level = if locked || svc.is_null() { "-".to_string() } else { level_display(svc) };
            rows.push(format!("| {} | {} | {} | {} | {} |", name, upstream, proxy_url, auth, level));
        }
    }

    // Build available-but-not-connected guidance from catalog
    let catalog = load_catalog();
    let not_connected: Vec<&(String, String)> = catalog
        .iter()
        .filter(|(id, _)| !connected.contains(id))
        .collect();
    let available_section = if not_connected.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = not_connected.iter().map(|(_, name)| name.clone()).collect();
        format!(
            "**Need a service that's not connected?** SafeClaw also supports: {}. \
             Tell the user to connect it in the SafeClaw console (URL above) — \
             do not configure API keys or credentials yourself.",
            names.join(", ")
        )
    };

    // Build help sections from service.toml `help` field for each connected service.
    // Template variables like {{wallet.safe}} are resolved from vault service data.
    let mut guidance_sections = vec![];
    let vault_services = vault_data.get("services").and_then(|s| s.as_object());
    // Vault-connected services
    if let Some(services) = vault_services {
        for (name, svc_data) in services {
            let svc_def = registry.get(name);
            let help = svc_def.and_then(|d| d.service.help.as_deref());
            if let Some(help) = help {
                let display_name = svc_def.map(|d| d.service.name.as_str()).unwrap_or(name);
                let resolved = resolve_guidance_templates(help, svc_data);
                guidance_sections.push(format!("## {}\n\n{}", display_name, resolved));
            }
        }
    }
    // System services with help (not in vault, always available)
    for (id, def) in registry.all() {
        if def.service.help.is_some()
            && def.service.category == "system"
            && !vault_services.map_or(false, |s| s.contains_key(id.as_str()))
        {
            let help = def.service.help.as_deref().unwrap();
            guidance_sections.push(format!("## {}\n\n{}", def.service.name, help));
        }
    }
    let guidance_text = guidance_sections.join("\n\n");

    template
        .replace("{{PROXY_BASE}}", &proxy_base)
        .replace("{{CONSOLE_URL}}", console_url)
        .replace("{{SERVICE_TABLE}}", &rows.join("\n"))
        .replace("{{AVAILABLE_SERVICES}}", &available_section)
        .replace("{{GUIDANCE_SECTIONS}}", &guidance_text)
}

/// Resolve `{{wallet.*}}` and other template variables in guidance text
/// from vault service data (the JSON stored per-service in vault.enc).
fn resolve_guidance_templates(template: &str, svc_data: &serde_json::Value) -> String {
    let mut result = template.to_string();
    // {{wallet.*}} — e.g. {{wallet.safe}}, {{wallet.chains}}
    while let Some(start) = result.find("{{wallet.") {
        let Some(end) = result[start..].find("}}") else { break };
        let key = &result[start + 9..start + end]; // after "{{wallet." before "}}"
        let value = svc_data
            .get("wallet")
            .and_then(|w| w.get(key))
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| "unknown".to_string());
        result = format!("{}{}{}", &result[..start], value, &result[start + end + 2..]);
    }
    result
}

/// Return the static AGENTS.md snippet (managed block).
///
/// This is now fully static — dynamic service info lives in safeclaw.md.
pub fn generate_agents_md_snippet(_vault_data: &serde_json::Value, _proxy_port: u16) -> String {
    read_template("agents-snippet.md", include_str!("../../templates/agents-snippet.md"))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn auth_display(svc: &serde_json::Value) -> String {
    let auth = match svc.get("auth") {
        Some(a) if !a.is_null() => a,
        _ => return "none".to_string(),
    };
    let auth_type = auth
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");
    match auth_type {
        "header" => {
            let name = auth
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            format!("header ({})", name)
        }
        "query" => {
            let name = auth
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            format!("query ({})", name)
        }
        other => other.to_string(),
    }
}

fn level_display(svc: &serde_json::Value) -> String {
    let levels = match svc.get("levels") {
        Some(l) if !l.is_null() => l,
        _ => return "ask-always".to_string(),
    };
    let write = levels.get("write").and_then(|l| l.as_str());
    let read = levels.get("read").and_then(|l| l.as_str());
    match (write, read) {
        (Some(w), Some(r)) if w == r => w.to_string(),
        (Some(w), Some(r)) => format!("write:{}, read:{}", w, r),
        (Some(w), None) => format!("write:{}", w),
        (None, Some(r)) => format!("read:{}", r),
        (None, None) => "ask-always".to_string(),
    }
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn two_service_vault_data() -> serde_json::Value {
        json!({
            "services": {
                "anthropic": {
                    "upstream": "https://api.anthropic.com",
                    "auth": { "type": "header", "name": "x-api-key", "secret": "sk-test" },
                    "levels": { "write": "allow", "read": "allow" }
                },
                "gmail": {
                    "upstream": "https://gmail.googleapis.com",
                    "auth": { "type": "oauth2" },
                    "levels": { "write": "ask-always", "read": "ask" }
                }
            }
        })
    }

    #[test]
    fn safeclaw_md_unlocked_contains_service_rows() {
        let s = generate_safeclaw_md(&two_service_vault_data(), false, 23295, "https://example.com/console");
        assert!(s.contains("anthropic"));
        assert!(s.contains("gmail"));
        assert!(s.contains("header (x-api-key)"));
        assert!(s.contains("oauth2"));
    }

    #[test]
    fn safeclaw_md_locked_hides_auth_details() {
        let names = json!({ "services": { "anthropic": null, "gmail": null } });
        let s = generate_safeclaw_md(&names, true, 23295, "https://example.com/console");
        assert!(s.contains("anthropic"));
        assert!(s.contains("gmail"));
        assert!(!s.contains("header ("));
    }

    #[test]
    fn safeclaw_md_level_display_mixed() {
        let s = generate_safeclaw_md(&two_service_vault_data(), false, 23295, "https://example.com/console");
        // gmail has write:ask-always, read:ask
        assert!(s.contains("write:ask-always, read:ask"));
    }

    #[test]
    fn safeclaw_md_level_display_same() {
        let s = generate_safeclaw_md(&two_service_vault_data(), false, 23295, "https://example.com/console");
        // anthropic has write:allow, read:allow → just "allow"
        assert!(s.contains("| allow |"));
    }

    #[test]
    fn resolve_guidance_templates_replaces_wallet_fields() {
        let svc_data = json!({
            "wallet": { "safe": "0xABC123", "chains": ["sepolia", "base"] }
        });
        let result = resolve_guidance_templates("Address: {{wallet.safe}}, chains: {{wallet.chains}}", &svc_data);
        assert!(result.contains("0xABC123"), "safe not resolved: {}", result);
        assert!(result.contains("sepolia"), "chains not resolved: {}", result);
        assert!(!result.contains("{{"), "unresolved template: {}", result);
    }

    #[test]
    fn resolve_guidance_templates_missing_field() {
        let svc_data = json!({});
        let result = resolve_guidance_templates("Safe: {{wallet.safe}}", &svc_data);
        assert_eq!(result, "Safe: unknown");
    }

    #[test]
    fn agents_snippet_is_static() {
        let s1 = generate_agents_md_snippet(&two_service_vault_data(), 23295);
        let names = json!({ "services": { "anthropic": null } });
        let s2 = generate_agents_md_snippet(&names, 23295);
        // Snippet is now fully static — same output regardless of input
        assert_eq!(s1, s2);
        assert!(s1.contains("SafeClaw"));
        assert!(s1.contains("safeclaw.md"));
        assert!(s1.contains("SAFECLAW:BEGIN"));
    }
}
