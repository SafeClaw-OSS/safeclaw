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
/// `secrets` should be the full vault JSON when unlocked, or a minimal
/// `{"services": {"name": null, ...}}` when locked.

pub fn generate_safeclaw_md(secrets: &serde_json::Value, locked: bool, proxy_port: u16, console_url: &str) -> String {
    let template = read_template("safeclaw.md", include_str!("../../templates/safeclaw.md"));
    let proxy_base = format!("http://localhost:{}", proxy_port);

    // Collect connected service IDs
    let connected: std::collections::HashSet<String> = secrets
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
    if let Some(services) = secrets.get("services").and_then(|s| s.as_object()) {
        for (name, svc) in services {
            // Skip internal services — check both vault data and service.toml
            let has_upstream = crate::service::is_proxy_service(svc)
                || registry.get(name).and_then(|d| d.upstream.as_ref()).is_some();
            if !has_upstream {
                continue;
            }
            let proxy_url = format!("{}/{}/", proxy_base, name);
            let upstream = if locked || svc.is_null() { "-".to_string() } else {
                svc.get("upstream").and_then(|u| u.as_str())
                    .or_else(|| registry.get(name).and_then(|d| d.upstream.as_ref()).and_then(|u| u.url.as_deref()))
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

    template
        .replace("{{PROXY_BASE}}", &proxy_base)
        .replace("{{CONSOLE_URL}}", console_url)
        .replace("{{SERVICE_TABLE}}", &rows.join("\n"))
        .replace("{{AVAILABLE_SERVICES}}", &available_section)
}

/// Return the static AGENTS.md snippet (managed block).
///
/// This is now fully static — dynamic service info lives in safeclaw.md.
pub fn generate_agents_md_snippet(_secrets: &serde_json::Value, _proxy_port: u16) -> String {
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

    fn two_service_secrets() -> serde_json::Value {
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
        let s = generate_safeclaw_md(&two_service_secrets(), false, 23295, "https://example.com/console");
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
        let s = generate_safeclaw_md(&two_service_secrets(), false, 23295, "https://example.com/console");
        // gmail has write:ask-always, read:ask
        assert!(s.contains("write:ask-always, read:ask"));
    }

    #[test]
    fn safeclaw_md_level_display_same() {
        let s = generate_safeclaw_md(&two_service_secrets(), false, 23295, "https://example.com/console");
        // anthropic has write:allow, read:allow → just "allow"
        assert!(s.contains("| allow |"));
    }

    #[test]
    fn agents_snippet_is_static() {
        let s1 = generate_agents_md_snippet(&two_service_secrets(), 23295);
        let names = json!({ "services": { "anthropic": null } });
        let s2 = generate_agents_md_snippet(&names, 23295);
        // Snippet is now fully static — same output regardless of input
        assert_eq!(s1, s2);
        assert!(s1.contains("SafeClaw"));
        assert!(s1.contains("safeclaw.md"));
        assert!(s1.contains("SAFECLAW:BEGIN"));
    }
}
