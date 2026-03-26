/// Workspace file generation: safeclaw.md and AGENTS.md snippets.

/// Generate safeclaw.md content describing all services and their proxy URLs.
///
/// When `locked` is true, auth/level details are omitted (only names shown).
/// `secrets` should be the full vault JSON when unlocked, or a minimal
/// `{"services": {"name": null, ...}}` when locked.
pub fn generate_safeclaw_md(secrets: &serde_json::Value, locked: bool, proxy_port: u16) -> String {
    let proxy_base = format!("http://localhost:{}", proxy_port);
    let mut lines = vec![
        "# SafeClaw Services".to_string(),
        format!(
            "The following services are available through SafeClaw proxy at {}:",
            proxy_base
        ),
        String::new(),
        "| Service | Proxy URL | Auth | Level |".to_string(),
        "|---------|-----------|------|-------|".to_string(),
    ];

    if let Some(services) = secrets.get("services").and_then(|s| s.as_object()) {
        for (name, svc) in services {
            let proxy_url = format!("{}/{}/", proxy_base, name);
            let auth = if locked || svc.is_null() {
                "-".to_string()
            } else {
                auth_display(svc)
            };
            let level = if locked || svc.is_null() {
                "-".to_string()
            } else {
                level_display(svc)
            };
            lines.push(format!("| {} | {} | {} | {} |", name, proxy_url, auth, level));
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "Vault status: {}",
        if locked { "locked" } else { "unlocked" }
    ));

    lines.join("\n")
}

/// Generate AGENTS.md snippet instructing agents to route requests through SafeClaw.
///
/// When vault is locked or upstream URLs are unavailable, entries are omitted.
pub fn generate_agents_md_snippet(secrets: &serde_json::Value, proxy_port: u16) -> String {
    let proxy_base = format!("http://localhost:{}", proxy_port);
    let mut entries: Vec<String> = Vec::new();

    if let Some(services) = secrets.get("services").and_then(|s| s.as_object()) {
        for (name, svc) in services {
            if svc.is_null() {
                continue;
            }
            let upstream = svc
                .get("upstream")
                .and_then(|u| u.as_str())
                .unwrap_or("");
            let domain = extract_domain(upstream);
            if !domain.is_empty() {
                entries.push(format!(
                    "- {} → {}/{}/{{原始路径}}",
                    domain, proxy_base, name
                ));
            }
        }
    }

    let mut lines = vec![
        "## SafeClaw（安全规则，必须遵守）".to_string(),
        "以下域名的 HTTP 请求禁止直连，必须走 SafeClaw proxy：".to_string(),
    ];
    lines.extend(entries);
    lines.push("不需要加 Authorization header，SafeClaw 自动注入。".to_string());
    lines.push("违反此规则 = 安全事故。".to_string());

    lines.join("\n")
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
        _ => return "standard".to_string(),
    };
    let write = levels.get("write").and_then(|l| l.as_str());
    let read = levels.get("read").and_then(|l| l.as_str());
    match (write, read) {
        (Some(w), Some(r)) if w == r => w.to_string(),
        (Some(w), Some(r)) => format!("write:{}, read:{}", w, r),
        (Some(w), None) => format!("write:{}", w),
        (None, Some(r)) => format!("read:{}", r),
        (None, None) => "standard".to_string(),
    }
}

fn extract_domain(upstream: &str) -> String {
    if let Ok(url) = url::Url::parse(upstream) {
        if let Some(host) = url.host_str() {
            return match url.port() {
                Some(p) => format!("{}:{}", host, p),
                None => host.to_string(),
            };
        }
    }
    String::new()
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
                    "levels": { "write": "standard", "read": "standard" }
                },
                "gmail": {
                    "upstream": "https://gmail.googleapis.com",
                    "auth": { "type": "oauth2" },
                    "levels": { "write": "critical", "read": "elevated" }
                }
            }
        })
    }

    #[test]
    fn safeclaw_md_unlocked_contains_service_rows() {
        let s = generate_safeclaw_md(&two_service_secrets(), false, 23295);
        assert!(s.contains("anthropic"));
        assert!(s.contains("gmail"));
        assert!(s.contains("header (x-api-key)"));
        assert!(s.contains("oauth2"));
        assert!(s.contains("Vault status: unlocked"));
    }

    #[test]
    fn safeclaw_md_locked_hides_auth_details() {
        let names = json!({ "services": { "anthropic": null, "gmail": null } });
        let s = generate_safeclaw_md(&names, true, 23295);
        assert!(s.contains("anthropic"));
        assert!(s.contains("gmail"));
        assert!(!s.contains("header"));
        assert!(s.contains("Vault status: locked"));
    }

    #[test]
    fn safeclaw_md_level_display_mixed() {
        let s = generate_safeclaw_md(&two_service_secrets(), false, 23295);
        // gmail has write:critical, read:elevated
        assert!(s.contains("write:critical, read:elevated"));
    }

    #[test]
    fn safeclaw_md_level_display_same() {
        let s = generate_safeclaw_md(&two_service_secrets(), false, 23295);
        // anthropic has write:standard, read:standard → just "standard"
        assert!(s.contains("standard"));
    }

    #[test]
    fn agents_snippet_contains_domains() {
        let s = generate_agents_md_snippet(&two_service_secrets(), 23295);
        assert!(s.contains("api.anthropic.com"));
        assert!(s.contains("gmail.googleapis.com"));
        assert!(s.contains("http://localhost:23295/anthropic/"));
        assert!(s.contains("SafeClaw"));
    }

    #[test]
    fn agents_snippet_locked_shows_no_domains() {
        let names = json!({ "services": { "anthropic": null } });
        let s = generate_agents_md_snippet(&names, 23295);
        // No upstream → no domain entries, but header/footer still present
        assert!(s.contains("SafeClaw"));
        assert!(!s.contains("api.anthropic.com"));
    }

    #[test]
    fn extract_domain_strips_path() {
        assert_eq!(extract_domain("https://api.openai.com/v1"), "api.openai.com");
        assert_eq!(
            extract_domain("https://example.com:8443/path"),
            "example.com:8443"
        );
        assert_eq!(extract_domain("not-a-url"), "");
    }
}
