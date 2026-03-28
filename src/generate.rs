/// Workspace file generation: safeclaw.md and AGENTS.md snippets.

/// Generate safeclaw.md content describing all services and their proxy URLs.
///
/// When `locked` is true, auth/level details are omitted (only names shown).
/// `secrets` should be the full vault JSON when unlocked, or a minimal
/// `{"services": {"name": null, ...}}` when locked.
pub fn generate_safeclaw_md(secrets: &serde_json::Value, locked: bool, proxy_port: u16) -> String {
    let proxy_base = format!("http://localhost:{}", proxy_port);
    let mut lines = vec![
        "<!-- SAFECLAW:GENERATED FILE - DO NOT EDIT. Changes may be overwritten by SafeClaw sync. -->".to_string(),
        "# SafeClaw Services".to_string(),
        format!(
            "Route API calls through the SafeClaw proxy at `{}`. Do NOT call upstream APIs directly.",
            proxy_base
        ),
        String::new(),
        "## Usage".to_string(),
        "Replace the upstream base URL with the proxy URL. Do NOT add Authorization headers.".to_string(),
        "SafeClaw auto-injects credentials (API key / OAuth2 token) before forwarding.".to_string(),
        String::new(),
        "## Service Table".to_string(),
        "| Service | Upstream | Proxy URL | Auth | Approval Level |".to_string(),
        "|---------|----------|-----------|------|----------------|".to_string(),
    ];

    if let Some(services) = secrets.get("services").and_then(|s| s.as_object()) {
        for (name, svc) in services {
            let proxy_url = format!("{}/{}/", proxy_base, name);
            let upstream = if locked || svc.is_null() {
                "-".to_string()
            } else {
                svc.get("upstream")
                    .and_then(|u| u.as_str())
                    .unwrap_or("-")
                    .to_string()
            };
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
            lines.push(format!("| {} | {} | {} | {} | {} |", name, upstream, proxy_url, auth, level));
        }
    }

    lines.push(String::new());
    lines.push("## Example".to_string());
    lines.push(format!(
        "```\n# Call OpenAI via proxy (no Authorization header needed):\ncurl -X POST {proxy_base}/openai/v1/chat/completions \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"model\":\"gpt-4o\",\"messages\":[...]}}'\n\n# Call Gmail via proxy:\ncurl {proxy_base}/gmail/gmail/v1/users/me/messages\n```"
    ));
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
                // Strip trailing slash for clean URL example
                let upstream_clean = upstream.trim_end_matches('/');
                entries.push(format!(
                    "- **{name}**: replace `{upstream_clean}` with `{proxy_base}/{name}` — e.g. `{proxy_base}/{name}/some/api/path`"
                ));
            }
        }
    }

    let mut lines = vec![
        "<!-- SAFECLAW:BEGIN - managed block. Changes inside this block may be overwritten by SafeClaw sync. -->".to_string(),
        "## SafeClaw Proxy (MANDATORY security rules)".to_string(),
        String::new(),
        "All HTTP requests to the following services MUST go through the SafeClaw proxy.".to_string(),
        "Direct calls to these APIs are forbidden.".to_string(),
        String::new(),
        "### How to use".to_string(),
        "1. Replace the upstream base URL with the proxy URL shown below.".to_string(),
        "2. Do NOT add an Authorization header — SafeClaw injects credentials automatically.".to_string(),
        "3. Keep the original API path and query parameters unchanged.".to_string(),
        String::new(),
        "### Services".to_string(),
    ];
    lines.extend(entries);
    lines.push(String::new());
    lines.push("### Example".to_string());
    lines.push(format!(
        "```\n# Wrong (direct call — FORBIDDEN):\ncurl https://api.openai.com/v1/chat/completions ...\n\n# Correct (via SafeClaw proxy):\ncurl {proxy_base}/openai/v1/chat/completions ...\n# (no Authorization header needed)\n```"
    ));
    lines.push(String::new());
    lines.push("Violating these rules is a security incident.".to_string());
    lines.push(String::new());
    lines.push("### Approval Required (HTTP 202)".to_string());
    lines.push(String::new());
    lines.push("Some operations require human approval. When the proxy returns HTTP 202:".to_string());
    lines.push(String::new());
    lines.push("```json".to_string());
    lines.push(r#"{"id":"<uuid>","safeclaw_approve_url":"https://...","expires_at":1711548300}"#.to_string());
    lines.push("```".to_string());
    lines.push(String::new());
    lines.push("**Do this:**".to_string());
    lines.push("1. Tell the user what you were doing and share the approval URL (use inline button if supported).".to_string());
    lines.push("2. Poll `GET <proxy>/approve/<id>` every 5 seconds.".to_string());
    lines.push("3. On `{\"status\":\"approved\",\"response\":{...}}` — use `response.body` as the upstream API result and continue.".to_string());
    lines.push("4. On `{\"status\":\"rejected\"}` — tell the user the action was blocked.".to_string());
    lines.push("5. On `{\"status\":\"expired\"}` or 404 — tell the user the window expired, ask to retry.".to_string());
    lines.push(String::new());
    lines.push(format!("Poll URL: `{proxy_base}/approve/<id>`"));
    lines.push(String::new());
    lines.push("<!-- SAFECLAW:END -->".to_string());

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
        assert!(!s.contains("header ("));
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
