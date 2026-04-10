/// Policy engine: access levels, rules, and evaluation logic.
///
/// Rule matching uses standard regex (Rust `regex` crate, RE2 semantics).
/// - `match_pattern`: matched against `"METHOD /path"` (e.g. `"POST /v1/chat/completions"`)
/// - `body_pattern`: matched against the request body text (optional)
use serde::{Deserialize, Serialize};
use regex::Regex;

// ── Access Level ───────────────────────────────────────────────────────────────

/// Controls whether a proxy request requires human approval.
///
/// - `Allow`: pass through immediately, no approval needed
/// - `Ask`: require human approval once, then cache the session (TTL-based)
/// - `AskAlways`: require human approval for every request, never cache
/// - `Deny`: block unconditionally (used as default for unconfigured services)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessLevel {
    Allow,
    Ask,
    AskAlways,
    Deny,
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessLevel::Allow => write!(f, "allow"),
            AccessLevel::Ask => write!(f, "ask"),
            AccessLevel::AskAlways => write!(f, "ask-always"),
            AccessLevel::Deny => write!(f, "deny"),
        }
    }
}

// ── Policy Types ───────────────────────────────────────────────────────────────

/// Per-request policy rule. Matched against `"METHOD /path"` and optionally
/// the request body, using standard regex (RE2 semantics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique identifier (e.g. "send-email"). Used as key for vault overrides.
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable label for console UI (e.g. "Send email").
    #[serde(default)]
    pub label: Option<String>,
    /// Regex matched against `"METHOD /path"` (e.g. `"POST /gmail/v1/users/me/messages/send"`).
    /// Omit to match all requests.
    #[serde(default, rename = "match")]
    pub match_pattern: Option<String>,
    /// Regex matched against request body text. Omit to skip body matching.
    #[serde(default, rename = "body")]
    pub body_pattern: Option<String>,
    pub level: AccessLevel,
    /// Session TTL in seconds (for `ask` level; cached after first approval)
    #[serde(default, rename = "sessionTTL")]
    pub session_ttl: Option<u64>,
}

/// Per-service read/write access levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevels {
    pub write: Option<AccessLevel>,
    pub read: Option<AccessLevel>,
}

/// Global policy defaults (stored in vault.enc under "policy_defaults")
///
/// Note: `unknown_domain` was removed. The proxy enforces domain allowlisting
/// by construction — upstream URLs are derived from `service_config.upstream`,
/// and unconfigured services return 403 UNKNOWN_SERVICE. Agents cannot target
/// arbitrary domains through the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Approval timeout in seconds (default 300)
    pub timeout: Option<u64>,
    pub levels: Option<ServiceLevels>,
    /// Per-category defaults (e.g. "llm", "service", "channel").
    /// Takes priority over `levels` when the service's category matches.
    #[serde(default)]
    pub type_levels: Option<std::collections::HashMap<String, ServiceLevels>>,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        let mut type_levels = std::collections::HashMap::new();
        type_levels.insert("llm".into(), ServiceLevels {
            write: Some(AccessLevel::Allow),
            read: Some(AccessLevel::Allow),
        });
        type_levels.insert("channel".into(), ServiceLevels {
            write: Some(AccessLevel::Allow),
            read: Some(AccessLevel::Allow),
        });
        Self {
            timeout: Some(300),
            levels: Some(ServiceLevels {
                write: Some(AccessLevel::AskAlways),
                read: Some(AccessLevel::AskAlways),
            }),
            type_levels: Some(type_levels),
        }
    }
}

// ── Policy Evaluation ──────────────────────────────────────────────────────────

/// Determine the access level for a given request.
/// Priority: service rules > service levels > type defaults > global defaults > fallback
pub fn evaluate_policy(
    method: &str,
    path: &str,
    body: Option<&str>,
    rules: Option<&Vec<PolicyRule>>,
    service_levels: Option<&ServiceLevels>,
    defaults: &PolicyDefaults,
    service_category: Option<&str>,
) -> AccessLevel {
    // 1. Check service rules (most specific)
    if let Some(rules) = rules {
        for rule in rules {
            if matches_rule(rule, method, path, body) {
                return rule.level.clone();
            }
        }
    }

    // 2. Check service-level access levels
    if let Some(levels) = service_levels {
        let level = if is_write_method(method) {
            &levels.write
        } else {
            &levels.read
        };
        if let Some(l) = level {
            return l.clone();
        }
    }

    // 3. Check type-level defaults (e.g. "llm" → allow)
    if let (Some(cat), Some(ref type_levels)) = (service_category, &defaults.type_levels) {
        if let Some(type_def) = type_levels.get(cat) {
            let level = if is_write_method(method) {
                &type_def.write
            } else {
                &type_def.read
            };
            if let Some(l) = level {
                return l.clone();
            }
        }
    }

    // 4. Fall back to global policy defaults
    if let Some(ref def_levels) = defaults.levels {
        let level = if is_write_method(method) {
            &def_levels.write
        } else {
            &def_levels.read
        };
        if let Some(l) = level {
            return l.clone();
        }
    }

    // 5. Default: ask-always (safe default — require approval for every request)
    AccessLevel::AskAlways
}

fn is_write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn matches_rule(rule: &PolicyRule, method: &str, path: &str, body: Option<&str>) -> bool {
    // Match against "METHOD /path" using regex
    if let Some(ref pattern) = rule.match_pattern {
        let path_no_query = path.split('?').next().unwrap_or(path);
        let input = format!("{} {}", method, path_no_query);
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(&input) {
                    return false;
                }
            }
            Err(e) => {
                tracing::warn!("Invalid match regex '{}': {}", pattern, e);
                return false;
            }
        }
    }
    // Match against body using regex
    if let Some(ref pattern) = rule.body_pattern {
        let body_text = body.unwrap_or("");
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(body_text) {
                    return false;
                }
            }
            Err(e) => {
                tracing::warn!("Invalid body regex '{}': {}", pattern, e);
                return false;
            }
        }
    }
    true
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> PolicyDefaults {
        PolicyDefaults::default()
    }

    fn rule(match_pat: &str) -> PolicyRule {
        PolicyRule {
            id: None,
            label: None,
            match_pattern: Some(match_pat.to_string()),
            body_pattern: None,
            level: AccessLevel::AskAlways,
            session_ttl: None,
        }
    }

    #[test]
    fn default_no_category_is_ask_always() {
        let level = evaluate_policy("GET", "/foo", None, None, None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn llm_category_is_allow() {
        let level = evaluate_policy("POST", "/v1/chat/completions", None, None, None, &defaults(), Some("llm"));
        assert_eq!(level, AccessLevel::Allow);
    }

    #[test]
    fn write_method_ask_via_service_levels() {
        let levels = ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: Some(AccessLevel::Allow),
        };
        let level = evaluate_policy("POST", "/create", None, None, Some(&levels), &defaults(), None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn service_levels_override_type_defaults() {
        let levels = ServiceLevels {
            write: Some(AccessLevel::AskAlways),
            read: None,
        };
        let level = evaluate_policy("POST", "/foo", None, None, Some(&levels), &defaults(), Some("llm"));
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn rule_takes_priority_over_service_levels() {
        let mut r = rule("DELETE /api/admin");
        r.level = AccessLevel::AskAlways;
        let rules = vec![r];
        let levels = ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: None,
        };
        let level = evaluate_policy(
            "DELETE",
            "/api/admin",
            None,
            Some(&rules),
            Some(&levels),
            &defaults(),
            None,
        );
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn rule_method_mismatch_falls_through() {
        let rules = vec![rule("DELETE /.*")];
        let level = evaluate_policy("GET", "/foo", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways); // falls to global default
    }

    #[test]
    fn global_defaults_apply_when_no_service_levels() {
        let mut def = defaults();
        def.levels = Some(ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: None,
        });
        let level = evaluate_policy("POST", "/x", None, None, None, &def, None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn regex_wildcard_path() {
        let mut r = rule("GET /gmail/v1/users/me/messages/.*");
        r.level = AccessLevel::Ask;
        let rules = vec![r];
        let level = evaluate_policy("GET", "/gmail/v1/users/me/messages/abc123", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn regex_no_match_falls_through() {
        let mut r = rule("POST /gmail/v1/users/me/messages/send");
        r.level = AccessLevel::Deny;
        let rules = vec![r];
        // GET doesn't match POST rule
        let level = evaluate_policy("GET", "/gmail/v1/users/me/messages/send", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways); // global default
    }

    #[test]
    fn body_pattern_matches() {
        let mut r = rule("POST /v1/chat/completions");
        r.body_pattern = Some("o3|o4-mini".to_string());
        r.level = AccessLevel::Ask;
        let rules = vec![r];
        let body = r#"{"model": "o3", "messages": []}"#;
        let level = evaluate_policy("POST", "/v1/chat/completions", Some(body), Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn body_pattern_no_match_falls_through() {
        let mut r = rule("POST /v1/chat/completions");
        r.body_pattern = Some("o3|o4-mini".to_string());
        r.level = AccessLevel::Deny;
        let rules = vec![r];
        let body = r#"{"model": "gpt-4o", "messages": []}"#;
        let level = evaluate_policy("POST", "/v1/chat/completions", Some(body), Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways); // no match, falls through
    }

    #[test]
    fn match_any_method_with_path_only() {
        let mut r = rule("/admin/.*");
        r.level = AccessLevel::Deny;
        let rules = vec![r];
        // Both GET and POST should match
        assert_eq!(
            evaluate_policy("GET", "/admin/settings", None, Some(&rules), None, &defaults(), None),
            AccessLevel::Deny,
        );
        assert_eq!(
            evaluate_policy("POST", "/admin/delete", None, Some(&rules), None, &defaults(), None),
            AccessLevel::Deny,
        );
    }
}
