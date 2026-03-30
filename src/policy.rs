/// Policy engine: access levels, rules, and evaluation logic.
use serde::{Deserialize, Serialize};

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

/// Per-request rule override for specific method/path patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub method: Option<String>,
    #[serde(rename = "pathSuffix")]
    pub path_suffix: Option<String>,
    pub level: AccessLevel,
    /// Session TTL in seconds (for `ask` level; cached after first approval)
    #[serde(rename = "sessionTTL")]
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

// ── Push Notification Types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushSubscription {
    pub endpoint: String,
    pub keys: PushKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushKeys {
    pub p256dh: String,
    pub auth: String,
}

// ── Policy Evaluation ──────────────────────────────────────────────────────────

/// Determine the access level for a given request.
/// Priority: service rules > service levels > type defaults > global defaults > fallback
pub fn evaluate_policy(
    method: &str,
    path: &str,
    rules: Option<&Vec<PolicyRule>>,
    service_levels: Option<&ServiceLevels>,
    defaults: &PolicyDefaults,
    service_category: Option<&str>,
) -> AccessLevel {
    // 1. Check service rules (most specific)
    if let Some(rules) = rules {
        for rule in rules {
            if matches_rule(rule, method, path) {
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

fn matches_rule(rule: &PolicyRule, method: &str, path: &str) -> bool {
    if let Some(ref m) = rule.method {
        if m != method {
            return false;
        }
    }
    if let Some(ref suffix) = rule.path_suffix {
        if !path.contains(suffix.as_str()) {
            return false;
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

    #[test]
    fn default_no_category_is_ask_always() {
        let level = evaluate_policy("GET", "/foo", None, None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn llm_category_is_allow() {
        let level = evaluate_policy("POST", "/v1/chat/completions", None, None, &defaults(), Some("llm"));
        assert_eq!(level, AccessLevel::Allow);
    }

    #[test]
    fn write_method_ask_via_service_levels() {
        let levels = ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: Some(AccessLevel::Allow),
        };
        let level = evaluate_policy("POST", "/create", None, Some(&levels), &defaults(), None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn service_levels_override_type_defaults() {
        let levels = ServiceLevels {
            write: Some(AccessLevel::AskAlways),
            read: None,
        };
        // Even though category is "llm" (default allow), service-level override wins
        let level = evaluate_policy("POST", "/foo", None, Some(&levels), &defaults(), Some("llm"));
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn rule_takes_priority_over_service_levels() {
        let rules = vec![PolicyRule {
            method: Some("DELETE".to_string()),
            path_suffix: Some("/admin".to_string()),
            level: AccessLevel::AskAlways,
            session_ttl: None,
        }];
        let levels = ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: None,
        };
        let level = evaluate_policy(
            "DELETE",
            "/api/admin",
            Some(&rules),
            Some(&levels),
            &defaults(),
            None,
        );
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn rule_method_mismatch_falls_through() {
        let rules = vec![PolicyRule {
            method: Some("DELETE".to_string()),
            path_suffix: None,
            level: AccessLevel::AskAlways,
            session_ttl: None,
        }];
        let level = evaluate_policy("GET", "/foo", Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn global_defaults_apply_when_no_service_levels() {
        let mut def = defaults();
        def.levels = Some(ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: None,
        });
        let level = evaluate_policy("POST", "/x", None, None, &def, None);
        assert_eq!(level, AccessLevel::Ask);
    }
}
