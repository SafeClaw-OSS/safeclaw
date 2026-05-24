/// Policy engine: access levels, rules, and evaluation logic.
///
/// Rule matching uses path patterns (nginx-style, longest match wins):
/// - `match`: `"METHOD /path/with/*/wildcards"` — `*` matches one path segment
/// - `body`: regex matched against request body text (optional)
///
/// Specificity (highest priority first):
///   1. Rules with `body` pattern > rules without (more conditions = more specific)
///   2. Longer literal path > shorter (nginx longest-match principle)
///   3. Exact path > path with wildcards
///   4. With method > without method (any-method)
///   5. TOML order as tiebreaker
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

/// Per-request policy rule.
///
/// `match` uses path patterns (nginx-style):
///   - `"GET /gmail/v1/users/me/messages"` — exact match with method
///   - `"DELETE /repos/*/git/refs/*"` — `*` matches one path segment
///   - `"/admin/*"` — no method = matches any method
///
/// `body` uses regex (for unstructured content matching).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique identifier (e.g. "send-email"). Used as key for vault overrides.
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable label for console UI (e.g. "Send email").
    #[serde(default)]
    pub label: Option<String>,
    /// Path pattern: `"METHOD /path"` or `"/path"` (any method).
    /// `*` matches exactly one path segment. Omit to match all requests.
    #[serde(default, rename = "match")]
    pub match_pattern: Option<String>,
    /// Regex matched against request body text. Omit to skip body matching.
    #[serde(default)]
    pub body: Option<String>,
    pub level: AccessLevel,
    /// Cache TTL in seconds after approval (for `ask` level only).
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}

/// Per-service read/write access levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevels {
    pub write: Option<AccessLevel>,
    pub read: Option<AccessLevel>,
    /// Default ask-level cache TTL in seconds for this service.
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}

/// Sparse override for a single built-in rule, keyed by rule id in the vault.
/// Only the fields set here replace the built-in rule's equivalents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    pub level: AccessLevel,
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}

/// Apply sparse overrides onto built-in rules, matching by `id`.
/// Rules without an `id`, or whose `id` has no override, are left unchanged.
pub fn merge_rule_overrides(
    built_in: &[PolicyRule],
    overrides: &std::collections::HashMap<String, RuleOverride>,
) -> Vec<PolicyRule> {
    built_in.iter().map(|rule| {
        let ov = rule.id.as_ref().and_then(|id| overrides.get(id));
        match ov {
            Some(o) => PolicyRule {
                level: o.level.clone(),
                ask_ttl: o.ask_ttl.or(rule.ask_ttl),
                ..rule.clone()
            },
            None => rule.clone(),
        }
    }).collect()
}

/// Global policy defaults (stored in vault.enc under "policy_defaults")
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
            ask_ttl: None,
        });
        type_levels.insert("channel".into(), ServiceLevels {
            write: Some(AccessLevel::Allow),
            read: Some(AccessLevel::Allow),
            ask_ttl: None,
        });
        Self {
            timeout: Some(300),
            levels: Some(ServiceLevels {
                write: Some(AccessLevel::AskAlways),
                read: Some(AccessLevel::AskAlways),
                ask_ttl: None,
            }),
            type_levels: Some(type_levels),
        }
    }
}

// ── Path Pattern Matching ─────────────────────────────────────────────────────

/// Parse a match pattern into (optional_method, path_pattern).
/// Examples: `"GET /foo/bar"` → `(Some("GET"), "/foo/bar")`
///           `"/foo/*"` → `(None, "/foo/*")`
fn parse_match_pattern(pattern: &str) -> (Option<&str>, &str) {
    if let Some(space_pos) = pattern.find(' ') {
        let method = &pattern[..space_pos];
        // Only treat as method if it's all uppercase ASCII (HTTP method)
        if method.bytes().all(|b| b.is_ascii_uppercase()) {
            return (Some(method), &pattern[space_pos + 1..]);
        }
    }
    (None, pattern)
}

/// Match a request path against a pattern. `*` matches exactly one path segment.
fn path_matches(pattern: &str, path: &str) -> bool {
    let pat_segments: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let path_segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();

    if pat_segments.len() != path_segments.len() {
        return false;
    }
    for (p, s) in pat_segments.iter().zip(path_segments.iter()) {
        if *p == "*" {
            continue;
        }
        if p != s {
            return false;
        }
    }
    true
}

/// Compute specificity score for a match pattern. Higher = more specific.
///
/// Scoring (nginx longest-match principle):
///   - Base: number of literal (non-wildcard) path segments × 10
///   - Bonus +5 if method is specified
///   - Bonus +1000 if rule has body pattern
fn specificity(rule: &PolicyRule) -> u32 {
    let mut score: u32 = 0;

    if rule.body.is_some() {
        score += 1000;
    }

    if let Some(ref pattern) = rule.match_pattern {
        let (method, path) = parse_match_pattern(pattern);
        if method.is_some() {
            score += 5;
        }
        // Count literal segments (non-wildcard)
        for seg in path.split('/') {
            if !seg.is_empty() && seg != "*" {
                score += 10;
            }
        }
    }

    score
}

/// Check if a single rule matches the given request.
fn matches_rule(rule: &PolicyRule, method: &str, path: &str, body: Option<&str>) -> bool {
    if let Some(ref pattern) = rule.match_pattern {
        let path_no_query = path.split('?').next().unwrap_or(path);
        let (rule_method, rule_path) = parse_match_pattern(pattern);

        // Check method (if specified)
        if let Some(m) = rule_method {
            if m != method {
                return false;
            }
        }
        // Check path pattern
        if !path_matches(rule_path, path_no_query) {
            return false;
        }
    }
    // Check body regex
    if let Some(ref pattern) = rule.body {
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

// ── Policy Evaluation ──────────────────────────────────────────────────────────

/// Determine the access level for a given request.
/// Priority: service rules (most specific match) > service levels > type defaults > global defaults
pub fn evaluate_policy(
    method: &str,
    path: &str,
    body: Option<&str>,
    rules: Option<&Vec<PolicyRule>>,
    service_levels: Option<&ServiceLevels>,
    defaults: &PolicyDefaults,
    service_category: Option<&str>,
) -> AccessLevel {
    evaluate_policy_with_match(method, path, body, rules, service_levels, defaults, service_category).0
}

/// Same as [`evaluate_policy`] but also returns the matching rule (if any)
/// and its TTL. The matched-rule reference lets callers identify the exact
/// scope of an approval — e.g. caching `ask` decisions by rule id so the
/// TTL applies to the specific scope the user said "yes" to, not every
/// request to the service.
///
/// Returned tuple: `(level, matched_rule_id, ttl_seconds)`. Both extras are
/// `None` when no rule matched (level came from category / global default);
/// the caller should still cache under `(service, None)` in that case.
pub fn evaluate_policy_with_match(
    method: &str,
    path: &str,
    body: Option<&str>,
    rules: Option<&Vec<PolicyRule>>,
    service_levels: Option<&ServiceLevels>,
    defaults: &PolicyDefaults,
    service_category: Option<&str>,
) -> (AccessLevel, Option<String>, Option<u64>) {
    // 1. Check service rules — most specific match wins (nginx-style)
    if let Some(rules) = rules {
        let mut best: Option<(u32, &PolicyRule)> = None;
        for rule in rules {
            if matches_rule(rule, method, path, body) {
                let s = specificity(rule);
                if best.is_none() || s > best.unwrap().0 {
                    best = Some((s, rule));
                }
            }
        }
        if let Some((_, rule)) = best {
            return (rule.level.clone(), rule.id.clone(), rule.ask_ttl);
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
            return (l.clone(), None, levels.ask_ttl);
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
                return (l.clone(), None, type_def.ask_ttl);
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
            return (l.clone(), None, def_levels.ask_ttl);
        }
    }

    // 5. Safe default
    (AccessLevel::AskAlways, None, None)
}

/// Find the ask_ttl for the best matching rule.
pub fn find_ask_ttl(
    rules: Option<&Vec<PolicyRule>>,
    service_levels: Option<&ServiceLevels>,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Option<u64> {
    // Check per-rule ask_ttl (best matching rule)
    if let Some(rules) = rules {
        let mut best: Option<(u32, &PolicyRule)> = None;
        for rule in rules {
            if matches_rule(rule, method, path, body) {
                let s = specificity(rule);
                if best.is_none() || s > best.unwrap().0 {
                    best = Some((s, rule));
                }
            }
        }
        if let Some((_, rule)) = best {
            if let Some(ttl) = rule.ask_ttl {
                return Some(ttl);
            }
        }
    }
    // Fall back to service-level ask_ttl
    service_levels.and_then(|l| l.ask_ttl)
}

fn is_write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> PolicyDefaults {
        PolicyDefaults::default()
    }

    fn rule(match_pat: &str, level: AccessLevel) -> PolicyRule {
        PolicyRule {
            id: None,
            label: None,
            match_pattern: Some(match_pat.to_string()),
            body: None,
            level,
            ask_ttl: None,
        }
    }

    // ── Path pattern matching ──────────────────────────────────────────────

    #[test]
    fn exact_path_matches() {
        assert!(path_matches("/gmail/v1/users/me/messages", "/gmail/v1/users/me/messages"));
    }

    #[test]
    fn exact_path_no_match() {
        assert!(!path_matches("/gmail/v1/users/me/messages", "/gmail/v1/users/me/labels"));
    }

    #[test]
    fn wildcard_matches_one_segment() {
        assert!(path_matches("/repos/*/issues", "/repos/myrepo/issues"));
        assert!(!path_matches("/repos/*/issues", "/repos/myrepo/pulls"));
    }

    #[test]
    fn wildcard_does_not_match_multiple_segments() {
        assert!(!path_matches("/repos/*", "/repos/owner/repo"));
    }

    #[test]
    fn multiple_wildcards() {
        assert!(path_matches("/repos/*/*/git/refs/*", "/repos/owner/repo/git/refs/heads"));
    }

    #[test]
    fn trailing_slash_normalized() {
        assert!(path_matches("/foo/bar/", "/foo/bar"));
        assert!(path_matches("/foo/bar", "/foo/bar/"));
    }

    // ── parse_match_pattern ────────────────────────────────────────────────

    #[test]
    fn parse_with_method() {
        let (m, p) = parse_match_pattern("POST /foo/bar");
        assert_eq!(m, Some("POST"));
        assert_eq!(p, "/foo/bar");
    }

    #[test]
    fn parse_without_method() {
        let (m, p) = parse_match_pattern("/foo/bar");
        assert_eq!(m, None);
        assert_eq!(p, "/foo/bar");
    }

    #[test]
    fn parse_path_with_space_not_method() {
        // "not ALLCAPS" shouldn't be parsed as method
        let (m, p) = parse_match_pattern("foo /bar");
        assert_eq!(m, None);
        assert_eq!(p, "foo /bar");
    }

    // ── Specificity ────────────────────────────────────────────────────────

    #[test]
    fn specificity_exact_with_method_beats_wildcard() {
        let r1 = rule("POST /gmail/v1/users/me/messages/send", AccessLevel::Deny);
        let r2 = rule("POST /gmail/v1/users/me/messages/*", AccessLevel::Allow);
        assert!(specificity(&r1) > specificity(&r2));
    }

    #[test]
    fn specificity_body_rule_beats_no_body() {
        let r1 = PolicyRule {
            match_pattern: Some("POST /v1/chat/completions".into()),
            body: Some("o3".into()),
            ..rule("POST /v1/chat/completions", AccessLevel::Ask)
        };
        let r2 = rule("POST /v1/chat/completions", AccessLevel::Allow);
        assert!(specificity(&r1) > specificity(&r2));
    }

    #[test]
    fn specificity_longer_path_beats_shorter() {
        let r1 = rule("GET /gmail/v1/users/me/messages", AccessLevel::Allow);
        let r2 = rule("GET /gmail/v1/users/me", AccessLevel::Ask);
        assert!(specificity(&r1) > specificity(&r2));
    }

    #[test]
    fn specificity_with_method_beats_without() {
        let r1 = rule("GET /foo", AccessLevel::Allow);
        let r2 = rule("/foo", AccessLevel::Allow);
        assert!(specificity(&r1) > specificity(&r2));
    }

    // ── evaluate_policy ────────────────────────────────────────────────────

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
        let levels = ServiceLevels { write: Some(AccessLevel::Ask), read: Some(AccessLevel::Allow), ask_ttl: None };
        let level = evaluate_policy("POST", "/create", None, None, Some(&levels), &defaults(), None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn service_levels_override_type_defaults() {
        let levels = ServiceLevels { write: Some(AccessLevel::AskAlways), read: None, ask_ttl: None };
        let level = evaluate_policy("POST", "/foo", None, None, Some(&levels), &defaults(), Some("llm"));
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn rule_takes_priority_over_service_levels() {
        let rules = vec![rule("DELETE /api/admin", AccessLevel::AskAlways)];
        let levels = ServiceLevels { write: Some(AccessLevel::Ask), read: None, ask_ttl: None };
        let level = evaluate_policy("DELETE", "/api/admin", None, Some(&rules), Some(&levels), &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn method_mismatch_falls_through() {
        let rules = vec![rule("DELETE /foo", AccessLevel::Deny)];
        let level = evaluate_policy("GET", "/foo", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::AskAlways);
    }

    #[test]
    fn wildcard_path_matches() {
        let rules = vec![rule("GET /gmail/v1/users/me/messages/*", AccessLevel::Ask)];
        let level = evaluate_policy("GET", "/gmail/v1/users/me/messages/abc123", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Ask);
    }

    #[test]
    fn most_specific_rule_wins_regardless_of_order() {
        // Less specific first in list, more specific second — more specific should still win
        let rules = vec![
            rule("POST /gmail/v1/users/me/messages/*", AccessLevel::Ask),
            rule("POST /gmail/v1/users/me/messages/send", AccessLevel::Deny),
        ];
        let level = evaluate_policy("POST", "/gmail/v1/users/me/messages/send", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Deny); // exact beats wildcard
    }

    #[test]
    fn body_rule_beats_path_only_rule() {
        let mut body_rule = rule("POST /v1/chat/completions", AccessLevel::Deny);
        body_rule.body = Some("o3|o4-mini".to_string());
        let path_rule = rule("POST /v1/chat/completions", AccessLevel::Allow);
        let rules = vec![path_rule, body_rule];
        let body = r#"{"model": "o3"}"#;
        let level = evaluate_policy("POST", "/v1/chat/completions", Some(body), Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Deny); // body rule wins
    }

    #[test]
    fn body_no_match_falls_to_path_rule() {
        let mut body_rule = rule("POST /v1/chat/completions", AccessLevel::Deny);
        body_rule.body = Some("o3|o4-mini".to_string());
        let path_rule = rule("POST /v1/chat/completions", AccessLevel::Allow);
        let rules = vec![path_rule, body_rule];
        let body = r#"{"model": "gpt-4o"}"#;
        let level = evaluate_policy("POST", "/v1/chat/completions", Some(body), Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Allow); // body rule doesn't match, path rule wins
    }

    #[test]
    fn no_method_matches_any_method() {
        let rules = vec![rule("/admin/*", AccessLevel::Deny)];
        assert_eq!(evaluate_policy("GET", "/admin/settings", None, Some(&rules), None, &defaults(), None), AccessLevel::Deny);
        assert_eq!(evaluate_policy("POST", "/admin/delete", None, Some(&rules), None, &defaults(), None), AccessLevel::Deny);
    }

    #[test]
    fn global_defaults_apply_when_no_service_levels() {
        let mut def = defaults();
        def.levels = Some(ServiceLevels { write: Some(AccessLevel::Ask), read: None, ask_ttl: None });
        let level = evaluate_policy("POST", "/x", None, None, None, &def, None);
        assert_eq!(level, AccessLevel::Ask);
    }

    // ── find_ask_ttl ───────────────────────────────────────────────────────

    #[test]
    fn ask_ttl_from_matching_rule() {
        let mut r = rule("GET /data/*", AccessLevel::Ask);
        r.ask_ttl = Some(600);
        let rules = vec![r];
        assert_eq!(find_ask_ttl(Some(&rules), None, "GET", "/data/123", None), Some(600));
    }

    #[test]
    fn ask_ttl_falls_back_to_service_level() {
        let levels = ServiceLevels { write: None, read: None, ask_ttl: Some(1800) };
        assert_eq!(find_ask_ttl(None, Some(&levels), "GET", "/foo", None), Some(1800));
    }

    // ── merge_rule_overrides ───────────────────────────────────────────────

    #[test]
    fn override_replaces_level_by_id() {
        let built_in = vec![
            PolicyRule {
                id: Some("send-email".into()),
                label: Some("Send email".into()),
                match_pattern: Some("POST /gmail/v1/users/me/messages/send".into()),
                body: None,
                level: AccessLevel::AskAlways,
                ask_ttl: None,
            },
        ];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("send-email".into(), RuleOverride {
            level: AccessLevel::Ask, ask_ttl: None,
        });
        let merged = merge_rule_overrides(&built_in, &overrides);
        assert_eq!(merged[0].level, AccessLevel::Ask);
        // Match pattern / label preserved
        assert_eq!(merged[0].label.as_deref(), Some("Send email"));
    }

    #[test]
    fn override_missing_id_leaves_rule_untouched() {
        let built_in = vec![rule("GET /foo", AccessLevel::Allow)];
        let overrides = std::collections::HashMap::new();
        let merged = merge_rule_overrides(&built_in, &overrides);
        assert_eq!(merged[0].level, AccessLevel::Allow);
    }
}
