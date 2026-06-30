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

// ── Risk Tier ──────────────────────────────────────────────────────────────────

/// Author-assigned risk classification for a policy rule. Decouples *what the
/// rule is* (a stable, recipe-author judgement) from *what it costs the user*
/// (the `AccessLevel`, derived live via [`RiskPolicy`]). A rule declares a
/// `risk` instead of a hard `level` so a single user-editable `risk_policy`
/// map can re-tune every same-tier rule at once — e.g. "auto-allow everything
/// low-risk" — without touching each rule. `risk` hangs on the *rule*
/// (matcher + optional body predicate), not a fixed action enum, so future
/// predicate rules (`amount > $100`) classify the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskTier::Low => write!(f, "low"),
            RiskTier::Medium => write!(f, "medium"),
            RiskTier::High => write!(f, "high"),
        }
    }
}

impl RiskTier {
    /// Parse a kebab-case tier name. Returns `None` for anything else so
    /// callers can treat an unknown/absent tier as "no risk declared".
    pub fn parse(s: &str) -> Option<RiskTier> {
        match s {
            "low" => Some(RiskTier::Low),
            "medium" => Some(RiskTier::Medium),
            "high" => Some(RiskTier::High),
            _ => None,
        }
    }
}

/// Maps each [`RiskTier`] to a concrete [`AccessLevel`]. This is the *only*
/// user-editable knob between a rule's author-assigned risk and the approval
/// behaviour: change `medium` here and every medium-risk rule across every
/// service re-tunes on the next request. Lives in [`PolicyDefaults`] (vault
/// `aux.policy_defaults`), so it is read live during evaluation — never
/// snapshot into resolved rule levels — which is what keeps an edit realtime
/// with zero cache invalidation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPolicy {
    pub low: AccessLevel,
    pub medium: AccessLevel,
    pub high: AccessLevel,
}

impl Default for RiskPolicy {
    fn default() -> Self {
        // Conservative author baseline: only read-only/no-side-effect (low)
        // auto-passes; reading private content (medium) asks once; anything
        // irreversible / outbound (high) asks every time. Users loosen this
        // explicitly — never silently.
        Self {
            low: AccessLevel::Allow,
            medium: AccessLevel::Ask,
            high: AccessLevel::AskAlways,
        }
    }
}

impl RiskPolicy {
    pub fn get(&self, tier: RiskTier) -> AccessLevel {
        match tier {
            RiskTier::Low => self.low.clone(),
            RiskTier::Medium => self.medium.clone(),
            RiskTier::High => self.high.clone(),
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
    /// Author-assigned risk tier. When set (and `level` is not), the effective
    /// access level is derived live from the vault's `risk_policy` at
    /// evaluation time. Most rules should set `risk` (tunable) rather than
    /// `level` (pinned).
    #[serde(default)]
    pub risk: Option<RiskTier>,
    /// Explicit access level. When set, it *pins* the decision and overrides
    /// any `risk` (an escape hatch, e.g. a hard `deny` regardless of policy).
    /// Optional: a `risk`-only rule leaves this `None` and resolves via
    /// `risk_policy`. A rule with neither falls through to service levels.
    #[serde(default)]
    pub level: Option<AccessLevel>,
    /// Cache TTL in seconds after approval (for `ask` level only).
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}

impl PolicyRule {
    /// Resolve this rule's effective access level given the live `risk_policy`.
    /// Precedence: explicit `level` (pin) > `risk_policy[risk]` (tunable) >
    /// `None` (rule declared neither → caller falls through to service levels).
    /// `risk_policy` is `None` only in legacy/default-less paths; a `risk`-only
    /// rule then also yields `None` (fall through), never a silent decision.
    pub fn effective_level(&self, risk_policy: Option<&RiskPolicy>) -> Option<AccessLevel> {
        self.level
            .clone()
            .or_else(|| self.risk.and_then(|r| risk_policy.map(|rp| rp.get(r))))
    }
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
/// Only the fields set here replace the built-in rule's equivalents. A user
/// may pin a `level` (highest precedence) OR reclassify `risk` (re-tunes via
/// `risk_policy`); see [`merge_rule_overrides`] for how the two compose.
/// `level` is `Option` for back-compat: pre-risk-tier vaults stored only
/// `level`, which still deserializes and still pins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    #[serde(default)]
    pub level: Option<AccessLevel>,
    #[serde(default)]
    pub risk: Option<RiskTier>,
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}

/// Field-wise merge of two ServiceLevels with user > registry precedence.
/// Returns `None` only if both inputs are absent. Each field independently
/// takes the user's value when set, otherwise falls back to the registry's.
/// Lets the user override just one of (read, write) without forcing them
/// to restate the other.
pub fn merge_service_levels(
    user: Option<&ServiceLevels>,
    registry: Option<&ServiceLevels>,
) -> Option<ServiceLevels> {
    match (user, registry) {
        (None, None) => None,
        (Some(u), None) => Some(u.clone()),
        (None, Some(r)) => Some(r.clone()),
        (Some(u), Some(r)) => Some(ServiceLevels {
            read: u.read.clone().or_else(|| r.read.clone()),
            write: u.write.clone().or_else(|| r.write.clone()),
            ask_ttl: u.ask_ttl.or(r.ask_ttl),
        }),
    }
}

/// Apply sparse overrides onto built-in rules, matching by `id`.
/// Rules without an `id`, or whose `id` has no override, are left unchanged.
///
/// The merge bakes the user's intent into the rule's (`level`, `risk`) pair so
/// that [`PolicyRule::effective_level`] alone — read live against `risk_policy`
/// at eval — yields the full precedence:
///
/// - `override.level` → pin (the author's `risk` is kept only for display;
///   `level` wins in `effective_level`).
/// - `override.risk` (no `override.level`) → reclassify: supersede the author's
///   `level` AND `risk` by clearing `level`, so the new tier governs.
/// - neither → the author's rule is unchanged (modulo `ask_ttl`).
///
/// This keeps resolution itself a pure function of the (merged) rule + the live
/// `risk_policy`, with no separate override lookup on the hot path.
pub fn merge_rule_overrides(
    built_in: &[PolicyRule],
    overrides: &std::collections::HashMap<String, RuleOverride>,
) -> Vec<PolicyRule> {
    built_in.iter().map(|rule| {
        let ov = rule.id.as_ref().and_then(|id| overrides.get(id));
        match ov {
            Some(o) => {
                let (level, risk) = if o.level.is_some() {
                    // Pin: keep the author's risk for display, but level wins.
                    (o.level.clone(), o.risk.or(rule.risk))
                } else if o.risk.is_some() {
                    // Reclassify: the new tier supersedes the author's level too,
                    // else a pinned author `level` would shadow the user's risk.
                    (None, o.risk)
                } else {
                    (rule.level.clone(), rule.risk)
                };
                PolicyRule {
                    level,
                    risk,
                    ask_ttl: o.ask_ttl.or(rule.ask_ttl),
                    ..rule.clone()
                }
            }
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
    /// Risk-tier → access-level map. The one user-editable knob between a
    /// rule's author-assigned `risk` and its approval behaviour; `None` falls
    /// back to [`RiskPolicy::default`]. Read live at eval so an edit re-tunes
    /// every same-tier rule on the next request. Rides the existing
    /// `policy_defaults` GET/POST endpoints — no new surface, no migration.
    #[serde(default)]
    pub risk_policy: Option<RiskPolicy>,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        // Design stance: SafeClaw is *first* a credential-separating proxy —
        // the agent never holds the secret, the daemon injects it — and only
        // *secondly* an approval gate for high-risk operations. So the
        // baseline is `allow` (inject + forward, no per-call friction);
        // tightening to `ask` / `ask-always` / `deny` is opt-in per-service
        // via `[policy] rules` on genuinely risky paths. This matches how
        // people actually use API keys: you don't passkey-approve every call,
        // you approve the dangerous ones. (The llm/channel entries below are
        // now redundant with the global default but kept explicit so a future
        // stricter global default doesn't silently re-gate them.)
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
                write: Some(AccessLevel::Allow),
                read: Some(AccessLevel::Allow),
                ask_ttl: None,
            }),
            type_levels: Some(type_levels),
            risk_policy: Some(RiskPolicy::default()),
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
    // 1. Check service rules — most specific match wins (nginx-style).
    //    The matched rule's level is resolved live from `risk_policy`:
    //    explicit `level` pins; otherwise `risk` maps through the tier table.
    //    A rule that declares NEITHER yields no decision and falls through to
    //    the service-level defaults below (step 2) — we do NOT invent a level
    //    for it; the existing default chain already answers "nothing specific".
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
            if let Some(level) = rule.effective_level(defaults.risk_policy.as_ref()) {
                return (level, rule.id.clone(), rule.ask_ttl);
            }
            // else: matched but undecided → fall through to service levels.
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

    fn levels(read: Option<AccessLevel>, write: Option<AccessLevel>, ask_ttl: Option<u64>) -> ServiceLevels {
        ServiceLevels { read, write, ask_ttl }
    }

    #[test]
    fn merge_service_levels_both_absent_returns_none() {
        assert!(merge_service_levels(None, None).is_none());
    }

    #[test]
    fn merge_service_levels_user_only_passes_through() {
        let u = levels(Some(AccessLevel::Allow), None, Some(60));
        let m = merge_service_levels(Some(&u), None).unwrap();
        assert!(matches!(m.read, Some(AccessLevel::Allow)));
        assert!(m.write.is_none());
        assert_eq!(m.ask_ttl, Some(60));
    }

    #[test]
    fn merge_service_levels_registry_only_passes_through() {
        let r = levels(Some(AccessLevel::Ask), Some(AccessLevel::Deny), None);
        let m = merge_service_levels(None, Some(&r)).unwrap();
        assert!(matches!(m.read, Some(AccessLevel::Ask)));
        assert!(matches!(m.write, Some(AccessLevel::Deny)));
    }

    #[test]
    fn merge_service_levels_user_wins_fieldwise() {
        // User sets only read; registry sets both. Result: user's read,
        // registry's write — proves the merge is field-wise, not all-or-nothing.
        let u = levels(Some(AccessLevel::Allow), None, None);
        let r = levels(Some(AccessLevel::Ask), Some(AccessLevel::Deny), Some(30));
        let m = merge_service_levels(Some(&u), Some(&r)).unwrap();
        assert!(matches!(m.read, Some(AccessLevel::Allow)));
        assert!(matches!(m.write, Some(AccessLevel::Deny)));
        assert_eq!(m.ask_ttl, Some(30));
    }

    fn rule(match_pat: &str, level: AccessLevel) -> PolicyRule {
        PolicyRule {
            id: None,
            label: None,
            match_pattern: Some(match_pat.to_string()),
            body: None,
            risk: None,
            level: Some(level),
            ask_ttl: None,
        }
    }

    /// A risk-only rule (no explicit `level`) — resolves via `risk_policy`.
    fn risk_rule(match_pat: &str, risk: RiskTier) -> PolicyRule {
        PolicyRule {
            id: None,
            label: None,
            match_pattern: Some(match_pat.to_string()),
            body: None,
            risk: Some(risk),
            level: None,
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
    fn default_no_category_is_allow() {
        // Baseline with nothing configured is `allow` — SafeClaw is a
        // credential-separating proxy first; gating is opt-in per risky path.
        let level = evaluate_policy("GET", "/foo", None, None, None, &defaults(), None);
        assert_eq!(level, AccessLevel::Allow);
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
        // A DELETE rule does not apply to a GET → fall through to the default
        // (now `allow`).
        let rules = vec![rule("DELETE /foo", AccessLevel::Deny)];
        let level = evaluate_policy("GET", "/foo", None, Some(&rules), None, &defaults(), None);
        assert_eq!(level, AccessLevel::Allow);
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
                risk: None,
                level: Some(AccessLevel::AskAlways),
                ask_ttl: None,
            },
        ];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("send-email".into(), RuleOverride {
            level: Some(AccessLevel::Ask), risk: None, ask_ttl: None,
        });
        let merged = merge_rule_overrides(&built_in, &overrides);
        assert_eq!(merged[0].level, Some(AccessLevel::Ask));
        // Match pattern / label preserved
        assert_eq!(merged[0].label.as_deref(), Some("Send email"));
    }

    #[test]
    fn override_missing_id_leaves_rule_untouched() {
        let built_in = vec![rule("GET /foo", AccessLevel::Allow)];
        let overrides = std::collections::HashMap::new();
        let merged = merge_rule_overrides(&built_in, &overrides);
        assert_eq!(merged[0].level, Some(AccessLevel::Allow));
    }

    /// Back-compat: a RuleOverride sealed by an OLD daemon (when `level` was a
    /// required field, no `risk`) must still deserialize — existing vaults are
    /// not migrated. And a new risk-only override round-trips. Guards the
    /// "no migration" claim against an accidental future `deny_unknown_fields`
    /// or a non-default field.
    #[test]
    fn rule_override_deserializes_old_and_new_shapes() {
        // Old shape: just a level (what pre-risk-tier vaults stored).
        let old: RuleOverride = serde_json::from_str(r#"{"level":"ask"}"#).unwrap();
        assert_eq!(old.level, Some(AccessLevel::Ask));
        assert_eq!(old.risk, None);
        // Old shape with ttl.
        let old2: RuleOverride = serde_json::from_str(r#"{"level":"ask-always","ask_ttl":1800}"#).unwrap();
        assert_eq!(old2.level, Some(AccessLevel::AskAlways));
        assert_eq!(old2.ask_ttl, Some(1800));
        // New shape: reclassify by risk only.
        let new: RuleOverride = serde_json::from_str(r#"{"risk":"low"}"#).unwrap();
        assert_eq!(new.risk, Some(RiskTier::Low));
        assert_eq!(new.level, None);
        // Empty object is valid (all fields optional) — a no-op override.
        let empty: RuleOverride = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.level, None);
        assert_eq!(empty.risk, None);
        // Round-trip the new shape.
        let back: RuleOverride = serde_json::from_str(&serde_json::to_string(&new).unwrap()).unwrap();
        assert_eq!(back.risk, Some(RiskTier::Low));
    }

    // ── Risk tiers ─────────────────────────────────────────────────────────

    /// A risk-only rule resolves through the default risk_policy:
    /// low→allow, medium→ask, high→ask-always. This is the headline behaviour
    /// that turns "read one Gmail message" (list=low, get=medium) from two
    /// approvals into one.
    #[test]
    fn risk_only_rule_resolves_via_default_risk_policy() {
        let low = vec![risk_rule("GET /gmail/v1/users/me/messages", RiskTier::Low)];
        assert_eq!(
            evaluate_policy("GET", "/gmail/v1/users/me/messages", None, Some(&low), None, &defaults(), None),
            AccessLevel::Allow
        );
        let medium = vec![risk_rule("GET /gmail/v1/users/me/messages/*", RiskTier::Medium)];
        assert_eq!(
            evaluate_policy("GET", "/gmail/v1/users/me/messages/abc", None, Some(&medium), None, &defaults(), None),
            AccessLevel::Ask
        );
        let high = vec![risk_rule("POST /gmail/v1/users/me/messages/send", RiskTier::High)];
        assert_eq!(
            evaluate_policy("POST", "/gmail/v1/users/me/messages/send", None, Some(&high), None, &defaults(), None),
            AccessLevel::AskAlways
        );
    }

    /// Editing risk_policy globally re-tunes every same-tier rule at once —
    /// the batch capability that motivated tiers over per-rule config.
    #[test]
    fn editing_risk_policy_retunes_all_same_tier_rules() {
        let mut def = defaults();
        def.risk_policy = Some(RiskPolicy {
            low: AccessLevel::Allow,
            medium: AccessLevel::Allow, // user loosens medium globally
            high: AccessLevel::AskAlways,
        });
        let rules = vec![risk_rule("GET /x/*", RiskTier::Medium)];
        assert_eq!(
            evaluate_policy("GET", "/x/abc", None, Some(&rules), None, &def, None),
            AccessLevel::Allow
        );
    }

    /// An explicit `level` pins the decision regardless of `risk` / risk_policy
    /// (the escape hatch, e.g. a hard deny).
    #[test]
    fn explicit_level_pins_over_risk() {
        let mut r = risk_rule("DELETE /gmail/v1/users/me/messages/*", RiskTier::High);
        r.level = Some(AccessLevel::Deny);
        let rules = vec![r];
        assert_eq!(
            evaluate_policy("DELETE", "/gmail/v1/users/me/messages/abc", None, Some(&rules), None, &defaults(), None),
            AccessLevel::Deny
        );
    }

    /// override.risk reclassifies a single rule (user wants just THIS action
    /// looser) — supersedes the author's level too, then maps via risk_policy.
    #[test]
    fn override_risk_reclassifies_single_rule() {
        let built_in = vec![{
            let mut r = risk_rule("GET /gmail/v1/users/me/messages/*", RiskTier::Medium);
            r.id = Some("read-email".into());
            r
        }];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("read-email".into(), RuleOverride {
            level: None, risk: Some(RiskTier::Low), ask_ttl: None,
        });
        let merged = merge_rule_overrides(&built_in, &overrides);
        assert_eq!(merged[0].risk, Some(RiskTier::Low));
        assert_eq!(merged[0].level, None);
        assert_eq!(
            evaluate_policy("GET", "/gmail/v1/users/me/messages/abc", None, Some(&merged), None, &defaults(), None),
            AccessLevel::Allow
        );
    }

    /// override.level pins even when the author classified by risk; the
    /// author's risk is preserved for display but the pin wins at eval.
    #[test]
    fn override_level_pins_over_author_risk() {
        let built_in = vec![{
            let mut r = risk_rule("POST /x/send", RiskTier::High);
            r.id = Some("send".into());
            r
        }];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("send".into(), RuleOverride {
            level: Some(AccessLevel::Deny), risk: None, ask_ttl: None,
        });
        let merged = merge_rule_overrides(&built_in, &overrides);
        assert_eq!(merged[0].level, Some(AccessLevel::Deny));
        assert_eq!(merged[0].risk, Some(RiskTier::High)); // preserved for display
        assert_eq!(
            evaluate_policy("POST", "/x/send", None, Some(&merged), None, &defaults(), None),
            AccessLevel::Deny
        );
    }

    /// A matched rule that declares NEITHER risk nor level yields no decision
    /// and falls through to the service-level defaults — we do not invent a
    /// level for it (Q2: the existing default chain already answers this).
    #[test]
    fn rule_with_neither_risk_nor_level_falls_through() {
        let bare = PolicyRule {
            id: None, label: None,
            match_pattern: Some("GET /x".into()),
            body: None, risk: None, level: None, ask_ttl: None,
        };
        let svc = ServiceLevels { read: Some(AccessLevel::Ask), write: None, ask_ttl: None };
        // Falls through to service levels (Ask), not the global allow default.
        assert_eq!(
            evaluate_policy("GET", "/x", None, Some(&vec![bare]), Some(&svc), &defaults(), None),
            AccessLevel::Ask
        );
    }

    /// With no risk_policy available at all (degenerate/legacy), a risk-only
    /// rule produces no decision and falls through rather than guessing.
    #[test]
    fn risk_only_rule_without_risk_policy_falls_through() {
        let mut def = defaults();
        def.risk_policy = None;
        let rules = vec![risk_rule("GET /x", RiskTier::Low)];
        let svc = ServiceLevels { read: Some(AccessLevel::AskAlways), write: None, ask_ttl: None };
        assert_eq!(
            evaluate_policy("GET", "/x", None, Some(&rules), Some(&svc), &def, None),
            AccessLevel::AskAlways
        );
    }
}
