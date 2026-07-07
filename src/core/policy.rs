//! Policy engine — path-matched rules → access decisions.
//!
//! **One vocabulary**: [`AccessLevel`] (`allow | ask | ask-always | deny`) — the
//! access DECISION. It is what a rule declares, what the read/write floor
//! declares, and what evaluation returns. (An earlier revision split an
//! author-assigned `risk` CLASSIFICATION from the resolved `level`, bridged by a
//! per-vault risk→level map. That indirection is gone: a rule states its
//! decision directly, and the recipe author writes `allow`/`ask` on the action
//! instead of a `low`/`high` label.)
//!
//! Resolution order (PROTOCOL.md §6.4): most-restrictive matching rule
//! (deny-override / fail-safe) → connection default → category default →
//! global default → floor (`ask-always`).
//!
//! Rule matching uses path patterns (nginx-style):
//! - `match`: `"METHOD /path/with/*/wildcards"` — `*` matches one path segment
//! - `body`: regex matched against request body text (optional)
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;

// ── Access Level ───────────────────────────────────────────────────────────────

/// The access DECISION for a request.
///
/// - `Allow`: pass through immediately, no approval
/// - `Ask`: approve once, then cache for the rule's `ttl`
/// - `AskAlways`: approve every request, never cache
/// - `Deny`: block unconditionally
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl AccessLevel {
    /// Parse a kebab-case level name. `None` for anything else.
    pub fn parse(s: &str) -> Option<AccessLevel> {
        match s {
            "allow" => Some(AccessLevel::Allow),
            "ask" => Some(AccessLevel::Ask),
            "ask-always" => Some(AccessLevel::AskAlways),
            "deny" => Some(AccessLevel::Deny),
            _ => None,
        }
    }

    /// Restrictiveness rank — higher = stricter. Used to resolve overlapping
    /// rules by "most restrictive wins" (deny-override / fail-safe, à la AWS
    /// IAM / Cedar). PROTOCOL.md §6.4.
    pub fn restrictiveness(&self) -> u8 {
        match self {
            AccessLevel::Allow => 0,
            AccessLevel::Ask => 1,
            AccessLevel::AskAlways => 2,
            AccessLevel::Deny => 3,
        }
    }
}

// ── Rules ───────────────────────────────────────────────────────────────────────

/// A fully-formed policy rule — from a service's `policy.toml`, or the merged
/// result after user edits. A matched rule decides the request via its `level`.
/// `level` hangs on the *rule* (matcher + optional `body` predicate), so future
/// predicate rules (`amount > $100`) decide the same way. A rule with no `level`
/// is malformed — it can never decide — and is skipped at evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique id (e.g. "send-email"). The key for user edits / the ask-cache scope.
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable label for the console.
    #[serde(default)]
    pub label: Option<String>,
    /// Path pattern: `"METHOD /path"` or `"/path"` (any method). `*` = one segment.
    #[serde(default, rename = "match")]
    pub match_pattern: Option<String>,
    /// Regex matched against request body text. Omit to skip body matching.
    #[serde(default)]
    pub body: Option<String>,
    /// The access decision when this rule matches.
    #[serde(default)]
    pub level: Option<AccessLevel>,
    /// Cache TTL (seconds) after an `ask` approval, scoped to this rule
    /// (PROTOCOL.md §6.1 `policy.rules[].ttl`).
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl PolicyRule {
    /// The access decision for this rule. `None` only if the rule declares no
    /// `level` (malformed) → caller falls through to defaults.
    pub fn effective_level(&self) -> Option<AccessLevel> {
        self.level
    }
}

/// Read/write access levels — a floor DECISION for when no rule matches. Used at
/// the connection, category, and global layers. The read/write split is the
/// method-derived base: `is_write_method` picks `write` for mutating methods,
/// `read` otherwise.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Levels {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<AccessLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<AccessLevel>,
    /// `ask`-cache TTL when the floor decision is `ask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

/// A sparse user edit to one rule, keyed by rule id in `aux.policy.connections.
/// <id>.rules`. Two modes:
///   - **override** an existing built-in rule (set `level` and/or `ttl`; the id
///     matches a built-in),
///   - **add** a new rule (carries its own `match` — the presence of `match` is
///     what makes it a new rule rather than an override).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<AccessLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

// ── Per-connection + global policy (sealed in `aux.policy`) ──────────────────────

/// A connection's user policy layer (PROTOCOL.md `M.policy.connections.<id>`).
/// Sparse — present only for connections the user actually customised. The
/// built-in rule set comes from the connection's *service* definition; this adds a
/// per-connection default override and per-rule edits/additions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionPolicy {
    /// Override this connection's default read/write floor (over the service's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Levels>,
    /// Per-rule edits (override built-in by id) and additions (new id + match).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rules: HashMap<String, RuleConfig>,
}

/// The whole policy tree (`aux.policy`, PROTOCOL.md §5.2 / §6.4 `M.policy`).
/// Replaces the old split `policy_defaults` + `service_state`. Sparse: a fresh
/// vault has none and the daemon uses [`Policy::default`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Approval hold timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Global default floor (when no rule and no more-specific default match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Levels>,
    /// Per-category default floor (e.g. "llm", "channel"). Beats `default`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub categories: HashMap<String, Levels>,
    /// Per-connection user policy, keyed by `connection_id`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub connections: HashMap<String, ConnectionPolicy>,
}

impl Default for Policy {
    fn default() -> Self {
        // Design stance: SafeClaw is *first* a credential-separating proxy —
        // the agent never holds the secret, the daemon injects it — and only
        // *secondly* an approval gate for risky operations. So the baseline
        // floor is `allow` (inject + forward, no per-call friction); services
        // tighten genuinely sensitive paths with a stricter `level` on rules.
        // (llm/channel are redundant with the global default but kept explicit
        // so a future stricter global default doesn't silently re-gate them.)
        let allow_rw = || Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Allow),
            ttl: None,
        };
        let mut categories = HashMap::new();
        categories.insert("llm".into(), allow_rw());
        categories.insert("channel".into(), allow_rw());
        Self {
            timeout: Some(300),
            default: Some(allow_rw()),
            categories,
            connections: HashMap::new(),
        }
    }
}

impl Policy {
    /// Overlay a user's sparse `aux.policy` onto the compiled defaults so unset
    /// parts (global floor, category defaults) keep safe values. Called at
    /// unlock/refresh to produce the effective policy the evaluator reads.
    pub fn effective(user: Option<&Policy>) -> Policy {
        let mut p = Policy::default();
        if let Some(u) = user {
            if u.timeout.is_some() {
                p.timeout = u.timeout;
            }
            if u.default.is_some() {
                p.default = u.default.clone();
            }
            for (k, v) in &u.categories {
                p.categories.insert(k.clone(), v.clone());
            }
            p.connections = u.connections.clone();
        }
        p
    }
}

// ── Merge ─────────────────────────────────────────────────────────────────────

/// Field-wise merge of two [`Levels`] with user > built-in precedence. Each field
/// independently takes the user's value when set, else the built-in's.
pub fn merge_levels(user: Option<&Levels>, built_in: Option<&Levels>) -> Option<Levels> {
    match (user, built_in) {
        (None, None) => None,
        (Some(u), None) => Some(u.clone()),
        (None, Some(r)) => Some(r.clone()),
        (Some(u), Some(r)) => Some(Levels {
            read: u.read.or(r.read),
            write: u.write.or(r.write),
            ttl: u.ttl.or(r.ttl),
        }),
    }
}

/// Merge a connection's user [`RuleConfig`] edits onto a service's built-in
/// rules. By id: an edit overrides `level` / `ttl` (and `label`/`body` if given)
/// of the matching built-in; an entry with a `match` whose id is *not* built-in
/// is appended as a new rule. PROTOCOL.md §6.4 `M.policy` (logical merged view).
pub fn merge_rules(
    built_in: &[PolicyRule],
    user: &HashMap<String, RuleConfig>,
) -> Vec<PolicyRule> {
    let mut out: Vec<PolicyRule> = built_in
        .iter()
        .map(|rule| {
            let edit = rule.id.as_ref().and_then(|id| user.get(id));
            match edit {
                Some(e) => PolicyRule {
                    level: e.level.or(rule.level),
                    ttl: e.ttl.or(rule.ttl),
                    label: e.label.clone().or_else(|| rule.label.clone()),
                    body: e.body.clone().or_else(|| rule.body.clone()),
                    ..rule.clone()
                },
                None => rule.clone(),
            }
        })
        .collect();
    // New rules: user entries with a `match` and an id not present in built-ins.
    let built_in_ids: std::collections::HashSet<&str> =
        built_in.iter().filter_map(|r| r.id.as_deref()).collect();
    for (id, e) in user {
        if built_in_ids.contains(id.as_str()) {
            continue;
        }
        if let Some(ref m) = e.match_pattern {
            out.push(PolicyRule {
                id: Some(id.clone()),
                label: e.label.clone(),
                match_pattern: Some(m.clone()),
                body: e.body.clone(),
                level: e.level,
                ttl: e.ttl,
            });
        }
    }
    out
}

// ── Path Pattern Matching ─────────────────────────────────────────────────────

/// Parse a match pattern into (optional_method, path_pattern).
fn parse_match_pattern(pattern: &str) -> (Option<&str>, &str) {
    if let Some(space_pos) = pattern.find(' ') {
        let method = &pattern[..space_pos];
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

/// Specificity score (nginx longest-match): used only as a tiebreaker between
/// equally-restrictive matching rules, so the ask-cache scope is deterministic.
///   - `+1000` if rule has body regex
///   - `+5` if method specified
///   - `+10` per literal (non-wildcard) path segment
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
        if let Some(m) = rule_method {
            if m != method {
                return false;
            }
        }
        if !path_matches(rule_path, path_no_query) {
            return false;
        }
    }
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

fn is_write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Determine the access level for a request. See [`evaluate_with_match`].
pub fn evaluate(
    method: &str,
    path: &str,
    body: Option<&str>,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    category: Option<&str>,
) -> AccessLevel {
    evaluate_with_match(method, path, body, rules, connection_levels, policy, category).0
}

/// Resolve the access decision for a request, returning `(level,
/// matched_rule_id, ttl)`.
///
/// Resolution (PROTOCOL.md §6.4):
///   1. Among ALL matching rules, the **most restrictive** effective level wins
///      (deny-override / fail-safe). Ties broken by specificity for a
///      deterministic ask-cache scope (`(connection, rule_id, method)`).
///   2. else connection default (read/write floor),
///   3. else category default,
///   4. else global default,
///   5. else `ask-always` (safe floor).
/// `matched_rule_id` / `ttl` are `Some` only when a rule decided (step 1).
pub fn evaluate_with_match(
    method: &str,
    path: &str,
    body: Option<&str>,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    category: Option<&str>,
) -> (AccessLevel, Option<String>, Option<u64>) {
    // 1. Rules — most-restrictive matching wins (deny-override).
    if let Some(rules) = rules {
        let mut best: Option<(u8, u32, &PolicyRule, AccessLevel)> = None;
        for rule in rules {
            if !matches_rule(rule, method, path, body) {
                continue;
            }
            let Some(level) = rule.effective_level() else {
                continue; // rule declares no level → no decision; skip.
            };
            let key = (level.restrictiveness(), specificity(rule));
            if best.is_none() || key > (best.unwrap().0, best.unwrap().1) {
                best = Some((key.0, key.1, rule, level));
            }
        }
        if let Some((_, _, rule, level)) = best {
            return (level, rule.id.clone(), rule.ttl);
        }
    }

    // 2-4. Default floor: connection → category → global. Read/write split.
    let pick = |lv: &Levels| -> Option<(AccessLevel, Option<u64>)> {
        let l = if is_write_method(method) { lv.write } else { lv.read };
        l.map(|l| (l, lv.ttl))
    };
    if let Some(lv) = connection_levels {
        if let Some((l, ttl)) = pick(lv) {
            return (l, None, ttl);
        }
    }
    if let Some(cat) = category {
        if let Some(lv) = policy.categories.get(cat) {
            if let Some((l, ttl)) = pick(lv) {
                return (l, None, ttl);
            }
        }
    }
    if let Some(lv) = policy.default.as_ref() {
        if let Some((l, ttl)) = pick(lv) {
            return (l, None, ttl);
        }
    }

    // 5. Safe floor.
    (AccessLevel::AskAlways, None, None)
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::default()
    }

    fn rule(id: &str, pat: &str, level: AccessLevel) -> PolicyRule {
        PolicyRule {
            id: Some(id.into()),
            label: None,
            match_pattern: Some(pat.into()),
            body: None,
            level: Some(level),
            ttl: None,
        }
    }

    // ── AccessLevel ──────────────────────────────────────────────────────────
    #[test]
    fn access_level_parses_and_ranks() {
        assert_eq!(AccessLevel::parse("ask-always"), Some(AccessLevel::AskAlways));
        assert_eq!(AccessLevel::parse("nope"), None);
        assert!(AccessLevel::Deny.restrictiveness() > AccessLevel::Allow.restrictiveness());
    }

    // ── Path matching / specificity (unchanged engine) ───────────────────────
    #[test]
    fn wildcard_matches_one_segment() {
        assert!(path_matches("/repos/*/issues", "/repos/r/issues"));
        assert!(!path_matches("/repos/*", "/repos/o/r"));
    }

    #[test]
    fn specificity_exact_with_method_beats_wildcard() {
        assert!(
            specificity(&rule("a", "POST /m/send", AccessLevel::AskAlways))
                > specificity(&rule("b", "POST /m/*", AccessLevel::Allow))
        );
    }

    // ── Level resolution ─────────────────────────────────────────────────────
    #[test]
    fn level_on_rule_decides() {
        // The headline: list (allow) + read (ask) = read an email in ONE
        // approval, not two.
        let low = vec![rule("list", "GET /m", AccessLevel::Allow)];
        assert_eq!(evaluate("GET", "/m", None, Some(&low), None, &policy(), None), AccessLevel::Allow);
        let med = vec![rule("read", "GET /m/*", AccessLevel::Ask)];
        assert_eq!(evaluate("GET", "/m/1", None, Some(&med), None, &policy(), None), AccessLevel::Ask);
        let high = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        assert_eq!(evaluate("POST", "/m/send", None, Some(&high), None, &policy(), None), AccessLevel::AskAlways);
        let del = vec![rule("del", "DELETE /m/*", AccessLevel::Deny)];
        assert_eq!(evaluate("DELETE", "/m/1", None, Some(&del), None, &policy(), None), AccessLevel::Deny);
    }

    #[test]
    fn rule_with_no_level_is_skipped() {
        // A malformed rule (no level) can never decide → falls through to the
        // global default (allow).
        let bad = vec![PolicyRule {
            id: Some("bad".into()),
            label: None,
            match_pattern: Some("GET /x".into()),
            body: None,
            level: None,
            ttl: None,
        }];
        assert_eq!(evaluate("GET", "/x", None, Some(&bad), None, &policy(), None), AccessLevel::Allow);
    }

    // ── Conflict resolution: deny-override / most-restrictive ─────────────────
    #[test]
    fn most_restrictive_matching_rule_wins() {
        // Two rules match the same request; the stricter (deny) wins even though
        // it's less specific — fail-safe, not most-specific.
        let rules = vec![
            rule("broad", "DELETE /m/*", AccessLevel::Deny),      // less specific, stricter
            rule("narrow", "DELETE /m/safe", AccessLevel::Allow), // more specific, looser
        ];
        assert_eq!(
            evaluate("DELETE", "/m/safe", None, Some(&rules), None, &policy(), None),
            AccessLevel::Deny
        );
    }

    // ── Default floor chain ──────────────────────────────────────────────────
    #[test]
    fn no_rule_falls_through_to_connection_then_category_then_global() {
        // No matching rule → connection floor wins when set.
        let conn = Levels { read: Some(AccessLevel::Ask), write: None, ttl: None };
        assert_eq!(
            evaluate("GET", "/unmatched", None, Some(&vec![]), Some(&conn), &policy(), None),
            AccessLevel::Ask
        );
        // No connection floor → category (llm = allow).
        assert_eq!(
            evaluate("POST", "/v1/chat", None, None, None, &policy(), Some("llm")),
            AccessLevel::Allow
        );
        // No category match → global default (allow).
        assert_eq!(
            evaluate("GET", "/x", None, None, None, &policy(), Some("unknown")),
            AccessLevel::Allow
        );
    }

    // ── Merge: override by id + add new rule ──────────────────────────────────
    #[test]
    fn merge_overrides_level_by_id() {
        let built_in = vec![rule("read", "GET /m/*", AccessLevel::Ask)];
        let mut user = HashMap::new();
        user.insert("read".into(), RuleConfig { level: Some(AccessLevel::Allow), ..Default::default() });
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged[0].level, Some(AccessLevel::Allow));
        assert_eq!(merged[0].match_pattern.as_deref(), Some("GET /m/*")); // preserved
    }

    #[test]
    fn merge_lets_user_tighten_a_rule_to_deny() {
        let built_in = vec![rule("del", "DELETE /m/*", AccessLevel::AskAlways)];
        let mut user = HashMap::new();
        user.insert("del".into(), RuleConfig { level: Some(AccessLevel::Deny), ..Default::default() });
        let merged = merge_rules(&built_in, &user);
        assert_eq!(evaluate("DELETE", "/m/1", None, Some(&merged), None, &policy(), None), AccessLevel::Deny);
    }

    #[test]
    fn merge_adds_new_rule_with_match() {
        let built_in = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        let mut user = HashMap::new();
        user.insert("vip".into(), RuleConfig {
            match_pattern: Some("POST /m/vip".into()),
            level: Some(AccessLevel::Allow),
            ..Default::default()
        });
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|r| r.id.as_deref() == Some("vip") && r.level == Some(AccessLevel::Allow)));
    }

    #[test]
    fn merge_levels_user_wins_fieldwise() {
        let u = Levels { read: Some(AccessLevel::Allow), write: None, ttl: None };
        let r = Levels { read: Some(AccessLevel::Ask), write: Some(AccessLevel::Deny), ttl: Some(30) };
        let m = merge_levels(Some(&u), Some(&r)).unwrap();
        assert_eq!(m.read, Some(AccessLevel::Allow)); // user
        assert_eq!(m.write, Some(AccessLevel::Deny)); // recipe
        assert_eq!(m.ttl, Some(30));
    }

    // ── ask-cache scope: method is part of the key (regression) ──────────────
    #[test]
    fn matched_rule_id_and_ttl_returned_for_ask_cache() {
        let mut rules = vec![rule("read", "GET /x", AccessLevel::Ask)];
        rules[0].ttl = Some(60);
        let (lvl, id, ttl) = evaluate_with_match("GET", "/x", None, Some(&rules), None, &policy(), None);
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(id.as_deref(), Some("read"));
        assert_eq!(ttl, Some(60));
    }
}
