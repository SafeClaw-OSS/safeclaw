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
//! (deny-override / fail-safe) → connection default → tag default →
//! global default → floor (`ask-always`).
//!
//! Rule matching uses path patterns (nginx-style):
//! - `match`: `"METHOD /path/with/*/wildcards"` — `*` matches one path segment
//! - `body`: regex matched against request body text (optional), compiled once
//!   when its rule is loaded ([`BodyPattern`])
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

// ── Body patterns ──────────────────────────────────────────────────────────────

/// A rule's `body` predicate, compiled once when the rule is loaded (a
/// definition at the gate, a user edit when the sealed policy is read) and
/// matched with `is_match` only, so no request ever compiles a regex. The
/// builder limits follow the regex crate's "Untrusted input" guidance: a
/// bounded pattern length and an explicit compiled-size limit.
#[derive(Clone)]
pub struct BodyPattern {
    source: String,
    /// `Err` only for a user edit (`aux.policy`) whose pattern does not
    /// compile; a definition carrying one is rejected at the gate. See
    /// `matches_rule` for how such a rule decides. Shared, so the copies a
    /// per-request rule merge makes reuse one compiled program and its cache.
    compiled: Result<std::sync::Arc<Regex>, String>,
}

impl BodyPattern {
    /// Compile `source` under the definition limits, or say why it cannot be.
    pub fn compile(source: &str) -> Result<BodyPattern, String> {
        use crate::service::limits::{
            BODY_REGEX_DFA_SIZE_LIMIT, BODY_REGEX_NEST_LIMIT, BODY_REGEX_SIZE_LIMIT,
            MAX_BODY_PATTERN_BYTES,
        };
        if source.len() > MAX_BODY_PATTERN_BYTES {
            return Err(format!(
                "is {} bytes; the limit is {}",
                source.len(),
                MAX_BODY_PATTERN_BYTES
            ));
        }
        RegexBuilder::new(source)
            .size_limit(BODY_REGEX_SIZE_LIMIT)
            .dfa_size_limit(BODY_REGEX_DFA_SIZE_LIMIT)
            .nest_limit(BODY_REGEX_NEST_LIMIT)
            .build()
            .map(|re| BodyPattern {
                source: source.to_string(),
                compiled: Ok(std::sync::Arc::new(re)),
            })
            .map_err(|e| e.to_string())
    }

    /// A user edit's pattern: compiled now; one that does not compile is kept
    /// as unreadable rather than failing the whole sealed policy.
    pub fn lenient(source: &str) -> BodyPattern {
        Self::compile(source).unwrap_or_else(|e| BodyPattern {
            source: source.to_string(),
            compiled: Err(e),
        })
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Why the pattern does not compile, when it does not.
    pub fn error(&self) -> Option<&str> {
        self.compiled.as_ref().err().map(String::as_str)
    }

    /// Does the pattern match `text`? `None` when it is unreadable.
    fn is_match(&self, text: &str) -> Option<bool> {
        self.compiled.as_ref().ok().map(|re| re.is_match(text))
    }
}

impl std::fmt::Debug for BodyPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BodyPattern({:?})", self.source)
    }
}

impl Serialize for BodyPattern {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BodyPattern {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(BodyPattern::lenient(&String::deserialize(d)?))
    }
}

/// Serde for a rule's `match`: accept either a single `"METHOD /path"` string or
/// a list of them (OR — any pattern matches). A single pattern serializes back
/// as a bare string so registry.json stays byte-stable for the common one-match
/// rule; a list serializes as a list. Used by the core [`PolicyRule`] and mirrored
/// by the service-registry (`PolicyFileRule`) and registry-response types.
pub(crate) mod match_spec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        Ok(match OneOrMany::deserialize(d)? {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        })
    }

    pub fn serialize<S: Serializer>(v: &[String], s: S) -> Result<S::Ok, S::Error> {
        if v.len() == 1 {
            v[0].serialize(s)
        } else {
            v.serialize(s)
        }
    }
}

// ── Access Level ───────────────────────────────────────────────────────────────

/// The access DECISION for a request.
///
/// - `Allow`: pass through immediately, no approval
/// - `Ask`: approve once; the approval holds for the rule's / floor's `ttl`
///   (what it covers: `crate::approval::reuse`)
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
    /// Path pattern(s): `"METHOD /path"` or `"/path"` (any method). `*` = one
    /// segment. Accepts a single string OR a list — a list is an OR (the rule
    /// fires if ANY pattern matches), for one logical operation exposed at
    /// several endpoints (e.g. a Beta and an Alpha endpoint that do the same
    /// thing). This is the REST-side equivalent of the `body` regex's OR that
    /// collapses several GraphQL mutations into one rule. Empty = no path/method
    /// constraint (the rule decides on `body` alone, or unconditionally).
    #[serde(
        default,
        rename = "match",
        skip_serializing_if = "Vec::is_empty",
        with = "match_spec"
    )]
    pub match_patterns: Vec<String>,
    /// Regex matched against request body text. Omit to skip body matching.
    #[serde(default)]
    pub body: Option<BodyPattern>,
    /// A structured field condition, AND-combined with `match`/`body`:
    /// `"vars.<name> <op> <literal>"`, e.g. `"vars.amount > 80"`. The var is
    /// resolved from the request's matching `[requests]` shape (service.toml);
    /// an UNDEFINED var makes the condition — and so the rule — not match
    /// (policy is an explicit contract, we never fabricate a decision). See
    /// [`Condition`] and design/request-scope.md.
    #[serde(default)]
    pub when: Option<String>,
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
/// the connection, tag, and global layers. The read/write split is the
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
    pub body: Option<BodyPattern>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
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
    /// Per-tag default floor, keyed by service tag (e.g. "ai", "messaging").
    /// Beats `default`. Serde name stays `categories` — the map is sealed in
    /// `aux.policy`, and its KEYS are data, so the tags cutover needed no
    /// schema change (stale old-name keys simply never match).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub categories: HashMap<String, Levels>,
    /// Per-connection user policy, keyed by `connection_id`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub connections: HashMap<String, ConnectionPolicy>,
    /// The owner's switch for installed services (definitions stored with a
    /// source): off (absent) = the vault neither loads nor adds them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_installed_services: bool,
}

impl Default for Policy {
    fn default() -> Self {
        // Design stance: SafeClaw is *first* a credential-separating proxy —
        // the agent never holds the secret, the daemon injects it — and only
        // *secondly* an approval gate for risky operations. So the baseline
        // floor is `allow` (inject + forward, no per-call friction); services
        // tighten genuinely sensitive paths with a stricter `level` on rules.
        // (ai/messaging are redundant with the global default but kept
        // explicit so a future stricter global default doesn't silently
        // re-gate them.)
        let allow_rw = || Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Allow),
            ttl: None,
        };
        let mut categories = HashMap::new();
        categories.insert("ai".into(), allow_rw());
        categories.insert("messaging".into(), allow_rw());
        Self {
            // ONE approval window (SSOT, user decision 2026-07-14): every
            // pending-op surface derives from this — broker asks, CLI
            // ceremonies (op.rs stamps it), the value stash, the relay poll
            // budget, and the grant-page countdown.
            timeout: Some(1800),
            default: Some(allow_rw()),
            categories,
            connections: HashMap::new(),
            allow_installed_services: false,
        }
    }
}

impl Policy {
    /// Overlay a user's sparse `aux.policy` onto the compiled defaults so unset
    /// parts (global floor, tag defaults) keep safe values. Called at
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
            p.allow_installed_services = u.allow_installed_services;
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
pub fn merge_rules(built_in: &[PolicyRule], user: &HashMap<String, RuleConfig>) -> Vec<PolicyRule> {
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
                    when: e.when.clone().or_else(|| rule.when.clone()),
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
                match_patterns: vec![m.clone()],
                body: e.body.clone(),
                when: e.when.clone(),
                level: e.level,
                ttl: e.ttl,
            });
        }
    }
    out
}

/// A connection's own rule edit that cannot be enforced as written on a
/// scoped request (the service declares a `[requests]` shape for its path),
/// with the reason; `None` when every edit covering the request is
/// enforceable.
///
/// An approval on a scoped path binds only the matched shape's `scope`
/// values, so a rule whose decision depends on anything else could be
/// approved for one request and then decide a different request the approval
/// still matches. The same invariant the compiled policies are held to (the
/// gate, `service::gate`: a deciding field must be bound), applied per
/// request to the user's edits:
///   - a `when` on a var the matched shape declares but does not bind;
///   - a `body` regex (the body is never bound).
///
/// Each edit is judged as the rule it produces: the MERGED rule
/// ([`merge_rules`]), so an edit of only `level` on a built-in rule that has
/// a `body` decides on that body and is judged so. Only rules a user edit
/// touches (`aux.policy.connections.<id>.rules`) are checked, only those that
/// decide `ask` or `ask-always` (an `allow` or `deny` mints no approval and
/// is re-decided on every request), and only those whose `match` covers this
/// request. A `when` naming a var this shape does not declare never fires
/// here (P3) and is not refused.
/// `shape` / `declared` / `binds` describe the matched shape
/// (`crate::service::RequestScope`).
pub fn unenforceable_user_rule(
    built_in: &[PolicyRule],
    user: &HashMap<String, RuleConfig>,
    method: &str,
    path: &str,
    shape: &str,
    declared: &[String],
    binds: &[String],
) -> Option<String> {
    let merged = merge_rules(built_in, user);
    let mut edited: Vec<(&str, &PolicyRule)> = merged
        .iter()
        .filter_map(|r| {
            let id = r.id.as_deref()?;
            user.contains_key(id).then_some((id, r))
        })
        .collect();
    edited.sort_by_key(|(id, _)| *id);
    for (id, rule) in edited {
        // Only an ask decision mints an approval this could ride: `allow` and
        // `deny` (or no level) are re-decided on every request.
        if !matches!(rule.level, Some(AccessLevel::Ask | AccessLevel::AskAlways)) {
            continue;
        }
        let covers = rule.match_patterns.is_empty()
            || rule
                .match_patterns
                .iter()
                .any(|p| pattern_matches(p, method, path));
        if !covers {
            continue;
        }
        if rule.body.is_some() {
            return Some(format!(
                "this connection's policy rule '{}' decides on the request body, which an approval \
                 on this path does not bind (it binds only the [requests.{}] scope fields); remove \
                 the rule's body match, or gate it with `when` on a bound field",
                id, shape
            ));
        }
        let Some(cond) = rule.when.as_deref().and_then(Condition::parse) else {
            continue; // an unparseable `when` never matches (P3)
        };
        let var = cond.var_name();
        // The declared fields the `when` can resolve to, by the same lookup
        // evaluation uses (`extract_request_scope` inserts each var as `name`
        // and as `<shape>.name`). None: it never resolves on this path.
        let qualified = format!("{}.", shape);
        let fields: Vec<&str> = [Some(var), var.strip_prefix(qualified.as_str())]
            .into_iter()
            .flatten()
            .filter(|f| declared.iter().any(|d| d == f))
            .collect();
        if fields.iter().any(|f| !binds.iter().any(|b| b == f)) {
            return Some(format!(
                "this connection's policy rule '{}' gates on `vars.{}`, which the [requests.{}] \
                 shape does not bind, so an approval could not hold it fixed; gate the rule on a \
                 bound field instead",
                id, var, shape
            ));
        }
    }
    None
}

// ── Path Pattern Matching ─────────────────────────────────────────────────────

/// Parse a match pattern into (optional_method, path_pattern). The first word
/// is the method when it is ASCII letters in any case (`DELETE /x`,
/// `delete /x`); every rule source (policy.toml, inline policy, a user edit)
/// reads it the same way, and matching compares it case-insensitively.
fn parse_match_pattern(pattern: &str) -> (Option<&str>, &str) {
    if let Some((method, path)) = pattern.split_once(' ') {
        if !method.is_empty() && method.bytes().all(|b| b.is_ascii_alphabetic()) {
            return (Some(method), path.trim_start());
        }
    }
    (None, pattern)
}

/// Why a definition's `match` pattern could never match a request, or `None`
/// when it is well formed: `"/path"` or `"METHOD /path"`, the path starting
/// with `/`, free of whitespace, `?` and `#` (matching sees the path without
/// its query), with `**` only as the final segment.
pub(crate) fn match_pattern_problem(pattern: &str) -> Option<String> {
    let (method, path) = parse_match_pattern(pattern);
    if method.is_none() && pattern.contains(char::is_whitespace) {
        return Some(format!(
            "match '{}' must be \"/path\" or \"METHOD /path\" (METHOD in letters)",
            pattern
        ));
    }
    if !path.starts_with('/') {
        return Some(format!("match '{}': the path must start with '/'", pattern));
    }
    if path.contains(char::is_whitespace) || path.contains(['?', '#']) {
        return Some(format!(
            "match '{}': the path may not contain whitespace, '?' or '#'",
            pattern
        ));
    }
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    if let Some((_, init)) = segments.split_last() {
        if init.contains(&"**") {
            return Some(format!(
                "match '{}': '**' is only allowed as the final segment",
                pattern
            ));
        }
    }
    None
}

/// Could one request match both patterns? Methods agree when either is absent
/// or they are equal ignoring case; paths agree segment by segment (`*` is
/// any one segment, a final `**` any one or more). A path-level check only:
/// it decides whether a rule can apply on a path a `[requests]` shape covers.
pub(crate) fn patterns_overlap(a: &str, b: &str) -> bool {
    let (ma, pa) = parse_match_pattern(a);
    let (mb, pb) = parse_match_pattern(b);
    if let (Some(x), Some(y)) = (ma, mb) {
        if !x.eq_ignore_ascii_case(y) {
            return false;
        }
    }
    let split = |p: &str| -> (Vec<String>, bool) {
        let mut segs: Vec<String> = p
            .trim_end_matches('/')
            .split('/')
            .map(str::to_string)
            .collect();
        let rest = segs.last().is_some_and(|s| s == "**");
        if rest {
            segs.pop();
        }
        (segs, rest)
    };
    let (sa, ra) = split(pa);
    let (sb, rb) = split(pb);
    let seg_ok = |x: &String, y: &String| x == "*" || y == "*" || x == y;
    let common = sa.len().min(sb.len());
    if !sa
        .iter()
        .zip(sb.iter())
        .take(common)
        .all(|(x, y)| seg_ok(x, y))
    {
        return false;
    }
    match (ra, rb) {
        // Fixed lengths must agree.
        (false, false) => sa.len() == sb.len(),
        // `a/**` needs at least one segment past its prefix; `b` fixed supplies it.
        (true, false) => sb.len() > sa.len(),
        (false, true) => sa.len() > sb.len(),
        // Both open-ended: a path long enough for both exists.
        (true, true) => true,
    }
}

/// Match a request path against a pattern. `*` matches exactly one path
/// segment; a trailing `**` matches one-or-more remaining segments (only
/// meaningful as the final segment — it lets a single rule cover
/// variable-depth paths like git refs `git/refs/heads/feature/x` or nested
/// file paths). `**` anywhere but last is treated as a literal (won't match).
fn path_matches(pattern: &str, path: &str) -> bool {
    let pat_segments: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let path_segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();

    // Trailing `**`: the fixed prefix must match segment-for-segment, and the
    // path must have at least one further segment for `**` to cover.
    if let Some((last, prefix)) = pat_segments.split_last() {
        if *last == "**" {
            if path_segments.len() <= prefix.len() {
                return false;
            }
            return prefix
                .iter()
                .zip(path_segments.iter())
                .all(|(p, s)| *p == "*" || p == s);
        }
    }

    if pat_segments.len() != path_segments.len() {
        return false;
    }
    pat_segments
        .iter()
        .zip(path_segments.iter())
        .all(|(p, s)| *p == "*" || p == s)
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
    // A match list scores by its most-specific pattern (the best case): a rule
    // is at least as specific as its tightest alternative.
    let path_score = rule
        .match_patterns
        .iter()
        .map(|pattern| {
            let (method, path) = parse_match_pattern(pattern);
            let mut s: u32 = if method.is_some() { 5 } else { 0 };
            for seg in path.split('/') {
                if !seg.is_empty() && seg != "*" && seg != "**" {
                    s += 10;
                }
            }
            s
        })
        .max()
        .unwrap_or(0);
    score + path_score
}

// ── `when` field conditions ──────────────────────────────────────────────────

/// Extracted request variables, `var-name → value` (the value as a string: a
/// JSON number renders canonically, a JSON string is itself, a query param is
/// its raw value). Produced by the service layer from the matching `[requests]`
/// shape (service.toml); consumed here to evaluate a rule's `when`. Both the
/// bare name (`amount`) and, for a matched shape, the qualified name
/// (`purchase.amount`) are inserted so a rule spanning several shapes can
/// disambiguate. Empty when a request matched no shape.
pub type VarMap = std::collections::HashMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Gt,
    Lt,
    Ge,
    Le,
    Eq,
    Ne,
}

/// A parsed `when` predicate: `vars.<name> <op> <literal>`. v1 grammar — one
/// comparison, no boolean combinators (compose by writing separate rules, which
/// resolve most-restrictive-wins). The `vars.` prefix mirrors K8s
/// ValidatingAdmissionPolicy's `variables.<name>` and keeps room for future
/// built-ins without a parser dependency.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    /// The var name with the `vars.` prefix stripped (may be qualified,
    /// e.g. `purchase.amount`).
    var: String,
    op: CmpOp,
    /// The literal: numeric if it parsed as one, else the raw (unquoted) string.
    lit_num: Option<f64>,
    lit_str: String,
}

impl Condition {
    /// Parse `"vars.<name> <op> <literal>"`. Returns `None` for any malformed
    /// input (no `vars.` prefix, unknown operator, empty operand) — build-time
    /// verification rejects those, so at runtime `None` is treated as a
    /// non-matching rule (fail-safe: an unparseable predicate never *grants*).
    pub fn parse(s: &str) -> Option<Condition> {
        let s = s.trim();
        // Operators longest-first so `>=` isn't read as `>`.
        const OPS: &[(&str, CmpOp)] = &[
            (">=", CmpOp::Ge),
            ("<=", CmpOp::Le),
            ("==", CmpOp::Eq),
            ("!=", CmpOp::Ne),
            (">", CmpOp::Gt),
            ("<", CmpOp::Lt),
        ];
        let (lhs, op, rhs) = OPS.iter().find_map(|(tok, op)| {
            let idx = s.find(tok)?;
            Some((s[..idx].trim(), *op, s[idx + tok.len()..].trim()))
        })?;
        let var = lhs.strip_prefix("vars.")?.trim();
        if var.is_empty() || rhs.is_empty() {
            return None;
        }
        // A quoted literal is always a string; else try numeric, fall back to
        // a bare string.
        let (lit_num, lit_str) =
            if let Some(inner) = rhs.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                (None, inner.to_string())
            } else {
                (rhs.parse::<f64>().ok(), rhs.to_string())
            };
        Some(Condition {
            var: var.to_string(),
            op,
            lit_num,
            lit_str,
        })
    }

    /// The referenced var name (`vars.` already stripped; may be qualified
    /// `shape.name`). Used by build-time verification to check membership in the
    /// service's declared `[requests]` vars.
    pub fn var_name(&self) -> &str {
        &self.var
    }

    /// Why this condition could never decide a request, or `None`: a numeric
    /// literal must be finite (`NaN`, `inf`, `1e400` compare as nothing
    /// useful), and an ordering comparison needs a number (an ordering
    /// against `80usd` or a quoted string is never true, see [`Self::eval`]).
    pub fn never_fires(&self) -> Option<&'static str> {
        match self.lit_num {
            Some(n) if !n.is_finite() => Some("its literal is not a finite number"),
            None if matches!(self.op, CmpOp::Gt | CmpOp::Lt | CmpOp::Ge | CmpOp::Le) => {
                Some("an ordering comparison needs a numeric literal")
            }
            _ => None,
        }
    }

    /// Evaluate against the request vars. An undefined var → `false` (P3: the
    /// rule simply doesn't match; the engine invents no decision). Ordering
    /// comparisons need both sides numeric; equality falls back to string.
    pub fn eval(&self, vars: &VarMap) -> bool {
        let Some(value) = vars.get(&self.var) else {
            return false;
        };
        // Trim so a padded amount (`"100 "`, `"\t80"`) that the upstream still
        // reads as a number can't slip under a threshold gate by failing our
        // parse; reject non-finite (NaN/inf) so exotic encodings don't compare
        // in surprising ways. A value that still isn't a finite number stays
        // `None` → an ordering condition is false (the base rule keeps gating).
        let value_num = value.trim().parse::<f64>().ok().filter(|n| n.is_finite());
        match self.op {
            CmpOp::Eq => match self.lit_num {
                Some(n) => value_num == Some(n),
                None => value == &self.lit_str,
            },
            CmpOp::Ne => match self.lit_num {
                Some(n) => value_num != Some(n),
                None => value != &self.lit_str,
            },
            // Ordering: only meaningful when both sides are numbers. A
            // non-numeric value (or a non-numeric literal) can't satisfy `>`,
            // so the condition is false — never an error, never a grant.
            CmpOp::Gt | CmpOp::Lt | CmpOp::Ge | CmpOp::Le => match (value_num, self.lit_num) {
                (Some(v), Some(n)) => match self.op {
                    CmpOp::Gt => v > n,
                    CmpOp::Lt => v < n,
                    CmpOp::Ge => v >= n,
                    CmpOp::Le => v <= n,
                    _ => unreachable!(),
                },
                _ => false,
            },
        }
    }
}

/// Does a single `"METHOD /path"` (or `"/path"`) pattern match this request?
/// The method/path half of rule matching, exposed so the service layer can
/// resolve which `[requests]` shape a request hits with the SAME grammar the
/// policy rules use (no second matcher to drift). The method compares
/// case-insensitively: the proxy normalizes it to uppercase at ingress, and a
/// caller that did not still matches the rule it names.
pub(crate) fn pattern_matches(pattern: &str, method: &str, path: &str) -> bool {
    let path_no_query = path.split('?').next().unwrap_or(path);
    let (rule_method, rule_path) = parse_match_pattern(pattern);
    if let Some(m) = rule_method {
        if !m.eq_ignore_ascii_case(method) {
            return false;
        }
    }
    path_matches(rule_path, path_no_query)
}

/// Check if a single rule matches the given request.
fn matches_rule(
    rule: &PolicyRule,
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
) -> bool {
    if !rule.match_patterns.is_empty() {
        // OR across the rule's patterns: the rule's path/method predicate holds
        // if ANY listed "METHOD /path" matches this request.
        let any = rule
            .match_patterns
            .iter()
            .any(|pattern| pattern_matches(pattern, method, path));
        if !any {
            return false;
        }
    }
    if let Some(ref pattern) = rule.body {
        match pattern.is_match(body.unwrap_or("")) {
            Some(true) => {}
            Some(false) => return false,
            // An unreadable pattern (only a user edit can carry one; the gate
            // rejects a definition with one) never loosens a decision: the
            // rule matches wherever it would restrict, and never where it
            // would allow.
            None => {
                if !matches!(
                    rule.level,
                    Some(AccessLevel::Ask | AccessLevel::AskAlways | AccessLevel::Deny)
                ) {
                    return false;
                }
            }
        }
    }
    // `when` field condition: an unparseable predicate or an undefined/failing
    // var means the rule does NOT match (P3 — never fabricate a decision).
    if let Some(ref cond) = rule.when {
        match Condition::parse(cond) {
            Some(c) if c.eval(vars) => {}
            _ => return false,
        }
    }
    true
}

// ── Policy Evaluation ──────────────────────────────────────────────────────────

/// The read/write split the default floors and the reuse classes use. Fails
/// closed: only `GET`, `HEAD` and `OPTIONS` (any case) are reads; every other
/// method, including extension methods (`MOVE`, `PROPPATCH`, …), is a write.
pub(crate) fn is_write_method(method: &str) -> bool {
    !["GET", "HEAD", "OPTIONS"]
        .iter()
        .any(|read| read.eq_ignore_ascii_case(method))
}

/// Determine the access level for a request. See [`evaluate_with_match`].
pub fn evaluate(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> AccessLevel {
    evaluate_with_match(
        method,
        path,
        body,
        vars,
        rules,
        connection_levels,
        policy,
        tags,
    )
    .0
}

/// What decided a request: a matched rule, or a default floor (connection,
/// tag, global, or the safe floor). The unit an `ask` approval is reused by
/// (`crate::approval::Reuse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedBy {
    /// A rule matched; its `id` and `label` as declared.
    Rule {
        id: Option<String>,
        label: Option<String>,
    },
    /// No rule matched.
    Floor,
}

/// Resolve the access decision for a request, returning `(level,
/// matched_rule_id, ttl)`. See [`evaluate_decision`], which also says what
/// decided it.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_match(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> (AccessLevel, Option<String>, Option<u64>) {
    let (level, by, ttl) = evaluate_decision(
        method,
        path,
        body,
        vars,
        rules,
        connection_levels,
        policy,
        tags,
    );
    let id = match by {
        DecidedBy::Rule { id, .. } => id,
        DecidedBy::Floor => None,
    };
    (level, id, ttl)
}

/// The stricter of two decisions for one request: `overlay` only where it is
/// more restrictive than `base`, a tie keeps `base`. How a policy that may
/// only tighten (a vault definition's) joins the decision made without it.
pub fn stricter(
    base: (AccessLevel, DecidedBy, Option<u64>),
    overlay: (AccessLevel, DecidedBy, Option<u64>),
) -> (AccessLevel, DecidedBy, Option<u64>) {
    if overlay.0.restrictiveness() > base.0.restrictiveness() {
        overlay
    } else {
        base
    }
}

/// Resolve the access decision for a request, returning `(level, what decided
/// it, ttl)`.
///
/// Resolution (PROTOCOL.md §6.4):
///   1. Among ALL matching rules, the **most restrictive** effective level wins
///      (deny-override / fail-safe). Ties broken by specificity for a
///      deterministic ask-cache scope (`(connection, rule_id, method)`).
///   2. else connection default (read/write floor),
///   3. else tag default (the service's tags matched against the
///      `Policy.categories` floor map; several hits → most restrictive wins),
///   4. else global default,
///   5. else `ask-always` (safe floor).
///
/// [`DecidedBy::Rule`] when a rule decided (step 1), else
/// [`DecidedBy::Floor`].
#[allow(clippy::too_many_arguments)]
pub fn evaluate_decision(
    method: &str,
    path: &str,
    body: Option<&str>,
    vars: &VarMap,
    rules: Option<&Vec<PolicyRule>>,
    connection_levels: Option<&Levels>,
    policy: &Policy,
    tags: &[String],
) -> (AccessLevel, DecidedBy, Option<u64>) {
    // The `ask`-cache window a matched rule inherits when it pins no `ttl` of
    // its own: the ttl of the most-specific floor (connection → tag → global),
    // the SAME precedence as the read/write floor decision below. Direction-
    // independent (Levels.ttl is a single value). Resolved up front because a
    // rule decision returns early; consumed only by an `ask` rule (a floor
    // decision returns its own floor's ttl), and a final constant fills in
    // when nothing pins a window at all.
    let floor_ttl = connection_levels
        .and_then(|lv| lv.ttl)
        .or_else(|| {
            tags.iter()
                .filter_map(|t| policy.categories.get(t))
                .find_map(|lv| lv.ttl)
        })
        .or_else(|| policy.default.as_ref().and_then(|lv| lv.ttl));

    // 1. Rules — most-restrictive matching wins (deny-override).
    if let Some(rules) = rules {
        let mut best: Option<(u8, u32, &PolicyRule, AccessLevel)> = None;
        for rule in rules {
            if !matches_rule(rule, method, path, body, vars) {
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
            // The rule's own ttl wins; else it inherits the default-floor window.
            let by = DecidedBy::Rule {
                id: rule.id.clone(),
                label: rule.label.clone(),
            };
            return (level, by, rule.ttl.or(floor_ttl));
        }
    }

    // 2-4. Default floor: connection → tag → global. Read/write split.
    let pick = |lv: &Levels| -> Option<(AccessLevel, Option<u64>)> {
        let l = if is_write_method(method) {
            lv.write
        } else {
            lv.read
        };
        l.map(|l| (l, lv.ttl))
    };
    if let Some(lv) = connection_levels {
        if let Some((l, ttl)) = pick(lv) {
            return (l, DecidedBy::Floor, ttl);
        }
    }
    // A service may carry several tags; if more than one hits a floor that
    // decides this method, the most restrictive wins (fail-closed, mirrors
    // the rule-layer deny-override above).
    let tag_hit = tags
        .iter()
        .filter_map(|t| policy.categories.get(t))
        .filter_map(|lv| pick(lv))
        .max_by_key(|(l, _)| l.restrictiveness());
    if let Some((l, ttl)) = tag_hit {
        return (l, DecidedBy::Floor, ttl);
    }
    if let Some(lv) = policy.default.as_ref() {
        if let Some((l, ttl)) = pick(lv) {
            return (l, DecidedBy::Floor, ttl);
        }
    }

    // 5. Safe floor.
    (AccessLevel::AskAlways, DecidedBy::Floor, None)
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
            match_patterns: vec![pat.into()],
            body: None,
            when: None,
            level: Some(level),
            ttl: None,
        }
    }

    // ── ask-once window (ttl) resolution ─────────────────────────────────────
    #[test]
    fn ask_rule_without_ttl_inherits_floor_window() {
        let rules = vec![rule("del", "DELETE /x", AccessLevel::Ask)]; // ttl: None
        let conn = Levels {
            read: None,
            write: None,
            ttl: Some(1234),
        };

        // A matched ask rule that pins no ttl inherits the connection-floor window.
        let (_l, id, ttl) = evaluate_with_match(
            "DELETE",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            Some(&conn),
            &policy(),
            &[],
        );
        assert_eq!(id.as_deref(), Some("del"));
        assert_eq!(ttl, Some(1234));

        // The rule's own ttl wins over the floor window.
        let mut pinned = rules.clone();
        pinned[0].ttl = Some(60);
        let (_l2, _id2, ttl2) = evaluate_with_match(
            "DELETE",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&pinned),
            Some(&conn),
            &policy(),
            &[],
        );
        assert_eq!(ttl2, Some(60));

        // No ttl anywhere in the floors → None (the proxy applies its constant).
        let bare = Levels::default();
        let (_l3, _id3, ttl3) = evaluate_with_match(
            "DELETE",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            Some(&bare),
            &policy(),
            &[],
        );
        assert_eq!(ttl3, None);
    }

    // ── AccessLevel ──────────────────────────────────────────────────────────
    #[test]
    fn access_level_parses_and_ranks() {
        assert_eq!(
            AccessLevel::parse("ask-always"),
            Some(AccessLevel::AskAlways)
        );
        assert_eq!(AccessLevel::parse("nope"), None);
        assert!(AccessLevel::Deny.restrictiveness() > AccessLevel::Allow.restrictiveness());
    }

    // ── Connection rule edits on scoped paths ────────────────────────────────
    #[test]
    fn user_rule_on_a_scoped_path_must_decide_on_bound_fields() {
        let built_in = vec![rule("pay", "POST /pay", AccessLevel::Ask)];
        let declared = vec!["amount".to_string(), "memo".to_string()];
        let binds = vec!["amount".to_string()];
        let check = |user: &HashMap<String, RuleConfig>, m: &str, p: &str| {
            unenforceable_user_rule(&built_in, user, m, p, "purchase", &declared, &binds)
        };
        let add = |pat: Option<&str>, when: Option<&str>, body: Option<&str>| RuleConfig {
            match_pattern: pat.map(str::to_string),
            when: when.map(str::to_string),
            body: body.map(BodyPattern::lenient),
            level: Some(AccessLevel::AskAlways),
            ..Default::default()
        };
        let mut user = HashMap::new();
        // Gating on a bound field is enforceable.
        user.insert(
            "big".to_string(),
            add(Some("POST /pay"), Some("vars.amount > 100"), None),
        );
        assert_eq!(check(&user, "POST", "/pay"), None);

        // A declared but unbound field decides: refused, by rule and field.
        user.insert(
            "memo".to_string(),
            add(Some("POST /pay"), Some("vars.memo == \"x\""), None),
        );
        let e = check(&user, "post", "/pay").expect("refused");
        assert!(e.contains("'memo'") && e.contains("vars.memo"), "{e}");
        assert!(!e.contains('\u{2014}'), "no em dash in copy");
        // Only where the rule's match covers the request.
        assert_eq!(check(&user, "POST", "/other"), None);
        user.remove("memo");

        // Qualified by this shape: the same field; by another shape: never
        // resolves here, so not refused. An undeclared var never fires.
        user.insert(
            "q".to_string(),
            add(Some("POST /pay"), Some("vars.purchase.memo == 1"), None),
        );
        assert!(check(&user, "POST", "/pay").is_some());
        user.insert(
            "q".to_string(),
            add(Some("POST /pay"), Some("vars.refund.memo == 1"), None),
        );
        assert_eq!(check(&user, "POST", "/pay"), None);
        user.insert(
            "q".to_string(),
            add(Some("POST /pay"), Some("vars.nope == 1"), None),
        );
        assert_eq!(check(&user, "POST", "/pay"), None);
        user.remove("q");

        // An override of a built-in rule by id is checked on the built-in's
        // match, with the built-in's level.
        user.insert(
            "pay".to_string(),
            RuleConfig {
                when: Some("vars.memo == 1".into()),
                ..Default::default()
            },
        );
        assert!(check(&user, "POST", "/pay").unwrap().contains("'pay'"));
        user.remove("pay");

        // A body match on a covered scoped path: refused (the body is never bound).
        user.insert("b".to_string(), add(Some("/pay"), None, Some("refund")));
        let e = check(&user, "POST", "/pay").expect("refused");
        assert!(e.contains("'b'") && e.contains("body"), "{e}");
        assert_eq!(check(&user, "POST", "/elsewhere"), None);
        user.remove("b");

        // `allow` / `deny` edits mint no approval: never refused.
        for level in [AccessLevel::Allow, AccessLevel::Deny] {
            let mut only = HashMap::new();
            only.insert(
                "protect".to_string(),
                RuleConfig {
                    level: Some(level),
                    ..add(Some("POST /pay"), Some("vars.memo == 1"), Some("bitcoin"))
                },
            );
            assert_eq!(check(&only, "POST", "/pay"), None, "{level:?}");
        }

        // A declared var whose own name has a dot resolves verbatim, as at
        // evaluation.
        let dotted = vec!["a.b".to_string(), "amount".to_string()];
        let mut only = HashMap::new();
        only.insert(
            "d".to_string(),
            add(Some("POST /pay"), Some("vars.a.b == 1"), None),
        );
        assert!(unenforceable_user_rule(
            &built_in, &only, "POST", "/pay", "purchase", &dotted, &binds
        )
        .is_some());
    }

    #[test]
    fn scoped_check_judges_the_merged_rule() {
        // A built-in `deny` that decides on the body; an edit of only its
        // level to `ask` produces an ask that decides on the body, which an
        // approval on this scoped path does not bind: refused.
        let built_in = vec![PolicyRule {
            body: Some(BodyPattern::compile("gift").unwrap()),
            ..rule("gifts", "POST /pay", AccessLevel::Deny)
        }];
        let declared = vec!["amount".to_string()];
        let binds = vec!["amount".to_string()];
        let check = |user: &HashMap<String, RuleConfig>| {
            unenforceable_user_rule(
                &built_in, user, "POST", "/pay", "purchase", &declared, &binds,
            )
        };
        let mut user = HashMap::new();
        assert_eq!(check(&user), None, "the built-in deny mints no approval");
        user.insert(
            "gifts".to_string(),
            RuleConfig {
                level: Some(AccessLevel::Ask),
                ..Default::default()
            },
        );
        let e = check(&user).expect("level-only edit on a body rule");
        assert!(e.contains("'gifts'") && e.contains("body"), "{e}");
        // A `ttl`-only edit keeps the deny: nothing to refuse.
        user.insert(
            "gifts".to_string(),
            RuleConfig {
                ttl: Some(60),
                ..Default::default()
            },
        );
        assert_eq!(check(&user), None);
        // A built-in ask gated on a field this shape does not bind, edited
        // only in ttl: the merged rule still decides on that field.
        let built_in = vec![PolicyRule {
            when: Some("vars.memo == 1".into()),
            ..rule("memo", "POST /pay", AccessLevel::Ask)
        }];
        let declared = vec!["amount".to_string(), "memo".to_string()];
        let mut user = HashMap::new();
        user.insert(
            "memo".to_string(),
            RuleConfig {
                ttl: Some(60),
                ..Default::default()
            },
        );
        assert!(unenforceable_user_rule(
            &built_in, &user, "POST", "/pay", "purchase", &declared, &binds
        )
        .is_some());
    }

    #[test]
    fn method_word_is_case_insensitive_at_every_source() {
        assert_eq!(
            parse_match_pattern("delete /repos/*/*"),
            (Some("delete"), "/repos/*/*")
        );
        assert_eq!(parse_match_pattern("Patch /x"), (Some("Patch"), "/x"));
        assert_eq!(parse_match_pattern("/x"), (None, "/x"));
        // A user edit's `match` is read the same way.
        let mut user = HashMap::new();
        user.insert(
            "del".to_string(),
            RuleConfig {
                match_pattern: Some("delete /repos/*/*".into()),
                level: Some(AccessLevel::Deny),
                ..Default::default()
            },
        );
        let rules = merge_rules(&[], &user);
        let level = evaluate(
            "DELETE",
            "/repos/o/r",
            None,
            &VarMap::new(),
            Some(&rules),
            None,
            &policy(),
            &[],
        );
        assert_eq!(level, AccessLevel::Deny);
        // Specificity counts the method in any case.
        assert_eq!(
            specificity(&rule("a", "delete /x", AccessLevel::Ask)),
            specificity(&rule("b", "DELETE /x", AccessLevel::Ask))
        );
    }

    #[test]
    fn match_patterns_that_cannot_match_are_named() {
        for good in [
            "/x",
            "GET /x",
            "get /x/*",
            "/repos/*/*/git/refs/**",
            "POST /",
        ] {
            assert_eq!(match_pattern_problem(good), None, "{good}");
        }
        for bad in [
            "x", "GET x", "/a b", "/x?y=1", "/x#f", "/a/**/b", "GE T /x", "",
        ] {
            assert!(match_pattern_problem(bad).is_some(), "{bad}");
        }
    }

    #[test]
    fn pattern_overlap() {
        assert!(patterns_overlap("POST /buy", "POST /buy"));
        assert!(patterns_overlap("/buy", "POST /buy"));
        assert!(patterns_overlap("post /buy", "POST /buy"));
        assert!(patterns_overlap("POST /*", "POST /buy"));
        assert!(patterns_overlap("/**", "POST /a/b"));
        assert!(patterns_overlap("/a/**", "/a/*/c"));
        assert!(patterns_overlap("/a/**", "/*/b/**"));
        assert!(!patterns_overlap("GET /buy", "POST /buy"));
        assert!(!patterns_overlap("POST /buy", "POST /refund"));
        assert!(!patterns_overlap("/a/*", "/a/b/c"));
        assert!(!patterns_overlap("/a/**", "/a"));
        assert!(!patterns_overlap("/a/b/**", "/a/c/d"));
    }

    #[test]
    fn body_patterns_compile_once_and_unreadable_ones_never_loosen() {
        let p = BodyPattern::compile("gift|card").unwrap();
        assert_eq!(p.is_match("a gift"), Some(true));
        assert_eq!(p.is_match("cash"), Some(false));
        assert!(BodyPattern::compile("(unclosed").is_err());
        assert!(BodyPattern::compile(&"a".repeat(2000)).is_err());
        // Serde: a sealed user edit with a bad pattern still loads.
        let edit: RuleConfig = serde_json::from_value(
            serde_json::json!({"match": "POST /x", "body": "(", "level": "deny"}),
        )
        .unwrap();
        let body = edit.body.as_ref().unwrap();
        assert!(body.error().is_some());
        assert_eq!(serde_json::to_value(body).unwrap(), serde_json::json!("("));
        // The rule that carries it restricts everywhere its match covers, and
        // never allows.
        let with = |level| {
            vec![PolicyRule {
                body: Some(BodyPattern::lenient("(")),
                ..rule("r", "POST /x", level)
            }]
        };
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Ask),
            ttl: None,
        };
        let decide = |rules: &Vec<PolicyRule>| {
            evaluate(
                "POST",
                "/x",
                Some("anything"),
                &VarMap::new(),
                Some(rules),
                Some(&floor),
                &policy(),
                &[],
            )
        };
        assert_eq!(decide(&with(AccessLevel::Deny)), AccessLevel::Deny);
        assert_eq!(
            decide(&with(AccessLevel::AskAlways)),
            AccessLevel::AskAlways
        );
        assert_eq!(
            decide(&with(AccessLevel::Allow)),
            AccessLevel::Ask,
            "falls to the floor"
        );
    }

    // ── Method normalization (fail closed) ───────────────────────────────────
    #[test]
    fn only_get_head_options_are_reads() {
        for m in ["GET", "HEAD", "OPTIONS", "get", "Head", "options"] {
            assert!(!is_write_method(m), "{m} is a read");
        }
        for m in [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "delete",
            "MOVE",
            "PROPPATCH",
            "COPY",
            "MKCOL",
            "TRACE",
            "",
        ] {
            assert!(is_write_method(m), "{m} is a write");
        }
    }

    #[test]
    fn rule_method_matches_case_insensitively() {
        let rules = vec![rule("del", "DELETE /x", AccessLevel::Deny)];
        let floor = Levels {
            read: Some(AccessLevel::Allow),
            write: Some(AccessLevel::Ask),
            ttl: None,
        };
        let decide = |m: &str| {
            evaluate_decision(
                m,
                "/x",
                None,
                &VarMap::new(),
                Some(&rules),
                Some(&floor),
                &policy(),
                &[],
            )
        };
        // A lowercase `delete` hits the DELETE rule, never a floor.
        let (level, by, _) = decide("delete");
        assert_eq!(level, AccessLevel::Deny);
        assert!(matches!(by, DecidedBy::Rule { id: Some(ref id), .. } if id == "del"));
        // An extension method falls to the WRITE floor, not the read one.
        for m in ["MOVE", "PROPPATCH", "propfind"] {
            let (level, by, _) = decide(m);
            assert_eq!(by, DecidedBy::Floor);
            assert_eq!(level, AccessLevel::Ask, "{m} takes the write floor");
        }
        assert_eq!(decide("GET").0, AccessLevel::Allow);
    }

    // ── Path matching / specificity (unchanged engine) ───────────────────────
    #[test]
    fn wildcard_matches_one_segment() {
        assert!(path_matches("/repos/*/issues", "/repos/r/issues"));
        assert!(!path_matches("/repos/*", "/repos/o/r"));
    }

    #[test]
    fn double_star_matches_variable_depth() {
        // One rule covers any-depth refs (heads/main, heads/feature/x, tags/v1).
        let p = "/repos/*/*/git/refs/**";
        assert!(path_matches(p, "/repos/o/r/git/refs/heads/main"));
        assert!(path_matches(p, "/repos/o/r/git/refs/heads/feature/x"));
        assert!(path_matches(p, "/repos/o/r/git/refs/tags/v1"));
        // `**` requires at least one segment — the bare prefix does not match.
        assert!(!path_matches(p, "/repos/o/r/git/refs"));
        // Fixed prefix still has to line up.
        assert!(!path_matches(p, "/repos/o/r/git/blobs/abc"));
        // A single `*` is still exactly one segment (no accidental widening).
        assert!(!path_matches(
            "/repos/*/*/git/refs/*",
            "/repos/o/r/git/refs/heads/main"
        ));
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
        assert_eq!(
            evaluate(
                "GET",
                "/m",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&low),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Allow
        );
        let med = vec![rule("read", "GET /m/*", AccessLevel::Ask)];
        assert_eq!(
            evaluate(
                "GET",
                "/m/1",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&med),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
        let high = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        assert_eq!(
            evaluate(
                "POST",
                "/m/send",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&high),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::AskAlways
        );
        let del = vec![rule("del", "DELETE /m/*", AccessLevel::Deny)];
        assert_eq!(
            evaluate(
                "DELETE",
                "/m/1",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&del),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Deny
        );
    }

    #[test]
    fn match_list_is_an_or_across_patterns() {
        // One rule, two endpoints (different method AND path depth) for the same
        // logical operation — both fire it, unrelated requests don't.
        let rules = vec![PolicyRule {
            id: Some("open-network".into()),
            label: None,
            match_patterns: vec![
                "POST /v1/projects/*/network-restrictions/apply".into(),
                "PATCH /v1/projects/*/network-restrictions".into(),
            ],
            body: None,
            when: None,
            level: Some(AccessLevel::AskAlways),
            ttl: None,
        }];
        let ev = |m: &str, p: &str| {
            evaluate(
                m,
                p,
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy(),
                &[],
            )
        };
        assert_eq!(
            ev("POST", "/v1/projects/abc/network-restrictions/apply"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            ev("PATCH", "/v1/projects/abc/network-restrictions"),
            AccessLevel::AskAlways
        );
        // Wrong method on the PATCH path, or an unrelated path → no match → floor.
        assert_eq!(
            ev("GET", "/v1/projects/abc/network-restrictions"),
            AccessLevel::Allow
        );
        assert_eq!(
            ev("POST", "/v1/projects/abc/database/query"),
            AccessLevel::Allow
        );
    }

    #[test]
    fn match_spec_roundtrips_string_and_list() {
        // Single stays a bare string on the wire; a list stays a list.
        let one = PolicyRule {
            id: None,
            label: None,
            match_patterns: vec!["POST /a".into()],
            body: None,
            when: None,
            level: Some(AccessLevel::Ask),
            ttl: None,
        };
        let j = serde_json::to_value(&one).unwrap();
        assert_eq!(j.get("match").unwrap(), &serde_json::json!("POST /a"));
        let back: PolicyRule = serde_json::from_value(j).unwrap();
        assert_eq!(back.match_patterns, vec!["POST /a".to_string()]);

        let many = PolicyRule {
            id: None,
            label: None,
            match_patterns: vec!["POST /a".into(), "PATCH /b".into()],
            body: None,
            when: None,
            level: Some(AccessLevel::Ask),
            ttl: None,
        };
        let j = serde_json::to_value(&many).unwrap();
        assert_eq!(
            j.get("match").unwrap(),
            &serde_json::json!(["POST /a", "PATCH /b"])
        );
        // A bare-string `match` still deserializes (back-compat).
        let from_str: PolicyRule =
            serde_json::from_value(serde_json::json!({"match": "GET /x", "level": "ask"})).unwrap();
        assert_eq!(from_str.match_patterns, vec!["GET /x".to_string()]);
    }

    #[test]
    fn rule_with_no_level_is_skipped() {
        // A malformed rule (no level) can never decide → falls through to the
        // global default (allow).
        let bad = vec![PolicyRule {
            id: Some("bad".into()),
            label: None,
            match_patterns: vec!["GET /x".into()],
            body: None,
            when: None,
            level: None,
            ttl: None,
        }];
        assert_eq!(
            evaluate(
                "GET",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&bad),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Allow
        );
    }

    // ── Conflict resolution: deny-override / most-restrictive ─────────────────
    #[test]
    fn most_restrictive_matching_rule_wins() {
        // Two rules match the same request; the stricter (deny) wins even though
        // it's less specific — fail-safe, not most-specific.
        let rules = vec![
            rule("broad", "DELETE /m/*", AccessLevel::Deny), // less specific, stricter
            rule("narrow", "DELETE /m/safe", AccessLevel::Allow), // more specific, looser
        ];
        assert_eq!(
            evaluate(
                "DELETE",
                "/m/safe",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Deny
        );
    }

    // ── Default floor chain ──────────────────────────────────────────────────
    #[test]
    fn no_rule_falls_through_to_connection_then_tag_then_global() {
        // No matching rule → connection floor wins when set.
        let conn = Levels {
            read: Some(AccessLevel::Ask),
            write: None,
            ttl: None,
        };
        assert_eq!(
            evaluate(
                "GET",
                "/unmatched",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&vec![]),
                Some(&conn),
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
        // No connection floor → tag floor (ai = allow).
        assert_eq!(
            evaluate(
                "POST",
                "/v1/chat",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &policy(),
                &["ai".into()]
            ),
            AccessLevel::Allow
        );
        // No tag match → global default (allow).
        assert_eq!(
            evaluate(
                "GET",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &policy(),
                &["unknown".into()]
            ),
            AccessLevel::Allow
        );
    }

    #[test]
    fn multiple_tag_floors_most_restrictive_wins() {
        let mut p = policy();
        p.categories.insert(
            "wallet".into(),
            Levels {
                read: Some(AccessLevel::AskAlways),
                write: Some(AccessLevel::Deny),
                ttl: None,
            },
        );
        // ai says allow, wallet says ask-always/deny → the stricter floor wins.
        let tags = vec!["ai".to_string(), "wallet".to_string()];
        assert_eq!(
            evaluate(
                "GET",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &p,
                &tags
            ),
            AccessLevel::AskAlways
        );
        assert_eq!(
            evaluate(
                "POST",
                "/x",
                None,
                &crate::core::policy::VarMap::new(),
                None,
                None,
                &p,
                &tags
            ),
            AccessLevel::Deny
        );
    }

    // ── Merge: override by id + add new rule ──────────────────────────────────
    #[test]
    fn merge_overrides_level_by_id() {
        let built_in = vec![rule("read", "GET /m/*", AccessLevel::Ask)];
        let mut user = HashMap::new();
        user.insert(
            "read".into(),
            RuleConfig {
                level: Some(AccessLevel::Allow),
                ..Default::default()
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged[0].level, Some(AccessLevel::Allow));
        assert_eq!(merged[0].match_patterns, vec!["GET /m/*".to_string()]); // preserved
    }

    #[test]
    fn merge_lets_user_tighten_a_rule_to_deny() {
        let built_in = vec![rule("del", "DELETE /m/*", AccessLevel::AskAlways)];
        let mut user = HashMap::new();
        user.insert(
            "del".into(),
            RuleConfig {
                level: Some(AccessLevel::Deny),
                ..Default::default()
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(
            evaluate(
                "DELETE",
                "/m/1",
                None,
                &crate::core::policy::VarMap::new(),
                Some(&merged),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Deny
        );
    }

    #[test]
    fn merge_adds_new_rule_with_match() {
        let built_in = vec![rule("send", "POST /m/send", AccessLevel::AskAlways)];
        let mut user = HashMap::new();
        user.insert(
            "vip".into(),
            RuleConfig {
                match_pattern: Some("POST /m/vip".into()),
                level: Some(AccessLevel::Allow),
                ..Default::default()
            },
        );
        let merged = merge_rules(&built_in, &user);
        assert_eq!(merged.len(), 2);
        assert!(merged
            .iter()
            .any(|r| r.id.as_deref() == Some("vip") && r.level == Some(AccessLevel::Allow)));
    }

    #[test]
    fn merge_levels_user_wins_fieldwise() {
        let u = Levels {
            read: Some(AccessLevel::Allow),
            write: None,
            ttl: None,
        };
        let r = Levels {
            read: Some(AccessLevel::Ask),
            write: Some(AccessLevel::Deny),
            ttl: Some(30),
        };
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
        let (lvl, id, ttl) = evaluate_with_match(
            "GET",
            "/x",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            None,
            &policy(),
            &[],
        );
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(id.as_deref(), Some("read"));
        assert_eq!(ttl, Some(60));
    }

    // ── `when` field conditions (Phase 2) ────────────────────────────────────
    #[test]
    fn condition_parses_and_evaluates() {
        let mut vars = VarMap::new();
        vars.insert("amount".into(), "100".into());
        vars.insert("merchant".into(), "acme".into());

        assert!(Condition::parse("vars.amount > 80").unwrap().eval(&vars));
        assert!(!Condition::parse("vars.amount > 200").unwrap().eval(&vars));
        assert!(Condition::parse("vars.amount >= 100").unwrap().eval(&vars));
        assert!(Condition::parse("vars.amount <= 100").unwrap().eval(&vars));
        assert!(Condition::parse(r#"vars.merchant == "acme""#)
            .unwrap()
            .eval(&vars));
        assert!(Condition::parse(r#"vars.merchant != "evil""#)
            .unwrap()
            .eval(&vars));
        // Undefined var → false (P3), never a panic.
        assert!(!Condition::parse("vars.missing > 0").unwrap().eval(&vars));
        // A padded numeric string still compares (can't evade a threshold by
        // whitespace); non-finite never satisfies an ordering.
        let mut padded = VarMap::new();
        padded.insert("amount".into(), " 100 ".into());
        assert!(Condition::parse("vars.amount > 80").unwrap().eval(&padded));
        let mut naan = VarMap::new();
        naan.insert("amount".into(), "NaN".into());
        assert!(!Condition::parse("vars.amount > 80").unwrap().eval(&naan));
        // Ordering against a non-numeric value → false, not an error.
        assert!(!Condition::parse("vars.merchant > 0").unwrap().eval(&vars));
        // Malformed → None (build-time rejects; runtime treats as non-match).
        assert!(Condition::parse("amount > 80").is_none()); // no vars. prefix
        assert!(Condition::parse("vars.amount ~ 80").is_none()); // unknown op
        assert!(Condition::parse("vars. > 80").is_none()); // empty var
    }

    #[test]
    fn when_composes_with_most_restrictive_wins() {
        // The snaplii shape: a base `ask` on every purchase, and an
        // `ask-always` refinement for amount > 80. Most-restrictive-wins picks
        // ask-always when both match, ask when only the base does.
        let rules = vec![
            PolicyRule {
                id: Some("p".into()),
                label: None,
                match_patterns: vec!["POST /buy".into()],
                body: None,
                when: None,
                level: Some(AccessLevel::Ask),
                ttl: None,
            },
            PolicyRule {
                id: Some("pl".into()),
                label: None,
                match_patterns: vec!["POST /buy".into()],
                body: None,
                when: Some("vars.amount > 80".into()),
                level: Some(AccessLevel::AskAlways),
                ttl: None,
            },
        ];
        let mut big = VarMap::new();
        big.insert("amount".into(), "100".into());
        let mut small = VarMap::new();
        small.insert("amount".into(), "50".into());

        assert_eq!(
            evaluate(
                "POST",
                "/buy",
                None,
                &big,
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::AskAlways
        );
        assert_eq!(
            evaluate(
                "POST",
                "/buy",
                None,
                &small,
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
        // Amount undefined (no shape matched / field absent) → the `when` rule
        // doesn't fire, the base `ask` still gates the spend (never a bypass).
        assert_eq!(
            evaluate(
                "POST",
                "/buy",
                None,
                &VarMap::new(),
                Some(&rules),
                None,
                &policy(),
                &[]
            ),
            AccessLevel::Ask
        );
    }
}
