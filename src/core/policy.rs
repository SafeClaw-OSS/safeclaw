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
//! - `body`: regex matched against request body text (optional)
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub body: Option<String>,
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
    pub body: Option<String>,
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
/// policy rules use (no second matcher to drift).
pub(crate) fn pattern_matches(pattern: &str, method: &str, path: &str) -> bool {
    let path_no_query = path.split('?').next().unwrap_or(path);
    let (rule_method, rule_path) = parse_match_pattern(pattern);
    if let Some(m) = rule_method {
        if m != method {
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

fn is_write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
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

/// Resolve the access decision for a request, returning `(level,
/// matched_rule_id, ttl)`.
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
/// `matched_rule_id` / `ttl` are `Some` only when a rule decided (step 1).
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
    // The `ask`-cache window a matched rule inherits when it pins no `ttl` of
    // its own: the ttl of the most-specific floor (connection → tag → global),
    // the SAME precedence as the read/write floor decision below. Direction-
    // independent (Levels.ttl is a single value). Resolved up front because a
    // rule decision returns early; consumed only by an `ask` rule (a
    // floor-`ask` never caches), and a final constant fills in when nothing
    // pins a window at all.
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
            return (level, rule.id.clone(), rule.ttl.or(floor_ttl));
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
            return (l, None, ttl);
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
        return (l, None, ttl);
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
