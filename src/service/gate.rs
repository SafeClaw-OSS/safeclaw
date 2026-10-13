//! The one gate for service definitions.
//!
//! Definition text is untrusted input: it comes from community repositories,
//! local folders, or a team member writing the vault. [`admit`] is the only
//! way to turn it into a [`ServiceDef`] (the type carries a private field, so
//! nothing else can build one, and it has no `Deserialize`): every reader of
//! `aux.services`, of an on-disk service directory and of the compiled-in
//! catalog goes through here, and every consumer holds only what came out
//! ("parse, don't validate"; LangSec full recognition before processing).
//!
//! The gate recognizes the whole definition or rejects the whole definition
//! (CWE-636, no failing open): an unknown field anywhere, an unknown level, a
//! `body` regex that does not compile, a `when` that does not parse, a
//! consent filter the console does not implement, a duplicate rule id, an
//! empty label, a string carrying a control or bidi character, or anything
//! over a limit ([`crate::service::limits`]) rejects it with a precise
//! message. No rule is ever dropped on the way through.
//!
//! Pure and synchronous: no DNS, no network. Hosts and URLs are read with the
//! HTTP client's own URL parser and judged by the address floor in
//! [`crate::core::egress`].

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::core::egress::{check_host_entry, check_url};
use crate::core::policy::{
    match_pattern_problem, patterns_overlap, AccessLevel, BodyPattern, Condition, Levels,
    PolicyRule,
};
use crate::service::limits::*;
use crate::service::{AuthDef, RequestShape, ServiceDef, ServiceMeta, ServicePolicy, VarDef};

/// The filters the console implements for a consent template
/// (`{{ vars.<name> | <filter> }}`): `email` renders the bound value as a
/// decoded message card (the approval view in the console). A filter outside
/// this set would show the approver nothing, so a definition naming one is
/// rejected.
pub const CONSENT_FILTERS: &[&str] = &["email"];

/// Consent-URL query params the OAuth flow itself controls; an
/// `authorize_params` map may never set these (the frontend applies the map
/// first and the protocol params after, so an entry here would silently lose;
/// it is rejected instead).
const RESERVED_AUTHORIZE_PARAMS: &[&str] = &[
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
];

// ── Raw (untrusted) shapes: serde targets that only the gate reads ──────────

/// service.toml as written. `deny_unknown_fields` rejects stale v3 sections
/// and any tool-named section (`[git]`, `[docker]`) at parse.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    service: ServiceMeta,
    #[serde(default)]
    auth: Option<AuthDef>,
    #[serde(default)]
    setup: Option<String>,
    #[serde(default)]
    policy: Option<RawInlinePolicy>,
    #[serde(default)]
    requests: HashMap<String, RequestShape>,
}

/// The inline `[policy]` of a service.toml (`[policy.levels]` +
/// `[[policy.rules]]`), the older alternative to a policy.toml.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInlinePolicy {
    #[serde(default)]
    levels: Option<RawLevels>,
    #[serde(default)]
    rules: Vec<RawInlineRule>,
}

/// A read/write floor: `[default]` in policy.toml, `[policy.levels]` inline.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLevels {
    #[serde(default)]
    read: Option<String>,
    #[serde(default)]
    write: Option<String>,
    #[serde(default)]
    ttl: Option<u64>,
}

/// An inline `[[policy.rules]]` entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInlineRule {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path_exact: Option<String>,
    /// Never supported by the matcher; named here so it is rejected with a
    /// precise message instead of a generic unknown-field one.
    #[serde(default)]
    path_suffix: Option<String>,
    level: String,
}

/// policy.toml as written: `[default]` + `[[rule]]`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyFile {
    #[serde(default)]
    default: Option<RawLevels>,
    #[serde(default)]
    rule: Vec<RawRule>,
}

/// A `[[rule]]` in policy.toml.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    label: String,
    #[serde(
        rename = "match",
        deserialize_with = "crate::core::policy::match_spec::deserialize"
    )]
    match_pattern: Vec<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    when: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    ttl: Option<u64>,
}

// ── The gate ─────────────────────────────────────────────────────────────────

/// Turn untrusted definition text into a validated [`ServiceDef`], or reject
/// it whole with every problem found.
///
/// `key` is the name the definition is stored or found under (its
/// `aux.services` key, its service directory name); when given, the declared
/// `[service] id` must equal it. `policy_toml` is the paired policy.toml, if
/// any. The messages carry no control or bidi characters (they quote the
/// definition, and are printed and logged).
pub fn admit(
    key: Option<&str>,
    service_toml: &str,
    policy_toml: Option<&str>,
) -> Result<ServiceDef, Vec<String>> {
    admit_inner(key, service_toml, policy_toml).map_err(|mut errs| {
        if errs.len() > MAX_REPORTED_PROBLEMS {
            let more = errs.len() - MAX_REPORTED_PROBLEMS;
            errs.truncate(MAX_REPORTED_PROBLEMS);
            errs.push(format!("... and {} more problems", more));
        }
        errs.into_iter()
            .map(|e| crate::util::terminal_safe(&e).into_owned())
            .collect()
    })
}

fn admit_inner(
    key: Option<&str>,
    service_toml: &str,
    policy_toml: Option<&str>,
) -> Result<ServiceDef, Vec<String>> {
    // Bytes first: nothing larger than the limit reaches the parser.
    let mut errs = Vec::new();
    check_file_size("service.toml", service_toml, &mut errs);
    if let Some(p) = policy_toml {
        check_file_size("policy.toml", p, &mut errs);
    }
    if !errs.is_empty() {
        return Err(errs);
    }

    // Syntax, then every string and key, before any message quotes a value.
    let service_table = parse_table("service.toml", service_toml)?;
    let policy_table = match policy_toml {
        Some(p) => Some(parse_table("policy.toml", p)?),
        None => None,
    };
    check_strings_in_table(&service_table, "", true, &mut errs);
    if let Some(t) = &policy_table {
        check_strings_in_table(t, "", false, &mut errs);
    }
    if !errs.is_empty() {
        return Err(errs);
    }

    // The schema: an unknown field anywhere is a parse error here.
    let raw: RawService = toml::from_str(service_toml)
        .map_err(|e| vec![toml_problem("service.toml", service_toml, &e, SCHEMA_ERROR)])?;
    let raw_policy: Option<RawPolicyFile> = match policy_toml {
        Some(p) => Some(
            toml::from_str(p)
                .map_err(|e| vec![toml_problem("policy.toml", p, &e, SCHEMA_ERROR)])?,
        ),
        None => None,
    };

    check_service(key, &raw, &mut errs);
    check_requests(&raw.requests, &mut errs);
    let policy = match (raw_policy, raw.policy.as_ref()) {
        (Some(_), Some(_)) => {
            errs.push(
                "the policy is declared twice (policy.toml and an inline [policy]); keep one"
                    .into(),
            );
            None
        }
        (Some(file), None) => Some(policy_from_file(file, &mut errs)),
        (None, Some(inline)) => Some(policy_from_inline(inline, &mut errs)),
        (None, None) => None,
    };
    // Cross-checks only over parts that passed on their own: a list over its
    // limit never reaches the pairwise work below.
    if !errs.is_empty() {
        return Err(errs);
    }
    if let Some(p) = &policy {
        check_rules_against_requests(&p.rules, &raw.requests, &mut errs);
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(ServiceDef {
        service: raw.service,
        auth: raw.auth,
        setup: raw.setup,
        policy,
        requests: raw.requests,
        _gate: (),
    })
}

fn check_file_size(name: &str, text: &str, errs: &mut Vec<String>) {
    if text.len() > MAX_FILE_BYTES {
        errs.push(format!(
            "{} is {} bytes; the limit is {}",
            name,
            text.len(),
            MAX_FILE_BYTES
        ));
    }
}

fn parse_table(name: &str, text: &str) -> Result<toml::Table, Vec<String>> {
    toml::from_str::<toml::Table>(text)
        .map_err(|e| vec![toml_problem(name, text, &e, SYNTAX_ERROR)])
}

const SYNTAX_ERROR: &str = "syntax error";
const SCHEMA_ERROR: &str = "does not match the definition format";

/// A TOML error as its kind and position only. The parser's own text quotes
/// the offending line and a schema error can quote a key or value; definition
/// text is never echoed, so only a fixed kind and the line and column are
/// reported. `default` is the kind when the error is none of the known ones.
fn toml_problem(name: &str, text: &str, e: &toml::de::Error, default: &str) -> String {
    let kind = toml_error_kind(e.message()).unwrap_or(default);
    match e.span().and_then(|span| line_col(text, span.start)) {
        Some((line, col)) => format!(
            "{}: parse error: {} at line {}, column {}",
            name, kind, line, col
        ),
        None => format!("{}: parse error: {}", name, kind),
    }
}

/// The fixed kind of a TOML error message, from its leading words only.
fn toml_error_kind(message: &str) -> Option<&'static str> {
    const KINDS: [(&str, &str); 8] = [
        ("unknown field", "unknown field"),
        ("missing field", "missing field"),
        ("duplicate field", "duplicate key"),
        ("duplicate key", "duplicate key"),
        ("invalid type", "a value has the wrong type"),
        ("invalid value", "invalid value"),
        ("invalid length", "wrong number of items"),
        ("unknown variant", "unknown value"),
    ];
    let m = message.trim_start();
    KINDS
        .iter()
        .find(|(prefix, _)| m.starts_with(prefix))
        .map(|(_, kind)| *kind)
}

/// 1-based line and column (in characters) of byte offset `at` in `text`.
fn line_col(text: &str, at: usize) -> Option<(usize, usize)> {
    let before = text.get(..at.min(text.len()))?;
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    Some((line, col))
}

// ── Strings: control / bidi characters and lengths, in every value and key ──

/// Walk every string value and key of a parsed file. Only the top-level
/// `setup` of a service.toml is prose: it may carry `\n` and `\t` and the
/// longer prose limit; everything else is a single line.
fn check_strings_in_table(
    table: &toml::Table,
    path: &str,
    service_file: bool,
    errs: &mut Vec<String>,
) {
    for (key, value) in table {
        check_string(&format!("a key in {}", or_root(path)), key, false, errs);
        // A message names the key, shortened: a long key is already an error.
        let mut shown = key.as_str();
        if shown.len() > 64 {
            let mut cut = 64;
            while !shown.is_char_boundary(cut) {
                cut -= 1;
            }
            shown = &shown[..cut];
        }
        let child = if path.is_empty() {
            shown.to_string()
        } else {
            format!("{}.{}", path, shown)
        };
        let prose = service_file && path.is_empty() && key == "setup";
        check_value(value, &child, prose, errs);
    }
}

fn or_root(path: &str) -> &str {
    if path.is_empty() {
        "the file"
    } else {
        path
    }
}

fn check_value(value: &toml::Value, path: &str, prose: bool, errs: &mut Vec<String>) {
    match value {
        toml::Value::String(s) => check_string(path, s, prose, errs),
        toml::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_value(item, &format!("{}[{}]", path, i), false, errs);
            }
        }
        toml::Value::Table(t) => check_strings_in_table(t, path, false, errs),
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
}

fn check_string(path: &str, s: &str, prose: bool, errs: &mut Vec<String>) {
    let limit = if prose {
        MAX_PROSE_BYTES
    } else {
        MAX_STRING_BYTES
    };
    if s.len() > limit {
        errs.push(format!(
            "{} is {} bytes; the limit is {}",
            path,
            s.len(),
            limit
        ));
        return;
    }
    if let Some(c) = s
        .chars()
        .find(|&c| !(prose && (c == '\n' || c == '\t')) && crate::util::is_unsafe_display_char(c))
    {
        errs.push(format!(
            "{} contains the control or bidi character U+{:04X}{}",
            path,
            c as u32,
            if prose {
                " (only \\n and \\t are allowed)"
            } else {
                ""
            }
        ));
    }
}

// ── [service] and [auth] ─────────────────────────────────────────────────────

/// A service / connection id usable as a phantom `<conn>` segment: `[a-z0-9_]`,
/// no `__` (the phantom delimiter), starting alphanumeric.
fn is_valid_service_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || s.contains("__") {
        return false;
    }
    s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A secret role key: env-style `[A-Z0-9_]`, starts with a letter, and,
/// because its lowercase becomes a phantom role segment (`__sc__<conn>__<role>__`),
/// it carries no `__` (the delimiter) and no trailing `_` (which would fuse
/// into the delimiter as `___` and make the advertised phantom unparseable).
fn is_valid_role(s: &str) -> bool {
    if s.is_empty() || s.contains("__") || s.ends_with('_') {
        return false;
    }
    s.starts_with(|c: char| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A name the console's consent grammar and `when` can address: `[A-Za-z0-9_]+`.
fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Within the limit? Over it, the error is recorded and the caller skips the
/// per-entry checks, so the work done never exceeds the limits.
fn check_count(what: &str, n: usize, limit: usize, errs: &mut Vec<String>) -> bool {
    if n > limit {
        errs.push(format!(
            "{} has {} entries; the limit is {}",
            what, n, limit
        ));
        return false;
    }
    true
}

/// A single host anchor entry: an exact host or a `*.suffix` wildcard
/// (leftmost, single label, over a domain of at least two labels).
/// Authorities only: no scheme, no path, no port, no template.
fn check_host(entry: &str, errs: &mut Vec<String>) {
    if entry.contains("://") || entry.contains('/') || entry.contains("{{") {
        errs.push(format!(
            "host '{}' must be a bare host (no scheme, path or template)",
            entry
        ));
        return;
    }
    if entry.contains(':') {
        errs.push(format!("host '{}' must not carry a port", entry));
        return;
    }
    if entry == "*" {
        errs.push("a bare '*' host is forbidden; anchor to an exact host or a '*.suffix'".into());
        return;
    }
    let base = match entry.strip_prefix("*.") {
        Some(suffix) => {
            if suffix.contains('*') {
                errs.push(format!(
                    "host '{}': '*' is only allowed as the leftmost single label",
                    entry
                ));
                return;
            }
            // A wildcard pins within a domain: never a whole TLD, never an IP.
            let domain = matches!(url::Host::parse(suffix), Ok(url::Host::Domain(_)));
            if !domain || !suffix.trim_end_matches('.').contains('.') {
                errs.push(format!(
                    "host '{}' is too broad; a wildcard needs a domain like *.example.com",
                    entry
                ));
                return;
            }
            suffix
        }
        None => {
            if entry.contains('*') {
                errs.push(format!(
                    "host '{}': '*' is only allowed as the leftmost single label",
                    entry
                ));
                return;
            }
            entry
        }
    };
    if let Err(e) = check_host_entry(base) {
        errs.push(if base == entry {
            e
        } else {
            format!("host '{}': {}", entry, e)
        });
    }
}

fn check_service(key: Option<&str>, raw: &RawService, errs: &mut Vec<String>) {
    let s = &raw.service;
    if !is_valid_service_id(&s.id) {
        errs.push(format!(
            "service id '{}' is not valid (^[a-z0-9][a-z0-9_]* , no '__', at most 64)",
            s.id
        ));
    }
    if let Some(k) = key {
        if k != s.id {
            errs.push(format!(
                "the definition is stored as '{}' but declares id '{}'; they must be the same",
                k, s.id
            ));
        }
    }
    if s.name.trim().is_empty() {
        errs.push("[service] name must not be empty".into());
    }

    // Hosts: non-hidden services must anchor at least one.
    if s.hosts.is_empty() && !s.hidden {
        errs.push("service declares no hosts (an anchor is required)".into());
    }
    if check_count("[service] hosts", s.hosts.len(), MAX_HOSTS, errs) {
        for h in &s.hosts {
            check_host(h, errs);
        }
    }

    // Secrets: env-style role keys, no duplicates.
    let mut seen_secret = HashSet::new();
    let secrets_ok = check_count("[service] secrets", s.secrets.len(), MAX_SECRETS, errs);
    for r in s.secrets.iter().filter(|_| secrets_ok) {
        if !is_valid_role(r) {
            errs.push(format!(
                "secret role '{}' is not a valid env key ([A-Z0-9_])",
                r
            ));
        }
        if !seen_secret.insert(r.to_ascii_uppercase()) {
            errs.push(format!("duplicate secret role '{}'", r));
        }
    }

    // Tags: lowercase-kebab slugs, no duplicates. Free vocabulary; only the
    // shape is enforced so the console can render any tag as a chip.
    let mut seen_tag = HashSet::new();
    let tags_ok = check_count("[service] tags", s.tags.len(), MAX_TAGS, errs);
    for t in s.tags.iter().filter(|_| tags_ok) {
        let kebab = !t.is_empty()
            && t.split('-').all(|seg| {
                !seg.is_empty()
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            });
        if !kebab {
            errs.push(format!(
                "tag '{}' is not lowercase-kebab ([a-z0-9] segments joined by '-')",
                t
            ));
        }
        if !seen_tag.insert(t.as_str()) {
            errs.push(format!("duplicate tag '{}'", t));
        }
    }

    if let Some(g) = &s.group {
        if !is_valid_service_id(g) {
            errs.push(format!("[service] group '{}' is not a service id", g));
        }
    }
    if let Some(a) = &s.activation {
        if a != "auto" {
            errs.push(format!(
                "[service] activation '{}' is unknown (the only value is \"auto\"; omit it otherwise)",
                a
            ));
        }
    }
    // secret_url is a display-only link, rendered as an <a href> by the
    // console: a plain web URL only.
    if let Some(u) = &s.secret_url {
        if let Err(e) = check_url("[service] secret_url", u, &["https", "http"], false) {
            errs.push(e);
        }
    }

    match &raw.auth {
        Some(AuthDef::Snaplii(_)) => {
            // The snaplii exchange input is the first `secrets` role; a def
            // without one can never mint.
            if !s.secrets.iter().any(|r| !r.trim().is_empty()) {
                errs.push(
                    "[auth] type=\"snaplii\" requires a [service] secrets entry (the exchange api key)"
                        .into(),
                );
            }
        }
        Some(AuthDef::Oauth2(o)) => check_oauth2(o, s, &seen_secret, errs),
        None => {}
    }
}

/// The oauth2 section is self-sufficient: the inline fields carry the
/// endpoints and client (there is no template layer; `provider` is a display
/// label only). Endpoints are https to a public host.
fn check_oauth2(
    o: &crate::service::OAuth2Def,
    s: &ServiceMeta,
    seen_secret: &HashSet<String>,
    errs: &mut Vec<String>,
) {
    if !(o.authorization_url.is_some() && o.token_url.is_some() && o.client_id.is_some()) {
        errs.push(
            "[auth] oauth2 must declare authorization_url + token_url + client_id inline".into(),
        );
    }
    if o.provider.as_deref().is_some_and(|p| p.trim().is_empty()) {
        errs.push("[auth] provider (display label) must not be empty (omit it instead)".into());
    }
    if o.client_id.as_deref().is_some_and(|c| c.trim().is_empty()) {
        errs.push("[auth] client_id must not be empty".into());
    }
    if let Some(u) = &o.authorization_url {
        if let Err(e) = check_url("[auth] authorization_url", u, &["https"], true) {
            errs.push(e);
        }
    }
    if let Some(u) = &o.token_url {
        if let Err(e) = check_url("[auth] token_url", u, &["https"], true) {
            errs.push(e);
        }
    }
    // Where the consent lands: not an egress target (a local listener or the
    // provider's own page catches it), so any host is allowed, but only the
    // forms a native or web OAuth client uses. The string checks above
    // already bound its length and characters.
    if let Some(u) = &o.redirect_uri {
        if let Some(problem) = redirect_uri_problem(u) {
            errs.push(format!("[auth] redirect_uri '{}' {}", u, problem));
        }
    }
    if let Some(style) = &o.oauth_style {
        if style != "form" && style != "json" {
            errs.push(format!(
                "[auth] oauth_style '{}' is unknown (\"form\" or \"json\")",
                style
            ));
        }
    }
    check_count("[auth] scopes", o.scopes.len(), MAX_OAUTH_SCOPES, errs);
    if o.scopes.iter().any(|sc| sc.trim().is_empty()) {
        errs.push("[auth] scopes has an empty entry".into());
    }
    let exposes_ok = check_count("[auth] exposes", o.exposes.len(), MAX_EXPOSES, errs);
    let claims_ok = check_count("[auth.claims]", o.claims.len(), MAX_CLAIMS, errs);
    let mut claim_roles: Vec<&String> = o.claims.keys().filter(|_| claims_ok).collect();
    claim_roles.sort();
    for role in claim_roles {
        let path = &o.claims[role];
        if !o.exposes.iter().any(|e| e == role) {
            errs.push(format!("[auth] claims key '{}' is not in exposes", role));
        }
        check_count(
            &format!("[auth.claims] '{}'", role),
            path.len(),
            MAX_CLAIM_PATH,
            errs,
        );
        if path.is_empty() || path.iter().any(|seg| seg.trim().is_empty()) {
            errs.push(format!(
                "[auth] claims path for '{}' has an empty segment",
                role
            ));
        }
    }
    // authorize_params are ADDITIONS to the consent URL, never overrides of
    // the protocol params the flow itself controls.
    let params_ok = check_count(
        "[auth.authorize_params]",
        o.authorize_params.len(),
        MAX_AUTHORIZE_PARAMS,
        errs,
    );
    let mut params: Vec<&String> = o.authorize_params.keys().filter(|_| params_ok).collect();
    params.sort();
    for k in params {
        if RESERVED_AUTHORIZE_PARAMS.contains(&k.as_str()) {
            errs.push(format!(
                "[auth] authorize_params may not set the reserved param '{}'",
                k
            ));
        }
    }
    // Durable token slots use RFC 6749 field names; each is a valid env KEY
    // that is ALSO declared in the top-level `secrets` (the uniform
    // durable-credential contract, SERVICES.md §3).
    let declared = |k: &str| s.secrets.iter().any(|r| r.eq_ignore_ascii_case(k));
    if o.refresh_token.trim().is_empty() {
        errs.push("[auth] oauth2 requires a refresh_token (the vault secret KEY the refresh token is stored under)".into());
    } else if !is_valid_role(&o.refresh_token) {
        errs.push(format!(
            "[auth] refresh_token '{}' is not a valid env key ([A-Z0-9_])",
            o.refresh_token
        ));
    } else if !declared(&o.refresh_token) {
        errs.push(format!(
            "[auth] refresh_token '{}' must be listed in the service's top-level secrets",
            o.refresh_token
        ));
    }
    if let Some(idt) = &o.id_token {
        if !is_valid_role(idt) {
            errs.push(format!(
                "[auth] id_token '{}' is not a valid env key ([A-Z0-9_])",
                idt
            ));
        } else if !declared(idt) {
            errs.push(format!(
                "[auth] id_token '{}' must be listed in the service's top-level secrets",
                idt
            ));
        }
    }
    for e in o.exposes.iter().filter(|_| exposes_ok) {
        if !is_valid_service_id(e) {
            errs.push(format!(
                "[auth] exposes entry '{}' is not a valid role ([a-z0-9_])",
                e
            ));
        }
        if seen_secret.contains(&e.to_ascii_uppercase()) {
            errs.push(format!(
                "[auth] exposes entry '{}' collides with a secret role",
                e
            ));
        }
    }
}

/// The out-of-band redirect: the provider shows the code on its own page.
const OOB_REDIRECT: &str = "urn:ietf:wg:oauth:2.0:oob";

/// Why `uri` is not a redirect an OAuth client uses, or `None`: an `http` or
/// `https` URL (loopback included, RFC 8252 §7.3), [`OOB_REDIRECT`], or a
/// private-use scheme in reverse-domain form (RFC 8252 §7.1: at least two
/// dot-separated labels of letters, digits and `-`, as in
/// `com.example.app:/cb`). Every other scheme is refused.
fn redirect_uri_problem(uri: &str) -> Option<&'static str> {
    let Ok(url) = url::Url::parse(uri) else {
        return Some("is not an absolute URI");
    };
    let scheme = url.scheme();
    let reverse_domain = scheme.contains('.')
        && scheme.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if matches!(scheme, "http" | "https") || uri == OOB_REDIRECT || reverse_domain {
        None
    } else {
        Some(
            "must be an http(s) URL, urn:ietf:wg:oauth:2.0:oob, or a reverse-domain app scheme (com.example.app:/cb)",
        )
    }
}

// ── [requests] ───────────────────────────────────────────────────────────────

fn check_match_list(what: &str, patterns: &[String], errs: &mut Vec<String>) {
    if !check_count(
        &format!("{} match", what),
        patterns.len(),
        MAX_MATCH_PATTERNS,
        errs,
    ) {
        return;
    }
    for p in patterns {
        if let Some(problem) = match_pattern_problem(p) {
            errs.push(format!("{}: {}", what, problem));
        }
    }
}

fn check_requests(requests: &HashMap<String, RequestShape>, errs: &mut Vec<String>) {
    if !check_count("[requests]", requests.len(), MAX_REQUESTS, errs) {
        return;
    }
    let mut names: Vec<&String> = requests.keys().collect();
    names.sort();
    for name in names {
        let shape = &requests[name];
        let what = format!("[requests.{}]", name);
        if !is_ident(name) {
            errs.push(format!(
                "{} is not a valid request name ([A-Za-z0-9_])",
                what
            ));
        }
        if shape.match_pattern.is_empty() {
            errs.push(format!("{} declares no `match`", what));
        }
        check_match_list(&what, &shape.match_pattern, errs);

        let vars_ok = check_count(&format!("{} vars", what), shape.vars.len(), MAX_VARS, errs);
        let mut vars: Vec<&String> = shape.vars.keys().filter(|_| vars_ok).collect();
        vars.sort();
        for var in vars {
            if !is_ident(var) {
                errs.push(format!(
                    "{} var '{}' is not a valid name ([A-Za-z0-9_])",
                    what, var
                ));
            }
            // A body address is an RFC 6901 pointer (leading '/'); a query
            // `at` is non-empty.
            match &shape.vars[var] {
                VarDef::BodyPointer(p) => check_pointer(&what, var, p, errs),
                VarDef::Located(at) => match at.location {
                    crate::service::VarLoc::Body => check_pointer(&what, var, &at.at, errs),
                    crate::service::VarLoc::Query => {
                        if at.at.is_empty() {
                            errs.push(format!("{} var '{}' query `at` is empty", what, var));
                        }
                    }
                },
            }
        }

        // scope ⊆ vars: only a declared field can be bound. No duplicates: a
        // repeated entry makes the approve digest (object, deduped) and the
        // redeem digest (vec) disagree.
        let scope_ok = check_count(
            &format!("{} scope", what),
            shape.scope.len(),
            MAX_SCOPE,
            errs,
        );
        let mut seen_scope = HashSet::new();
        for k in shape.scope.iter().filter(|_| scope_ok) {
            if !shape.vars.contains_key(k) {
                errs.push(format!(
                    "{} scope names '{}', which is not a declared var",
                    what, k
                ));
            }
            if !seen_scope.insert(k) {
                errs.push(format!("{} scope lists '{}' more than once", what, k));
            }
        }

        if let Some(consent) = &shape.consent {
            check_consent(&what, consent, &shape.scope, errs);
        }
    }
}

fn check_pointer(what: &str, var: &str, p: &str, errs: &mut Vec<String>) {
    if !p.starts_with('/') {
        errs.push(format!(
            "{} var '{}' body address '{}' must be a JSON Pointer (start with '/')",
            what, var, p
        ));
    }
}

/// A consent template is literal text and `{{ vars.<name> }}` or
/// `{{ vars.<name> | <filter> }}` tokens, nothing else. Every referenced var
/// must be in `scope` (P4 show ⊆ bind) and every filter one the console
/// implements ([`CONSENT_FILTERS`]).
fn check_consent(what: &str, template: &str, scope: &[String], errs: &mut Vec<String>) {
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            errs.push(format!("{} consent has an unclosed '{{{{'", what));
            return;
        };
        let inner = after[..end].trim();
        let (expr, filter) = match inner.split_once('|') {
            Some((e, f)) => (e.trim(), Some(f.trim())),
            None => (inner, None),
        };
        match expr.strip_prefix("vars.") {
            Some(var) if is_ident(var) => {
                if !scope.iter().any(|k| k == var) {
                    errs.push(format!(
                        "{} consent references '{{{}}}', which is not in `scope` (show ⊆ bind)",
                        what, var
                    ));
                }
            }
            _ => errs.push(format!(
                "{} consent token '{{{{ {} }}}}' must be {{{{ vars.<name> }}}} or {{{{ vars.<name> | <filter> }}}}",
                what, inner
            )),
        }
        if let Some(f) = filter {
            if !CONSENT_FILTERS.contains(&f) {
                errs.push(format!(
                    "{} consent filter '{}' is unknown (known: {})",
                    what,
                    f,
                    CONSENT_FILTERS.join(", ")
                ));
            }
        }
        rest = &after[end + 2..];
    }
}

// ── Policy ───────────────────────────────────────────────────────────────────

fn parse_level(what: &str, s: &str, errs: &mut Vec<String>) -> Option<AccessLevel> {
    let level = AccessLevel::parse(s);
    if level.is_none() {
        errs.push(format!(
            "{}: level '{}' is unknown (allow, ask, ask-always or deny)",
            what, s
        ));
    }
    level
}

/// A `ttl` from a definition may not exceed [`MAX_TTL_SECONDS`]; over it the
/// definition is refused, never clamped.
fn check_ttl(what: &str, ttl: Option<u64>, errs: &mut Vec<String>) {
    if let Some(t) = ttl.filter(|t| *t > MAX_TTL_SECONDS) {
        errs.push(format!(
            "{}: ttl = {} is over the limit of {} seconds (one year)",
            what, t, MAX_TTL_SECONDS
        ));
    }
}

fn levels_from(what: &str, raw: &RawLevels, errs: &mut Vec<String>) -> Levels {
    check_ttl(what, raw.ttl, errs);
    Levels {
        read: raw
            .read
            .as_deref()
            .and_then(|l| parse_level(&format!("{} read", what), l, errs)),
        write: raw
            .write
            .as_deref()
            .and_then(|l| parse_level(&format!("{} write", what), l, errs)),
        ttl: raw.ttl,
    }
}

/// A rule id: the key a user edit names it by. `[a-z0-9][a-z0-9_-]*`.
fn is_valid_rule_id(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn policy_from_file(file: RawPolicyFile, errs: &mut Vec<String>) -> ServicePolicy {
    let defaults = file
        .default
        .as_ref()
        .map(|d| levels_from("policy.toml [default]", d, errs));
    if !check_count("policy.toml rules", file.rule.len(), MAX_RULES, errs) {
        return ServicePolicy {
            defaults,
            rules: Vec::new(),
        };
    }
    // Body rules are capped on their own: each is a regex compiled at load
    // and matched against every request body the rule's paths see.
    let body_rules = file.rule.iter().filter(|r| r.body.is_some()).count();
    let bodies_ok = check_count(
        "policy.toml rules with a body",
        body_rules,
        MAX_BODY_RULES,
        errs,
    );
    let mut seen_ids = HashSet::new();
    let mut rules = Vec::with_capacity(file.rule.len());
    for r in file.rule {
        let what = format!("rule '{}'", r.id);
        if !is_valid_rule_id(&r.id) {
            errs.push(format!("{}: the id must be [a-z0-9][a-z0-9_-]*", what));
        }
        if !seen_ids.insert(r.id.clone()) {
            errs.push(format!("{}: the id is used by more than one rule", what));
        }
        if r.label.trim().is_empty() {
            errs.push(format!("{}: the label must not be empty", what));
        }
        check_match_list(&what, &r.match_pattern, errs);
        check_ttl(&what, r.ttl, errs);
        let level = match r.level.as_deref() {
            Some(l) => parse_level(&what, l, errs),
            None => {
                errs.push(format!(
                    "{}: declares no level (allow, ask, ask-always or deny)",
                    what
                ));
                None
            }
        };
        let body =
            r.body
                .as_deref()
                .filter(|_| bodies_ok)
                .and_then(|b| match BodyPattern::compile(b) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        errs.push(format!("{}: body regex {}", what, e));
                        None
                    }
                });
        if let Some(w) = &r.when {
            match Condition::parse(w) {
                None => errs.push(format!(
                    "{}: `when = \"{}\"` is not a valid condition (expected `vars.<name> <op> <literal>`)",
                    what, w
                )),
                Some(c) => {
                    if let Some(why) = c.never_fires() {
                        errs.push(format!(
                            "{}: `when = \"{}\"` can never be true: {}",
                            what, w, why
                        ));
                    }
                }
            }
        }
        rules.push(PolicyRule {
            id: Some(r.id),
            label: Some(r.label),
            match_patterns: r.match_pattern,
            body,
            when: r.when,
            level,
            ttl: r.ttl,
        });
    }
    ServicePolicy { defaults, rules }
}

fn policy_from_inline(inline: &RawInlinePolicy, errs: &mut Vec<String>) -> ServicePolicy {
    let defaults = inline
        .levels
        .as_ref()
        .map(|l| levels_from("[policy.levels]", l, errs));
    if !check_count("[[policy.rules]]", inline.rules.len(), MAX_RULES, errs) {
        return ServicePolicy {
            defaults,
            rules: Vec::new(),
        };
    }
    let mut rules = Vec::with_capacity(inline.rules.len());
    for (i, r) in inline.rules.iter().enumerate() {
        let what = format!("[[policy.rules]] #{}", i + 1);
        if r.path_suffix.is_some() {
            errs.push(format!(
                "{}: path_suffix is not supported; write the path in path_exact",
                what
            ));
        }
        let Some(path) = &r.path_exact else {
            errs.push(format!("{}: declares no path_exact", what));
            continue;
        };
        let path = path.trim_end_matches('/');
        let pattern = match &r.method {
            Some(m) => format!("{} {}", m, path),
            None => path.to_string(),
        };
        if r.method
            .as_deref()
            .is_some_and(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            errs.push(format!("{}: method must be letters (e.g. DELETE)", what));
        }
        if let Some(problem) = match_pattern_problem(&pattern) {
            errs.push(format!("{}: {}", what, problem));
        }
        let level = parse_level(&what, &r.level, errs);
        rules.push(PolicyRule {
            id: None,
            label: None,
            match_patterns: vec![pattern],
            body: None,
            when: None,
            level,
            ttl: None,
        });
    }
    ServicePolicy { defaults, rules }
}

/// Cross-checks of the policy against the paired `[requests]` shapes, the
/// invariant that a field deciding an approval must be bound by it. A shape
/// covers a rule when their `match` patterns overlap (a rule with no `match`
/// overlaps every shape); a request the rule matches resolves its vars from
/// one of the covering shapes.
///   - A `when` on `vars.<name>`: at least one shape covers the rule, and
///     every covering shape declares `<name>` and lists it in `scope`, so the
///     var resolves, and is held fixed by the approval, whichever covering
///     shape a request resolves to (else an ask-always approved at one value
///     could be redeemed at another).
///   - A `when` on `vars.<shape>.<name>`: that shape covers the rule,
///     declares `<name>` and lists it in `scope`.
///   - No `ask` / `ask-always` rule decides on the `body` on a path a shape
///     covers (an approval there binds only the shape's `scope` fields).
fn check_rules_against_requests(
    rules: &[PolicyRule],
    requests: &HashMap<String, RequestShape>,
    errs: &mut Vec<String>,
) {
    let mut shapes: Vec<(&String, &RequestShape)> = requests.iter().collect();
    shapes.sort_by_key(|(n, _)| *n);
    for (i, rule) in rules.iter().enumerate() {
        let what = match &rule.id {
            Some(id) => format!("rule '{}'", id),
            None => format!("[[policy.rules]] #{}", i + 1),
        };
        let covering: Vec<(&String, &RequestShape)> = shapes
            .iter()
            .copied()
            .filter(|(_, shape)| shape_covers_rule(shape, rule))
            .collect();
        if let Some(cond) = rule.when.as_deref().and_then(Condition::parse) {
            check_when_var(&what, cond.var_name(), requests, &covering, errs);
        }
        if rule.body.is_some()
            && matches!(rule.level, Some(AccessLevel::Ask | AccessLevel::AskAlways))
        {
            for (name, _) in &covering {
                errs.push(format!(
                    "{}: decides an ask on the request body on a path [requests.{}] covers, where an approval binds only the shape's `scope` fields; gate it with `when` on a bound field instead",
                    what, name
                ));
            }
        }
    }
}

/// Could a request match both `rule` and `shape`? A rule with no `match`
/// applies to every path.
fn shape_covers_rule(shape: &RequestShape, rule: &PolicyRule) -> bool {
    rule.match_patterns.is_empty()
        || rule.match_patterns.iter().any(|rp| {
            shape
                .match_pattern
                .iter()
                .any(|sp| patterns_overlap(rp, sp))
        })
}

/// The `when` var rules of [`check_rules_against_requests`]. `covering` is
/// the shapes that cover the rule, sorted by name.
fn check_when_var(
    what: &str,
    var: &str,
    requests: &HashMap<String, RequestShape>,
    covering: &[(&String, &RequestShape)],
    errs: &mut Vec<String>,
) {
    let binds = |s: &RequestShape, name: &str| s.scope.iter().any(|k| k == name);
    match var.split_once('.') {
        // `vars.<shape>.<name>`: that shape covers the rule, declares and
        // binds the var.
        Some((shape, name)) => match requests.get(shape) {
            _ if !is_ident(shape) || !is_ident(name) => errs.push(format!(
                "{}: `when` var '{}' must be `vars.<name>` or `vars.<shape>.<name>`",
                what, var
            )),
            None => errs.push(format!(
                "{}: `when` names shape '{}', which is not a [requests] shape",
                what, shape
            )),
            Some(s) if !s.vars.contains_key(name) => errs.push(format!(
                "{}: `when` references var '{}', which [requests.{}] does not declare",
                what, name, shape
            )),
            Some(s) if !binds(s, name) => errs.push(format!(
                "{}: `when` gates on var '{}', which [requests.{}] does not bind; a deciding field must be bound (add it to scope)",
                what, name, shape
            )),
            Some(_) if !covering.iter().any(|(n, _)| n.as_str() == shape) => {
                errs.push(format!(
                    "{}: `when` gates on `vars.{}`, but [requests.{}] does not cover the rule's `match`, so the var never resolves there",
                    what, var, shape
                ))
            }
            Some(_) => {}
        },
        // `vars.<name>`: every covering shape declares and binds it.
        None if covering.is_empty() => errs.push(format!(
            "{}: `when` gates on var '{}', but no [requests] shape covers the rule's `match`, so no request it matches carries vars; declare a shape for these paths or drop the `when`",
            what, var
        )),
        None => {
            for (n, s) in covering {
                if !s.vars.contains_key(var) {
                    errs.push(format!(
                        "{}: `when` references var '{}', which [requests.{}] does not declare; every shape covering the rule's `match` must declare and bind it",
                        what, var, n
                    ));
                } else if !binds(s, var) {
                    errs.push(format!(
                        "{}: `when` gates on var '{}', which [requests.{}] does not bind; every shape covering the rule's `match` must bind a deciding field (add it to scope)",
                        what, var, n
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// Test fixtures: admit a service.toml with no storage key and no policy.
#[cfg(test)]
pub(crate) fn admit_toml(service_toml: &str) -> Result<ServiceDef, Vec<String>> {
    admit(None, service_toml, None)
}
