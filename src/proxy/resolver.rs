//! Phantom parsing, scanning, and substitution (pure string mechanics).
//!
//! A phantom is the ONLY injection trigger: `__sc__<conn>__` for a connection's
//! sole injectable secret, or `__sc__<conn>__<role>__` when it exposes several.
//! `<conn>`/`<role>` ∈ `[a-z0-9_]` with `__` as the (only) delimiter, so the
//! charset survives env values, URL path/query, JSON, headers, and base64 (Basic
//! auth is decoded before matching). This module finds phantoms at any site and
//! substitutes them given a resolver; it holds no vault or policy knowledge.

use once_cell::sync::Lazy;
use regex::Regex;

/// The phantom grammar as a scanner: `__sc__` + a segment + an optional
/// `__`-delimited second segment + the closing `__`. A segment is
/// alphanumeric-bounded with internal single underscores (`github_work`), so the
/// `__` delimiter is never ambiguous. Matches ANYWHERE — including glued to a
/// prefix like telegram's `/bot__sc__telegram__/…` — because a phantom is a
/// value, not necessarily a whole word.
static PHANTOM_RE: Lazy<Regex> = Lazy::new(|| {
    // A segment is alnum runs joined by SINGLE underscores — never `__` (the
    // delimiter) and no leading/trailing `_`. This is what stops the scanner
    // from fusing two directly-adjacent phantoms (`__sc__a____sc__b__`) into one
    // over-long match that `parse_phantom` then rejects, silently dropping both.
    Regex::new(r"__sc__[a-z0-9]+(?:_[a-z0-9]+)*(?:__[a-z0-9]+(?:_[a-z0-9]+)*)?__")
        .expect("phantom regex is valid")
});

/// A parsed phantom. `conn` and `role` are already lowercase (the phantom
/// charset). `role == None` is the sole-secret / oauth-access short form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phantom {
    pub conn: String,
    pub role: Option<String>,
    /// The exact matched token (e.g. `__sc__github__`) — the de-dup key.
    pub raw: String,
}

/// A body segment (`<conn>` or `<role>`): non-empty, lowercase `[a-z0-9_]`.
fn is_valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parse a single token as a phantom, or `None`. The token must be EXACTLY the
/// phantom (the scanner feeds it maximal `[A-Za-z0-9_]` runs): start `__sc__`,
/// end `__`, a lowercase body split by `__` into one or two segments. `___`
/// (triple underscore) is rejected — the delimiter is exactly `__` and ids never
/// contain it.
pub fn parse_phantom(token: &str) -> Option<Phantom> {
    let body = token.strip_prefix("__sc__")?.strip_suffix("__")?;
    if body.is_empty() || body.contains("___") {
        return None;
    }
    let segs: Vec<&str> = body.split("__").collect();
    match segs.as_slice() {
        [conn] if is_valid_segment(conn) => Some(Phantom {
            conn: (*conn).to_string(),
            role: None,
            raw: token.to_string(),
        }),
        [conn, role] if is_valid_segment(conn) && is_valid_segment(role) => Some(Phantom {
            conn: (*conn).to_string(),
            role: Some((*role).to_string()),
            raw: token.to_string(),
        }),
        _ => None,
    }
}

/// True iff `input` contains at least one phantom. Cheap pre-check that avoids
/// running the full scan on the common (unbrokered) path.
pub fn contains_phantom(input: &str) -> bool {
    input.contains("__sc__") && PHANTOM_RE.is_match(input)
}

/// Every distinct phantom in `input`, in first-seen order.
pub fn collect_phantoms(input: &str) -> Vec<Phantom> {
    let mut out: Vec<Phantom> = Vec::new();
    if !input.contains("__sc__") {
        return out;
    }
    for m in PHANTOM_RE.find_iter(input) {
        // parse_phantom is the validator — the regex over-matches `___`, which
        // parse rejects, so a malformed token is skipped, not injected.
        if let Some(ph) = parse_phantom(m.as_str()) {
            if !out.iter().any(|p| p.raw == ph.raw) {
                out.push(ph);
            }
        }
    }
    out
}

/// Substitute every phantom in `input` for which `resolve` returns a value.
/// Returns `(rewritten, substituted_any)`. Phantoms `resolve` declines (returns
/// `None`) are left verbatim — the `__sc__…__` breadcrumb makes an un-injected
/// phantom recognisable downstream rather than silently dropped.
pub fn substitute<F>(input: &str, resolve: F) -> (String, bool)
where
    F: Fn(&Phantom) -> Option<String>,
{
    if !input.contains("__sc__") {
        return (input.to_string(), false);
    }
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut any = false;
    for m in PHANTOM_RE.find_iter(input) {
        if let Some(ph) = parse_phantom(m.as_str()) {
            if let Some(val) = resolve(&ph) {
                out.push_str(&input[last..m.start()]);
                out.push_str(&val);
                last = m.end();
                any = true;
            }
        }
    }
    out.push_str(&input[last..]);
    (out, any)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn p(conn: &str, role: Option<&str>) -> Phantom {
        Phantom {
            conn: conn.to_string(),
            role: role.map(str::to_string),
            raw: match role {
                None => format!("__sc__{conn}__"),
                Some(r) => format!("__sc__{conn}__{r}__"),
            },
        }
    }

    // ── parse table ─────────────────────────────────────────────────────────
    #[test]
    fn parse_valid_sole() {
        assert_eq!(parse_phantom("__sc__github__"), Some(p("github", None)));
    }

    #[test]
    fn parse_valid_conn_with_single_underscore() {
        // A single `_` is part of the id, not a delimiter.
        assert_eq!(
            parse_phantom("__sc__github_work__"),
            Some(p("github_work", None))
        );
    }

    #[test]
    fn parse_valid_role() {
        assert_eq!(
            parse_phantom("__sc__bb__username__"),
            Some(p("bb", Some("username")))
        );
        assert_eq!(
            parse_phantom("__sc__gmail__account_id__"),
            Some(p("gmail", Some("account_id")))
        );
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(parse_phantom("__sc____"), None); // empty body
        assert_eq!(parse_phantom("__sc__github"), None); // no trailing __
        assert_eq!(parse_phantom("sc__github__"), None); // no marker
        assert_eq!(parse_phantom("__sc__a__b__c__"), None); // 3 segments
        assert_eq!(parse_phantom("__sc__GitHub__"), None); // uppercase not allowed
        assert_eq!(parse_phantom("__sc__a___b__"), None); // triple underscore
        assert_eq!(parse_phantom("__sc__git-hub__"), None); // '-' out of charset
        assert_eq!(parse_phantom("x__sc__a__"), None); // prefixed → not a phantom
    }

    // ── scan / collect ──────────────────────────────────────────────────────
    #[test]
    fn collect_distinct_in_order() {
        let s = "a=__sc__github__ b=__sc__bb__username__ c=__sc__github__";
        let got = collect_phantoms(s);
        assert_eq!(got, vec![p("github", None), p("bb", Some("username"))]);
    }

    #[test]
    fn collect_adjacent_phantoms_not_fused() {
        // Two phantoms with no separator must both be found, not swallowed into
        // one over-long match that parse rejects.
        let got = collect_phantoms("__sc__a____sc__b__");
        assert_eq!(got, vec![p("a", None), p("b", None)]);
    }

    #[test]
    fn contains_phantom_fastpath() {
        assert!(!contains_phantom("nothing here"));
        assert!(!contains_phantom("Bearer sk-live-realtoken"));
        assert!(contains_phantom("Bearer __sc__stripe_key__"));
    }

    // ── substitution sites ──────────────────────────────────────────────────
    #[test]
    fn substitute_header_value() {
        let mut m = HashMap::new();
        m.insert("__sc__stripe_key__".to_string(), "sk-live-REAL".to_string());
        let (out, any) = substitute("Bearer __sc__stripe_key__", |ph| m.get(&ph.raw).cloned());
        assert!(any);
        assert_eq!(out, "Bearer sk-live-REAL");
    }

    #[test]
    fn substitute_url_path_telegram_shape() {
        // The telegram token lives in the URL PATH, never the authority.
        let mut m = HashMap::new();
        m.insert("__sc__telegram__".to_string(), "12345:ABCDEF".to_string());
        let (out, any) = substitute("/bot__sc__telegram__/sendMessage", |ph| m.get(&ph.raw).cloned());
        assert!(any);
        assert_eq!(out, "/bot12345:ABCDEF/sendMessage");
    }

    #[test]
    fn substitute_basic_userinfo_roundtrip() {
        // The git URL-userinfo shape, once base64-decoded, is "user:pass".
        let mut m = HashMap::new();
        m.insert("__sc__github__".to_string(), "ghp_REALTOKEN".to_string());
        let decoded = "x:__sc__github__";
        let (out, any) = substitute(decoded, |ph| m.get(&ph.raw).cloned());
        assert!(any);
        assert_eq!(out, "x:ghp_REALTOKEN");
    }

    #[test]
    fn substitute_declined_phantom_left_verbatim() {
        let (out, any) = substitute("Bearer __sc__unknown__", |_| None);
        assert!(!any);
        assert_eq!(out, "Bearer __sc__unknown__");
    }

    #[test]
    fn substitute_multiple_roles_one_pass() {
        let mut m = HashMap::new();
        m.insert("__sc__bb__username__".to_string(), "alice".to_string());
        m.insert("__sc__bb__api_token__".to_string(), "t0ken".to_string());
        let (out, _) = substitute(
            "__sc__bb__username__:__sc__bb__api_token__",
            |ph| m.get(&ph.raw).cloned(),
        );
        assert_eq!(out, "alice:t0ken");
    }
}
