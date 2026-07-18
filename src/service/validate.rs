//! Static safety validator for v4 service.toml definitions.
//!
//! Two callers gate an untrusted definition through this before it can become a
//! live connection: the `sc service` CLI and the console's custom-TOML editor
//! (per-vault `aux.services`, re-validated at unlock). The runtime anchor
//! re-checks host egress at forward time (defense in depth); this validator
//! catches problems up front and rejects things the runtime can't see in
//! isolation — a bad host anchor, egress to a private/loopback/metadata
//! address, a stale v3 or tool-named section (rejected at parse by
//! `deny_unknown_fields`), and an incomplete `[oauth2]` section (it must be
//! inline-complete — there is no provider-template layer).
//!
//! Pure + synchronous: no DNS, no network. Hosts that are *domain names* are
//! accepted (resolution-time SSRF is a separate runtime concern); only literal
//! private/loopback/link-local IPs and loopback hostnames are blocked.

use std::collections::HashSet;
use std::net::IpAddr;

use super::ServiceDef;

/// True if `host` (no scheme, no port) is a literal IP in a range we must never
/// let a definition egress to.
fn host_is_blocked_ip(host: &str) -> bool {
    // ipv6 literals are bracketed: [::1]
    let h = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16 — incl. cloud metadata 169.254.169.254
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
        Err(_) => false, // domain name — not blocked here
    }
}

/// True if `host` is an RFC-6761 loopback NAME. The SSRF floor is otherwise
/// IP-range based (`host_is_blocked_ip`, which already covers the 169.254/16
/// metadata IP) — mainstream forward-proxy hygiene. We add ONLY the loopback
/// names here; NO `.internal` / `metadata.google.internal` name special-cases
/// (CREDENTIAL_BROKER.md §14): a credential only reaches a host a HUMAN deliberately
/// anchored (curated PR / `sc connect` behind a passkey), we don't resolve DNS
/// at egress, and blocking `.internal` would wrongly reject a user's legitimate
/// self-hosted `*.internal` service.
fn host_is_blocked_name(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

/// True if `authority` (`host[:port]`, IPv4 or `[ipv6]`) is a safe egress
/// target — NOT loopback / private / link-local / metadata. The runtime anchor
/// calls this as the floor beneath the exact-FQDN host check before forwarding
/// (defense in depth over the connect-time check).
pub fn host_egress_allowed(authority: &str) -> bool {
    !(host_is_blocked_ip(authority) || host_is_blocked_name(authority))
}

/// A service / connection id usable as a phantom `<conn>` segment: `[a-z0-9_]`,
/// no `__` (the phantom delimiter), starting alphanumeric.
fn is_valid_service_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || s.contains("__") {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A secret role key: env-style `[A-Z0-9_]`, starts with a letter, and — because
/// its lowercase becomes a phantom role segment (`__sc__<conn>__<role>__`) — it
/// must carry no `__` (the delimiter) and no trailing `_` (which would fuse into
/// the delimiter as `___` and make the advertised phantom unparseable).
fn is_valid_role(s: &str) -> bool {
    if s.is_empty() || s.contains("__") || s.ends_with('_') {
        return false;
    }
    let first_ok = s
        .chars()
        .next()
        .map(|c| c.is_ascii_uppercase())
        .unwrap_or(false);
    first_ok
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A single host anchor entry: an exact FQDN or a `*.suffix` wildcard (leftmost,
/// single label). Authorities only — no scheme, no path, no port, no template.
fn validate_host(entry: &str, errs: &mut Vec<String>) {
    if entry.contains("://") || entry.contains('/') || entry.contains("{{") {
        errs.push(format!(
            "host '{}' must be a bare authority (no scheme/path/template)",
            entry
        ));
        return;
    }
    if entry.contains(':') {
        errs.push(format!("host '{}' must not carry a port", entry));
        return;
    }
    if entry == "*" {
        errs.push("a bare '*' host is forbidden — anchor to an exact FQDN or a '*.suffix'".into());
        return;
    }
    let base = if let Some(suffix) = entry.strip_prefix("*.") {
        // A `*.suffix` wildcard: the suffix itself must carry no further '*' and
        // be a real multi-label domain to pin within.
        if suffix.contains('*') || suffix.is_empty() {
            errs.push(format!(
                "host '{}': '*' is only allowed as the leftmost single label",
                entry
            ));
            return;
        }
        suffix
    } else {
        if entry.contains('*') {
            errs.push(format!(
                "host '{}': '*' is only allowed as the leftmost single label",
                entry
            ));
            return;
        }
        entry
    };
    if host_is_blocked_ip(base) || host_is_blocked_name(base) {
        errs.push(format!(
            "host '{}' is loopback / private / link-local — not allowed",
            entry
        ));
    }
}

/// Validate a v4 `service.toml` source. `first_party` is kept for CLI
/// compatibility but no longer gates anything (exec steps were removed with the
/// v3 execution surface). Returns `Ok(())` or every problem found.
pub fn validate_recipe(toml_str: &str, _first_party: bool) -> Result<(), Vec<String>> {
    validate_service_inner(toml_str)
}

/// Validate a v4 `service.toml` source — the custom-service (`aux.services`)
/// path. Same checks as `validate_recipe` (the old shipped-provider set is
/// gone; `[oauth2]` must be inline-complete everywhere).
pub fn validate_service(toml_str: &str) -> Result<(), Vec<String>> {
    validate_service_inner(toml_str)
}

fn validate_service_inner(toml_str: &str) -> Result<(), Vec<String>> {
    // deny_unknown_fields on ServiceDef/OAuth2Def turns every stale v3 section
    // and every tool-named section into a parse error here.
    let def: ServiceDef = match toml::from_str(toml_str) {
        Ok(d) => d,
        Err(e) => return Err(vec![format!("parse error: {}", e)]),
    };

    let mut errs = Vec::new();

    if !is_valid_service_id(&def.service.id) {
        errs.push(format!(
            "service id '{}' is not valid (^[a-z0-9][a-z0-9_]* , no '__')",
            def.service.id
        ));
    }

    // Hosts: non-hidden services must anchor at least one; every entry is an
    // exact FQDN or a `*.suffix` wildcard.
    if def.service.hosts.is_empty() && !def.service.hidden {
        errs.push("service declares no hosts (an anchor is required)".into());
    }
    for h in &def.service.hosts {
        validate_host(h, &mut errs);
    }

    // Secrets: env-style role keys, no duplicates.
    let mut seen_secret = HashSet::new();
    for s in &def.service.secrets {
        if !is_valid_role(s) {
            errs.push(format!(
                "secret role '{}' is not a valid env key ([A-Z0-9_])",
                s
            ));
        }
        if !seen_secret.insert(s.to_ascii_uppercase()) {
            errs.push(format!("duplicate secret role '{}'", s));
        }
    }

    // Tags: lowercase-kebab slugs, no duplicates. Free vocabulary (custom
    // services may invent business tags); only the SHAPE is enforced so the
    // console can render any tag as a filter chip verbatim.
    let mut seen_tag = HashSet::new();
    for t in &def.service.tags {
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

    // secret_url: auxiliary display-only link, but it IS rendered as an <a href>
    // by the console — require a plain web URL so a custom definition can't
    // smuggle a javascript:/data: link into the UI.
    if let Some(u) = &def.service.secret_url {
        if !(u.starts_with("https://") || u.starts_with("http://")) {
            errs.push(format!("secret_url '{}' must be an http(s) URL", u));
        }
    }

    // OAuth2: the section is SELF-SUFFICIENT — the inline fields must carry the
    // endpoints + client (there is no template layer; `provider` is a display
    // label only). Endpoint floor: https to a public host, no confidential
    // secret. Exposes are lowercase slugs that don't collide with secrets.
    if let Some(crate::service::AuthDef::Snaplii(_)) = &def.auth {
        // The snaplii mechanism's exchange input is the first `secrets` role —
        // a def without one can never mint.
        if def.mint_input_role().is_none() {
            errs.push(
                "[auth] type=\"snaplii\" requires a [service] secrets entry (the exchange api key)"
                    .into(),
            );
        }
    }
    if let Some(o) = def.oauth2() {
        if !(o.authorization_url.is_some() && o.token_url.is_some() && o.client_id.is_some()) {
            errs.push(
                "[auth] oauth2 must declare authorization_url + token_url + client_id inline"
                    .into(),
            );
        }
        if o.provider.as_deref().is_some_and(|p| p.trim().is_empty()) {
            errs.push("[auth] provider (display label) must not be empty (omit it instead)".into());
        }
        if let Some(u) = &o.authorization_url {
            validate_https_public_url("[auth] authorization_url", u, &mut errs);
        }
        if let Some(u) = &o.token_url {
            validate_https_public_url("[auth] token_url", u, &mut errs);
        }
        for (role, path) in &o.claims {
            if !o.exposes.iter().any(|e| e == role) {
                errs.push(format!("[auth] claims key '{}' is not in exposes", role));
            }
            if path.is_empty() || path.iter().any(|s| s.trim().is_empty()) {
                errs.push(format!(
                    "[auth] claims path for '{}' has an empty segment",
                    role
                ));
            }
        }
        // authorize_params are ADDITIONS to the consent URL — never overrides
        // of the protocol params the flow itself controls.
        for k in o.authorize_params.keys() {
            if RESERVED_AUTHORIZE_PARAMS.contains(&k.as_str()) {
                errs.push(format!(
                    "[auth] authorize_params may not set the reserved param '{}'",
                    k
                ));
            }
        }
        // Durable token slots use RFC 6749 field names; each must be a valid
        // uppercase env KEY that is ALSO declared in the top-level `secrets` set
        // (secrets is the uniform durable-credential contract — SERVICES.md §3).
        let declared = |k: &str| {
            def.service
                .secrets
                .iter()
                .any(|s| s.eq_ignore_ascii_case(k))
        };
        if o.refresh_token.trim().is_empty() {
            errs.push("[oauth2] requires a refresh_token (the vault secret KEY the refresh token is stored under)".into());
        } else if !is_valid_role(&o.refresh_token) {
            errs.push(format!(
                "[oauth2] refresh_token '{}' is not a valid env key ([A-Z0-9_])",
                o.refresh_token
            ));
        } else if !declared(&o.refresh_token) {
            errs.push(format!(
                "[oauth2] refresh_token '{}' must be listed in the service's top-level secrets",
                o.refresh_token
            ));
        }
        if let Some(idt) = &o.id_token {
            if !is_valid_role(idt) {
                errs.push(format!(
                    "[oauth2] id_token '{}' is not a valid env key ([A-Z0-9_])",
                    idt
                ));
            } else if !declared(idt) {
                errs.push(format!(
                    "[oauth2] id_token '{}' must be listed in the service's top-level secrets",
                    idt
                ));
            }
        }
        for e in &o.exposes {
            if !is_valid_service_id(e) {
                errs.push(format!(
                    "[oauth2] exposes entry '{}' is not a valid role ([a-z0-9_])",
                    e
                ));
            }
            if seen_secret.contains(&e.to_ascii_uppercase()) {
                errs.push(format!(
                    "[oauth2] exposes entry '{}' collides with a secret role",
                    e
                ));
            }
        }
    }

    // [requests] shapes (design/request-scope.md). Intra-service invariants — the
    // cross-file "when-var ∈ requests" check needs the paired policy.toml and
    // lives in `validate_service_policy` / the compiled-defs test.
    for (name, shape) in &def.requests {
        if shape.match_pattern.is_empty() {
            errs.push(format!("[requests.{}] declares no `match`", name));
        }
        // A body pointer must be an RFC 6901 pointer (leading '/'); a query
        // `at` must be non-empty. Catches `vars.x = "amount"` (missing '/').
        for (var, def_) in &shape.vars {
            match def_ {
                crate::service::VarDef::BodyPointer(p)
                | crate::service::VarDef::Located {
                    location: crate::service::VarLoc::Body,
                    at: p,
                } => {
                    if !p.starts_with('/') {
                        errs.push(format!(
                            "[requests.{}] var '{}' body address '{}' must be a JSON Pointer (start with '/')",
                            name, var, p
                        ));
                    }
                }
                crate::service::VarDef::Located {
                    location: crate::service::VarLoc::Query,
                    at,
                } => {
                    if at.is_empty() {
                        errs.push(format!(
                            "[requests.{}] var '{}' query `at` is empty",
                            name, var
                        ));
                    }
                }
            }
        }
        // scope ⊆ vars: you can only bind a field you declared. Reject
        // duplicates too — a repeated entry makes the approve digest (object,
        // deduped) and redeem digest (vec, not) permanently disagree.
        let mut seen_scope = HashSet::new();
        for k in &shape.scope {
            if !shape.vars.contains_key(k) {
                errs.push(format!(
                    "[requests.{}] scope names '{}', which is not a declared var",
                    name, k
                ));
            }
            if !seen_scope.insert(k) {
                errs.push(format!(
                    "[requests.{}] scope lists '{}' more than once",
                    name, k
                ));
            }
        }
        // P4 show ⊆ bind: every {token} a consent template interpolates must be
        // in scope. (A `render` hint needs no check — its console renderer only
        // reads the bound `scope_vars`, so show ⊆ bind holds by construction.)
        if let Some(consent) = &shape.consent {
            for tok in crate::service::consent_tokens(consent) {
                if !shape.scope.contains(&tok) {
                    errs.push(format!(
                        "[requests.{}] consent references '{{{}}}', which is not in `scope` (show ⊆ bind)",
                        name, tok
                    ));
                }
            }
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Cross-file check: every `vars.<name>` a policy.toml rule's `when` references
/// must be a var declared by SOME `[requests]` shape in the paired
/// service.toml, and every `when` must parse. Runs where both files are
/// available (the compiled-defaults test; a future console paired submit).
pub fn validate_service_policy(service_toml: &str, policy_toml: &str) -> Result<(), Vec<String>> {
    let def: ServiceDef =
        toml::from_str(service_toml).map_err(|e| vec![format!("service parse: {}", e)])?;
    let policy: crate::service::PolicyFileDef =
        toml::from_str(policy_toml).map_err(|e| vec![format!("policy parse: {}", e)])?;
    let declared: HashSet<&str> = def
        .requests
        .values()
        .flat_map(|s| s.vars.keys().map(|k| k.as_str()))
        .collect();
    // A field the DECISION depends on must also be BOUND — else an ask-always
    // approved for `risk == "high"` could be redeemed at `risk == "low"`
    // (the grant wouldn't lock the deciding field). So a `when` var must be in
    // SOME shape's scope, not merely declared.
    let bound: HashSet<&str> = def
        .requests
        .values()
        .flat_map(|s| s.scope.iter().map(|k| k.as_str()))
        .collect();
    let mut errs = Vec::new();
    for rule in &policy.rule {
        let Some(when) = &rule.when else { continue };
        let Some(cond) = crate::core::policy::Condition::parse(when) else {
            errs.push(format!("rule '{}': `when = \"{}\"` is not a valid condition (expected `vars.<name> <op> <literal>`)", rule.id, when));
            continue;
        };
        // Strip a `shape.` qualifier for the membership check.
        let bare = cond
            .var_name()
            .rsplit('.')
            .next()
            .unwrap_or(cond.var_name());
        if !declared.contains(bare) {
            errs.push(format!(
                "rule '{}': `when` references var '{}', which no [requests] shape declares",
                rule.id,
                cond.var_name()
            ));
        } else if !bound.contains(bare) {
            errs.push(format!(
                "rule '{}': `when` gates on var '{}', which is not in any shape's `scope` — a deciding field must be bound (add it to scope)",
                rule.id, cond.var_name()
            ));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Consent-URL query params the OAuth flow itself controls — an
/// `authorize_params` map may never set these (the frontend applies the map
/// FIRST and the protocol params after, so an entry here would silently lose;
/// reject it loudly instead).
const RESERVED_AUTHORIZE_PARAMS: &[&str] = &[
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
];

/// A provider endpoint must be an https literal to a public host.
fn validate_https_public_url(label: &str, url: &str, errs: &mut Vec<String>) {
    if !url.starts_with("https://") {
        errs.push(format!("{}: URL must be https:// (got '{}')", label, url));
    }
    let Some(authority) = url
        .split_once("://")
        .map(|(_, r)| r.split('/').next().unwrap_or(r))
    else {
        errs.push(format!("{}: URL has no scheme://host ('{}')", label, url));
        return;
    };
    if host_is_blocked_ip(authority) || host_is_blocked_name(authority) {
        errs.push(format!(
            "{}: egress host '{}' is loopback / private / link-local",
            label, authority
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GITHUB: &str = r#"
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
"#;

    #[test]
    fn valid_direct_service() {
        assert!(validate_recipe(GITHUB, true).is_ok());
        assert!(validate_recipe(GITHUB, false).is_ok());
    }

    #[test]
    fn oauth2_must_be_inline_complete() {
        // A provider label with no inline wiring is no longer resolvable —
        // there is no template layer to fill the gaps.
        let label_only = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
"#;
        assert!(validate_recipe(label_only, false).is_err());
        assert!(validate_service(label_only).is_err());
    }

    #[test]
    fn inline_oauth2_is_self_sufficient() {
        let inline = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_REFRESH_TOKEN"]
[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "ACME_REFRESH_TOKEN"
"#;
        assert!(validate_service(inline).is_ok());
        // A provider label on top of complete inline fields is fine (label only).
        let labeled = inline.replace("[oauth2]", "[oauth2]\nprovider = \"acme\"");
        assert!(validate_service(&labeled).is_ok());
        // Incomplete inline is rejected.
        let broken = inline.replace("token_url = \"https://auth.acme.dev/token\"\n", "");
        assert!(validate_service(&broken).is_err());
        // http:// endpoints are rejected.
        let http = inline.replace("https://auth.acme.dev/token", "http://auth.acme.dev/token");
        assert!(validate_service(&http).is_err());
        // A literal client_secret is a public client's by convention — fine.
        let secret = inline.replace(
            "client_id = \"acme-public\"",
            "client_id = \"acme-public\"\nclient_secret = \"shh\"",
        );
        assert!(validate_service(&secret).is_ok());
        // The retired client_type assertion is an unknown field now.
        let stale = inline.replace(
            "client_id = \"acme-public\"",
            "client_id = \"acme-public\"\nclient_secret = \"shh\"\nclient_type = \"public\"",
        );
        assert!(validate_service(&stale).is_err());
    }

    #[test]
    fn oauth2_claims_and_authorize_params_are_checked() {
        let base = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_REFRESH_TOKEN"]
[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "ACME_REFRESH_TOKEN"
exposes = ["account_id"]
"#;
        let good = format!("{base}[auth.claims]\naccount_id = [\"ns\", \"leaf\"]\n");
        assert!(validate_service(&good).is_ok());
        // claims key must be an exposes role; path segments must be non-empty.
        let stray = format!("{base}[auth.claims]\nother = [\"x\"]\n");
        assert!(validate_service(&stray).is_err());
        let hollow = format!("{base}[auth.claims]\naccount_id = []\n");
        assert!(validate_service(&hollow).is_err());
        // authorize_params may add params but never reserved protocol ones.
        let extra = format!("{base}[auth.authorize_params]\nfoo_flag = \"true\"\n");
        assert!(validate_service(&extra).is_ok());
        let reserved =
            format!("{base}[auth.authorize_params]\nredirect_uri = \"https://evil.example\"\n");
        assert!(validate_service(&reserved).is_err());
    }

    #[test]
    fn rejects_tool_named_section() {
        let toml = format!("{}\n[git]\nhelper = \"x\"\n", GITHUB);
        let errs = validate_recipe(&toml, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("parse error")), "{:?}", errs);
    }

    #[test]
    fn rejects_v3_upstream_section() {
        let toml = r#"
[service]
id = "x"
name = "X"
[[upstream]]
id = "default"
url = "https://x.com"
"#;
        let errs = validate_recipe(toml, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("parse error")), "{:?}", errs);
    }

    #[test]
    fn host_rules() {
        // exact FQDN + single-label wildcard OK.
        let ok = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.com", "*.openai.azure.com"]
secrets = ["ACME_TOKEN"]
"#;
        assert!(
            validate_recipe(ok, true).is_ok(),
            "{:?}",
            validate_recipe(ok, true)
        );
        // bare '*' forbidden.
        let bad = ok.replace("\"*.openai.azure.com\"", "\"*\"");
        assert!(validate_recipe(&bad, true).is_err());
        // scheme/path forbidden.
        let scheme = ok.replace("\"api.acme.com\"", "\"https://api.acme.com\"");
        assert!(validate_recipe(&scheme, true).is_err());
        let path = ok.replace("\"api.acme.com\"", "\"api.acme.com/v1\"");
        assert!(validate_recipe(&path, true).is_err());
    }

    #[test]
    fn rejects_private_and_loopback_hosts() {
        // Literal private/loopback/link-local IPs (169.254.169.254 = the metadata
        // IP, covered by the range, not a name special-case) + loopback names.
        // `metadata.google.internal` / `*.internal` are NOT name-blocked (§7).
        for bad in [
            "10.0.0.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "localhost",
        ] {
            let toml = GITHUB.replace("\"api.github.com\"", &format!("\"{}\"", bad));
            let errs = validate_recipe(&toml, true).unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.contains("loopback") || e.contains("not allowed")),
                "{} should be blocked, got {:?}",
                bad,
                errs
            );
        }
    }

    #[test]
    fn allows_internal_names_only_ip_floor_blocks() {
        // §7: a `.internal` / metadata NAME is allowed at authoring (a legit
        // self-hosted service may be `foo.internal`); the metadata IP is blocked
        // by the range floor, so there's no name special-case to maintain.
        let toml = GITHUB.replace("\"api.github.com\"", "\"metadata.google.internal\"");
        assert!(
            validate_recipe(&toml, true).is_ok(),
            "{:?}",
            validate_recipe(&toml, true)
        );
        let internal = GITHUB.replace("\"api.github.com\"", "\"vault.corp.internal\"");
        assert!(validate_recipe(&internal, true).is_ok());
    }

    #[test]
    fn rejects_bad_service_id() {
        let bad = GITHUB.replace("id = \"github\"", "id = \"Git Hub\"");
        assert!(validate_recipe(&bad, true)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("not valid")));
        let dbl = GITHUB.replace("id = \"github\"", "id = \"git__hub\"");
        assert!(validate_recipe(&dbl, true)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("not valid")));
        let dash = GITHUB.replace("id = \"github\"", "id = \"git-hub\"");
        assert!(validate_recipe(&dash, true)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("not valid")));
    }

    #[test]
    fn rejects_bad_secret_role() {
        let bad = GITHUB.replace("\"GITHUB_TOKEN\"", "\"github-token\"");
        assert!(validate_recipe(&bad, true)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("env key")));
    }

    #[test]
    fn secret_url_optional_and_https_only() {
        // Absent: fine (GITHUB fixture has none). Present https: fine.
        let with = GITHUB.replace(
            "secrets = [\"GITHUB_TOKEN\"]",
            "secrets = [\"GITHUB_TOKEN\"]\nsecret_url = \"https://github.com/settings/tokens?type=beta\"",
        );
        assert!(validate_recipe(&with, true).is_ok());
        // Rendered as a link — a non-web scheme must be rejected.
        let bad = with.replace(
            "https://github.com/settings/tokens?type=beta",
            "javascript:alert(1)",
        );
        assert!(validate_recipe(&bad, true)
            .unwrap_err()
            .iter()
            .any(|e| e.contains("secret_url")));
    }

    #[test]
    fn tags_lowercase_kebab_no_dups() {
        let ok = GITHUB.replace(
            "name = \"GitHub\"",
            "name = \"GitHub\"\ntags = [\"app\", \"code-hosting\"]",
        );
        assert!(validate_recipe(&ok, true).is_ok());
        for bad_tags in [
            "[\"App\"]",
            "[\"code_hosting\"]",
            "[\"-app\"]",
            "[\"\"]",
            "[\"app\", \"app\"]",
        ] {
            let bad = GITHUB.replace(
                "name = \"GitHub\"",
                &format!("name = \"GitHub\"\ntags = {}", bad_tags),
            );
            assert!(
                validate_recipe(&bad, true)
                    .unwrap_err()
                    .iter()
                    .any(|e| e.contains("tag")),
                "expected tag error for {}",
                bad_tags
            );
        }
    }

    #[test]
    fn compiled_services_pass_validator() {
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            validate_recipe(toml_str, false)
                .unwrap_or_else(|e| panic!("compiled service '{}' failed validator: {:?}", id, e));
        }
    }

    /// The cross-file gate (the de-facto build check for in-tree defs): for
    /// every compiled service that ships a policy.toml, every rule `when` must
    /// parse and reference a var some `[requests]` shape declares. This is what
    /// makes `vars.amount > 80` in snaplii's policy fail the test suite if the
    /// service.toml ever drops the `amount` var.
    #[test]
    fn compiled_policies_when_vars_are_declared() {
        let services: std::collections::HashMap<&str, &str> =
            crate::generated_services::compiled_service_tomls()
                .iter()
                .copied()
                .collect();
        for (id, policy_toml) in crate::generated_services::compiled_policy_tomls() {
            let Some(service_toml) = services.get(id) else {
                continue; // policy with no paired service — nothing to cross-check
            };
            validate_service_policy(service_toml, policy_toml)
                .unwrap_or_else(|e| panic!("service '{}' policy/requests mismatch: {:?}", id, e));
        }
    }

    // ── [requests] verification (Phase 2) ────────────────────────────────────

    const REQ_SERVICE: &str = r#"
[service]
id = "pay"
name = "Pay"
hosts = ["api.pay.com"]
secrets = ["PAY_KEY"]
[requests.purchase]
match = "POST /buy"
vars.amount = "/amount"
scope = ["amount"]
consent = "Spend {{ vars.amount }}"
"#;

    #[test]
    fn requests_valid_service_passes() {
        validate_service(REQ_SERVICE).expect("well-formed [requests] passes");
    }

    #[test]
    fn consent_var_must_be_in_scope() {
        let bad = REQ_SERVICE.replace(
            r#"consent = "Spend {{ vars.amount }}""#,
            r#"consent = "Send {{ vars.secret }}""#,
        );
        let e = validate_service(&bad).unwrap_err();
        assert!(
            e.iter()
                .any(|s| s.contains("consent references '{secret}'")),
            "got {:?}",
            e
        );
    }

    #[test]
    fn scope_must_name_a_declared_var() {
        let bad = REQ_SERVICE.replace(r#"scope = ["amount"]"#, r#"scope = ["amount", "ghost"]"#);
        let e = validate_service(&bad).unwrap_err();
        assert!(
            e.iter()
                .any(|s| s.contains("'ghost', which is not a declared var")),
            "got {:?}",
            e
        );
    }

    #[test]
    fn body_pointer_must_start_with_slash() {
        let bad = REQ_SERVICE.replace(r#"vars.amount = "/amount""#, r#"vars.amount = "amount""#);
        let e = validate_service(&bad).unwrap_err();
        assert!(
            e.iter().any(|s| s.contains("must be a JSON Pointer")),
            "got {:?}",
            e
        );
    }

    #[test]
    fn policy_when_var_must_be_declared() {
        let policy_ok = r#"
[[rule]]
id = "big"
label = "big"
match = "POST /buy"
when = "vars.amount > 80"
level = "ask-always"
"#;
        validate_service_policy(REQ_SERVICE, policy_ok).expect("when var 'amount' is declared");

        let policy_bad = policy_ok.replace("vars.amount > 80", "vars.total > 80");
        let e = validate_service_policy(REQ_SERVICE, &policy_bad).unwrap_err();
        assert!(
            e.iter().any(|s| s.contains("references var 'total'")),
            "got {:?}",
            e
        );

        let policy_malformed = policy_ok.replace("vars.amount > 80", "amount is big");
        let e = validate_service_policy(REQ_SERVICE, &policy_malformed).unwrap_err();
        assert!(
            e.iter().any(|s| s.contains("not a valid condition")),
            "got {:?}",
            e
        );
    }

    #[test]
    fn policy_when_var_must_be_bound_in_scope() {
        // A var declared but NOT in scope: gating on it is rejected (a deciding
        // field must be bound, else the approved decision can differ from the
        // redeemed one).
        let svc = REQ_SERVICE.replace(
            "vars.amount = \"/amount\"",
            "vars.amount = \"/amount\"\nvars.risk = \"/risk\"",
        );
        let policy = r#"
[[rule]]
id = "risky"
label = "risky"
match = "POST /buy"
when = "vars.risk == \"high\""
level = "ask-always"
"#;
        let e = validate_service_policy(&svc, policy).unwrap_err();
        assert!(
            e.iter().any(|s| s.contains("not in any shape's `scope`")),
            "got {:?}",
            e
        );
    }

    #[test]
    fn duplicate_scope_entry_rejected() {
        let bad = REQ_SERVICE.replace(r#"scope = ["amount"]"#, r#"scope = ["amount", "amount"]"#);
        let e = validate_service(&bad).unwrap_err();
        assert!(
            e.iter().any(|s| s.contains("more than once")),
            "got {:?}",
            e
        );
    }

    #[test]
    fn host_egress_allowed_blocks_private_ips_and_loopback_names() {
        assert!(host_egress_allowed("api.gitlab.com"));
        assert!(host_egress_allowed("git.acme.com:8443"));
        assert!(!host_egress_allowed("127.0.0.1"));
        assert!(!host_egress_allowed("10.0.0.5"));
        // The metadata IP is blocked by the link-local RANGE (169.254/16)…
        assert!(!host_egress_allowed("169.254.169.254"));
        assert!(!host_egress_allowed("localhost"));
        // …but the metadata NAME is NOT name-blocked (§7 — no special-case).
        assert!(host_egress_allowed("metadata.google.internal"));
        assert!(host_egress_allowed("vault.corp.internal"));
    }
}
