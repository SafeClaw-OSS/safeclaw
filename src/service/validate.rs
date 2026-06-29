//! Static safety validator for service.toml recipes.
//!
//! Two future callers gate an untrusted recipe through this before it can
//! become a live connection: the `sc recipe` CLI and the console's
//! custom-TOML upload editor. The runtime broker re-checks the host-literal
//! guard at forward time (defense in depth); this validator catches problems
//! up front and rejects things the runtime can't see in isolation —
//! plaintext `http`, egress to a private/loopback/metadata address, unknown
//! template tokens, and (for uploaded recipes) arbitrary `run` / exec steps.
//!
//! Pure + synchronous: no DNS, no network. Hosts that are *domain names* are
//! accepted (resolution-time SSRF is a separate runtime concern); only
//! literal private/loopback/link-local IPs and loopback hostnames are blocked.

use std::net::IpAddr;

use super::ServiceDef;

/// Tokens the broker render engine understands. Mirrors
/// `crate::server::broker::resolve_token` — keep in sync.
///
/// Secret tokens may carry a pipe filter: `secret.X | b64` / `secret.X | basic`
/// (whitespace-tolerant). The deprecated `secret_b64.X` / `secret_basic.X`
/// prefix aliases are still recognized (they take no filter).
fn token_is_known(tok: &str) -> bool {
    let tok = tok.trim();
    if tok == "uuid_v4" || tok == "oauth.access_token" {
        return true;
    }
    // Split off an optional `| filter`; validate the source.key and the filter
    // independently.
    let (source_key, filter) = match tok.split_once('|') {
        Some((src, f)) => (src.trim(), Some(f.trim())),
        None => (tok, None),
    };
    let ns = match source_key.split_once('.').map(|(ns, _)| ns) {
        Some(ns) => ns,
        None => return false,
    };
    match ns {
        // Canonical secret form: `b64` / `basic` / `basic:<user>` filters (or none).
        "secret" => is_known_secret_filter(filter),
        // Deprecated aliases carry their encoding in the prefix — no filter.
        "secret_b64" | "secret_basic" => filter.is_none(),
        // Per-connection config slot `{{connection.<param>}}` (CONNECTION_SCHEMA.md
        // §4). Takes no filter; whether `<param>` is actually declared is enforced
        // for the host by `validate_url` and otherwise at render time.
        "connection" => filter.is_none(),
        _ => false,
    }
}

/// A secret token's pipe filter is known iff it is absent, `b64`, `basic`, or
/// `basic:<user>` with a non-empty, colon-free username. Shared by the recipe
/// validator and the compiled-recipe guard (keep in lockstep with
/// `broker::apply_secret_filter`).
fn is_known_secret_filter(filter: Option<&str>) -> bool {
    match filter {
        None | Some("b64") | Some("basic") => true,
        Some(f) => f
            .strip_prefix("basic:")
            .map_or(false, |u| !u.is_empty() && !u.contains(':')),
    }
}

/// Extract the inner text of every `{{…}}` occurrence in `s`.
fn scan_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                out.push(after[..end].trim().to_string());
                rest = &after[end + 2..];
            }
            None => break,
        }
    }
    out
}

/// The scheme+authority of `url` — everything up to the first `/` after the
/// scheme (or end-of-string). `None` if there is no `scheme://`.
fn authority_of(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    Some(after_scheme.split('/').next().unwrap_or(after_scheme))
}

/// True if `host` (no scheme, may carry `:port` / `[ipv6]`) is a literal IP in
/// a range we must never let a recipe egress to.
fn host_is_blocked_ip(host: &str) -> bool {
    // ipv6 literals are bracketed: [::1]:443
    let h = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        // ipv4 host[:port] — strip a trailing :port
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

/// True if `host` is a loopback / metadata hostname.
fn host_is_blocked_name(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "metadata.google.internal"
        || h.ends_with(".internal")
}

/// True if `authority` (`host[:port]`, IPv4 or `[ipv6]`) is a safe egress
/// target — NOT loopback / private / link-local / metadata. The runtime recheck
/// of a `{{connection.host}}` template, once resolved to a concrete host, calls
/// this before forwarding (CONNECTION_SCHEMA.md §4 — defense in depth over the
/// connect-time check).
pub fn host_egress_allowed(authority: &str) -> bool {
    !(host_is_blocked_ip(authority) || host_is_blocked_name(authority))
}

fn validate_url(upstream_id: &str, url: &str, declared_conn_params: &[String], errs: &mut Vec<String>) {
    if !url.starts_with("https://") {
        errs.push(format!(
            "upstream '{}': URL must be https:// (got '{}')",
            upstream_id, url
        ));
        // Still try the authority checks below where possible.
    }
    let Some(authority) = authority_of(url) else {
        errs.push(format!(
            "upstream '{}': URL has no scheme://host ('{}')",
            upstream_id, url
        ));
        return;
    };
    if authority.contains("{{") {
        // The ONE allowed host template (CONNECTION_SCHEMA.md §4): every token in
        // the authority is a declared `{{connection.<param>}}` slot. Its resolved
        // value is SSRF-checked at forward time (`host_egress_allowed`). Any other
        // host token (`{{secret.*}}`, an undeclared param) is rejected.
        let toks = scan_tokens(authority);
        let all_declared = !toks.is_empty()
            && toks.iter().all(|t| {
                t.strip_prefix("connection.")
                    .map(|p| declared_conn_params.iter().any(|d| d == p.trim()))
                    .unwrap_or(false)
            });
        if !all_declared {
            errs.push(format!(
                "upstream '{}': host is templated ('{}') — only a declared \
                 {{{{connection.<param>}}}} slot may template the host",
                upstream_id, authority
            ));
        }
        return; // a (declared) templated host can't be IP-checked statically
    }
    if host_is_blocked_ip(authority) || host_is_blocked_name(authority) {
        errs.push(format!(
            "upstream '{}': egress host '{}' is loopback / private / link-local — not allowed",
            upstream_id, authority
        ));
    }
}

/// A recipe / provider / connection id slug: `^[a-z0-9][a-z0-9_-]{0,63}$`
/// (CONNECTIONS_AND_AUTH.md §1/§5). No `:`, `/`, `.` — so a namespaced
/// `<connection_id>:<role>` vault key can never be forged from an id, and an id
/// can never traverse paths.
fn is_valid_slug(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Validate one recipe's `service.toml` source.
///
/// `first_party = true` for in-tree / trusted recipes (which may use `run` /
/// exec steps — e.g. nodpay, openclaw-dashboard); `false` for user-uploaded
/// recipes, where exec is forbidden and an upstream may only proxy.
///
/// Returns `Ok(())` or every problem found (so the UI can show them all).
pub fn validate_recipe(toml_str: &str, first_party: bool) -> Result<(), Vec<String>> {
    let def: ServiceDef = match toml::from_str(toml_str) {
        Ok(d) => d,
        Err(e) => return Err(vec![format!("parse error: {}", e)]),
    };

    let mut errs = Vec::new();

    if !is_valid_slug(&def.service.id) {
        errs.push(format!(
            "service id '{}' is not a valid slug (^[a-z0-9][a-z0-9_-]{{0,63}}$)",
            def.service.id
        ));
    }

    for u in &def.upstream {
        let declared_params: &[String] = u
            .connection
            .as_ref()
            .map(|c| c.params.as_slice())
            .unwrap_or(&[]);
        validate_url(&u.id, &u.url, declared_params, &mut errs);

        // Known-token check across every rendered surface.
        let mut surfaces: Vec<(&str, String)> = vec![(u.url.as_str(), "url".to_string())];
        for (k, v) in &u.headers {
            surfaces.push((v.as_str(), format!("header '{}'", k)));
        }
        for (k, v) in &u.query {
            surfaces.push((v.as_str(), format!("query '{}'", k)));
        }
        for (surface, label) in surfaces {
            for tok in scan_tokens(surface) {
                if !token_is_known(&tok) {
                    errs.push(format!(
                        "upstream '{}': unknown template token '{{{{{}}}}}' in {}",
                        u.id, tok, label
                    ));
                }
            }
        }
    }

    if !first_party {
        for api in &def.api {
            for step in &api.steps {
                if step.run.is_some() || !step.target.starts_with("upstream:") {
                    errs.push(format!(
                        "exec/non-upstream step (target '{}') is not allowed in an uploaded recipe",
                        step.target
                    ));
                }
            }
        }
    }

    // Streaming services must be allow-policy. A streamed body (e.g. a git
    // packfile) is live — it can't be paused to run the per-request passkey
    // ceremony — so `stream.rs` only serves allow-level streaming services.
    // Reject a declared non-allow level at LOAD time rather than failing
    // opaquely at request time. (Approval-gated streaming is a future pre-grant
    // *window*, not per-request — GIT_INTEGRATION.md §7.1.)
    if def.upstream.iter().any(|u| u.stream) {
        if let Some(levels) = def.policy.as_ref().and_then(|p| p.levels.as_ref()) {
            for key in ["read", "write"] {
                if let Some(level) = levels.get(key) {
                    if level != "allow" {
                        errs.push(format!(
                            "streaming service declares {} = \"{}\"; streaming requires \"allow\" \
                             (a live stream can't be gated by per-request approval)",
                            key, level
                        ));
                    }
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

/// Validate a `services/_providers/<name>.toml` source (a `[provider.<name>]`
/// template). The OSS-recipe safety rule (CONNECTIONS_AND_AUTH.md §2): a LITERAL
/// `client_secret` may appear ONLY for a `client_type = "public"` client — a
/// confidential Web-app secret must never be committed to a public recipe. Also
/// checks the provider name is a slug and the OAuth endpoints are https
/// literals to a public host.
pub fn validate_provider(toml_str: &str) -> Result<(), Vec<String>> {
    let def: super::ProviderFileDef = match toml::from_str(toml_str) {
        Ok(d) => d,
        Err(e) => return Err(vec![format!("parse error: {}", e)]),
    };

    let mut errs = Vec::new();
    for (name, p) in &def.provider {
        if !is_valid_slug(name) {
            errs.push(format!("provider '{}': name is not a valid slug", name));
        }
        if p.client_secret.is_some() && p.client_type.as_deref() != Some("public") {
            errs.push(format!(
                "provider '{}': a literal client_secret requires client_type = \"public\" \
                 (a confidential Web-app secret must never be committed to a recipe)",
                name
            ));
        }
        if let Some(u) = &p.authorization_url {
            validate_url(&format!("provider '{}' authorization_url", name), u, &[], &mut errs);
        }
        if let Some(u) = &p.token_url {
            validate_url(&format!("provider '{}' token_url", name), u, &[], &mut errs);
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GITHUB: &str = r#"
[service]
id = "github"
name = "GitHub"
category = "integration"
[[upstream]]
id = "default"
url = "https://api.github.com"
auth = { env = "github_token" }
[upstream.headers]
Authorization = "Bearer {{secret.github_token}}"
[[api]]
path = "*"
  [[api.steps]]
  target = "upstream:default"
  returns = true
"#;

    #[test]
    fn valid_first_party_and_uploaded() {
        assert!(validate_recipe(GITHUB, true).is_ok());
        // proxy-only recipe is fine as an upload too
        assert!(validate_recipe(GITHUB, false).is_ok());
    }

    #[test]
    fn valid_oauth_and_path_template() {
        let oauth = r#"
[service]
id = "gmail"
name = "Gmail"
category = "integration"
[[upstream]]
id = "default"
url = "https://gmail.googleapis.com"
[upstream.auth]
type = "oauth2"
env = "gmail_refresh_token"
[upstream.headers]
Authorization = "Bearer {{oauth.access_token}}"
"#;
        assert!(validate_recipe(oauth, false).is_ok());

        let telegram = r#"
[service]
id = "telegram"
name = "Telegram"
category = "channel"
[[upstream]]
id = "default"
url = "https://api.telegram.org/bot{{secret.telegram_bot_token}}"
auth = { env = "telegram_bot_token" }
"#;
        assert!(validate_recipe(telegram, false).is_ok());
    }

    #[test]
    fn rejects_plaintext_http() {
        let toml = GITHUB.replace("https://api.github.com", "http://api.github.com");
        let errs = validate_recipe(&toml, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("https")), "{:?}", errs);
    }

    #[test]
    fn rejects_templated_host() {
        let toml = GITHUB.replace("https://api.github.com", "https://{{secret.host}}.evil.com");
        let errs = validate_recipe(&toml, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("templated")), "{:?}", errs);
    }

    #[test]
    fn rejects_unknown_token() {
        let toml = GITHUB.replace("{{secret.github_token}}", "{{auth_value}}");
        let errs = validate_recipe(&toml, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("unknown template token")), "{:?}", errs);
    }

    #[test]
    fn accepts_pipe_filter_tokens() {
        // The canonical filter grammar is a known token.
        assert!(token_is_known("secret.k | b64"));
        assert!(token_is_known("secret.k | basic"));
        assert!(token_is_known("secret.k | basic:oauth2"));
        assert!(token_is_known("secret.k"));
        assert!(token_is_known("secret_b64.k"));
        assert!(token_is_known("secret_basic.k"));
        // Unknown filter / alias-with-filter / malformed basic:user are NOT known.
        assert!(!token_is_known("secret.k | urlenc"));
        assert!(!token_is_known("secret.k | basic:"));
        assert!(!token_is_known("secret.k | basic:a:b"));
        assert!(!token_is_known("secret_b64.k | basic"));
        assert!(!token_is_known("auth_value"));

        // End to end through validate_recipe: a header using the pipe form
        // validates clean.
        let toml = GITHUB.replace("{{secret.github_token}}", "{{secret.github_token | b64}}");
        assert!(validate_recipe(&toml, true).is_ok());
    }

    #[test]
    fn streaming_requires_allow_policy() {
        const STREAM: &str = r#"
[service]
id = "git-host"
name = "Git host"
category = "integration"
[[upstream]]
id = "git"
url = "https://github.com"
stream = true
auth = { secret = "github_token" }
[upstream.headers]
Authorization = "Basic {{secret.github_token | basic}}"
"#;
        // No policy block → defaults to allow at runtime → OK.
        assert!(validate_recipe(STREAM, true).is_ok());
        // Explicit allow → OK.
        let ok = format!("{}\n[policy.levels]\nread = \"allow\"\nwrite = \"allow\"\n", STREAM);
        assert!(validate_recipe(&ok, true).is_ok());
        // A non-allow level on a streaming service is rejected at load time.
        let bad = format!("{}\n[policy.levels]\nread = \"ask\"\nwrite = \"allow\"\n", STREAM);
        let errs = validate_recipe(&bad, true).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("streaming requires \"allow\"")),
            "{:?}",
            errs
        );
    }

    #[test]
    fn rejects_private_and_loopback_and_metadata_hosts() {
        for bad in [
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://127.0.0.1",
            "https://169.254.169.254",
            "https://localhost",
            "https://metadata.google.internal",
        ] {
            let toml = GITHUB.replace("https://api.github.com", bad);
            let errs = validate_recipe(&toml, true).unwrap_err();
            assert!(
                errs.iter().any(|e| e.contains("loopback") || e.contains("not allowed")),
                "{} should be blocked, got {:?}",
                bad,
                errs
            );
        }
    }

    #[test]
    fn exec_step_gated_by_first_party() {
        let exec = r#"
[service]
id = "nodpay"
name = "NodPay"
category = "integration"
[[api]]
method = "POST"
path = "/sign"
  [[api.steps]]
  target = "safeclaw"
  run = "npx nodpay sign"
  returns = true
"#;
        // first-party recipe may use exec
        assert!(validate_recipe(exec, true).is_ok());
        // uploaded recipe may not
        let errs = validate_recipe(exec, false).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("not allowed in an uploaded recipe")), "{:?}", errs);
    }

    #[test]
    fn parse_error_is_reported() {
        let errs = validate_recipe("this is not toml = = =", false).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("parse error")), "{:?}", errs);
    }

    // ── provider validation: literal client_secret ⇒ client_type="public" ───

    const GOOGLE_PROVIDER: &str = r#"
[provider.google]
auth_mode = "oauth2"
flow = "authorization_code"
authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
pkce = true
client_id = "499410884315-x.apps.googleusercontent.com"
client_secret = "GOCSPX-public-desktop"
client_type = "public"
"#;

    #[test]
    fn public_desktop_provider_with_secret_ok() {
        assert!(validate_provider(GOOGLE_PROVIDER).is_ok());
    }

    #[test]
    fn confidential_secret_in_recipe_rejected() {
        // A literal client_secret with a non-public client_type is the exact
        // mistake the rule guards against (committing a confidential secret).
        let bad = GOOGLE_PROVIDER.replace("client_type = \"public\"", "client_type = \"confidential\"");
        let errs = validate_provider(&bad).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("client_type = \"public\"")), "{:?}", errs);

        // Omitting client_type entirely is also rejected (no default to public).
        let bad2 = GOOGLE_PROVIDER.replace("client_type = \"public\"\n", "");
        let errs2 = validate_provider(&bad2).unwrap_err();
        assert!(errs2.iter().any(|e| e.contains("client_type = \"public\"")), "{:?}", errs2);
    }

    #[test]
    fn confidential_provider_without_committed_secret_ok() {
        // A confidential client that does NOT ship its secret in the recipe is
        // fine (the daemon/self-hoster supplies it out of band).
        let conf = GOOGLE_PROVIDER
            .replace("client_secret = \"GOCSPX-public-desktop\"\n", "")
            .replace("client_type = \"public\"", "client_type = \"confidential\"");
        assert!(validate_provider(&conf).is_ok());
    }

    #[test]
    fn rejects_bad_service_id_slug() {
        let bad = GITHUB.replace("id = \"github\"", "id = \"Git Hub\"");
        let errs = validate_recipe(&bad, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("not a valid slug")), "{:?}", errs);
    }

    #[test]
    fn slug_rules() {
        for ok in ["gmail", "openclaw-dashboard", "openai-codex", "a1_b-2"] {
            assert!(is_valid_slug(ok), "{ok} should be a valid slug");
        }
        for bad in ["", "-leading", "Upper", "has:colon", "has/slash", "has.dot"] {
            assert!(!is_valid_slug(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn compiled_providers_pass_validator() {
        // The shipped services/_providers/*.toml must pass — a guard so a future
        // edit that drops client_type="public" while keeping the literal secret
        // fails CI instead of silently shipping a leak.
        let mut checked = 0;
        for (_name, toml_str) in crate::generated_services::compiled_provider_tomls() {
            validate_provider(toml_str)
                .unwrap_or_else(|e| panic!("compiled provider failed validator: {:?}", e));
            checked += 1;
        }
        assert!(checked >= 1, "expected at least the google provider compiled in");
    }

    #[test]
    fn google_oauth_family_has_distinct_default_secret_names() {
        // DP1 (CONNECTION_SCHEMA.md §9): gmail / gdrive / gcalendar share the
        // Google provider but each holds a *separate scoped token*. As default
        // (bare-name) connections their secret roles MUST NOT collide. (A general
        // global-uniqueness check would false-positive on intentional sharing —
        // e.g. two `openai` recipes reusing one OPENAI_API_KEY — so we guard the
        // one family where distinctness is load-bearing.)
        let names: std::collections::HashSet<&str> =
            ["GMAIL_REFRESH_TOKEN", "GOOGLE_DRIVE_REFRESH_TOKEN", "GOOGLE_CALENDAR_REFRESH_TOKEN"]
                .into_iter()
                .collect();
        assert_eq!(names.len(), 3, "the Google OAuth family secret names must be distinct");
    }

    #[test]
    fn connection_host_slot_validates() {
        // A host templated with a DECLARED `{{connection.host}}` slot is allowed
        // (CONNECTION_SCHEMA.md §4); the resolved host is SSRF-checked at runtime.
        let ok = r#"
[service]
id = "acme-forge"
name = "Acme Forge"
category = "integration"
[[upstream]]
id = "rest"
url = "https://{{connection.host}}/api/v4"
auth = { secret = "FORGE_TOKEN" }
[upstream.connection]
params = ["host"]
[upstream.headers]
PRIVATE-TOKEN = "{{secret.FORGE_TOKEN}}"
"#;
        assert!(validate_recipe(ok, true).is_ok(), "{:?}", validate_recipe(ok, true));

        // Undeclared connection param in the host → rejected.
        let undeclared = ok.replace("params = [\"host\"]", "params = []");
        assert!(validate_recipe(&undeclared, true).is_err());

        // A `{{secret.*}}` in the host is never allowed (SSRF / credential leak).
        let secret_host = ok.replace("{{connection.host}}", "{{secret.FORGE_TOKEN}}");
        let errs = validate_recipe(&secret_host, true).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("templated")), "{:?}", errs);
    }

    #[test]
    fn host_egress_allowed_blocks_private_and_metadata() {
        assert!(host_egress_allowed("api.gitlab.com"));
        assert!(host_egress_allowed("git.acme.com:8443"));
        assert!(!host_egress_allowed("127.0.0.1"));
        assert!(!host_egress_allowed("10.0.0.5"));
        assert!(!host_egress_allowed("169.254.169.254"));
        assert!(!host_egress_allowed("localhost"));
        assert!(!host_egress_allowed("metadata.google.internal"));
    }
}
