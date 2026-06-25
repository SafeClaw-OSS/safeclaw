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
fn token_is_known(tok: &str) -> bool {
    let tok = tok.trim();
    if tok == "uuid_v4" || tok == "oauth.access_token" {
        return true;
    }
    matches!(
        tok.split_once('.').map(|(ns, _)| ns),
        Some("secret") | Some("secret_b64") | Some("secret_basic")
    )
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

fn validate_url(upstream_id: &str, url: &str, errs: &mut Vec<String>) {
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
        errs.push(format!(
            "upstream '{}': host is templated ('{}') — only the path may carry {{{{…}}}}",
            upstream_id, authority
        ));
        return; // can't reason about a templated host further
    }
    if host_is_blocked_ip(authority) || host_is_blocked_name(authority) {
        errs.push(format!(
            "upstream '{}': egress host '{}' is loopback / private / link-local — not allowed",
            upstream_id, authority
        ));
    }
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

    for u in &def.upstream {
        validate_url(&u.id, &u.url, &mut errs);

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
}
