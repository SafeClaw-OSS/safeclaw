//! Shared plumbing for the resident credential proxy: the env bundle `sc run`
//! pastes onto a child, and the resident CA path. One place so `sc run` and the
//! daemon never disagree on the proxy address or the CA location.
//!
//! Routing DETECTION (probe host / `is_routed` / `$HTTPS_PROXY` introspection) is
//! deliberately gone (AGENT_SURFACE §9): the broker is opt-in, so the agent
//! routes every credential request EXPLICITLY (`sc run` / `--proxy`) — the
//! "phantom sent unrouted" state is unreachable, so there's nothing to detect.

use std::path::PathBuf;
use std::time::Duration;

use crate::config::default_state_dir;

/// Resident CA cert path: `$SAFECLAW_CA_PATH` when set (a hand-configured
/// remote daemon — the PUBLIC `ca.pem` copied over manually; the private
/// `ca.key` never leaves the daemon), else `<state_dir>/ca.pem`, where the
/// local daemon generated it on first start.
pub fn resident_ca_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SAFECLAW_CA_PATH") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_state_dir().join("ca.pem")
}

/// The proxy URL a child's `HTTPS_PROXY` points at: the API-face root
/// (`scheme://host:port`, from `active::api_face_root`) with `<vid>:<key>`
/// spliced into the userinfo. The vid (username) routes to a vault; the key
/// (password) is the agent's identity, verified by the proxy before any
/// substitution (§8). An absent key leaves the password slot empty
/// (`<vid>:@`) — the proxy 407s such a request (participating but
/// unauthenticated), the human-without-an-agent-key case. Deriving from the
/// API-face root keeps proxy and control on ONE daemon host (the invariant).
pub fn proxy_url_for_vault(api_root: &str, vid: &str, key: Option<&str>) -> String {
    let key_enc = key.map(|k| urlencoding::encode(k).into_owned()).unwrap_or_default();
    let (scheme, rest) = api_root.split_once("://").unwrap_or(("http", api_root));
    format!(
        "{}://{}:{}@{}",
        scheme,
        urlencoding::encode(vid),
        key_enc,
        rest.trim_end_matches('/')
    )
}

/// The env bundle that routes a child through the resident proxy and trusts its
/// CA. `proxy_url` is the full `http://<vid>:<key>@127.0.0.1:<port>` the child's
/// `HTTPS_PROXY` gets — the agent's own `$SAFECLAW_PROXY_URL` verbatim, or one
/// built from the resolved vault + key. `parent_git_config_count` is the
/// inherited `GIT_CONFIG_COUNT` (if any) so our credential-helper registration
/// CHAINS at the next free index rather than clobbering an already-configured
/// helper. Returns ordered `(key, value)` pairs — no plaintext secret is ever
/// included; the agent writes the phantom.
pub fn build_bundle(
    proxy_url: &str,
    ca: &str,
    parent_git_config_count: Option<u32>,
) -> Vec<(String, String)> {
    let mut b = vec![
        ("HTTPS_PROXY".to_string(), proxy_url.to_string()),
        ("HTTP_PROXY".to_string(), proxy_url.to_string()),
        ("NO_PROXY".to_string(), "localhost,127.0.0.1".to_string()),
        // Node 24+ built-in fetch honours the proxy env only with this set.
        ("NODE_USE_ENV_PROXY".to_string(), "1".to_string()),
        ("SSL_CERT_FILE".to_string(), ca.to_string()),
        ("REQUESTS_CA_BUNDLE".to_string(), ca.to_string()),
        ("CURL_CA_BUNDLE".to_string(), ca.to_string()),
        ("NODE_EXTRA_CA_CERTS".to_string(), ca.to_string()),
        ("GIT_SSL_CAINFO".to_string(), ca.to_string()),
        ("DENO_CERT".to_string(), ca.to_string()),
    ];
    // git's per-process config env (no gitconfig writes): register our helper at
    // the next free index. `!` is git's shell-command marker.
    let idx = parent_git_config_count.unwrap_or(0);
    b.push(("GIT_CONFIG_COUNT".to_string(), (idx + 1).to_string()));
    b.push((format!("GIT_CONFIG_KEY_{}", idx), "credential.helper".to_string()));
    b.push((format!("GIT_CONFIG_VALUE_{}", idx), "!sc git-credential".to_string()));
    b
}

/// Is the daemon's control plane answering at `control_root` (from
/// `active::control_root` — env-first host)? `sc run`'s liveness gate — the
/// proxy shares the daemon process, so control up ⇒ proxy up.
pub async fn control_plane_up(control_root: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("{}/health", control_root.trim_end_matches('/'));
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_carries_vault_and_key() {
        // vid in the username, api-key in the password, spliced into the
        // API-face root (same host as every other derived URL).
        assert_eq!(
            proxy_url_for_vault("http://127.0.0.1:23294", "default", Some("sc_agent_k9")),
            "http://default:sc_agent_k9@127.0.0.1:23294"
        );
        // No key → empty password slot (the proxy 407s it).
        assert_eq!(
            proxy_url_for_vault("http://127.0.0.1:23294", "default", None),
            "http://default:@127.0.0.1:23294"
        );
        // A remote API-face root keeps its host AND custom port.
        assert_eq!(
            proxy_url_for_vault("https://box.example.com:9999/", "v1", Some("k")),
            "https://v1:k@box.example.com:9999"
        );
    }

    #[test]
    fn bundle_has_full_family_and_helper() {
        let proxy = proxy_url_for_vault("http://127.0.0.1:23294", "abc", Some("k1"));
        let b = build_bundle(&proxy, "/x/ca.pem", None);
        let get = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("HTTPS_PROXY").unwrap(), proxy);
        assert_eq!(get("HTTP_PROXY"), get("HTTPS_PROXY"));
        assert_eq!(get("NO_PROXY").unwrap(), "localhost,127.0.0.1");
        assert_eq!(get("NODE_USE_ENV_PROXY").unwrap(), "1");
        for k in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "GIT_SSL_CAINFO",
            "DENO_CERT",
        ] {
            assert_eq!(get(k).unwrap(), "/x/ca.pem");
        }
        assert_eq!(get("GIT_CONFIG_COUNT").unwrap(), "1");
        assert_eq!(get("GIT_CONFIG_KEY_0").unwrap(), "credential.helper");
        assert_eq!(get("GIT_CONFIG_VALUE_0").unwrap(), "!sc git-credential");
    }

    #[test]
    fn bundle_chains_git_config_indices() {
        // Parent already set two entries → we append at index 2, count becomes 3.
        let proxy = proxy_url_for_vault("http://127.0.0.1:23294", "abc", Some("k1"));
        let b = build_bundle(&proxy, "/x/ca.pem", Some(2));
        let get = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("GIT_CONFIG_COUNT").unwrap(), "3");
        assert_eq!(get("GIT_CONFIG_KEY_2").unwrap(), "credential.helper");
        assert_eq!(get("GIT_CONFIG_VALUE_2").unwrap(), "!sc git-credential");
        // We do NOT touch the parent's lower indices.
        assert!(get("GIT_CONFIG_KEY_0").is_none());
    }
}
