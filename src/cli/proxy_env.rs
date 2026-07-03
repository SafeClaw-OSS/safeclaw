//! Shared plumbing for the resident credential proxy: the env bundle `sc run`
//! pastes onto a child, the resident CA path, and the liveness probe. One place
//! so `sc run` and `sc status` never disagree on the proxy address, the CA
//! location, or how `routed` is decided.

use std::path::PathBuf;
use std::time::Duration;

use crate::config::{default_state_dir, CONTROL_PORT, PROXY_PORT};

/// The magic host the proxy self-answers for liveness. Not DNS-resolvable, so a
/// direct (unproxied) request can never reach it — only the proxy responds.
pub const PROBE_URL: &str = "http://sc.probe/";

/// Resident CA cert path — `<state_dir>/ca.pem`, where the daemon generated it
/// on first start.
pub fn resident_ca_path() -> PathBuf {
    default_state_dir().join("ca.pem")
}

/// The proxy authority for probing (no userinfo): `http://127.0.0.1:<PROXY_PORT>`.
pub fn proxy_base() -> String {
    format!("http://127.0.0.1:{}", PROXY_PORT)
}

/// The proxy URL a child's `HTTPS_PROXY` points at: the active vault id in the
/// userinfo with an explicit empty password (so every tool encodes it
/// identically), letting the proxy learn which vault to broker for from the
/// CONNECT `Proxy-Authorization` header.
pub fn proxy_url_for_vault(vid: &str) -> String {
    format!("http://{}:@127.0.0.1:{}", urlencoding::encode(vid), PROXY_PORT)
}

/// The env bundle that routes a child through the resident proxy and trusts its
/// CA. `parent_git_config_count` is the inherited `GIT_CONFIG_COUNT` (if any) so
/// our credential-helper registration CHAINS at the next free index rather than
/// clobbering an already-configured helper. Returns ordered `(key, value)`
/// pairs — no plaintext secret is ever included; the agent writes the phantom.
pub fn build_bundle(vid: &str, ca: &str, parent_git_config_count: Option<u32>) -> Vec<(String, String)> {
    let proxy = proxy_url_for_vault(vid);
    let mut b = vec![
        ("HTTPS_PROXY".to_string(), proxy.clone()),
        ("HTTP_PROXY".to_string(), proxy),
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

/// Probe the resident proxy at `proxy_url` (a full `http://host:port` authority)
/// by fetching `sc.probe` THROUGH it. True only when our proxy answers with its
/// probe JSON — a direct attempt (no proxy) can't resolve `sc.probe`, so a dead
/// proxy reads as `false`, never a spurious success.
pub async fn probe_via(proxy_url: &str) -> bool {
    let Ok(proxy) = reqwest::Proxy::all(proxy_url) else {
        return false;
    };
    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_millis(700))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client.get(PROBE_URL).send().await {
        Ok(r) if r.status().is_success() => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("proxy").and_then(|p| p.as_bool()))
            .unwrap_or(false),
        _ => false,
    }
}

/// Is the daemon's control plane answering on localhost `CONTROL_PORT`?
pub async fn control_plane_up() -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("http://127.0.0.1:{}/health", CONTROL_PORT);
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

/// Does THIS process's inherited env route it through the resident proxy, and is
/// that proxy actually answering? True only when the bundle is present (an
/// `HTTPS_PROXY` pointing at the proxy port AND a CA var) AND the proxy responds
/// to the probe (vars set but proxy dead ⇒ `false`). Spec §14 `routed`.
pub async fn is_routed() -> bool {
    let https = match std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };
    // Point at the resident proxy port — an unrelated corporate proxy isn't ours.
    if !https.contains(&format!(":{}", PROXY_PORT)) {
        return false;
    }
    // A CA var must also be present, or the child would reject our leaf cert.
    let has_ca = [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
        "DENO_CERT",
    ]
    .iter()
    .any(|k| std::env::var_os(k).is_some());
    if !has_ca {
        return false;
    }
    probe_via(&https).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_carries_vault_and_empty_password() {
        // vid in userinfo, explicit empty password, resident proxy port.
        assert_eq!(
            proxy_url_for_vault("default"),
            format!("http://default:@127.0.0.1:{}", PROXY_PORT)
        );
    }

    #[test]
    fn bundle_has_full_family_and_helper() {
        let b = build_bundle("abc", "/x/ca.pem", None);
        let get = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("HTTPS_PROXY").unwrap(),
            format!("http://abc:@127.0.0.1:{}", PROXY_PORT)
        );
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
        let b = build_bundle("abc", "/x/ca.pem", Some(2));
        let get = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("GIT_CONFIG_COUNT").unwrap(), "3");
        assert_eq!(get("GIT_CONFIG_KEY_2").unwrap(), "credential.helper");
        assert_eq!(get("GIT_CONFIG_VALUE_2").unwrap(), "!sc git-credential");
        // We do NOT touch the parent's lower indices.
        assert!(get("GIT_CONFIG_KEY_0").is_none());
    }
}
