//! Sync nudge — the ONE browser-reachable control route, and it carries no
//! authority at all.
//!
//! Motivation: a console-initiated OAuth connect pre-seals `{code_verifier,
//! state}` into the cloud vault, and the loopback auto-catch listener
//! (auth/loopback.rs) only opens once this daemon's sync notices that entry.
//! The watch loop's long-poll makes that eventually-fast, not instantly-fast —
//! and the redirect races the user's consent click. So right after sealing, the
//! console fires a fire-and-forget `no-cors` POST here: "worth syncing vault X
//! now". The daemon then pulls FROM THE CLOUD with its own device key and acts
//! on the sealed truth it finds there.
//!
//! Zero-trust contract (the console keeps its F-25 posture: no CorsLayer, the
//! control plane never trusts a browser):
//!   - The request carries a HINT, never data: no code, no state, no verifier —
//!     nothing from the body is acted on except "which vault to sync", and that
//!     only selects among vaults this daemon already has locally.
//!   - Uniform reply: 204 with an empty body for known vault, unknown vault,
//!     rate-limited, or malformed — a probing page learns nothing (vault
//!     existence included).
//!   - Host allowlist: only `127.0.0.1` / `localhost` / `[::1]` Hosts are
//!     served (bland 404 otherwise), so a DNS-rebinding page — whose fetch is
//!     same-origin to its own evil domain and could READ the reply — gets
//!     nothing. (There is nothing to read either way; belt and braces.)
//!   - Rate-limited: at most one sync per vault per NUDGE_MIN_INTERVAL and one
//!     accepted nudge per NUDGE_GLOBAL_FLOOR overall, so a hostile local page
//!     spamming this route degrades into a slow `sc sync` loop, bounded and
//!     harmless.
//!
//! The browser can't read the 204 (`no-cors` ⇒ opaque response) and doesn't
//! need to: sync remains the path of record; this is purely a latency shave.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::state::AppState;

/// Per-vault: a nudge within this window of the last ACCEPTED one is dropped.
const NUDGE_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Across all vaults: accepted nudges can't exceed one per this floor.
const NUDGE_GLOBAL_FLOOR: Duration = Duration::from_secs(1);
/// A `{"vault":"<uuid>"}` hint is ~50 bytes; anything bigger isn't ours.
const MAX_NUDGE_BODY: usize = 512;

/// Last-accepted instants — module-local: this is throttle bookkeeping for one
/// route, not daemon state (nothing else reads it, nothing persists).
static LAST_NUDGE: Lazy<Mutex<(Option<Instant>, HashMap<String, Instant>)>> =
    Lazy::new(|| Mutex::new((None, HashMap::new())));

/// `POST /sync/nudge` — body `{"vault":"<id>"}` (content-type ignored: the
/// console sends `text/plain` so the `no-cors` fetch stays a CORS simple
/// request and arrives without a preflight).
pub async fn sync_nudge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // DNS-rebinding guard: a rebound page reaches this socket with ITS host in
    // the Host header. Loopback names only; anything else is a bland 404.
    if !host_is_loopback(&headers) {
        return StatusCode::NOT_FOUND;
    }

    // Everything below returns 204 — uniform for malformed / unknown /
    // throttled / accepted, so the reply carries zero bits about this daemon.
    let Some(vault_id) = parse_vault(&body) else {
        return StatusCode::NO_CONTENT;
    };
    if crate::server::handlers::op::validate_vault_id(&vault_id).is_err() {
        return StatusCode::NO_CONTENT;
    }
    // Only vaults that already exist locally are worth a pull; an arbitrary id
    // must not turn this daemon into a cloud-request proxy.
    if !state
        .config
        .state_dir
        .join("vaults")
        .join(&vault_id)
        .is_dir()
    {
        return StatusCode::NO_CONTENT;
    }

    {
        let mut last = LAST_NUDGE.lock().unwrap();
        let now = Instant::now();
        let (global, per_vault) = &mut *last;
        if global.is_some_and(|t| now.duration_since(t) < NUDGE_GLOBAL_FLOOR) {
            return StatusCode::NO_CONTENT;
        }
        if per_vault
            .get(&vault_id)
            .is_some_and(|t| now.duration_since(*t) < NUDGE_MIN_INTERVAL)
        {
            return StatusCode::NO_CONTENT;
        }
        *global = Some(now);
        per_vault.insert(vault_id.clone(), now);
    }

    tracing::debug!(vault = %vault_id, "sync nudge accepted; pulling");
    // Detached: the browser gets its 204 immediately; the sync (which registers
    // any pending loopback connects and opens 8765) runs on its own.
    tokio::spawn(async move {
        if let Err(e) = crate::sync::sync_vault_now(&state, &vault_id).await {
            tracing::debug!(vault = %vault_id, "nudged sync failed: {}", e);
        }
    });
    StatusCode::NO_CONTENT
}

fn host_is_loopback(headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    // Strip any port; bracket form is IPv6.
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map(|(n, _)| n).unwrap_or(host)
    };
    matches!(name, "127.0.0.1" | "localhost" | "::1")
}

fn parse_vault(body: &Bytes) -> Option<String> {
    if body.len() > MAX_NUDGE_BODY {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(v.get("vault")?.as_str()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_host(h: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(axum::http::header::HOST, h.parse().unwrap());
        m
    }

    #[test]
    fn loopback_hosts_pass_and_rebinds_fail() {
        for ok in [
            "127.0.0.1:23293",
            "127.0.0.1",
            "localhost:23293",
            "[::1]:23293",
        ] {
            assert!(host_is_loopback(&headers_with_host(ok)), "{ok}");
        }
        for bad in [
            "evil.example:23293",
            "safeclaw.pro",
            "127.0.0.1.evil.example",
        ] {
            assert!(!host_is_loopback(&headers_with_host(bad)), "{bad}");
        }
        assert!(!host_is_loopback(&HeaderMap::new()));
    }

    #[test]
    fn vault_hint_parses_and_oversize_is_dropped() {
        assert_eq!(
            parse_vault(&Bytes::from(r#"{"vault":"abc"}"#)).as_deref(),
            Some("abc")
        );
        assert_eq!(parse_vault(&Bytes::from("not json")), None);
        let big = format!(r#"{{"vault":"{}"}}"#, "x".repeat(MAX_NUDGE_BODY));
        assert_eq!(parse_vault(&Bytes::from(big)), None);
    }
}
