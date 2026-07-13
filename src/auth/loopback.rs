//! OAuth loopback auto-catch — the on-demand listener that removes manual paste.
//!
//! Every oauth2 service redirects consent to the SAME fixed loopback URL
//! (`crate::service::DEFAULT_LOOPBACK_REDIRECT`, port 8765). Historically nothing
//! listened there, so the browser showed a dead page and the user copied the URL
//! back into the console by hand. This module binds that port — but only while a
//! connect actually needs it — and completes the connect for them:
//!
//! 1. The browser (console) seals `{ code_verifier, state }` into
//!    `aux.connecting[<id>]` **before** opening consent (no code yet) and syncs
//!    it up. The daemon's sync tick registers `state → (vault, connection)` in
//!    [`AppState::oauth_pending`] and calls [`ensure_running`].
//! 2. The user consents; Google redirects the popup to
//!    `http://127.0.0.1:8765/safeclaw/oauth/callback?code=…&state=…`, caught here.
//! 3. We match `state` to its pending connect, inject the `code`, and drive the
//!    EXISTING [`crate::auth::connect::process_vault_connects`] machinery
//!    (exchange → seal refresh_token → MOVE to `connections` → push). The code
//!    never returns to the browser — the daemon self-completes (cloud-blind, and
//!    robust to the popup losing `window.opener`).
//!
//! **On-demand, single shared window.** The listener opens only while some
//! connect is awaiting its redirect and self-closes when the last one clears (2h
//! ceiling per entry, `LOOPBACK_PENDING_TTL`). [`ensure_running`] is guarded by
//! [`AppState::oauth_listener_running`] so N concurrent connects — across every
//! vault — share exactly ONE listener; the daemon never spawns a second 8765 and
//! races itself into a port conflict.
//!
//! **Security.** One listener + `state`-routing serves every provider; `state`
//! (RFC 6749 §10.12) is an unguessable per-flow token. It binds `127.0.0.1` only
//! (unreachable off-box). A request whose `state` matches no live pending connect
//! gets a **bland 404** — no header, no branding — so an idle probe or a
//! DNS-rebinding page learns nothing. A caught code is useless without the
//! code_verifier (which never leaves the browser/sealed vault) and single-use
//! (the match is removed on catch; the daemon also keeps a redeemed-code ledger).
//! When 8765 is already bound (a second daemon on the box), auto-catch is simply
//! off and the console's manual paste still completes the connect.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Router,
};

use crate::state::AppState;

/// How often the live listener checks whether it can close (no connect pending).
/// Small enough that the port doesn't linger long after a connect finishes; the
/// listener is benign so there is no rush.
const IDLE_CLOSE_POLL_SECS: u64 = 10;

/// The `?code&state` (+ optional `error`) an OAuth provider appends to the
/// loopback redirect. Unknown params (scope, authuser, …) are ignored.
#[derive(serde::Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    /// Present instead of `code` when the user denied consent or the request was
    /// malformed (RFC 6749 §4.1.2.1).
    #[serde(default)]
    error: String,
}

/// Parse the fixed loopback `(port, path)` out of `DEFAULT_LOOPBACK_REDIRECT`
/// (e.g. `http://127.0.0.1:8765/safeclaw/oauth/callback`) so the listener never
/// drifts from the redirect_uri baked into the service defs. Falls back to the
/// known literal if the const is ever an unexpected shape.
fn callback_target() -> (u16, String) {
    let fallback = (8765u16, "/safeclaw/oauth/callback".to_string());
    let parse = || -> Option<(u16, String)> {
        let rest = crate::service::DEFAULT_LOOPBACK_REDIRECT.strip_prefix("http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let port = authority.rsplit_once(':')?.1.parse::<u16>().ok()?;
        Some((port, path))
    };
    parse().unwrap_or(fallback)
}

/// Ensure the shared 8765 loopback listener is running. Idempotent and
/// single-instance: spawns exactly one listener task and no-ops while it's live,
/// so any number of concurrent connects share ONE window. Called by the connect
/// state machine whenever a connect is registered as awaiting its redirect.
pub fn ensure_running(state: Arc<AppState>) {
    {
        let mut running = state.oauth_listener_running.lock().unwrap();
        if *running {
            return; // one shared listener already covers every pending connect
        }
        *running = true;
    }
    tokio::spawn(async move {
        let bound = serve_until_idle(&state).await;
        *state.oauth_listener_running.lock().unwrap() = false;
        // A connect may have arrived during the graceful drain — re-arm so its
        // redirect still gets caught. Only after a clean (bound) close: never
        // re-arm a bind FAILURE, which would tight-spin against whatever already
        // owns 8765 (the next sync tick retries instead).
        if bound && state.has_loopback_pending() {
            ensure_running(state);
        }
    });
}

/// Bind 8765 and serve until no loopback connect is pending anymore, then close
/// (releasing the port). Returns whether it managed to bind — `false` means
/// another process owns 8765, so auto-catch is off and manual paste stands in.
async fn serve_until_idle(state: &Arc<AppState>) -> bool {
    let (port, path) = callback_target();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "oauth loopback: bind 127.0.0.1:{} failed ({}); auto-catch off, manual paste still works",
                port,
                e
            );
            return false;
        }
    };
    tracing::info!(
        "oauth loopback auto-catch open on http://{}{} (closes when idle)",
        addr,
        path
    );
    let app = Router::new()
        .route(&path, get(handle_callback))
        .with_state(state.clone());

    // Close as soon as no connect is awaiting a redirect. Polls rather than
    // signals so a reaped (2h) or completed connect both trip it without extra
    // wiring at the mutation sites.
    let idle = state.clone();
    let shutdown = async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(IDLE_CLOSE_POLL_SECS)).await;
            if !idle.has_loopback_pending() {
                break;
            }
        }
    };

    if let Err(e) = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::warn!("oauth loopback listener error: {} — manual paste still works", e);
    }
    tracing::info!("oauth loopback auto-catch closed (no connect pending)");
    true
}

async fn handle_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CallbackQuery>,
) -> (StatusCode, Html<String>) {
    // Bland 404 unless `state` matches a LIVE pending connect. An idle hit, a
    // random local process, or a DNS-rebinding page learns nothing: no branding,
    // no signal. Consuming the match here makes it single-use.
    let Some(pending) = state.take_loopback_pending(&q.state) else {
        return (StatusCode::NOT_FOUND, Html(String::new()));
    };

    // Provider returned an error, or no code — nothing to exchange. The console's
    // "waiting" state will time out to the manual-paste fallback.
    if !q.error.is_empty() || q.code.is_empty() {
        let why = if q.error.is_empty() {
            "no authorization code was returned".to_string()
        } else {
            q.error.clone()
        };
        tracing::info!(vault = %pending.vault_id, conn = %pending.conn_id, "oauth loopback: redirect carried no usable code ({})", why);
        return (StatusCode::OK, Html(done_page("Connection cancelled", &why)));
    }

    // Inject the caught code into its pending entry and drive the EXISTING
    // exchange → seal → MOVE → push machinery. Awaited so the page reflects the
    // real outcome. The raw code never lands in durable storage: on success the
    // entry is MOVEd to `connections` in the same re-seal; on a transient miss M
    // is discarded unsealed.
    let mut injected = std::collections::BTreeMap::new();
    injected.insert(pending.conn_id.clone(), q.code);
    let report =
        crate::auth::connect::process_vault_connects(&state, &pending.vault_id, Some(injected))
            .await;

    let page = if report.completed.iter().any(|c| *c == pending.conn_id) {
        tracing::info!(vault = %pending.vault_id, conn = %pending.conn_id, "oauth loopback: connect completed via auto-catch");
        done_page(
            "Connected",
            "SafeClaw finished the connection. You can close this window.",
        )
    } else if report.failed.iter().any(|(c, _)| *c == pending.conn_id) {
        done_page(
            "Connection failed",
            "The authorization could not be completed. Return to SafeClaw and try connecting again.",
        )
    } else {
        // Locked vault, transient provider error, or the entry was already
        // completed. The console keeps waiting / offers the paste fallback.
        done_page(
            "Almost there",
            "Return to SafeClaw. If the connection doesn't appear shortly, try connecting again.",
        )
    };
    (StatusCode::OK, Html(page))
}

/// A minimal self-closing result page for the consent popup. Deliberately
/// generic (no account/secret detail); auto-closes after a beat.
fn done_page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>{t}</title>\
<style>body{{font:15px/1.6 -apple-system,system-ui;max-width:420px;margin:14vh auto;padding:0 24px;text-align:center;color:#111}}h2{{margin:0 0 6px;font-size:20px}}p{{color:#555}}</style>\
<h2>{t}</h2><p>{b}</p>\
<script>setTimeout(function(){{try{{window.close()}}catch(e){{}}}},1500)</script>",
        t = html_escape(title),
        b = html_escape(body),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_target_matches_the_baked_redirect() {
        // The listener's bind port + route path must track the redirect_uri the
        // service defs ship, or the redirect lands on nothing.
        let (port, path) = callback_target();
        assert_eq!(port, 8765);
        assert_eq!(path, "/safeclaw/oauth/callback");
        // And it really is derived from the const, not a hardcoded duplicate.
        assert!(crate::service::DEFAULT_LOOPBACK_REDIRECT.contains(&format!(":{}{}", port, path)));
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(html_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }
}
