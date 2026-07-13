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
//! **On-demand, one shared window PER PORT.** Which ports may ever open is the
//! allowlist parsed from locally-installed service defs
//! ([`crate::service::ServiceRegistry::loopback_allowlist`], today `{8765,
//! 1455}`) — vault content can pick among them but never extend them. A
//! listener opens only while some connect is awaiting a redirect on its port
//! and self-closes when the last one clears (2h ceiling per entry,
//! `LOOPBACK_PENDING_TTL`). [`ensure_running`] is guarded per-port by
//! [`AppState::oauth_listener_running`] so N concurrent connects — across every
//! vault — share exactly ONE listener per port; the daemon never races itself
//! into a port conflict.
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

/// Ensure the shared loopback listener for `port` is running. Idempotent and
/// single-instance PER PORT: spawns exactly one listener task per port and
/// no-ops while it's live, so any number of concurrent connects on that port
/// share ONE window. Called by the connect state machine with each distinct
/// pending port ([`AppState::pending_loopback_ports`]) — the caller has already
/// allowlist-checked the port at registration.
pub fn ensure_running(state: Arc<AppState>, port: u16) {
    {
        let mut running = state.oauth_listener_running.lock().unwrap();
        if !running.insert(port) {
            return; // this port's shared listener already covers its pendings
        }
    }
    tokio::spawn(async move {
        let bound = serve_until_idle(&state, port).await;
        state.oauth_listener_running.lock().unwrap().remove(&port);
        // A connect may have arrived during the graceful drain — re-arm so its
        // redirect still gets caught. Only after a clean (bound) close: never
        // re-arm a bind FAILURE, which would tight-spin against whatever already
        // owns the port (the next sync tick retries instead).
        if bound && state.has_loopback_pending_on(port) {
            ensure_running(state, port);
        }
    });
}

/// Bind `port` and serve until no loopback connect is pending on it anymore,
/// then close (releasing it). Returns whether it managed to bind — `false`
/// means another process owns the port (e.g. the Codex CLI's own login on
/// 1455), so auto-catch on it is off and manual paste stands in.
async fn serve_until_idle(state: &Arc<AppState>, port: u16) -> bool {
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
        "oauth loopback auto-catch open on http://{} (closes when idle)",
        addr
    );
    // Catch-all route: the match is keyed on `state` (unguessable, single-use),
    // not the path — one router serves every callback path a provider might
    // use on this port, and a non-matching hit gets the same bland 404 either
    // way, so path-shape leaks nothing.
    let app = Router::new()
        .fallback(get(handle_callback))
        .with_state(state.clone());

    // Close as soon as no connect is awaiting a redirect on THIS port. Polls
    // rather than signals so a reaped (2h) or completed connect both trip it
    // without extra wiring at the mutation sites.
    let idle = state.clone();
    let shutdown = async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(IDLE_CLOSE_POLL_SECS)).await;
            if !idle.has_loopback_pending_on(port) {
                break;
            }
        }
    };

    if let Err(e) = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::warn!(
            "oauth loopback listener error: {} — manual paste still works",
            e
        );
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
        return (
            StatusCode::OK,
            Html(done_page("Connection cancelled", &why)),
        );
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
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_covers_the_shipped_redirects() {
        // The listener may only bind ports the SHIPPED service defs announce —
        // the canonical 8765 plus openai_codex's registered 1455. A new
        // provider port must land here via a reviewed service.toml, never via
        // vault content.
        let allowed = crate::service::ServiceRegistry::compiled_only().loopback_allowlist();
        assert!(
            allowed.contains(&8765),
            "canonical callback missing: {allowed:?}"
        );
        assert!(
            allowed.contains(&1455),
            "openai_codex callback missing: {allowed:?}"
        );
        assert_eq!(
            allowed.len(),
            2,
            "unexpected extra loopback ports: {allowed:?}"
        );
    }

    #[test]
    fn loopback_port_accepts_loopback_only() {
        use crate::service::loopback_port;
        assert_eq!(
            loopback_port(crate::service::DEFAULT_LOOPBACK_REDIRECT),
            Some(8765)
        );
        assert_eq!(
            loopback_port("http://localhost:1455/auth/callback"),
            Some(1455)
        );
        assert_eq!(loopback_port("https://127.0.0.1:8765/cb"), None); // not http
        assert_eq!(loopback_port("http://evil.example:8765/cb"), None); // not loopback
        assert_eq!(loopback_port("http://127.0.0.1/cb"), None); // no explicit port
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(html_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }
}
