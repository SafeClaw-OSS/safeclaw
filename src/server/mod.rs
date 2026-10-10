//! HTTP server: control/API plane (`CONTROL_PORT`, `:23293`) router.
//!
//! v1 URL surface (PROTOCOL.md §4.1 / `[[v1-endpoint-design]]` /
//! `[[architecture-final-2026-05-27]]`):
//!
//! ```text
//! POST /v/{vid}/op              op creation (lifecycle, Use, Export)
//! GET  /v/{vid}/passkeys        the vault members' passkeys (from their ledgers)
//! GET  /v/{vid}/events          SSE lifecycle stream
//! GET  /registry                static service catalog (no vault contents)
//! GET  /v/{vid}/registry        per-vault live view (catalog + connected state)
//! GET  /op/{op_id}              poll op status + cached value
//! POST /op/{op_id}/approve      U submits grant G → T validates, dispatches act
//! POST /op/{op_id}/reject       U denies
//! POST /op/{op_id}/cancel       requester withdraws its own op
//! GET  /health                  custodian health
//! GET  /skill.md                skill file for agents (?agent=claude|cursor|codex)
//! ```
//!
//! Deleted in the trust reset (contract 4): `/pubkey`, `POST
//! /v/{vid}/pending-passkeys` and the `POST /v/{vid}/export/{key}` stub (with
//! it the last agent-gated control route).
//!
//! Public root paths (`/health`, `/registry`, `/skill.md`) were originally
//! prefixed `/c/*`; the prefix was dropped 2026-05-27 to align with the
//! "zero remapping" backend story (SaaS proxy forwards the same URLs).
//!
//! Vault selection is via URL path (`{vid}`). The custodian does no
//! principal authentication — that's a deployment-layer concern (the
//! SafeClaw pro-backend is the auth boundary).

pub mod broker;
pub mod broker_flow;
pub mod handlers;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// Maximum request body size for all control-plane endpoints.
/// 256 KB is ample for any legitimate operation descriptor or grant.
const MAX_BODY_BYTES: usize = 256 * 1024;

pub fn app_router(state: Arc<AppState>) -> Router {
    // ── Control plane ────────────────────────────────────────────────────
    // Vault lifecycle, op approval, passkeys, registry. Not agent-gated:
    // op/approve is gated by the op_id capability + passkey signature (the
    // passkey wall); registry/passkeys are auth-free localhost reads. This is
    // exactly the surface the old admin port carried.
    let mut router = Router::new()
        // Custodian-level (no vault context).
        .route("/health", get(handlers::health::health))
        .route("/registry", get(handlers::registry::catalog))
        .route("/skill.md", get(handlers::skill::skill_md))
        // Vault-scoped.
        .route("/v/{vid}/op", post(handlers::op::create))
        // Local value deposit for connection-add / secret-set write ops — the
        // op itself carries only a salted digest (its JSON rides to the cloud
        // relay for the grant page; plaintext values never do).
        .route("/v/{vid}/op-payload", post(handlers::op_payload::create))
        // Local unlocked-only secret write (no passkey while the vault is open —
        // see secret_set_local.rs). `sc set` tries this first; a locked vault
        // answers `{written:false,locked:true}` and the CLI falls back to the op.
        .route("/v/{vid}/secret", post(handlers::secret_set_local::create))
        .route("/v/{vid}/sync", post(handlers::metadata::sync_now))
        .route("/v/{vid}/passkeys", get(handlers::metadata::passkeys))
        .route("/v/{vid}/events", get(handlers::events::stream))
        .route(
            "/v/{vid}/secret-keys",
            get(handlers::secret_keys::secret_keys),
        )
        .route("/v/{vid}/registry", get(handlers::registry::vault_registry))
        .route("/v/{vid}/usage", get(handlers::usage::usage))
        // Device egress-proxy hot-reload (after `sc proxy set/clear`) — no vault
        // context, no params: re-reads the local stored value into the live
        // clients so the daemon re-points egress without a restart/re-unlock.
        .route("/proxy/reload", post(handlers::proxy::reload))
        // Live ambient egress-proxy report (from `sc run`) — the daemon follows
        // the operator's current shell proxy without a persisted `sc proxy set`.
        // In-memory only; LOOPBACK-ONLY (it takes a caller-chosen proxy value).
        .route("/proxy/ambient", post(handlers::proxy::ambient))
        // Browser-fired sync hint (a `no-cors` POST from the console right
        // after it pre-seals an OAuth connect). Authority-free by contract:
        // host-allowlisted, rate-limited, uniform 204 — see nudge.rs. The
        // no-CorsLayer posture below is unaffected (the console never reads
        // the reply; `no-cors` responses are opaque).
        .route("/sync/nudge", post(handlers::nudge::sync_nudge))
        // Op-flat (vault context lives on the approval record).
        // GET /op/{id} returns the JSON poll response (status + cached value).
        // The agent / CLI polls this; the human approves on safeclaw.pro via
        // the op-relay, so the daemon serves no approval HTML of its own.
        .route("/op/{op_id}", get(handlers::approve::get_op))
        .route("/op/{op_id}/approve", post(handlers::approve::approve_op))
        .route("/op/{op_id}/reject", post(handlers::approve::reject_op))
        // Requester withdrawal (design/approvals-inbox.md D1-E): the CLI that
        // created an op voids it on Ctrl-C / SIGTERM / timeout. Never a user
        // rejection; an Export needs its waiter secret.
        .route("/op/{op_id}/cancel", post(handlers::op::cancel))
        .with_state(state);
    router = router.layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // CORS: the only browser inbound was the embedded op-page, now deleted —
    // approval happens on safeclaw.pro, not against the daemon. With no browser
    // flow left, no CorsLayer is added (the broker plane must stay off browsers
    // anyway — F-25). Self-host dev that fronts the daemon with a browser can
    // still terminate CORS at its reverse proxy.
    router
}
