//! HTTP server: admin port (`:23294`) router.
//!
//! v1 URL surface (PROTOCOL.md §4.1 / `[[v1-endpoint-design]]` /
//! `[[architecture-final-2026-05-27]]`):
//!
//! ```text
//! POST /v/{vid}/op              R-side op creation (or U-direct: Enroll/Write/Export)
//! GET  /v/{vid}/passkeys        list enrolled credentials for this vault
//! GET  /v/{vid}/events          SSE lifecycle stream
//! GET  /registry                static service catalog (no vault contents)
//! GET  /v/{vid}/registry        per-vault live view (catalog + connected state)
//! GET  /op/{op_id}              poll op status + cached value
//! POST /op/{op_id}/approve      U submits grant G → T validates, dispatches act
//! POST /op/{op_id}/reject       U denies
//! GET  /health                  custodian health
//! GET  /pubkey                  custodian HPKE bootstrap key (placeholder)
//! GET  /admin/vaults            list all vault ids on this daemon (admin-gated)
//! GET  /skill.md                skill file for agents (?agent=claude|cursor|codex)
//! ```
//!
//! Public root paths (`/health`, `/registry`, `/pubkey`, `/skill.md`) were originally
//! prefixed `/c/*`; the prefix was dropped 2026-05-27 to align with the
//! "zero remapping" backend story (SaaS proxy forwards the same URLs).
//!
//! Vault selection is via URL path (`{vid}`). The custodian does no
//! principal authentication — that's a deployment-layer concern (the
//! SafeClaw pro-backend is the auth boundary).

pub mod broker;
pub mod handlers;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
    Router,
};

use crate::state::AppState;

/// Maximum request body size for all admin endpoints.
/// 256 KB is ample for any legitimate operation descriptor or grant.
const MAX_BODY_BYTES: usize = 256 * 1024;

pub fn app_router(state: Arc<AppState>) -> Router {
    // ── Control plane ────────────────────────────────────────────────────
    // Vault lifecycle, op approval, passkeys, registry, admin. NOT agent-key
    // gated: op/approve is gated by the op_id + passkey signature (the passkey
    // wall); admin by X-Admin-Key; registry/passkeys are auth-free localhost
    // reads. This is exactly the surface the old admin port carried.
    let mut router = Router::new()
        // Custodian-level (no vault context).
        .route("/health", get(handlers::health::health))
        .route("/pubkey", get(handlers::metadata::pubkey))
        .route("/registry", get(handlers::registry::catalog))
        .route("/skill.md", get(handlers::skill::skill_md))
        // Vault-scoped.
        .route("/v/{vid}/op", post(handlers::op::create))
        .route("/v/{vid}/sync", post(handlers::metadata::sync_now))
        .route("/v/{vid}/passkeys", get(handlers::metadata::passkeys))
        .route("/v/{vid}/pending-passkeys", post(handlers::pending_passkey::create))
        .route("/v/{vid}/events", get(handlers::events::stream))
        .route("/v/{vid}/approvals", get(handlers::approvals::list))
        .route("/v/{vid}/keys-known", get(handlers::keys_known::keys_known))
        .route("/v/{vid}/registry", get(handlers::registry::vault_registry))
        .route("/v/{vid}/usage", get(handlers::usage::usage))
        // Op-flat (vault context lives on the approval record).
        // GET /op/{id} returns the JSON poll response (status + cached value).
        // The agent / CLI polls this; the human approves on safeclaw.pro via
        // the op-relay, so the daemon serves no approval HTML of its own.
        .route("/op/{op_id}", get(handlers::approve::get_op))
        .route("/op/{op_id}/approve", post(handlers::approve::approve_op))
        .route("/op/{op_id}/reject", post(handlers::approve::reject_op))
        // Admin (X-Admin-Key gated; off when SAFECLAW_ADMIN_KEY unset).
        .route("/admin/vaults", get(handlers::admin::list_vaults))
        .route("/admin/vaults/{vid}", delete(handlers::admin::delete_vault))
        .with_state(state.clone());
    router = router.layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // ── Broker plane ─────────────────────────────────────────────────────
    // The four agent-facing routes (use / stream / export). These — and ONLY
    // these — carry the agent-key gate (`require_api_key`): every request must
    // present `Authorization: Bearer <agent-key>` whose sha256 is in the
    // cloud-synced account hash-set. They formerly lived on a second port
    // (:23295, now removed); merging them here keeps the gate scoped to the
    // broker surface so control routes are unaffected.
    let broker = broker_router(state);
    router = router.merge(broker);

    // CORS: the only browser inbound was the embedded op-page, now deleted —
    // approval happens on safeclaw.pro, not against the daemon. With no browser
    // flow left, no CorsLayer is added (the broker plane must stay off browsers
    // anyway — F-25). Self-host dev that fronts the daemon with a browser can
    // still terminate CORS at its reverse proxy.
    router
}

/// The agent-key-gated broker sub-router. Split out so the gate is a layer on
/// these four routes only — the control routes in `app_router` keep their own
/// (passkey / X-Admin-Key / auth-free-localhost) gating untouched.
fn broker_router(state: Arc<AppState>) -> Router {
    use crate::proxy::{env, stream, use_broker};
    use axum::routing::any;

    Router::new()
        .route("/v/{vid}/export/{key}", post(env::handle))
        .route("/v/{vid}/use/{service}", any(use_broker::handle_no_rest))
        .route("/v/{vid}/use/{service}/{*rest}", any(use_broker::handle))
        // Streaming passthrough (git smart-HTTP, etc.). Body limit DISABLED on
        // this route only — packfiles can be hundreds of MB and are streamed,
        // not buffered. Still behind the agent-key gate below.
        .route(
            "/v/{vid}/stream/{service}/{*rest}",
            any(stream::handle).layer(DefaultBodyLimit::disable()),
        )
        // Agent-key gate — scoped to exactly these broker routes.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api_key::require_api_key,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
