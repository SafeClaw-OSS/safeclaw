//! HTTP server: control/API plane (`CONTROL_PORT`, `:23295`) router.
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
pub mod broker_flow;
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
        .route("/v/{vid}/secret-keys", get(handlers::secret_keys::secret_keys))
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

    // ── Agent-surface control routes ─────────────────────────────────────
    // The only agent-facing HTTP route left on the control plane is the
    // `/export` disabled stub (raw-secret exfil off the agent surface — the
    // op-plane Export ceremony is the human path). Live credential traffic no
    // longer goes through an HTTP route: it rides the resident phantom-only
    // proxy (S2, a separate listener). This sub-router carries the agent-key
    // gate (`require_api_key`) so the stub stays scoped like the old broker
    // surface without touching the passkey/admin-gated control routes.
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
/// these broker routes only — the control routes in `app_router` keep their own
/// (passkey / X-Admin-Key / auth-free-localhost) gating untouched.
fn broker_router(state: Arc<AppState>) -> Router {
    use crate::proxy::env;

    Router::new()
        // /export → disabled stub (raw-secret export off the agent surface; the
        // op-plane Export ceremony is the human path).
        .route("/v/{vid}/export/{key}", post(env::disabled))
        // Agent-key gate — scoped to exactly this route.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api_key::require_api_key,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
