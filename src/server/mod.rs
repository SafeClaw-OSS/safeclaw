//! HTTP server: admin port (`:23294`) router.
//!
//! v1 URL surface (PROTOCOL.md §4.1 / `[[v1-endpoint-design]]` /
//! `[[architecture-final-2026-05-27]]`):
//!
//! ```text
//! POST /v/{vid}/op              R-side op creation (or U-direct: Enroll/Write/Export)
//! GET  /v/{vid}/passkeys        list enrolled credentials for this vault
//! GET  /v/{vid}/events          SSE lifecycle stream
//! GET  /menu                    static service catalog (no vault contents)
//! GET  /v/{vid}/registry        per-vault live view (catalog + connected state)
//! GET  /op/{op_id}              poll op status + cached value
//! POST /op/{op_id}/approve      U submits grant G → T validates, dispatches act
//! POST /op/{op_id}/reject       U denies
//! GET  /health                  custodian health
//! GET  /pubkey                  custodian HPKE bootstrap key (placeholder)
//! GET  /admin/vaults            list all vault ids on this daemon (admin-gated)
//! ```
//!
//! Public root paths (`/health`, `/menu`, `/pubkey`) were originally
//! prefixed `/c/*`; the prefix was dropped 2026-05-27 to align with the
//! "zero remapping" backend story (SaaS proxy forwards the same URLs).
//!
//! Vault selection is via URL path (`{vid}`). The custodian does no
//! principal authentication — that's a deployment-layer concern (the
//! SafeClaw pro-backend is the auth boundary).

pub mod broker;
pub mod cors;
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

pub fn admin_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        // Custodian-level (no vault context).
        .route("/health", get(handlers::health::health))
        .route("/pubkey", get(handlers::metadata::pubkey))
        .route("/menu", get(handlers::registry::menu))
        // Vault-scoped.
        .route("/v/{vid}/op", post(handlers::op::create))
        .route("/v/{vid}/passkeys", get(handlers::metadata::passkeys))
        .route("/v/{vid}/pending-passkeys", post(handlers::pending_passkey::create))
        .route("/v/{vid}/events", get(handlers::events::stream))
        .route("/v/{vid}/approvals", get(handlers::approvals::list))
        .route("/v/{vid}/keys-known", get(handlers::keys_known::keys_known))
        .route("/v/{vid}/registry", get(handlers::registry::vault_registry))
        .route("/v/{vid}/usage", get(handlers::usage::usage))
        // Op-flat (vault context lives on the approval record).
        .route("/op/{op_id}", get(handlers::approve::get_op))
        .route("/op/{op_id}/approve", post(handlers::approve::approve_op))
        .route("/op/{op_id}/reject", post(handlers::approve::reject_op))
        // CLI auth page (embedded static — no daemon state needed).
        // See `[[cli-implementation]]` Phase 2 + the doc comment in
        // `handlers::cli_auth` for the WebAuthn flow.
        .route("/cli/auth", get(handlers::cli_auth::index))
        .route("/cli/auth/main.js", get(handlers::cli_auth::main_js))
        .route("/cli/auth/sudp/bytes.js", get(handlers::cli_auth::sudp_bytes))
        .route("/cli/auth/sudp/canonical.js", get(handlers::cli_auth::sudp_canonical))
        .route("/cli/auth/sudp/hash.js", get(handlers::cli_auth::sudp_hash))
        .route("/cli/auth/sudp/aad.js", get(handlers::cli_auth::sudp_aad))
        .route("/cli/auth/sudp/binding.js", get(handlers::cli_auth::sudp_binding))
        .route("/cli/auth/sudp/kdf.js", get(handlers::cli_auth::sudp_kdf))
        .route("/cli/auth/sudp/webauthn.js", get(handlers::cli_auth::sudp_webauthn))
        // Admin (X-Admin-Key gated; off when SAFECLAW_ADMIN_KEY unset).
        .route("/admin/vaults", get(handlers::admin::list_vaults))
        .route("/admin/vaults/{vid}", delete(handlers::admin::delete_vault))
        .with_state(state);
    router = router.layer(DefaultBodyLimit::max(MAX_BODY_BYTES));
    if let Some(cors) = cors::build_cors() {
        router = router.layer(cors);
    }
    router
}
