//! HTTP server: admin port (`:23294`) router.
//!
//! v1 URL surface (PROTOCOL.md §4.1 / `[[v1-endpoint-design]]`):
//!
//! ```text
//! POST /v/{vid}/op              R-side op creation (or U-direct: Enroll/Write/Export)
//! GET  /v/{vid}/passkeys        list enrolled credentials for this vault
//! GET  /v/{vid}/events          SSE lifecycle stream
//! GET  /c/menu                  static service catalog (no vault contents)
//! GET  /v/{vid}/registry        per-vault live view (catalog + connected state)
//! GET  /op/{op_id}              poll op status + cached value
//! POST /op/{op_id}/approve      U submits grant G → T validates, dispatches act
//! POST /op/{op_id}/reject       U denies
//! GET  /c/health                custodian health
//! GET  /c/pubkey                custodian HPKE bootstrap key (placeholder)
//! ```
//!
//! Vault selection is via URL path (`{vid}`). The custodian does no
//! principal authentication — that's a deployment-layer concern (the
//! SafeClaw pro-backend is the auth boundary).

pub mod broker;
pub mod cors;
pub mod handlers;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub fn admin_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        // Custodian-level (no vault context).
        .route("/c/health", get(handlers::health::health))
        .route("/c/pubkey", get(handlers::metadata::pubkey))
        .route("/c/menu", get(handlers::registry::menu))
        // Vault-scoped.
        .route("/v/{vid}/op", post(handlers::op::create))
        .route("/v/{vid}/passkeys", get(handlers::metadata::passkeys))
        .route("/v/{vid}/events", get(handlers::events::stream))
        .route("/v/{vid}/approvals", get(handlers::approvals::list))
        .route("/v/{vid}/keys-known", get(handlers::keys_known::keys_known))
        .route("/v/{vid}/registry", get(handlers::registry::vault_registry))
        .route("/v/{vid}/usage", get(handlers::usage::usage))
        // Op-flat (vault context lives on the approval record).
        .route("/op/{op_id}", get(handlers::approve::get_op))
        .route("/op/{op_id}/approve", post(handlers::approve::approve_op))
        .route("/op/{op_id}/reject", post(handlers::approve::reject_op))
        .with_state(state);
    if let Some(cors) = cors::build_cors() {
        router = router.layer(cors);
    }
    router
}
