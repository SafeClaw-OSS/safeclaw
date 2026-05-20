//! HTTP server: admin port (`:23294`) router and handler wiring.
//!
//! CORS is intentionally NOT handled here — it is a web-layer concern and
//! belongs to whatever reverse proxy fronts the daemon (Caddy in our SaaS
//! deployment). Server-side relays (per-VM model, console proxy) don't need
//! CORS at all.

pub mod handlers;
pub mod tenant_extractor;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub fn admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health::health))
        .route("/challenge", get(handlers::challenge::challenge))
        .route("/grant", post(handlers::grant::grant))
        .route("/metadata/passkeys", get(handlers::metadata::passkeys))
        .route("/metadata/keys", get(handlers::metadata::vault_keys))
        .route("/approve/{id}", get(handlers::approve::get_approval))
        .route("/approve/{id}/details", post(handlers::approve::details))
        .route("/approve/{id}/confirm", post(handlers::approve::confirm))
        .route("/approve/{id}/reject", post(handlers::approve::reject))
        .with_state(state)
}
