//! HTTP server: admin port (`:23294`) router and handler wiring.
//!
//! CORS is added only when `SAFECLAW_CORS_ALLOW_ORIGINS` env var is set
//! (see [`cors::build_cors`]); production deployments terminate CORS at the
//! reverse proxy and leave it unset, while localhost dev sets it to allow
//! `http://localhost:3000` etc. for direct browser-to-daemon traffic.

pub mod cors;
pub mod handlers;
pub mod tenant_extractor;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub fn admin_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/health", get(handlers::health::health))
        .route("/challenge", get(handlers::challenge::challenge))
        .route("/grant", post(handlers::grant::grant))
        .route("/metadata/passkeys", get(handlers::metadata::passkeys))
        .route("/metadata/keys", get(handlers::metadata::vault_keys))
        .route("/approve/{id}", get(handlers::approve::get_approval))
        .route("/approve/{id}/details", post(handlers::approve::details))
        .route("/approve/{id}/confirm", post(handlers::approve::confirm))
        .route("/approve/{id}/reject", post(handlers::approve::reject))
        .with_state(state);
    if let Some(cors) = cors::build_cors() {
        router = router.layer(cors);
    }
    router
}
