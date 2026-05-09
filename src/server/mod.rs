//! HTTP server: admin port (`:23294`) router and handler wiring.

pub mod handlers;
pub mod tenant_extractor;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

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
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}
