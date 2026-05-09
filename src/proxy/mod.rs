//! Proxy port (`:23295`) — agent-facing transparent HTTP for virtual services.
//!
//! For toy v0 the only virtual service is `safeclaw-vault`: a request to
//! `/safeclaw-vault/<key_name>` either returns the previously-approved value
//! (if the agent already triggered an approval and the user confirmed) or
//! creates a fresh pending approval and returns 202.

pub mod safeclaw_vault;

use std::sync::Arc;

use axum::{
    routing::{any, get},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::state::AppState;

pub fn proxy_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/safeclaw-vault/{key}", any(safeclaw_vault::handle))
        .route(
            "/safeclaw-vault/{key}/poll",
            get(safeclaw_vault::poll),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}
