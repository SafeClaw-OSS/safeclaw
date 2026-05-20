//! Proxy port (`:23295`) — agent-facing transparent HTTP for virtual services.
//!
//! For demo v0 the only virtual service is `env`: a request to
//! `/env/<entry>` either returns the previously-approved value (if the agent
//! already triggered an approval and the user confirmed) or creates a fresh
//! pending approval and returns 202.

pub mod env;

use std::sync::Arc;

use axum::{
    routing::{any, get},
    Router,
};

use crate::server::cors::build_cors;
use crate::state::AppState;

pub fn proxy_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/env/{entry}", any(env::handle))
        .route("/env/{entry}/poll", get(env::poll))
        .with_state(state);
    if let Some(cors) = build_cors() {
        router = router.layer(cors);
    }
    router
}
