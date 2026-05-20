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

use crate::state::AppState;

// CORS not handled here — agents are server-side (CLI / daemons), no browser
// cross-origin path hits the proxy port. If a reverse proxy later fronts this
// port for browser use, CORS belongs there.

pub fn proxy_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/safeclaw-vault/{key}", any(safeclaw_vault::handle))
        .route(
            "/safeclaw-vault/{key}/poll",
            get(safeclaw_vault::poll),
        )
        .with_state(state)
}
