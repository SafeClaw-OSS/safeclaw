//! Proxy port (`:23295`) — agent-facing R-side sugar routes.
//!
//! v1 URL surface:
//!
//! ```text
//! POST /v/{vid}/export/{key}                R-side Export sugar
//! POST /v/{vid}/use/{service}/{*rest}       R-side Use (broker) sugar
//! ```
//!
//! Both compile the request to a sudp `Operation` and create a pending
//! approval, returning `{ op_id, r, expires_at, approve_url, poll_url }`.
//! U authorizes via `POST /op/{op_id}/approve` on the admin port. R polls
//! via `GET /op/{op_id}`.

pub mod env;
pub mod use_broker;

use std::sync::Arc;

use axum::{routing::post, Router};

use crate::server::cors::build_cors;
use crate::state::AppState;

pub fn proxy_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/v/{vid}/export/{key}", post(env::handle))
        .route("/v/{vid}/use/{service}/{*rest}", post(use_broker::handle))
        .with_state(state);
    if let Some(cors) = build_cors() {
        router = router.layer(cors);
    }
    router
}
