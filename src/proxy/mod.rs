//! Proxy port (`:23295`) — agent-facing R-side sugar routes.
//!
//! v1 URL surface:
//!
//! ```text
//! POST /v/{vid}/export/{key}                R-side Export sugar
//! POST /v/{vid}/use/{service}                R-side Use (no sub-path)
//! POST /v/{vid}/use/{service}/{*rest}       R-side Use (with sub-path)
//! ```
//!
//! Both compile the request to a sudp `Operation` and create a pending
//! approval, returning `{ op_id, r, expires_at, approve_url, poll_url }`.
//! U authorizes via `POST /op/{op_id}/approve` on the admin port. R polls
//! via `GET /op/{op_id}`.

pub mod env;
pub mod use_broker;

use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, routing::{any, post}, Router};

const MAX_BODY_BYTES: usize = 256 * 1024;

use crate::server::cors::build_cors;
use crate::state::AppState;

pub fn proxy_router(state: Arc<AppState>) -> Router {
    // F-25: the proxy port (:23295) is a machine-to-machine interface used
    // by AI agents — not by browsers. Applying the admin CORS config here
    // would expose it to cross-origin browser requests, which is undesirable.
    // We intentionally do NOT add any CorsLayer to this router.
    // The `build_cors` import is retained for potential future per-port
    // configuration; unused-import lint is suppressed via the use statement.
    let _ = build_cors; // keep import to document intentional non-use
    // /use/* accepts any HTTP method — the daemon forwards verbatim to
    // the upstream, so GET-shaped read routes (e.g. `GET inbox/recent`)
    // work alongside POST/PUT/PATCH/DELETE per the upstream's contract.
    // `/export/*` stays POST-only since it's an R-side sudp ceremony,
    // not a transparent upstream forward.
    let router = Router::new()
        .route("/v/{vid}/export/{key}", post(env::handle))
        .route("/v/{vid}/use/{service}", any(use_broker::handle_no_rest))
        .route("/v/{vid}/use/{service}/{*rest}", any(use_broker::handle))
        // Local-bearer gate: when a token is provisioned (config.local_bearer),
        // every broker request must carry `Authorization: Bearer <token>`.
        // No-op when unset (auth-free self-host default). Admin plane (registry/
        // op/approve) is gated by op_id + passkey signature, not this.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::local_bearer::require_bearer,
        ))
        .with_state(state);
    router.layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}
