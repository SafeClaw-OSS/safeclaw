pub mod routes;
pub mod static_files;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};

use crate::state::AppState;

use self::routes::*;
use self::static_files::*;

/// Rate-limiting middleware
async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();
    let allowed = {
        let mut rl = state.rate_limiter.lock().unwrap();
        rl.check(&ip)
    };
    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Rate limit exceeded" })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Build the server router
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        // ── Public ──────────────────────────────────────────────────────────
        .route("/health", get(health))
        .route("/pk", get(vm_pk))
        .route("/setup", get(serve_setup).post(setup))
        .route("/status", get(status_basic).post(status_authenticated))

        // ── Vault (authenticated) ───────────────────────────────────────────
        .route("/vault/unlock", post(vault_unlock))
        .route("/vault/lock", post(vault_lock))
        .route("/vault/credentials", post(vault_credentials))
        .route("/vault/update", post(vault_update))

        // ── Passkeys (authenticated) ────────────────────────────────────────
        .route("/passkeys/add", post(identity_add_passkey))
        .route("/passkeys/remove", post(identity_remove_passkey))

        // ── Process control (authenticated) ─────────────────────────────────
        .route("/restart", post(system_restart))
        .route("/shutdown", post(system_shutdown))

        // ── Static pages ────────────────────────────────────────────────────
        .route("/", get(serve_index))
        .route("/unlock", get(serve_unlock))
        .route("/admin", get(serve_admin))
        .route("/safeclaw-client.js", get(serve_client_js))

        // ── Middleware ────────────────────────────────────────────────────────
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors)
        .with_state(state)
}
