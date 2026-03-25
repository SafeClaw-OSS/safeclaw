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
        // ── Health ──────────────────────────────────────────────────────────
        .route("/health", get(health))

        // ── VM Public Key ────────────────────────────────────────────────────
        // Old path (used by HTML)
        .route("/vmPk", get(vm_pk))
        // New path
        .route("/vm-pk", get(vm_pk))

        // ── Status ───────────────────────────────────────────────────────────
        // Old path: GET for unauthenticated basic status (used by admin.html)
        .route("/admin/status", get(status_basic).post(status_authenticated))
        // New path
        .route("/system/status", get(status_basic).post(status_authenticated))

        // ── Setup ─────────────────────────────────────────────────────────────
        .route("/setup", post(setup))

        // ── Vault: Unlock ─────────────────────────────────────────────────────
        // Old paths (used by HTML)
        .route("/unlock", post(vault_unlock))
        .route("/admin/unlock", post(vault_unlock))
        // New path
        .route("/vault/unlock", post(vault_unlock))

        // ── Vault: Lock ───────────────────────────────────────────────────────
        // Old path (no auth — HTML sends no auth for lock)
        .route("/admin/lock", post(vault_lock_noauth))
        // New path (with auth)
        .route("/vault/lock", post(vault_lock))

        // ── Vault: Credentials ────────────────────────────────────────────────
        .route("/admin/credentials", post(vault_credentials))
        .route("/vault/credentials", post(vault_credentials))

        // ── Vault: Update ─────────────────────────────────────────────────────
        .route("/admin/update-secrets", post(vault_update))
        .route("/vault/update", post(vault_update))

        // ── Identity ──────────────────────────────────────────────────────────
        .route("/admin/add-passkey", post(identity_add_passkey))
        .route("/identity/add-passkey", post(identity_add_passkey))
        .route("/admin/remove-passkey", post(identity_remove_passkey))
        .route("/identity/remove-passkey", post(identity_remove_passkey))

        // ── System ────────────────────────────────────────────────────────────
        .route("/admin/restart", post(system_restart))
        .route("/system/restart", post(system_restart))
        .route("/admin/shutdown", post(system_shutdown))
        .route("/system/shutdown", post(system_shutdown))

        // ── Static Pages ──────────────────────────────────────────────────────
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/setup.html", get(serve_setup))
        .route("/setup", get(serve_setup))
        .route("/unlock.html", get(serve_unlock))
        .route("/unlock", get(serve_unlock))
        .route("/admin/unlock", get(serve_unlock))
        .route("/admin.html", get(serve_admin))
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
