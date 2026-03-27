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
        .route("/pk", get(server_pk))

        // ── Admin (instance management) ─────────────────────────────────────
        .route("/admin/setup", get(serve_setup).post(setup))
        .route("/admin/unlock", get(serve_unlock).post(vault_unlock))
        .route("/admin", get(serve_admin))
        .route("/admin/restart", post(system_restart))
        .route("/admin/shutdown", post(system_shutdown))
        .route("/admin/safeclaw.md", get(admin_safeclaw_md))
        .route("/admin/agents-snippet", get(admin_agents_snippet))

        // ── Vault (authenticated) ───────────────────────────────────────────
        .route("/vault/lock", post(vault_lock))
        .route("/vault/credentials", post(vault_credentials))
        .route("/vault/update", post(vault_update))

        // ── Vault Service CRUD ───────────────────────────────────────────────
        .route("/vault/services", get(vault_services_list))
        .route("/vault/services/add", post(vault_services_add))
        .route("/vault/services/update", post(vault_services_update))
        .route("/vault/services/remove", post(vault_services_remove))

        // ── Policy Defaults ──────────────────────────────────────────────────
        .route("/vault/policy", get(vault_policy_get))
        .route("/vault/policy/update", post(vault_policy_update))

        // ── Files ────────────────────────────────────────────────────────────
        .route("/vault/files", get(vault_files_list))
        .route("/vault/files/upload", post(vault_files_upload))
        .route("/vault/files/read", post(vault_files_read))
        .route("/vault/files/remove", post(vault_files_remove))

        // ── Push Notifications ───────────────────────────────────────────────
        .route("/vault/notifications/subscribe", post(vault_notifications_subscribe))

        // ── Notifications (poll queue) ───────────────────────────────────────
        .route("/notifications", get(notifications_get))

        // ── Approval Endpoints ───────────────────────────────────────────────
        .route("/approve/pending", get(approval_list_pending))
        .route("/approve/{id}", get(approval_get))
        .route("/approve/{id}/status", get(approval_status))
        .route("/approve/{id}/details", post(approval_details))
        .route("/approve/{id}/confirm", post(approval_confirm))
        .route("/approve/{id}/reject", post(approval_reject))

        // ── Audit Log ────────────────────────────────────────────────────────
        .route("/audit/log", get(audit_log_list))

        // ── Passkeys (authenticated) ────────────────────────────────────────
        .route("/passkeys/add", post(identity_add_passkey))
        .route("/passkeys/remove", post(identity_remove_passkey))

        // ── Static ──────────────────────────────────────────────────────────
        .route("/", get(serve_index))
        .route("/safeclaw-client.js", get(serve_client_js))

        // ── Middleware ────────────────────────────────────────────────────────
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors)
        .with_state(state)
}
