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
    // Check exempt prefixes before applying rate limit
    let path = req.uri().path().to_string();
    let exempt = state.config.rate_limit_exempt.iter().any(|prefix| path.starts_with(prefix.as_str()));
    if exempt {
        return next.run(req).await;
    }

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
        // ── WebAuthn ROR (Related Origin Requests) ──────────────────────────
        .route("/.well-known/webauthn", get(well_known_webauthn))

        // ── Public ──────────────────────────────────────────────────────────
        .route("/health", get(health))
        .route("/challenge", get(challenge))
        .route("/auth/verify", post(auth_verify))

        // ── Admin static pages + workspace helpers ─────────────────────────
        .route("/admin/setup", get(serve_setup))
        .route("/admin/unlock", get(serve_unlock))
        .route("/admin", get(serve_admin))
        .route("/admin/safeclaw.md", get(admin_safeclaw_md))
        .route("/admin/agents-snippet", get(admin_agents_snippet))

        // ── Vault (authenticated) ───────────────────────────────────────────
        .route("/vault/setup", post(setup))
        .route("/vault/unlock", post(vault_unlock))
        .route("/vault/lock", post(vault_lock))
        .route("/vault/read", post(vault_read))
        .route("/vault/write", post(vault_update))

        // ── Vault Service CRUD ───────────────────────────────────────────────
        .route("/vault/services", get(vault_services_list))
        .route("/vault/services/{name}/{key}", get(vault_service_field))
        .route("/vault/services/install", post(vault_services_add))
        .route("/vault/services/uninstall", post(vault_services_remove))

        // ── Policy Defaults ──────────────────────────────────────────────────
        .route("/vault/policy", get(vault_policy_get))
        .route("/vault/policy/update", post(vault_policy_update))

        // ── Files ────────────────────────────────────────────────────────────
        .route("/vault/files", get(vault_files_list))
        // /help is handled generically by the proxy layer (GET /{service}/help)
        .route("/vault/files/{id}", get(vault_files_read_approved))
        .route("/vault/files/upload", post(vault_files_upload))
        .route("/vault/files/download", post(vault_files_read))
        .route("/vault/files/delete", post(vault_files_remove))

        // ── Push Notifications ───────────────────────────────────────────────
        .route("/vault/notifications/subscribe", post(vault_notifications_subscribe))

        // ── Approval Endpoints ───────────────────────────────────────────────
        .route("/approve/pending", get(approval_list_pending))
        .route("/approve/{id}", get(approval_get))
        // /approve/{id}/status removed — polling moved to proxy port GET /approve/{id}
        .route("/approve/{id}/details", post(approval_details))
        .route("/approve/{id}/confirm", post(approval_confirm))
        .route("/approve/{id}/reject", post(approval_reject))

        // ── Admin Operations ─────────────────────────────────────────────────
        .route("/admin/upgrade", post(admin_upgrade))

        // ── Audit Log ────────────────────────────────────────────────────────
        .route("/audit/log", get(audit_log_list))

        // ── Passkeys (authenticated) ────────────────────────────────────────
        .route("/vault/passkeys/enroll", post(identity_add_passkey))
        .route("/vault/passkeys/revoke", post(identity_remove_passkey))
        .route("/vault/passkeys/public", get(passkeys_public))

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
