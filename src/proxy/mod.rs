pub mod forward;
pub mod locked;

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use http_body_util::BodyExt;
use hyper::body::Bytes;

use crate::config::Config;
use crate::state::VaultState;
use forward::{forward_request, parse_route, ServiceConfig};
use locked::{anthropic_locked, gemini_locked, openai_locked, openai_responses_locked};

/// Shared state for the proxy server
pub struct ProxyState {
    pub vault: Arc<VaultState>,
    pub config: Config,
}

pub fn build_proxy_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/health", any(proxy_health))
        .route("/{*path}", any(proxy_handler))
        .with_state(state)
}

async fn proxy_health(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "locked": state.vault.is_locked(),
        "uptime": 0,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let uri_path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
    let headers = req.headers().clone();

    tracing::debug!("proxy: {} {} locked={}", method, uri_path, state.vault.is_locked());

    let (route_service, route_path, _route_query) = match parse_route(&uri_path) {
        Some(r) => r,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid path" })),
            )
                .into_response();
        }
    };

    if state.vault.is_locked() {
        // Detect stream from headers / URL before reading body
        let accept_sse = headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("text/event-stream"))
            .unwrap_or(false);
        let stream_in_url = uri_path.contains("stream=true");

        // Read limited body to detect stream flag
        let body_bytes = match read_body_limited(req, 4096).await {
            Ok(b) => b,
            Err(_) => Bytes::new(),
        };

        let mut is_stream = accept_sse || stream_in_url;
        if !is_stream && !body_bytes.is_empty() {
            if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                is_stream = parsed.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
            }
        }

        let admin_url = &state.config.effective_admin_url();

        return if route_path.contains("/responses") {
            openai_responses_locked(is_stream, admin_url)
        } else if route_service == "anthropic" || route_path.contains("/messages") {
            anthropic_locked(is_stream, admin_url)
        } else if route_service == "google" || route_path.contains("generateContent") {
            gemini_locked(admin_url)
        } else {
            openai_locked(is_stream, admin_url)
        };
    }

    // Read full body for forwarding
    let body_bytes = match read_body_limited(req, 32 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Failed to read request body: {}", e) })),
            )
                .into_response();
        }
    };

    // Look up service config from vault secrets
    let service_config = {
        let secrets_guard = state.vault.secrets.lock().unwrap();
        let secrets = match secrets_guard.as_ref() {
            Some(s) => s.clone(),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({ "error": "vault is locked" })),
                )
                    .into_response();
            }
        };
        drop(secrets_guard);

        let svc_val = secrets
            .get("services")
            .and_then(|s| s.get(&route_service))
            .cloned();

        match svc_val {
            Some(v) => match serde_json::from_value::<ServiceConfig>(v) {
                Ok(cfg) => cfg,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({ "error": format!("Invalid service config: {}", e) })),
                    )
                        .into_response();
                }
            },
            None => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("unknown service: {}", route_service) })),
                )
                    .into_response();
            }
        }
    };

    forward_request(method, &uri_path, &headers, body_bytes, &service_config).await
}

async fn read_body_limited(req: Request, limit: usize) -> Result<Bytes, String> {
    let body = req.into_body();
    let collected = body
        .collect()
        .await
        .map_err(|e| format!("body read error: {}", e))?;
    let bytes = collected.to_bytes();
    if bytes.len() > limit {
        Ok(bytes.slice(..limit))
    } else {
        Ok(bytes)
    }
}
