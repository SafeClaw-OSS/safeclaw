pub mod forward;
pub mod locked;

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use http_body_util::BodyExt;
use hyper::body::Bytes;

use crate::approval::{ApprovalDecision, ApprovalManager};
use crate::audit::AuditLog;
use crate::config::Config;
use crate::policy::{evaluate_policy, AccessLevel};
use crate::state::VaultState;
use forward::{forward_request, parse_route, refresh_oauth2_token, ServiceConfig};
use locked::{anthropic_locked, gemini_locked, openai_locked, openai_responses_locked};

/// Shared state for the proxy server
pub struct ProxyState {
    pub vault: Arc<VaultState>,
    pub config: Config,
    pub approval_manager: Arc<ApprovalManager>,
    pub audit_log: Arc<AuditLog>,
    pub notifications: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
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
    let uri_path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = req.headers().clone();

    tracing::debug!(
        "proxy: {} {} locked={}",
        method,
        uri_path,
        state.vault.is_locked()
    );

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

        let body_bytes = match read_body_limited(req, 4096).await {
            Ok(b) => b,
            Err(_) => Bytes::new(),
        };

        let mut is_stream = accept_sse || stream_in_url;
        if !is_stream && !body_bytes.is_empty() {
            if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                is_stream = parsed
                    .get("stream")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
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
                state.audit_log.log_request(
                    &route_service,
                    method.as_str(),
                    &route_path,
                    "standard",
                    "blocked",
                    None,
                    None,
                    None,
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "service not configured",
                        "code": "UNKNOWN_SERVICE"
                    })),
                )
                    .into_response();
            }
        }
    };

    // ── Policy evaluation ──────────────────────────────────────────────────────

    let policy_defaults = state.vault.get_policy_defaults();
    let access_level = evaluate_policy(
        method.as_str(),
        &route_path,
        service_config.rules.as_ref(),
        service_config.levels.as_ref(),
        &policy_defaults,
    );

    tracing::debug!(
        "proxy: service={} method={} level={}",
        route_service,
        method,
        access_level
    );

    // ── Approval gate ──────────────────────────────────────────────────────────

    let needs_approval = match &access_level {
        AccessLevel::Standard => false,
        AccessLevel::Elevated => {
            // Skip approval if a valid elevated session exists
            !state.vault.check_elevated_session(&route_service)
        }
        AccessLevel::Critical => true, // always require approval
    };

    let approval_id: Option<String> = if needs_approval {
        let timeout = policy_defaults.timeout.unwrap_or(300);

        // Capture sanitised request details (no sensitive values)
        let details = {
            let mut d = serde_json::Map::new();
            if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
                d.insert("content_type".to_string(), serde_json::Value::String(ct.to_string()));
            }
            if !body_bytes.is_empty() {
                let preview = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(2048)]);
                d.insert("body_preview".to_string(), serde_json::Value::String(preview.into_owned()));
            }
            Some(serde_json::Value::Object(d))
        };

        let (id, rx) = state.approval_manager.create_approval(
            route_service.clone(),
            method.to_string(),
            route_path.clone(),
            timeout,
            details,
        );

        tracing::info!(
            "proxy: approval required id={} service={} method={} path={}",
            id,
            route_service,
            method,
            route_path
        );

        // Push lightweight in-memory notification (Web Push / RFC 8030 is a future enhancement)
        {
            let notif = serde_json::json!({
                "type": "approval",
                "id": id,
                "service": route_service,
                "method": method.to_string(),
                "level": access_level.to_string(),
            });
            state.notifications.lock().unwrap().push(notif);
        }

        // Spawn cleanup task for timeout
        {
            let mgr = state.approval_manager.clone();
            let id_clone = id.clone();
            let level_clone = access_level.clone();
            let vault_clone = state.vault.clone();
            let svc_clone = route_service.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(timeout)).await;
                // Only remove if it was elevated (for cache cleanup)
                if level_clone == AccessLevel::Elevated {
                    vault_clone.elevated_cache.lock().unwrap().remove(&svc_clone);
                }
                mgr.remove_timed_out(&id_clone);
            });
        }

        // Await approval decision
        let decision = tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            rx,
        )
        .await;

        match decision {
            Ok(Ok(ApprovalDecision::Approved)) => {
                tracing::info!("proxy: approval id={} approved", id);
                // Cache elevated session with TTL
                if access_level == AccessLevel::Elevated {
                    // Find TTL from matching rule, or default 3600s
                    let ttl = find_rule_ttl(
                        service_config.rules.as_ref(),
                        method.as_str(),
                        &route_path,
                    )
                    .unwrap_or(3600);
                    state.vault.set_elevated_session(&route_service, ttl);
                }
                Some(id)
            }
            Ok(Ok(ApprovalDecision::Rejected)) => {
                tracing::info!("proxy: approval id={} rejected", id);
                state.audit_log.log_request(
                    &route_service,
                    method.as_str(),
                    &route_path,
                    &access_level.to_string(),
                    "rejected",
                    None,
                    None,
                    Some(&id),
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "request rejected by vault owner" })),
                )
                    .into_response();
            }
            Ok(Err(_)) | Err(_) => {
                tracing::warn!("proxy: approval id={} timed out", id);
                state.audit_log.log_request(
                    &route_service,
                    method.as_str(),
                    &route_path,
                    &access_level.to_string(),
                    "timed_out",
                    None,
                    None,
                    Some(&id),
                );
                return (
                    StatusCode::REQUEST_TIMEOUT,
                    Json(serde_json::json!({ "error": "approval timed out" })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    // ── OAuth2 token refresh ───────────────────────────────────────────────────

    let resolved_bearer: Option<String> = if let Some(a) = &service_config.auth {
        if a.auth_type == "oauth2" {
            // Check in-memory cache first
            let cached = {
                let tokens = state.vault.oauth2_tokens.lock().unwrap();
                tokens.get(&route_service).cloned()
            };

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let token = if let Some((tok, exp)) = cached {
                if exp > now_secs + 60 {
                    // Valid with >60s margin
                    Some(tok)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(t) = token {
                Some(t)
            } else {
                // Refresh token
                match refresh_oauth2_token(a).await {
                    Ok((access_token, expires_at)) => {
                        state
                            .vault
                            .oauth2_tokens
                            .lock()
                            .unwrap()
                            .insert(route_service.clone(), (access_token.clone(), expires_at));
                        Some(access_token)
                    }
                    Err(e) => {
                        tracing::warn!("oauth2 refresh failed for {}: {}", route_service, e);
                        // Fall back to static access_token if present
                        a.access_token.clone()
                    }
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // ── Forward request ────────────────────────────────────────────────────────

    let request_start = Instant::now();
    let response = forward_request(
        method.clone(),
        &uri_path,
        &headers,
        body_bytes,
        &service_config,
        resolved_bearer.as_deref(),
    )
    .await;

    let duration_ms = request_start.elapsed().as_millis() as i64;
    let upstream_status = response.status().as_u16();

    state.audit_log.log_request(
        &route_service,
        method.as_str(),
        &route_path,
        &access_level.to_string(),
        "allowed",
        Some(duration_ms),
        Some(upstream_status),
        approval_id.as_deref(),
    );

    response
}

/// Find session TTL from matching rule (for elevated access).
fn find_rule_ttl(
    rules: Option<&Vec<crate::policy::PolicyRule>>,
    method: &str,
    path: &str,
) -> Option<u64> {
    let rules = rules?;
    for rule in rules {
        if let Some(ref m) = rule.method {
            if m != method {
                continue;
            }
        }
        if let Some(ref suffix) = rule.path_suffix {
            if !path.contains(suffix.as_str()) {
                continue;
            }
        }
        if let Some(ttl) = rule.session_ttl {
            return Some(ttl);
        }
    }
    None
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
