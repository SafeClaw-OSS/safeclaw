use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use http_body_util::BodyExt;
use hyper::body::Bytes;

use super::approval::{ApprovalManager, ApprovalStatus, CachedResponse};
use super::audit::AuditLog;
use crate::config::Config;
use super::policy::{evaluate_policy, AccessLevel};
use crate::state::VaultState;
use super::forward::{forward_request, parse_route};
use crate::auth::{AuthConfig, ServiceConfig};
use crate::auth::oauth2::refresh_token as refresh_oauth2_token;
use crate::service::ServiceRegistry;

/// Shared state for the proxy server
pub struct ProxyState {
    pub vault: Arc<VaultState>,
    pub config: Config,
    pub approval_manager: Arc<ApprovalManager>,
    pub audit_log: Arc<AuditLog>,
    pub services: ServiceRegistry,
}

pub fn build_proxy_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/health", any(proxy_health))
        .route("/approve/{id}", any(proxy_poll_approval))
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

// ── GET /approve/{id} — agent polls approval status ───────────────────────────

async fn proxy_poll_approval(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
) -> Response {
    let snapshot = match state.approval_manager.get_snapshot(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "approval not found" })),
            )
                .into_response();
        }
    };

    match snapshot.status {
        ApprovalStatus::Pending => {
            Json(serde_json::json!({ "status": "pending" })).into_response()
        }

        ApprovalStatus::Rejected => {
            Json(serde_json::json!({ "status": "rejected" })).into_response()
        }

        ApprovalStatus::Expired => {
            Json(serde_json::json!({ "status": "expired" })).into_response()
        }

        ApprovalStatus::Approved => {
            // Return cached response if already executed
            if let Some(cached) = snapshot.cached_response {
                return Json(serde_json::json!({
                    "status": "approved",
                    "response": {
                        "status": cached.status,
                        "headers": cached.headers,
                        "body": cached.body,
                    }
                }))
                .into_response();
            }

            // First poll after approval: take auth and execute upstream
            let auth_json = match state.approval_manager.take_auth_for_execute(&id) {
                Some(aj) => aj,
                None => {
                    // Race: another concurrent poll already took it, spin back pending
                    return Json(serde_json::json!({ "status": "pending" })).into_response();
                }
            };

            // Build service config for replay
            let auth_config = auth_json
                .clone()
                .and_then(|aj| serde_json::from_value::<AuthConfig>(aj).ok());

            let service_config = ServiceConfig {
                upstream: snapshot.upstream.clone(),
                auth: auth_config,
                levels: None,
                rules: None,
                category: None,
            };

            // OAuth2 token refresh if needed
            let resolved_bearer: Option<String> = if let Some(a) = &service_config.auth {
                if a.auth_type == "oauth2" {
                    let service_name = &snapshot.service;
                    let cached_token = {
                        let tokens = state.vault.oauth2_tokens.lock().unwrap();
                        tokens.get(service_name).cloned()
                    };
                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let valid_cached = cached_token
                        .filter(|(_, exp)| *exp > now_secs + 60)
                        .map(|(tok, _)| tok);

                    if let Some(t) = valid_cached {
                        Some(t)
                    } else {
                        let oauth_style = state.services.oauth_style(service_name);
                        match refresh_oauth2_token(a, oauth_style).await {
                            Ok((access_token, expires_at)) => {
                                state
                                    .vault
                                    .oauth2_tokens
                                    .lock()
                                    .unwrap()
                                    .insert(service_name.clone(), (access_token.clone(), expires_at));
                                Some(access_token)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "poll: oauth2 refresh failed for {}: {}",
                                    service_name,
                                    e
                                );
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

            // Parse method
            let method = match snapshot.method.parse::<axum::http::Method>() {
                Ok(m) => m,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "error": "invalid stored method" })),
                    )
                        .into_response();
                }
            };

            // For files service: inject approval ID so the vault endpoint can find the DEK
            let replay_uri = if snapshot.service == "files" {
                let sep = if snapshot.uri_path.contains('?') { "&" } else { "?" };
                format!("{}{}approval={}", snapshot.uri_path, sep, id)
            } else {
                snapshot.uri_path.clone()
            };

            // Execute upstream
            let upstream_resp = forward_request(
                method,
                &replay_uri,
                &snapshot.req_headers,
                snapshot.req_body.clone(),
                &service_config,
                resolved_bearer.as_deref(),
                &state.services,
                &snapshot.service,
            )
            .await;

            // Buffer the full response to cache + return as JSON
            let resp_status = upstream_resp.status().as_u16();
            let resp_headers: HashMap<String, String> = upstream_resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str().ok().map(|vs| (k.as_str().to_string(), vs.to_string()))
                })
                .collect();

            let body_bytes = match axum::body::to_bytes(upstream_resp.into_body(), 32 * 1024 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("poll: failed to read upstream body: {}", e);
                    // Don't cache; agent can retry
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({ "error": "failed to read upstream response" })),
                    )
                        .into_response();
                }
            };

            let body_json: serde_json::Value =
                serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
                    serde_json::Value::String(String::from_utf8_lossy(&body_bytes).into_owned())
                });

            let cached = CachedResponse {
                status: resp_status,
                headers: resp_headers.clone(),
                body: body_json.clone(),
            };
            state.approval_manager.set_cached_response(&id, cached);

            // Cache approval session so subsequent requests skip approval
            if let Some(auth) = auth_json {
                state.vault.set_approval_session(&snapshot.service, auth, 3600);
            }

            tracing::info!(
                "poll: executed approved request id={} service={} status={}",
                id,
                snapshot.service,
                resp_status
            );
            state.audit_log.log_request(
                &snapshot.service,
                &snapshot.method,
                // strip service prefix from uri_path for audit
                &format!("/{}", snapshot.uri_path.trim_start_matches('/').splitn(3, '/').nth(1).unwrap_or("")),
                "ask",
                "approved",
                None,
                Some(resp_status),
                Some(&id),
            );

            Json(serde_json::json!({
                "status": "approved",
                "response": {
                    "status": resp_status,
                    "headers": resp_headers,
                    "body": body_json,
                }
            }))
            .into_response()
        }
    }
}

// ── POST /any-path — main proxy handler ───────────────────────────────────────

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

        return state.services.locked_response(&route_service, is_stream, admin_url, &route_path)
            .unwrap_or_else(|| crate::service::locked::render("openai", is_stream, admin_url)
                .unwrap_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "vault locked").into_response()));
    }

    // Read full body for forwarding (and potential approval replay)
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
    let mut service_config = {
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
                    "allow",
                    "denied",
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

    // Infer category from service if not explicitly set in vault config
    let category = service_config.category.as_deref()
        .unwrap_or_else(|| state.services.default_category(&route_service));

    let policy_defaults = state.vault.get_policy_defaults();
    let access_level = evaluate_policy(
        method.as_str(),
        &route_path,
        service_config.rules.as_ref(),
        service_config.levels.as_ref(),
        &policy_defaults,
        Some(category),
    );

    tracing::debug!(
        "proxy: service={} method={} level={}",
        route_service,
        method,
        access_level
    );

    // ── Approval gate ──────────────────────────────────────────────────────────

    let cached_auth = if access_level == AccessLevel::Ask {
        state.vault.check_approval_session(&route_service)
    } else {
        None
    };

    let needs_approval = match &access_level {
        AccessLevel::Allow => false,
        AccessLevel::Ask => cached_auth.is_none(),
        AccessLevel::AskAlways => true,
        AccessLevel::Deny => {
            state.audit_log.log_request(
                &route_service,
                method.as_str(),
                &route_path,
                "deny",
                "denied",
                None,
                None,
                None,
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access denied by policy",
                    "code": "DENIED"
                })),
            )
                .into_response();
        }
    };

    if needs_approval {
        let timeout = policy_defaults.timeout.unwrap_or(300).max(10).min(3600);

        // Sanitised details (no secrets) for the console approve page
        let details = {
            let mut d = serde_json::Map::new();
            if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
                d.insert(
                    "content_type".to_string(),
                    serde_json::Value::String(ct.to_string()),
                );
            }
            if !body_bytes.is_empty() {
                let preview =
                    String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(2048)]);
                d.insert(
                    "body_preview".to_string(),
                    serde_json::Value::String(preview.into_owned()),
                );
            }
            Some(serde_json::Value::Object(d))
        };

        // Filter request headers for replay (strip hop-by-hop + auth)
        let replay_headers = filter_replay_headers(&headers);

        let id = state.approval_manager.create_approval(
            route_service.clone(),
            method.to_string(),
            route_path.clone(),
            uri_path.clone(),
            service_config.upstream.clone(),
            replay_headers,
            body_bytes.clone(),
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

        // Approval session cache cleanup on TTL
        {
            let mgr = state.approval_manager.clone();
            let id_clone = id.clone();
            let level_clone = access_level.clone();
            let vault_clone = state.vault.clone();
            let svc_clone = route_service.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(timeout)).await;
                if level_clone == AccessLevel::Ask {
                    vault_clone
                        .approval_cache
                        .lock()
                        .unwrap()
                        .remove(&svc_clone);
                }
                mgr.expire(&id_clone);
            });
        }

        // Web Push notification
        {
            let notif = serde_json::json!({
                "type": "approval",
                "id": id,
                "service": route_service,
                "method": method.to_string(),
                "level": access_level.to_string(),
            });
            let subs = state.vault.push_subscriptions.lock().unwrap().clone();
            let priv_key = state.vault.vapid_private_key.lock().unwrap().clone();
            if let Some(priv_b64) = priv_key {
                let vault_clone = state.vault.clone();
                tokio::spawn(async move {
                    let dead =
                        crate::notify::webpush::send_push_notification(&priv_b64, &subs, notif).await;
                    if !dead.is_empty() {
                        let mut active = vault_clone.push_subscriptions.lock().unwrap();
                        active.retain(|s| !dead.contains(&s.endpoint));
                    }
                });
            }
        }

        // Approval session cache TTL (for agent-side)
        if access_level == AccessLevel::Ask {
            let ttl = find_rule_ttl(service_config.rules.as_ref(), method.as_str(), &route_path)
                .unwrap_or(3600);
            // Cache a placeholder; real auth stored in PendingApproval.approved_auth
            // and injected into approval cache only after execution (in poll handler).
            let _ = ttl; // TTL applied at execute time
        }

        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + timeout;

        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "id": id,
                "safeclaw_approve_url": format!(
                    "{}/approve/{}",
                    state.config.effective_admin_url(),
                    id
                ),
                "expires_at": expires_at_unix,
            })),
        )
            .into_response();
    }

    // ── Inject effective auth for approval-cached session ─────────────────────

    if service_config.auth.is_none() {
        if let Some(aj) = cached_auth {
            service_config.auth = serde_json::from_value::<AuthConfig>(aj).ok();
        }
    }

    // ── OAuth2 token refresh ───────────────────────────────────────────────────

    let resolved_bearer: Option<String> = if let Some(a) = &service_config.auth {
        if a.auth_type == "oauth2" {
            let cached = {
                let tokens = state.vault.oauth2_tokens.lock().unwrap();
                tokens.get(&route_service).cloned()
            };

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let valid_cached = cached
                .filter(|(_, exp)| *exp > now_secs + 60)
                .map(|(tok, _)| tok);

            if let Some(t) = valid_cached {
                Some(t)
            } else {
                let oauth_style = state.services.oauth_style(&route_service);
                match refresh_oauth2_token(a, oauth_style).await {
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

    // ── Local service (CLI bridge) ───────────────────────────────────────────

    if state.services.is_local(&route_service) {
        let request_start = Instant::now();
        let response = handle_local_service(
            &state.services,
            &route_service,
            method.as_str(),
            &route_path,
            body_bytes,
        ).await;
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
            None,
        );
        return response;
    }

    // ── Forward request (proxy) ───────────────────────────────────────────────

    let request_start = Instant::now();
    let response = forward_request(
        method.clone(),
        &uri_path,
        &headers,
        body_bytes,
        &service_config,
        resolved_bearer.as_deref(),
        &state.services,
        &route_service,
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
        None,
    );

    response
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Strip headers that must not be replayed: hop-by-hop, auth, host, content-length.
fn filter_replay_headers(headers: &axum::http::HeaderMap) -> axum::http::HeaderMap {
    const STRIP: &[&str] = &[
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
        "authorization",
        "x-api-key",
        "api-key",
    ];
    let mut out = axum::http::HeaderMap::new();
    for (k, v) in headers.iter() {
        if !STRIP.contains(&k.as_str().to_lowercase().as_str()) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Find session TTL from matching rule (for `ask` access level).
fn find_rule_ttl(
    rules: Option<&Vec<super::policy::PolicyRule>>,
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

// ── Local service handler (CLI bridge) ────────────────────────────────────────

async fn handle_local_service(
    registry: &ServiceRegistry,
    service_name: &str,
    method: &str,
    path: &str,
    body: Bytes,
) -> Response {
    let api = match registry.find_local_api(service_name, method, path) {
        Some(a) => a,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("no local API matches {} {}", method, path),
                    "code": "NOT_FOUND"
                })),
            ).into_response();
        }
    };

    tracing::info!("local exec: {} {} → {}", method, path, api.command);

    let parts: Vec<&str> = api.command.split_whitespace().collect();
    if parts.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "empty command" })),
        ).into_response();
    }

    let result = tokio::process::Command::new(parts[0])
        .args(&parts[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match result {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("local exec failed to spawn '{}': {}", api.command, e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("spawn failed: {}", e) })),
            ).into_response();
        }
    };

    // Write body to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(&body).await;
        drop(stdin);
    }

    match child.wait_with_output().await {
        Ok(output) => {
            let status = if output.status.success() {
                StatusCode::OK
            } else {
                StatusCode::BAD_GATEWAY
            };

            let stdout = output.stdout;
            // Try to parse as JSON, otherwise return as text
            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&stdout) {
                (status, Json(json_val)).into_response()
            } else {
                let mut resp = Response::new(axum::body::Body::from(stdout));
                *resp.status_mut() = status;
                resp.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                resp
            }
        }
        Err(e) => {
            tracing::warn!("local exec wait failed for '{}': {}", api.command, e);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("exec failed: {}", e) })),
            ).into_response()
        }
    }
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
