//! `POST /v/{vid}/use/{service}/{*rest}` — R-side sugar for Use (broker).
//!
//! Compiles `(method, path, headers, body)` into a sudp `Operation { act: Use }`,
//! creates a pending approval, returns `{ op_id, r, expires_at }`. The user
//! authorizes via `POST /op/{op_id}/approve`; on approve, the daemon executes
//! `sudp::phases::consumption::execute_use` to inject `s_o` and forwards the
//! request upstream. R polls `GET /op/{op_id}` to retrieve the response.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::audit::{self, ApprovalRow, STATUS_ALLOWED};
use crate::error::{AppError, Result};
use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
use crate::server::handlers::op::validate_vault_id;
use crate::service::UpstreamDef;
use crate::state::{ApprovalEvent, AppState};
use uuid::Uuid;

/// Variant for the no-rest URL (`POST /v/{vid}/use/{service}`). Lets a
/// service whose [[api]] is path = "*" be called with no sub-path —
/// agent just hits the service root.
pub async fn handle_no_rest(
    state: State<Arc<AppState>>,
    addr: ConnectInfo<std::net::SocketAddr>,
    method: Method,
    Path((vault_id, service)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    handle_impl(state, addr, method, vault_id, service, String::new(), headers, body).await
}

pub async fn handle(
    state: State<Arc<AppState>>,
    addr: ConnectInfo<std::net::SocketAddr>,
    method: Method,
    Path((vault_id, service, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    handle_impl(state, addr, method, vault_id, service, rest, headers, body).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_impl(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    method: Method,
    vault_id: String,
    service: String,
    rest: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    validate_vault_id(&vault_id)?;

    // Locked-state gate (H3 / PROTOCOL.md §6.3). When the vault is Locked,
    // /use rejects without creating a pending op — agent must trigger an
    // unlock ceremony first. Future: dispatch the service's `[upstream.locked]
    // response` template here so the agent gets a service-shaped error.
    if state.is_vault_locked(&vault_id) {
        return Err(AppError::Conflict("vault locked — unlock first".into()));
    }

    // Service lookup.
    let svc = state
        .services
        .get(&service)
        .ok_or(AppError::NotFound)?;
    let upstream = svc.upstream.first().ok_or_else(|| {
        AppError::Conflict(format!("service '{}' has no upstream defined", service))
    })?;

    // Resolve the bare item name this upstream needs (v3 store-order
    // resolution happens daemon-side at execute-use time).
    let target = resolve_vault_target(upstream).unwrap_or_else(|| "unknown".to_string());

    // Capture request headers (excluding hop-by-hop) for replay or cache fast-path.
    let mut headers_map = serde_json::Map::new();
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop(name) {
            continue;
        }
        if let Ok(s) = v.to_str() {
            headers_map.insert(name.to_string(), Value::String(s.to_string()));
        }
    }

    // H3 cache fast-path: if the unlock ceremony already bootstrapped this
    // service's auth into secrets_cache, skip the approval flow entirely and
    // forward synchronously. Cache presence implies `allow`-policy at the
    // service-default level; per-rule overrides aren't evaluated yet here
    // (Phase 2 — see project_protocol_md_review §6.4 specificity scoring).
    if let Some(cached_secret) = state.cache_lookup(&vault_id, &service) {
        let path_str = format!("/{}", rest);
        let header_pairs: Vec<(String, String)> = headers_map
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        let body_vec = body.to_vec();
        let response = crate::server::broker::forward_to_upstream(
            &cached_secret,
            &upstream.url,
            method.as_str(),
            &path_str,
            header_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            body_vec,
            Some(&target),
        )
        .await?;
        // Audit: synthetic `allowed` row — no ApprovalRecord ever existed for
        // this forward (cache-hit bypassed the whole approval flow). created_at
        // == decided_at; credential_id == None (no passkey gesture happened).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Ok(store) = state.audits.for_tenant(&vault_id) {
            let row = ApprovalRow {
                id: Uuid::new_v4().to_string(),
                created_at: now,
                decided_at: Some(now),
                expires_at: now,
                status: STATUS_ALLOWED.into(),
                act_kind: "use".into(),
                service: Some(service.clone()),
                method: Some(method.as_str().to_string()),
                path: Some(path_str.clone()),
                target: Some(target.clone()),
                reason: None,
                credential_id: None,
                upstream_status: Some(response.status as i64),
            };
            if let Err(e) = store.insert(&row) {
                tracing::warn!(vault = %vault_id, "audit insert allowed (cache-hit) failed: {}", e);
            }
        }
        // Same response shape the agent sees when polling /op/{id} after a
        // cache-miss approval — `{ status, ok, response: BrokerResponse }`
        // — so the skill can handle 200-immediate and 202-then-poll uniformly.
        return Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "ok": true,
                "act": "use",
                "response": serde_json::to_value(&response).unwrap_or(Value::Null),
            })),
        ));
    }

    let body_b64 = STANDARD.encode(&body);

    let scope = json!({
        "service": service,
        "upstream_id": upstream.id,
        "upstream_url": upstream.url,
        "method": method.as_str(),
        "path": format!("/{}", rest),
        "headers": Value::Object(headers_map),
        "body": body_b64,
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let op = Operation {
        act: Act {
            kind: ActType::Use,
            target,
            scope,
        },
        bind: Bind {
            redeemer: vault_id.clone(),
            recipient: None,
        },
        valid: Valid::single_use(now, Some(now + 300)), // 5-minute pending TTL; matches ApprovalStore.
    };

    let ip: IpAddr = addr.ip();
    let r = {
        let mut store = state.challenges.lock().unwrap();
        store.issue(ip).ok_or(AppError::TooManyRequests)?
    };
    let (op_id, expires_at) = {
        let mut store = state.approvals.lock().unwrap();
        let id = store.create(vault_id.clone(), op.clone(), r.clone());
        let exp = store.get(&id).map(|r| r.expires_at_unix).unwrap_or(0);
        (id, exp)
    };

    // Persist `pending` audit row (mirror of op.rs::create path; this is the
    // /use sugar variant that wraps op-create internally).
    if let Ok(audit_store) = state.audits.for_tenant(&vault_id) {
        let row = audit::row_from_op(&op_id, &op, now as i64, expires_at as i64);
        if let Err(e) = audit_store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending (use) failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        tenant_id: vault_id,
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending_approval",
            "op_id": op_id,
            "r": r,
            "expires_at": expires_at,
            "approve_url": format!("/op/{}", op_id),
            "poll_url": format!("/op/{}", op_id),
        })),
    ))
}

fn resolve_vault_target(upstream: &UpstreamDef) -> Option<String> {
    let auth = upstream.auth.as_ref()?;
    // Preferred path: explicit `auth.env = "key"` in service.toml. In v3
    // the value of this field IS the bare item name (no `env.` prefix).
    if let Some(key) = auth.env.as_deref() {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    // Fallback: legacy `placeholder = "{{ env.key }}"` template. Kept so
    // unmigrated services still work; the `env.` prefix in the template
    // is part of dev-branch syntax and is stripped here.
    let placeholder = auth.placeholder.as_ref()?;
    extract_env_template(placeholder)
}

fn extract_env_template(s: &str) -> Option<String> {
    let start = s.find("{{")?;
    let end = s[start..].find("}}")?;
    let inner = s[start + 2..start + end].trim();
    let env_key = inner.strip_prefix("env.")?.trim();
    if env_key.is_empty() {
        return None;
    }
    Some(env_key.to_string())
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_env_simple() {
        assert_eq!(
            extract_env_template("{{ env.demo_api_key }}"),
            Some("demo_api_key".to_string())
        );
    }

    #[test]
    fn extract_env_no_spaces() {
        assert_eq!(
            extract_env_template("{{env.token}}"),
            Some("token".to_string())
        );
    }

    #[test]
    fn extract_env_missing() {
        assert_eq!(extract_env_template("literal-token"), None);
        assert_eq!(extract_env_template("{{not_env.x}}"), None);
        assert_eq!(extract_env_template("{{ env. }}"), None);
    }
}
