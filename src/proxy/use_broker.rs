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

use crate::error::{AppError, Result};
use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
use crate::server::handlers::op::validate_vault_id;
use crate::service::UpstreamDef;
use crate::state::{ApprovalEvent, AppState};

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

    // Service lookup.
    let svc = state
        .services
        .get(&service)
        .ok_or(AppError::NotFound)?;
    let upstream = svc.upstream.first().ok_or_else(|| {
        AppError::Conflict(format!("service '{}' has no upstream defined", service))
    })?;

    // Resolve vault target from auth template `{{ env.X }}`.
    let target = resolve_vault_target(upstream).unwrap_or_else(|| "env.unknown".to_string());

    // Capture request headers (excluding hop-by-hop) for replay.
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
    // Preferred path: explicit `auth.env = "key"` in service.toml.
    if let Some(key) = auth.env.as_deref() {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            return Some(format!("env.{}", trimmed));
        }
    }
    // Fallback: legacy `placeholder = "{{ env.key }}"` template. Kept so
    // unmigrated services still work; remove once all service.toml files
    // use the explicit field.
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
    Some(format!("env.{}", env_key))
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
            Some("env.demo_api_key".to_string())
        );
    }

    #[test]
    fn extract_env_no_spaces() {
        assert_eq!(
            extract_env_template("{{env.token}}"),
            Some("env.token".to_string())
        );
    }

    #[test]
    fn extract_env_missing() {
        assert_eq!(extract_env_template("literal-token"), None);
        assert_eq!(extract_env_template("{{not_env.x}}"), None);
        assert_eq!(extract_env_template("{{ env. }}"), None);
    }
}
