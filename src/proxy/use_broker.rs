//! `/use/<service>/<path…>` — agent-facing broker (sudp `ActType::Use`).
//!
//! Flow:
//!
//! ```text
//! agent → ANY /use/<service>/<rest…>   (with X-Safeclaw-Tenant + payload)
//!     └─ no approval_id query → daemon creates approval (Operation kind=Use,
//!        scope carries method/path/headers/body for replay) → 202
//!        { approval_id, approve_url, poll_url }
//! agent → GET /use/poll?approval_id=<id>
//!     └─ status pending     → 202
//!     └─ status approved    → 200 { status, response: {status, headers, body} }
//!     └─ status rejected    → 403
//! ```
//!
//! Post-confirm execution (Phase 3b.6, not yet wired): the approval handler
//! calls `sudp::phases::consumption::execute_use` to inject `s_o` into the
//! captured request and forward upstream via `core::forward`. The response is
//! cached on the ApprovalRecord and surfaced on the next poll.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::approval::ApprovalStatus;
use crate::error::{AppError, Result};
use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
use crate::server::tenant_extractor::TenantId;
use crate::service::UpstreamDef;
use crate::state::{ApprovalEvent, AppState};

#[derive(Debug, Deserialize)]
pub struct PollQuery {
    pub approval_id: Option<String>,
}

/// `ANY /use/{service}/{*rest}` — broker entry.
///
/// On first call (no `?approval_id=...`) the daemon captures the request,
/// constructs an `ActType::Use` Operation, stores it as a pending approval,
/// and returns 202 with the approval id. The user authorizes via passkey at
/// `/approve/{id}` (admin port).
pub async fn handle(
    State(state): State<Arc<AppState>>,
    tenant: TenantId,
    method: Method,
    Path((service, rest)): Path<(String, String)>,
    Query(q): Query<PollQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    // If the agent is polling an existing approval, route to poll.
    if let Some(approval_id) = q.approval_id.as_deref() {
        return poll_inner(&state, approval_id).await;
    }

    let TenantId(tenant_id) = tenant;

    // Service lookup.
    let svc = state
        .services
        .get(&service)
        .ok_or_else(|| AppError::NotFound)?;
    let upstream = svc.upstream.first().ok_or_else(|| {
        AppError::Conflict(format!("service '{}' has no upstream defined", service))
    })?;

    // Resolve which vault target this service uses. We scan the upstream's
    // auth definition for a `{{ env.X }}` template; that X becomes the
    // Operation's `target`. Failing the resolve, the approval still goes
    // through but with target = "env.unknown" so Phase 3b.6 can surface the
    // misconfiguration cleanly.
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
            redeemer: tenant_id.clone(),
            recipient: None,
        },
        valid: Valid {
            iat: now,
            exp: Some(now + 300), // 5-minute pending TTL; matches ApprovalStore.
        },
    };

    let approval_id = {
        let mut store = state.approvals.lock().unwrap();
        store.create(tenant_id.clone(), op.clone())
    };

    // Emit pending event for any /try watcher tab on this tenant.
    state.emit_event(ApprovalEvent {
        tenant_id: tenant_id.clone(),
        approval_id: approval_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending_approval",
            "approval_id": approval_id,
            "approve_url": format!("/approve/{}", approval_id),
            "poll_url": format!("/use/poll?approval_id={}", approval_id),
        })),
    ))
}

/// `GET /use/poll?approval_id=<id>` — agent polling endpoint.
pub async fn poll(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PollQuery>,
) -> Result<(StatusCode, Json<Value>)> {
    let id = q
        .approval_id
        .ok_or_else(|| AppError::BadRequest("missing approval_id query param".into()))?;
    poll_inner(&state, &id).await
}

async fn poll_inner(state: &Arc<AppState>, approval_id: &str) -> Result<(StatusCode, Json<Value>)> {
    let mut store = state.approvals.lock().unwrap();
    let rec = store.get(approval_id).ok_or(AppError::NotFound)?.clone();
    match &rec.status {
        ApprovalStatus::Pending => Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "status": "pending", "approval_id": approval_id })),
        )),
        ApprovalStatus::Approved => {
            let value = store.consume(approval_id).ok_or_else(|| {
                AppError::Internal("approved but no cached value".into())
            })?;
            // For broker (Use), `cached_value` carries the JSON-serialized
            // upstream response (status + headers + body). Phase 3b.6 writes
            // that; until then, the value is the raw secret string from a
            // legacy reveal path.
            let parsed: Value = serde_json::from_str(&value)
                .unwrap_or_else(|_| Value::String(value));
            Ok((StatusCode::OK, Json(json!({ "status": "ok", "response": parsed }))))
        }
        ApprovalStatus::Rejected { reason } => Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "status": "rejected", "reason": reason })),
        )),
        ApprovalStatus::Consumed => Ok((
            StatusCode::GONE,
            Json(json!({ "status": "consumed" })),
        )),
    }
}

/// Extract `env.X` from an auth template `{{ env.X }}`. Returns `env.X` (the
/// full dotted target inside the vault's flat ProtectedState).
///
/// service.toml carries the placeholder on `[upstream.auth].placeholder`
/// (e.g. `placeholder = "{{ env.demo_api_key }}"`). The vault-side `secret`
/// field on the runtime AuthConfig is populated post-resolution.
fn resolve_vault_target(upstream: &UpstreamDef) -> Option<String> {
    let auth = upstream.auth.as_ref()?;
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
            | "x-safeclaw-tenant"
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
