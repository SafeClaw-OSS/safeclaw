//! Broker flow helpers that outlive the retired `/use`+`/stream` ingress.
//!
//! The resident phantom-only proxy (S2) calls into these from its request
//! pipeline: register a pending approval op, answer a pending client, scrub
//! hop-by-hop headers, and mint an oauth2 access token. Keeping them in one
//! surviving module is what lets the v3 `broker.rs` template engine and the
//! `/use`+`/stream` handlers be deleted without stranding the reusable core.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::audit;
use crate::error::{AppError, Result};
use crate::protocol::Operation;
use crate::state::{ApprovalEvent, AppState};

/// The daemon's shared outbound HTTP client (redirect policy = none). Re-exported
/// here so the proxy pipeline has one obvious home for it.
pub use crate::core::forward::HTTP_CLIENT;

/// A hop-by-hop header (RFC 7230 §6.1) that must never be forwarded verbatim.
pub fn is_hop_by_hop(name_lc: &str) -> bool {
    matches!(
        name_lc,
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

/// The 202 "pending" body the proxy returns to a JSON-capable client: op id,
/// challenge `r`, the human approve link, and the poll url + pacing hints.
pub fn pending_202(op_id: &str, r: &str, expires_at: u64) -> axum::response::Response {
    use axum::response::IntoResponse;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let interval = crate::approval::store::POLL_INTERVAL_HINT_SECS;
    let mut resp = (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending",
            "op_id": op_id,
            "r": r,
            "approval": {
                "id": op_id,
                "approve_url": crate::cli::active::grant_url(op_id),
                "poll_url": format!("/op/{}", op_id),
                "expires_at": expires_at,
                "expires_in": expires_at.saturating_sub(now),
                "interval": interval,
            },
        })),
    )
        .into_response();
    let h = resp.headers_mut();
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("/op/{}", op_id)) {
        h.insert(axum::http::header::LOCATION, v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&interval.to_string()) {
        h.insert(axum::http::header::RETRY_AFTER, v);
    }
    resp
}

/// Shared tail of the Use pending-op flow: issue the challenge `r`, create the
/// `ApprovalRecord` (stamped with the policy context the approve handler reads
/// for its cache write), persist the `pending` audit row, register with the
/// cloud op-relay, and emit the `pending` SSE event. Returns
/// `(op_id, r, expires_at)`. Ingress-agnostic by design — the proxy compiles an
/// `authorize_only` Use `Operation` and funnels it through here.
pub fn register_pending_use(
    state: &Arc<AppState>,
    vault_id: &str,
    op: Operation,
    policy_context: Option<crate::approval::PolicyContext>,
    ip: IpAddr,
) -> Result<(String, String, u64)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let r = {
        let mut store = state.challenges.lock().unwrap();
        store.issue(ip).ok_or(AppError::TooManyRequests)?
    };

    let (op_id, expires_at) = {
        let mut store = state.approvals.lock().unwrap();
        let id =
            store.create_with_policy(vault_id.to_string(), op.clone(), r.clone(), policy_context);
        let exp = store.get(&id).map(|rec| rec.expires_at_unix).unwrap_or(0);
        (id, exp)
    };

    if let Ok(audit_store) = state.audits.for_vault(vault_id) {
        let row = audit::row_from_op(&op_id, &op, now as i64, expires_at as i64);
        if let Err(e) = audit_store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending (use) failed: {}", e);
        }
    }

    crate::relay::client::spawn_register_and_poll(
        state.clone(),
        vault_id.to_string(),
        op_id.clone(),
        serde_json::to_value(&op).unwrap_or(Value::Null),
        r.clone(),
        expires_at,
    );

    state.emit_event(ApprovalEvent {
        vault_id: vault_id.to_string(),
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok((op_id, r, expires_at))
}

/// Resolve the credential value the proxy injects for a phantom before egress.
/// For a direct service this is a no-op (returns the stored bytes). For an
/// `[oauth2]` service the `raw` bytes are the refresh token, not the access
/// token the upstream wants: exchange them at the provider's `/token` endpoint
/// (or reuse a still-valid cached access token) and return the fresh access
/// token. The access-token cache lives on `AppState::oauth_access`, keyed by
/// connection (never persisted). On `invalid_grant` the connection is flagged
/// needs-reauth and an `Unauthorized` propagates.
pub async fn resolve_auth_value(
    state: &crate::state::AppState,
    vault_id: &str,
    conn_id: &str,
    service_id: &str,
    raw: &[u8],
) -> Result<Vec<u8>> {
    let oauth = state.services.get(service_id).and_then(|s| s.oauth2.clone());
    let Some(oauth) = oauth else {
        return Ok(raw.to_vec());
    };

    // Cache hit — keyed by connection so two accounts of one service don't collide.
    if let Some(cached) = state.oauth_access_lookup(vault_id, conn_id) {
        return Ok(cached);
    }

    let resolved = state.services.resolve_oauth_config(&oauth);
    let token_url = resolved.token_url.as_deref().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but its provider has no token_url",
            service_id
        ))
    })?;
    let client_id = resolved.client_id.clone().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but its provider has no client_id",
            service_id
        ))
    })?;
    let client_secret = resolved.client_secret.clone();

    let refresh_token_str = std::str::from_utf8(raw).map_err(|_| {
        AppError::Internal(format!("oauth2 refresh_token for '{}' not utf-8", service_id))
    })?;
    let style = state.services.provider_oauth_style(&oauth.provider);

    let (access_token, expires_at) = crate::auth::oauth2::perform_refresh(
        token_url,
        &client_id,
        client_secret.as_deref(),
        refresh_token_str,
        style,
    )
    .await
    .map_err(|e| {
        tracing::warn!(vault = %vault_id, service = %service_id, "oauth2 refresh failed: {}", e);
        if e.contains("invalid_grant") {
            state.oauth_mark_reauth(vault_id, conn_id);
            AppError::Unauthorized(format!("oauth2 refresh_token invalid — reconnect {}", service_id))
        } else {
            AppError::Internal(format!("oauth2 refresh failed: {}", e))
        }
    })?;

    state.oauth_clear_reauth(vault_id, conn_id);
    let safe_expires_at = expires_at.saturating_sub(60);
    state.oauth_access_insert(vault_id, conn_id, access_token.as_bytes().to_vec(), safe_expires_at);
    Ok(access_token.into_bytes())
}
