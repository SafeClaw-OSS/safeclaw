//! Broker (Use) post-confirm execution.
//!
//! After `/approve/{id}/confirm` validates the user's passkey-signed grant
//! and the act is `ActType::Use`, this module:
//!   1. Constructs a `sudp::RedeemedGrant` from the validated safeclaw
//!      `ValidatedGrant` data.
//!   2. Calls `sudp::phases::consumption::execute_use<StdPrimitives>` to
//!      recover `s_o` (the secret bytes) for `act.target`.
//!   3. Builds the upstream HTTP request from `act.scope` (method, path,
//!      headers, body, upstream_url) and injects `s_o` into the auth header.
//!   4. Sends the upstream call and packages the response as a JSON object
//!      `{status, headers, body}` to be cached on the ApprovalRecord.
//!
//! Auth injection is bearer-only for now (covers the demo service +
//! github/openai/anthropic). Phase 3b.M follow-up will add basic / custom-
//! header / query-param variants by reading the service registry.

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sudp::grant::{GrantOpt, RedeemedGrant, WrappingKey};
use sudp::phases::consumption::open;
use sudp::primitives::StdPrimitives;

use crate::core::forward::HTTP_CLIENT;
use crate::error::{AppError, Result};
use crate::protocol::Operation;
use crate::storage::plaintext::VaultPlaintextView;
use crate::storage::SealedVault;

/// JSON-friendly upstream response packaged into the ApprovalRecord's
/// cached_value. Agent polls and gets this back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerResponse {
    pub status: u16,
    pub headers: Map<String, Value>,
    /// Response body. UTF-8 when possible, otherwise base64-encoded raw bytes
    /// with a `__base64__: true` marker alongside.
    pub body: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub body_base64: bool,
}

/// Run the cache-miss /use forwarder. Opens the vault, resolves the
/// requested item through the v3 store_order (so native-secrets *or*
/// external stores like GCP can back it), and forwards the captured
/// agent request to the upstream.
///
/// The grant has already been verified (β, assertion, freshness) by
/// `validate_grant` earlier in the call path; one-shot consumption is
/// enforced at the ApprovalRecord level (status flip to `Consumed`),
/// not by the sudp type system here.
/// Returned alongside the broker's HTTP response so the approve_op
/// handler can populate the secrets_cache for ask/allow paths (per
/// PROTOCOL.md §6.2). The bytes here are the resolved `s_o` —
/// scoped to the caller, which decides whether to cache them or
/// drop them on the floor (ask-always case).
pub struct UseForwardOutcome {
    pub response: BrokerResponse,
    pub s_o: Vec<u8>,
}

pub async fn execute_use_forward(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &SealedVault,
    state: &crate::state::AppState,
    vault_id: &str,
) -> Result<UseForwardOutcome> {
    let services = &state.services;
    let redeemed = RedeemedGrant {
        o: op.clone(),
        credential_id: credential_id_bytes.to_vec(),
        wrapping_key: WrappingKey::from_bytes(wrapping_key.to_vec()),
        opt: GrantOpt::default(),
    };
    let opened = open::<StdPrimitives>(&redeemed, vault)
        .map_err(|e| AppError::Unauthorized(format!("vault open: {}", e)))?;
    let view = VaultPlaintextView::from_protected_state(&opened.m)?;
    let s_o = view
        .resolve_value_async(&op.act.target)
        .await?
        .ok_or_else(|| {
            AppError::NotFound
        })?;

    // Extract request payload from the operation's scope.
    let scope = &op.act.scope;
    let upstream_url = scope
        .get("upstream_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Use scope missing upstream_url".into()))?;
    let method_str = scope
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET");
    let path = scope.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let body_b64 = scope.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let body_bytes = STANDARD
        .decode(body_b64)
        .map_err(|_| AppError::BadRequest("Use scope.body not base64".into()))?;

    let headers: Vec<(String, String)> = scope
        .get("headers")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // Look up the upstream config (headers/query templates) from the
    // service registry — these are the "modern" injection shape. Falls
    // back to bearer-only injection inside `forward_to_upstream_with_extras`
    // when the maps are empty.
    let service_id = scope.get("service").and_then(|v| v.as_str()).unwrap_or("");
    let upstream_id = scope
        .get("upstream_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let (tpl_headers, tpl_query) = services
        .get(service_id)
        .and_then(|svc| svc.upstream.iter().find(|u| u.id == upstream_id))
        .map(|u| (u.headers.clone(), u.query.clone()))
        .unwrap_or_default();

    // OAuth2 services: exchange the refresh_token (`s_o`) for a fresh
    // access_token via the provider's /token endpoint before forwarding.
    // No-op for non-oauth services (returns s_o unchanged).
    let auth_value = resolve_auth_value(state, vault_id, service_id, &s_o).await?;

    let response = forward_to_upstream_with_extras(
        &auth_value,
        upstream_url,
        method_str,
        path,
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        body_bytes,
        Some(op.act.target.as_str()),
        if tpl_headers.is_empty() { None } else { Some(&tpl_headers) },
        if tpl_query.is_empty() { None } else { Some(&tpl_query) },
    )
    .await?;
    // Return the raw `s_o` (refresh_token for oauth2 services, the
    // bearer for others) so the caller can cache it per policy TTL —
    // the access_token is cached separately in `state.oauth_access`.
    Ok(UseForwardOutcome { response, s_o })
}

/// Render an upstream-config template string by substituting the supported
/// `{{…}}` placeholders with values derived from `s_o`. Supported tokens:
///   - `{{auth_value}}`           — `s_o` as UTF-8
///   - `{{auth_value_b64}}`       — `base64(s_o)`
///   - `{{auth_value_basic}}`     — `base64(s_o + ':')`, the Stripe basic-auth shape
/// Unknown tokens pass through unchanged so future extensions stay safe.
fn render_upstream_template(tpl: &str, s_o: &[u8]) -> String {
    let mut out = String::with_capacity(tpl.len());
    let mut i = 0;
    let bytes = tpl.as_bytes();
    while i < bytes.len() {
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"{{" {
            if let Some(end) = tpl[i + 2..].find("}}") {
                let key = tpl[i + 2..i + 2 + end].trim();
                let replacement: Option<String> = match key {
                    "auth_value" => String::from_utf8(s_o.to_vec()).ok(),
                    "auth_value_b64" => Some(STANDARD.encode(s_o)),
                    "auth_value_basic" => {
                        let mut buf = s_o.to_vec();
                        buf.push(b':');
                        Some(STANDARD.encode(&buf))
                    }
                    _ => None,
                };
                if let Some(v) = replacement {
                    out.push_str(&v);
                    i += 2 + end + 2;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Resolve the auth value for a service before forwarding. For most
/// services this is a no-op (returns the input bytes — the bearer
/// stored in `cache.entries`). For oauth2 services, the `raw` bytes
/// are the *refresh_token*, not the access_token the upstream wants:
/// we exchange them at the provider's /token endpoint (or use a
/// cached access_token if one is still valid) and return the fresh
/// access_token.
///
/// The access_token cache lives on `AppState::oauth_access` keyed by
/// service — derived state, never persisted to vault. Cache hits
/// have ~60s safety margin so we don't hand the upstream a token
/// that's about to expire mid-request.
///
/// Errors propagate from `auth::oauth2::perform_refresh` — caller
/// can inspect for `invalid_grant` to mark the connection
/// needs-reauth (Stage 5 wires the UI; the daemon just logs warn
/// for now).
pub async fn resolve_auth_value(
    state: &crate::state::AppState,
    vault_id: &str,
    service_id: &str,
    raw: &[u8],
) -> Result<Vec<u8>> {
    let svc = state.services.get(service_id);
    let auth = svc
        .and_then(|s| s.upstream.first())
        .and_then(|u| u.auth.as_ref());
    let is_oauth = matches!(auth.and_then(|a| a.auth_type.as_deref()), Some("oauth2"));
    if !is_oauth {
        return Ok(raw.to_vec());
    }
    let auth = auth.expect("oauth2 branch implies auth present");

    // Cache hit — return the cached access_token directly.
    if let Some(cached) = state.oauth_access_lookup(vault_id, service_id) {
        return Ok(cached);
    }

    // Cache miss → call provider's /token endpoint to mint a fresh
    // access_token from our refresh_token.
    let token_url = auth.token_url.as_deref().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but missing auth.token_url",
            service_id
        ))
    })?;
    let client_id_env = auth.client_id_env.as_deref().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but missing auth.client_id_env",
            service_id
        ))
    })?;
    let client_id = std::env::var(client_id_env).map_err(|_| {
        AppError::Internal(format!(
            "oauth2 client_id env var '{}' not set (required by service '{}')",
            client_id_env, service_id
        ))
    })?;
    // client_secret is optional — PKCE flows (OpenAI Codex / Anthropic)
    // omit `client_secret_env`; confidential clients (Google) supply it.
    let client_secret = auth
        .client_secret_env
        .as_deref()
        .and_then(|n| std::env::var(n).ok());

    let refresh_token_str = std::str::from_utf8(raw).map_err(|_| {
        AppError::Internal(format!(
            "oauth2 refresh_token for '{}' not utf-8",
            service_id
        ))
    })?;
    let style = match auth.oauth_style.as_deref() {
        Some("json") => crate::auth::oauth2::OAuthStyle::Json,
        _ => crate::auth::oauth2::OAuthStyle::Form,
    };

    let (access_token, expires_at) = crate::auth::oauth2::perform_refresh(
        token_url,
        &client_id,
        client_secret.as_deref(),
        refresh_token_str,
        style,
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            vault = %vault_id, service = %service_id,
            "oauth2 refresh failed: {}", e,
        );
        // `invalid_grant` means refresh_token itself is dead — needs
        // user re-consent. Propagate as Unauthorized so the agent's
        // 4xx response cleanly distinguishes "auth gone" from
        // "upstream down".
        if e.contains("invalid_grant") {
            AppError::Unauthorized(format!("oauth2 refresh_token invalid — reconnect {}", service_id))
        } else {
            AppError::Internal(format!("oauth2 refresh failed: {}", e))
        }
    })?;

    // Cache with 60s safety margin so the next request mid-window
    // doesn't grab a near-expired token.
    let safe_expires_at = expires_at.saturating_sub(60);
    state.oauth_access_insert(
        vault_id,
        service_id,
        access_token.as_bytes().to_vec(),
        safe_expires_at,
    );
    Ok(access_token.into_bytes())
}

/// Forward an agent request to an upstream service with `s_o` injected
/// according to the service's auth shape. Default (no template config)
/// stays at the historical bearer-only injection; `extra_headers` and
/// `extra_query` come from `UpstreamDef.headers` / `UpstreamDef.query` —
/// the escape hatch for non-bearer shapes (Stripe basic, AWS signed
/// query, GitHub `token`, etc.). Either path runs after the request-level
/// hop-by-hop scrub.
pub async fn forward_to_upstream<'a>(
    s_o: &[u8],
    upstream_url: &str,
    method_str: &str,
    path: &str,
    headers_iter: impl IntoIterator<Item = (&'a str, &'a str)>,
    body_bytes: Vec<u8>,
    target_for_log: Option<&str>,
) -> Result<BrokerResponse> {
    forward_to_upstream_with_extras(
        s_o,
        upstream_url,
        method_str,
        path,
        headers_iter,
        body_bytes,
        target_for_log,
        None,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn forward_to_upstream_with_extras<'a>(
    s_o: &[u8],
    upstream_url: &str,
    method_str: &str,
    path: &str,
    headers_iter: impl IntoIterator<Item = (&'a str, &'a str)>,
    body_bytes: Vec<u8>,
    target_for_log: Option<&str>,
    extra_headers: Option<&std::collections::HashMap<String, String>>,
    extra_query: Option<&std::collections::HashMap<String, String>>,
) -> Result<BrokerResponse> {
    // Append query params from the upstream template (if any) onto `path`.
    // We don't try to deduplicate against query already in `path` — the
    // caller is responsible for not double-supplying.
    let path_with_query = match extra_query.filter(|m| !m.is_empty()) {
        Some(q) => {
            let extra = q
                .iter()
                .map(|(k, v)| {
                    let rendered = render_upstream_template(v, s_o);
                    format!(
                        "{}={}",
                        urlencoding::encode(k),
                        urlencoding::encode(&rendered)
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            if path.contains('?') {
                format!("{}&{}", path, extra)
            } else {
                format!("{}?{}", path, extra)
            }
        }
        _ => path.to_string(),
    };
    // URL itself may carry a template — e.g. Telegram's Bot API puts the
    // token in the URL path: `https://api.telegram.org/bot{{auth_value}}`.
    // Render with the same engine that handles headers/query templates so
    // the user/service author has one consistent placeholder vocabulary.
    let url_rendered = render_upstream_template(upstream_url, s_o);
    let full_url = format!(
        "{}{}",
        url_rendered.trim_end_matches('/'),
        path_with_query
    );
    let reqwest_method = reqwest::Method::from_str(method_str)
        .map_err(|_| AppError::BadRequest(format!("unsupported method: {}", method_str)))?;

    let mut headers = reqwest::header::HeaderMap::new();
    // Strip headers the upstream-template path is going to set itself
    // (otherwise the agent's incoming Authorization would shadow our
    // intentional override). When `extra_headers` is empty we use the
    // historical scrub list.
    let template_keys: std::collections::HashSet<String> = extra_headers
        .map(|m| m.keys().map(|k| k.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    for (k, v) in headers_iter {
        let lc = k.to_ascii_lowercase();
        if matches!(
            lc.as_str(),
            "authorization"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "x-api-key"
        ) || template_keys.contains(&lc)
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_str(k),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            headers.insert(hn, hv);
        }
    }

    // Auth injection. New shape: per-upstream header templates win when
    // present (escape hatch for non-bearer schemes). Legacy fallback:
    // hardcoded `Authorization: Bearer s_o`.
    if let Some(tpl_headers) = extra_headers.filter(|m| !m.is_empty()) {
        for (k, v) in tpl_headers {
            let rendered = render_upstream_template(v, s_o);
            if let (Ok(hn), Ok(hv)) = (
                reqwest::header::HeaderName::from_str(k),
                reqwest::header::HeaderValue::from_str(&rendered),
            ) {
                headers.insert(hn, hv);
            }
        }
    } else {
        let bearer_token = String::from_utf8(s_o.to_vec())
            .map_err(|_| AppError::Internal("s_o not utf8".into()))?;
        if let Ok(hv) =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", bearer_token))
        {
            headers.insert(reqwest::header::AUTHORIZATION, hv);
        }
    }

    tracing::info!(
        target = target_for_log.unwrap_or(""),
        method = %method_str,
        url = %full_url,
        "broker forward"
    );

    let resp = HTTP_CLIENT
        .request(reqwest_method, &full_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("upstream send: {}", e)))?;

    let status = resp.status().as_u16();
    let mut resp_headers = Map::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(s) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), Value::String(s.to_string()));
        }
    }
    let resp_bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("upstream body read: {}", e)))?;

    let (body, body_base64) = match std::str::from_utf8(&resp_bytes) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (STANDARD.encode(&resp_bytes), true),
    };

    Ok(BrokerResponse {
        status,
        headers: resp_headers,
        body,
        body_base64,
    })
}
