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
pub async fn execute_use_forward(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &SealedVault,
    services: &crate::service::ServiceRegistry,
) -> Result<BrokerResponse> {
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

    forward_to_upstream_with_extras(
        &s_o,
        upstream_url,
        method_str,
        path,
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        body_bytes,
        Some(op.act.target.as_str()),
        if tpl_headers.is_empty() { None } else { Some(&tpl_headers) },
        if tpl_query.is_empty() { None } else { Some(&tpl_query) },
    )
    .await
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
