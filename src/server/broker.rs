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
use sudp::primitives::StdPrimitives;

use crate::core::forward::HTTP_CLIENT;
use crate::error::{AppError, Result};
use crate::protocol::Operation;
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

/// Run Phase III.1 (execute_use) for the validated Use grant and forward the
/// captured agent request to the upstream service. Cache-miss path — used
/// when the secret isn't already in the daemon's secrets_cache.
pub async fn execute_use_forward(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &SealedVault,
) -> Result<BrokerResponse> {
    // Re-assemble a sudp::RedeemedGrant from our ValidatedGrant fields. The
    // grant has already been verified (β, assertion, freshness) by
    // validate_grant earlier in the call path; this struct is the input
    // shape sudp's execute_use expects.
    let redeemed = RedeemedGrant {
        o: op.clone(),
        credential_id: credential_id_bytes.to_vec(),
        wrapping_key: WrappingKey::from_bytes(wrapping_key.to_vec()),
        opt: GrantOpt::default(),
    };

    // Pull bytes out of sudp's sealed boundary. The closure extracts the
    // owned Vec<u8>; the async forward happens after sudp's lifetime guard
    // returns, by design (we can't await inside an FnOnce, but the secret
    // is moved out under our explicit responsibility).
    let s_o: Vec<u8> =
        sudp::phases::consumption::execute_use::<StdPrimitives, _, _>(redeemed, vault, |_target, s_o| {
            Ok(s_o.to_vec())
        })
        .map_err(|e| AppError::Internal(format!("execute_use: {}", e)))?;

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

    forward_to_upstream(
        &s_o,
        upstream_url,
        method_str,
        path,
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        body_bytes,
        Some(op.act.target.as_str()),
    )
    .await
}

/// Forward an agent request to an upstream service with `s_o` injected as the
/// bearer token. Shared between the cache-miss (post-execute_use) and the
/// cache-hit (H3 fast-path) call sites. Caller is responsible for having
/// `s_o` legitimately — either freshly derived via sudp, or pulled from
/// secrets_cache after a verified unlock grant.
pub async fn forward_to_upstream<'a>(
    s_o: &[u8],
    upstream_url: &str,
    method_str: &str,
    path: &str,
    headers_iter: impl IntoIterator<Item = (&'a str, &'a str)>,
    body_bytes: Vec<u8>,
    target_for_log: Option<&str>,
) -> Result<BrokerResponse> {
    let full_url = format!("{}{}", upstream_url.trim_end_matches('/'), path);
    let reqwest_method = reqwest::Method::from_str(method_str)
        .map_err(|_| AppError::BadRequest(format!("unsupported method: {}", method_str)))?;

    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in headers_iter {
        let lc = k.to_ascii_lowercase();
        if matches!(
            lc.as_str(),
            "authorization"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "x-api-key"
        ) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_str(k),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            headers.insert(hn, hv);
        }
    }

    // Bearer injection. Future: read service auth_type and dispatch.
    let bearer_token =
        String::from_utf8(s_o.to_vec()).map_err(|_| AppError::Internal("s_o not utf8".into()))?;
    if let Ok(hv) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", bearer_token)) {
        headers.insert(reqwest::header::AUTHORIZATION, hv);
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
