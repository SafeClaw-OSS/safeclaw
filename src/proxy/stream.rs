//! Generic streaming reverse-proxy passthrough.
//!
//! `ANY /v/{vid}/stream/{service}/{*rest}` forwards the agent's request to the
//! service's upstream with credentials injected, streaming BOTH the request and
//! response bodies (no buffering). Built for transports like git's smart-HTTP,
//! where a single packfile can be hundreds of MB. The daemon does **not**
//! interpret the protocol — it injects auth and forwards verbatim, so this one
//! route serves git (and any future raw transport) generically.
//!
//! Transparent cooperation, not interception: the agent reaches this knowingly
//! (e.g. it configured `git insteadOf` at connect time pointing here), so there
//! is no per-request passkey ceremony. It is gated to **allow-policy, streaming-
//! opted-in** services whose credential is already resident in the unlocked
//! cache; anything else is rejected (never silently proxied).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};

use crate::core::forward::HTTP_CLIENT;
use crate::core::policy::AccessLevel;
use crate::error::{AppError, Result};
use crate::server::broker::{render_template, RenderInputs};
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;

pub async fn handle(
    State(state): State<Arc<AppState>>,
    method: Method,
    Path((vault_id, service, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> Result<Response> {
    validate_vault_id(&vault_id)?;

    if state.is_vault_locked(&vault_id) {
        return Err(AppError::Conflict("vault locked — unlock first".into()));
    }

    let svc = state.services.get(&service).ok_or(AppError::NotFound)?;
    // Pick the streaming upstream. A service may carry several upstreams — e.g.
    // `github` has a `rest` upstream (REST API, /use/) and a `git` upstream
    // (smart-HTTP, /stream/) sharing one credential — so select by `stream`,
    // not position. No streaming upstream ⇒ this service isn't reachable here.
    let upstream = svc
        .upstream
        .iter()
        .find(|u| u.stream)
        .ok_or_else(|| {
            AppError::Conflict(format!(
                "service '{}' has no streaming-passthrough upstream",
                service
            ))
        })?;

    // Streaming bypasses the per-request approval ceremony, so it is gated to
    // allow-policy services only — the credential must already be resident in
    // the unlocked cache (bootstrapped at unlock for allow services). ask /
    // ask-always / deny never reach here.
    if state.services.default_read_level(&service) != AccessLevel::Allow {
        return Err(AppError::Forbidden(format!(
            "streaming requires an allow-policy service; '{}' is not allow",
            service
        )));
    }
    let cached = state.cache_lookup(&vault_id, &service).ok_or_else(|| {
        AppError::Conflict(format!(
            "no resident credential for '{}' — set it and unlock first",
            service
        ))
    })?;

    // Build the secret map for rendering the auth header(s). Prefer the
    // bootstrapped multi-secret map; fall back to a one-entry map keyed by the
    // primary item name.
    let primary = upstream
        .auth
        .as_ref()
        .and_then(|a| a.secret.as_deref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let secrets_map = state
        .cache_lookup_secrets(&vault_id, &service)
        .unwrap_or_else(|| {
            let mut m = HashMap::new();
            m.insert(primary.clone(), cached.clone());
            m
        });
    let inputs = RenderInputs {
        secrets: &secrets_map,
        oauth_access_token: None,
    };

    // Compose the upstream URL: <upstream.url>/<rest>[?query]. The upstream host
    // is a recipe literal (no templating in the authority — same SSRF stance as
    // the broker), so we don't re-render it here.
    let base = upstream.url.trim_end_matches('/');
    let mut full_url = format!("{}/{}", base, rest);
    if let Some(q) = uri.query() {
        full_url.push('?');
        full_url.push_str(q);
    }

    let reqwest_method = reqwest::Method::from_str(method.as_str())
        .map_err(|_| AppError::BadRequest(format!("unsupported method: {}", method)))?;

    // Forward the agent's headers (minus hop-by-hop and the ones we inject),
    // then write the rendered auth header(s) — replace-all-matching, so the
    // agent can't shadow our injected credential.
    let injected: HashSet<String> = upstream
        .headers
        .keys()
        .map(|k| k.to_ascii_lowercase())
        .collect();
    let mut out_headers = reqwest::header::HeaderMap::new();
    for (k, v) in headers.iter() {
        let lc = k.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lc) || lc == "authorization" || lc == "host" || injected.contains(&lc) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_str(k.as_str()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out_headers.insert(hn, hv);
        }
    }
    for (k, tpl) in &upstream.headers {
        let rendered = render_template(tpl, &inputs)?;
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_str(k),
            reqwest::header::HeaderValue::from_str(&rendered),
        ) {
            out_headers.insert(hn, hv);
        }
    }

    tracing::info!(service = %service, method = %method, url = %full_url, "stream forward");

    // Stream the request body upstream (no buffering).
    let reqwest_body = reqwest::Body::wrap_stream(body.into_data_stream());
    let resp = HTTP_CLIENT
        .request(reqwest_method, &full_url)
        .headers(out_headers)
        .body(reqwest_body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("upstream stream send: {}", e)))?;

    // Stream the response back.
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers().iter() {
        if is_hop_by_hop(&k.as_str().to_ascii_lowercase()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from_stream(resp.bytes_stream()))
        .map_err(|e| AppError::Internal(format!("stream response build: {}", e)))
}

fn is_hop_by_hop(name_lc: &str) -> bool {
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
            | "content-length"
    )
}
