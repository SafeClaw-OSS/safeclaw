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
//! (e.g. it configured `git insteadOf` at connect time pointing here).
//! `allow`-policy streaming services forward straight through (the credential is
//! resident in the unlocked cache from bootstrap). `ask` / `ask-always` services
//! can't pause a live stream for the 202+poll ceremony, so they use the
//! **captive-portal** pattern (docs/STREAMING_APPROVAL.md): reject-before-forward,
//! emit an approval link over SSE (the agent surfaces it), and let the agent
//! retry once the user taps their passkey — single-use for `ask-always`. `deny`
//! is refused.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, Path, State},
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
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    method: Method,
    Path((vault_id, connection, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> Result<Response> {
    validate_vault_id(&vault_id)?;

    if state.is_vault_locked(&vault_id) {
        return Err(AppError::VaultLocked);
    }

    // Resolve the connection → its service (recipe); for the default connection
    // `connection == service` (CONNECTION_SCHEMA.md §6).
    let service = state.resolve_connection_service(&vault_id, &connection);
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

    // Policy gate. A raw tool stream can't speak SafeClaw's 202+poll approval
    // dance, so for ask policies we use the captive-portal pattern
    // (docs/STREAMING_APPROVAL.md):
    //   - allow      → credential must be resident (bootstrapped at unlock).
    //   - ask        → reuse a prior approval within its TTL window; else prompt.
    //   - ask-always → single-use: burn the approval each stream (e.g. publish).
    //   - deny       → refuse.
    // On a miss we reject-before-forward (zero upstream side-effect) and fire the
    // approval ceremony: an SSE `pending` the agent surfaces as a link (plus the
    // link in this response). The agent re-runs the command once the user taps.
    let level = state.services.default_read_level(&service);
    let cached = match level {
        AccessLevel::Deny => {
            return Err(AppError::Forbidden(format!(
                "streaming blocked by policy (deny): '{}'",
                service
            )));
        }
        AccessLevel::Allow => state.cache_lookup(&vault_id, &connection).ok_or_else(|| {
            AppError::Conflict(format!(
                "no resident credential for '{}' — set it and unlock first",
                connection
            ))
        })?,
        AccessLevel::AskAlways => match state.cache_take(&vault_id, &connection) {
            Some(bytes) => bytes,
            None => {
                return stream_approval_required(
                    &state, &vault_id, &connection, &service, upstream, &method, &rest, &headers,
                    addr.ip(), level,
                )
                .await
            }
        },
        AccessLevel::Ask => match state.cache_lookup(&vault_id, &connection) {
            Some(bytes) => bytes,
            None => {
                return stream_approval_required(
                    &state, &vault_id, &connection, &service, upstream, &method, &rest, &headers,
                    addr.ip(), level,
                )
                .await
            }
        },
    };

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
        .cache_lookup_secrets(&vault_id, &connection)
        .unwrap_or_else(|| {
            let mut m = HashMap::new();
            m.insert(primary.clone(), cached.clone());
            m
        });
    // Runtime host-template guard (parity with the broker): the host may template
    // ONLY a declared `{{connection.<param>}}`; a `{{secret.*}}` in the authority
    // would leak a credential into the egress host. Defense in depth over the
    // load-time validator.
    if crate::proxy::use_broker::upstream_host_has_unsafe_template(upstream) {
        return Err(AppError::Conflict(format!(
            "service '{}' streaming upstream host is templated with a non-connection token — refusing to forward",
            service
        )));
    }
    let conn_config = state.connection_config(&vault_id, &connection);
    let inputs = RenderInputs {
        secrets: &secrets_map,
        oauth_access_token: None,
        connection: conn_config.as_ref(),
    };

    // Compose the upstream URL: <upstream.url>/<rest>[?query]. The host is a
    // recipe literal OR a declared `{{connection.host}}` slot (self-hosted forge);
    // render it with the same engine and SSRF-recheck the resolved host before
    // egress (CONNECTION_SCHEMA.md §4).
    let base = render_template(upstream.url.trim_end_matches('/'), &inputs)?;
    if let Some(authority) = base
        .split_once("://")
        .map(|(_, r)| r.split('/').next().unwrap_or(r))
    {
        if !crate::service::validate::host_egress_allowed(authority) {
            return Err(AppError::Forbidden(format!(
                "resolved egress host '{}' is loopback / private / link-local — refusing to forward",
                authority
            )));
        }
    }
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

/// Captive-portal approval for an `ask` / `ask-always` streamed op: compile a
/// body-less `Use` operation marked `scope.authorize_only`, register it through
/// the shared pending-use path (which emits the `pending` SSE the agent watches),
/// and reject this attempt with the approve link. The agent surfaces the link,
/// the user taps their passkey, and the retried stream finds the now-stashed
/// credential and forwards. Reject happens BEFORE any upstream call, so the
/// blocked attempt has zero side-effect and the retry is safe.
#[allow(clippy::too_many_arguments)]
async fn stream_approval_required(
    state: &Arc<AppState>,
    vault_id: &str,
    connection: &str,
    service: &str,
    upstream: &crate::service::UpstreamDef,
    method: &Method,
    rest: &str,
    headers: &HeaderMap,
    ip: std::net::IpAddr,
    level: AccessLevel,
) -> Result<Response> {
    use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};

    // The vault item this op authorizes: bare role → namespaced `[<conn>:]<role>`.
    let role = upstream
        .auth
        .as_ref()
        .and_then(|a| a.secret.as_deref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let target = crate::storage::plaintext::secret_address(connection, service, &role);

    // Honesty: every `{{secret.*}}` this op would release (for the approval card).
    let mut released = crate::server::broker::referenced_secrets(&upstream.url);
    for v in upstream.headers.values().chain(upstream.query.values()) {
        for n in crate::server::broker::referenced_secrets(v) {
            if !released.contains(&n) {
                released.push(n);
            }
        }
    }

    let mut headers_map = serde_json::Map::new();
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop(&name.to_ascii_lowercase()) {
            continue;
        }
        if let Ok(s) = v.to_str() {
            headers_map.insert(name.to_string(), serde_json::Value::String(s.to_string()));
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let scope = serde_json::json!({
        "connection_id": connection,
        "service": service,
        "upstream_id": upstream.id,
        "upstream_url": upstream.url,
        "method": method.as_str(),
        "path": format!("/{}", rest),
        "headers": serde_json::Value::Object(headers_map),
        // No body: the real request rides the retried stream, not this op.
        "secrets": released,
        // Marks the streaming captive-portal authorize op: on approve the daemon
        // resolves + stashes the secret for the retry stream but does NOT forward.
        "authorize_only": true,
        "stream": true,
    });
    let op = Operation {
        act: Act {
            kind: ActType::Use,
            target,
            scope,
        },
        bind: Bind {
            redeemer: vault_id.to_string(),
            recipient: None,
        },
        valid: Valid::single_use(now, Some(now + 300)),
    };

    // Streaming authorize grants always carry a policy context so the approve
    // handler stashes the resolved secret. The window bounds how long the user
    // has to re-run the command after tapping; `ask-always` then burns it
    // single-use on read (cache_take), `ask` reuses it within the window.
    let policy_context = Some(crate::approval::PolicyContext {
        level,
        rule_id: None,
        ttl_seconds: 300,
    });
    let (op_id, _r, _expires_at) =
        crate::proxy::use_broker::register_pending_use(state, vault_id, op, policy_context, ip)?;

    let approve_url = crate::cli::active::grant_url(&op_id);
    tracing::info!(service = %service, op = %op_id, "stream approval required (captive portal)");
    let body = format!(
        "SafeClaw approval required to use '{}'.\n\
         Approve with your passkey:\n  {}\n\
         Then re-run the same command.\n\
         (op_id: {})\n",
        service, approve_url, op_id
    );
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-safeclaw-approve-url", approve_url.as_str())
        .header("x-safeclaw-op-id", op_id.as_str())
        .body(Body::from(body))
        .map_err(|e| AppError::Internal(format!("approval response build: {}", e)))
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
