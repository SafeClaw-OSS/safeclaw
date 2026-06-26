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

use crate::audit::{self, ApprovalRow, STATUS_ALLOWED, STATUS_DENIED};
use crate::core::policy::AccessLevel;
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

    // Host-literal guard (anti-SSRF). The scheme+authority of an upstream URL
    // must be a constant: a `{{…}}` there could let a captured request — or a
    // malicious recipe — repoint the egress host. Templates are allowed only
    // in the path (e.g. Telegram's `/bot{{secret.telegram_bot_token}}`).
    if upstream_host_has_template(&upstream.url) {
        return Err(AppError::Conflict(format!(
            "service '{}' upstream host is templated — refusing to forward",
            service
        )));
    }

    // Resolve the bare item name this upstream needs (v3 store-order
    // resolution happens daemon-side at execute-use time).
    let target = resolve_vault_target(upstream).unwrap_or_else(|| "unknown".to_string());

    // Honesty: the full set of vault items this operation will release, so the
    // approval UI and audit show every secret — not just the primary `target`.
    // Scanned from the recipe's URL + header + query templates.
    let released_secrets = referenced_secret_names(upstream);

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

    // Per-request policy evaluation. Walks the user's merged rule list
    // (built-in policy.toml rules + sparse `rule_overrides` from
    // `aux.service_state`) under longest-match semantics, then falls back
    // to the user's category-level defaults, then to the daemon's safe
    // compiled defaults. `None` only when the vault entry is gone between
    // the lock check and here — should never happen but treat as locked.
    let path_for_eval = format!("/{}", rest);
    let body_text = std::str::from_utf8(&body).ok();
    let (level, matched_rule_id, level_ask_ttl) = state
        .evaluate_request_policy(
            &vault_id,
            &service,
            method.as_str(),
            &path_for_eval,
            body_text,
        )
        .ok_or_else(|| AppError::Conflict("vault locked — unlock first".into()))?;

    // Deny short-circuits: no upstream call, no pending op, agent gets 403
    // immediately. Audit row carries the resolved level so reviewers can
    // trace why the call was blocked.
    if level == AccessLevel::Deny {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Ok(store) = state.audits.for_vault(&vault_id) {
            let row = ApprovalRow {
                id: Uuid::new_v4().to_string(),
                created_at: now,
                decided_at: Some(now),
                expires_at: now,
                status: STATUS_DENIED.into(),
                act_kind: "use".into(),
                service: Some(service.clone()),
                method: Some(method.as_str().to_string()),
                path: Some(path_for_eval.clone()),
                target: Some(target.clone()),
                reason: Some("policy: deny".into()),
                credential_id: None,
                upstream_status: None,
            };
            let _ = store.insert(&row);
        }
        return Err(AppError::Forbidden(
            "blocked by policy (level=deny)".into(),
        ));
    }

    // Allow short-circuits straight to the cache fast-path if the bytes
    // are ready. Cache miss for an Allow request degrades to the pending-
    // op flow below — typical when the auth lives in an external store
    // that wasn't pre-resolved at unlock (e.g. GCP Secret Manager).
    if level == AccessLevel::Allow {
        if let Some(cached_secret) = state.cache_lookup(&vault_id, &service) {
        let path_str = format!("/{}", rest);
        let header_pairs: Vec<(String, String)> = headers_map
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        let body_vec = body.to_vec();
        // Build the v3 render inputs. OAuth2 services mint a fresh
        // access_token from the cached refresh_token (`cached_secret`) and
        // expose it as `{{oauth.access_token}}`. Non-oauth services render
        // their `{{secret.NAME}}` placeholders from the bootstrapped
        // allow-secrets map (full multi-secret set), falling back to a
        // one-entry map keyed by the primary item for recipes resolved
        // post-approval (no bootstrap entry).
        let is_oauth = upstream
            .auth
            .as_ref()
            .and_then(|a| a.auth_type.as_deref())
            == Some("oauth2");
        let (secrets_map, oauth_token) = if is_oauth {
            let access = crate::server::broker::resolve_auth_value(
                &state,
                &vault_id,
                &service,
                &cached_secret,
            )
            .await?;
            let token = String::from_utf8(access)
                .map_err(|_| AppError::Internal("oauth access_token not utf8".into()))?;
            (std::collections::HashMap::new(), Some(token))
        } else {
            let map = state
                .cache_lookup_secrets(&vault_id, &service)
                .unwrap_or_else(|| {
                    let mut m = std::collections::HashMap::new();
                    m.insert(target.clone(), cached_secret.clone());
                    m
                });
            (map, None)
        };
        let inputs = crate::server::broker::RenderInputs {
            secrets: &secrets_map,
            oauth_access_token: oauth_token.as_deref(),
        };
        let response = crate::server::broker::forward_to_upstream_with_extras(
            &inputs,
            &upstream.url,
            method.as_str(),
            &path_str,
            header_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            body_vec,
            Some(&target),
            if upstream.headers.is_empty() { None } else { Some(&upstream.headers) },
            if upstream.query.is_empty() { None } else { Some(&upstream.query) },
        )
        .await?;
        // Audit: synthetic `allowed` row — no ApprovalRecord ever existed for
        // this forward (cache-hit bypassed the whole approval flow). created_at
        // == decided_at; credential_id == None (no passkey gesture happened).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Ok(store) = state.audits.for_vault(&vault_id) {
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
        // Allow + cache miss falls through: pending op below will lazily
        // resolve via execute_use_forward (which walks store_order through
        // the adapter dispatch — works for GCP / 1P / etc.).
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
        // Full set of vault items this Use will release (for approval UI /
        // audit). Empty for oauth recipes (they release a minted access token
        // derived from the `target` refresh_token, not a `{{secret.*}}` item).
        "secrets": released_secrets,
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
    // Stamp the policy decision on the pending op so the approve handler
    // can populate the secrets_cache per PROTOCOL.md §6.2:
    //   - Ask: cache the resolved s_o for `ttl_seconds` after forward.
    //   - Allow: cache forever (until lock). This branch only fires for
    //     Allow + cache MISS (the fast-path above already covered cache
    //     hits) — typical example: an `allow` service whose secret lives
    //     in an external store (GCP) that wasn't pre-resolved at unlock.
    //   - AskAlways: explicit None → no cache write (the bytes get
    //     fresh-decrypted per request and dropped after forward).
    let policy_context = match level {
        AccessLevel::Ask => {
            let ttl = level_ask_ttl.unwrap_or(300);
            Some(crate::approval::PolicyContext {
                level: AccessLevel::Ask,
                rule_id: matched_rule_id.clone(),
                ttl_seconds: ttl,
            })
        }
        AccessLevel::Allow => Some(crate::approval::PolicyContext {
            level: AccessLevel::Allow,
            rule_id: matched_rule_id.clone(),
            ttl_seconds: 0, // not used for Allow (caches forever)
        }),
        _ => None,
    };

    let (op_id, expires_at) = {
        let mut store = state.approvals.lock().unwrap();
        let id = store.create_with_policy(vault_id.clone(), op.clone(), r.clone(), policy_context);
        let exp = store.get(&id).map(|r| r.expires_at_unix).unwrap_or(0);
        (id, exp)
    };

    // Persist `pending` audit row (mirror of op.rs::create path; this is the
    // /use sugar variant that wraps op-create internally).
    if let Ok(audit_store) = state.audits.for_vault(&vault_id) {
        let row = audit::row_from_op(&op_id, &op, now as i64, expires_at as i64);
        if let Err(e) = audit_store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending (use) failed: {}", e);
        }
    }

    // Slice-2 web approval: register this Use op with the cloud op-relay (if
    // configured) and poll for the browser-deposited sealed grant. No-op when
    // relay_url is unset (purely local daemon).
    crate::relay::client::spawn_register_and_poll(
        state.clone(),
        vault_id.clone(),
        op_id.clone(),
        serde_json::to_value(&op).unwrap_or(Value::Null),
        r.clone(),
        expires_at,
    );

    state.emit_event(ApprovalEvent {
        vault_id: vault_id,
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
            // Human taps their passkey here. Absolute cloud `/grant/{id}` page
            // when paired (the remote agent's user can't reach this localhost
            // daemon); relative local op-page for self-host. See active::grant_url.
            "approve_url": crate::cli::active::grant_url(&op_id),
            // Agent polls the LOCAL daemon (relative; resolves against VAULT_URL).
            "poll_url": format!("/op/{}", op_id),
        })),
    ))
}

/// Every distinct vault item the recipe's templates reference, scanned across
/// the upstream URL + header values + query values. Drives `scope.secrets`
/// (approval/audit honesty) — the full released set, not just the primary.
fn referenced_secret_names(upstream: &UpstreamDef) -> Vec<String> {
    let mut names = crate::server::broker::referenced_secrets(&upstream.url);
    for v in upstream.headers.values().chain(upstream.query.values()) {
        for n in crate::server::broker::referenced_secrets(v) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    names
}

/// True if the scheme+authority of `url` carries a `{{…}}` template. The
/// authority is everything between `://` and the first `/` (or end-of-string).
/// Templates in the *path* are fine; templates in the host are an SSRF risk.
fn upstream_host_has_template(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    authority.contains("{{")
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
    fn host_template_guard_allows_path_templates() {
        // Telegram carries its token in the *path* — host stays literal.
        assert!(!upstream_host_has_template(
            "https://api.telegram.org/bot{{secret.telegram_bot_token}}"
        ));
        assert!(!upstream_host_has_template("https://api.github.com"));
        assert!(!upstream_host_has_template(
            "https://www.googleapis.com/calendar/v3"
        ));
    }

    #[test]
    fn host_template_guard_blocks_authority_templates() {
        // A template in the scheme+authority could repoint the egress host.
        assert!(upstream_host_has_template("https://{{secret.x}}.evil.com"));
        assert!(upstream_host_has_template(
            "https://api.example.com.{{secret.x}}/v1"
        ));
        assert!(upstream_host_has_template("{{secret.host}}/path"));
    }

    #[test]
    fn referenced_secret_names_scans_all_template_surfaces() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".into(), "Bearer {{secret.tok}}".into());
        let mut query = std::collections::HashMap::new();
        query.insert("key".into(), "{{secret.qk}}".into());
        let upstream = UpstreamDef {
            id: "default".into(),
            url: "https://api.example.com/bot{{secret.url_tok}}".into(),
            auth: None,
            headers,
            query,
            stream: false,
            locked: None,
        };
        let mut names = referenced_secret_names(&upstream);
        names.sort();
        assert_eq!(names, vec!["qk", "tok", "url_tok"]);
    }

    #[test]
    fn referenced_secret_names_empty_for_oauth_recipe() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".into(), "Bearer {{oauth.access_token}}".into());
        let upstream = UpstreamDef {
            id: "default".into(),
            url: "https://gmail.googleapis.com".into(),
            auth: None,
            headers,
            query: std::collections::HashMap::new(),
            stream: false,
            locked: None,
        };
        assert!(referenced_secret_names(&upstream).is_empty());
    }

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
