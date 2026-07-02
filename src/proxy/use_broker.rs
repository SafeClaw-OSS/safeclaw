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
    Path((vault_id, connection)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    handle_impl(state, addr, method, vault_id, connection, String::new(), headers, body).await
}

pub async fn handle(
    state: State<Arc<AppState>>,
    addr: ConnectInfo<std::net::SocketAddr>,
    method: Method,
    Path((vault_id, connection, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    handle_impl(state, addr, method, vault_id, connection, rest, headers, body).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_impl(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    method: Method,
    vault_id: String,
    // The URL path segment. CONNECTION_SCHEMA.md §6: this is a `connection_id`,
    // which resolves to its `service` (recipe) via the unlocked cache; for the
    // default connection / an unconnected service `connection == service`.
    connection: String,
    rest: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>)> {
    validate_vault_id(&vault_id)?;

    // Locked-state gate (H3 / PROTOCOL.md §6.3). When the vault is Locked,
    // /use rejects without creating a pending op — agent must trigger an
    // unlock ceremony first. Returns a DISTINCT 423 (`error:"vault_locked"`) so
    // the agent tells "unlock needed → run `sc up`" apart from other 409s.
    // (A future opt-in could dispatch the recipe's `[upstream.locked]` template
    // for dumb tools pointed straight at /use.)
    if state.is_vault_locked(&vault_id) {
        return Err(AppError::VaultLocked);
    }

    // Resolve the connection → its service (recipe). CONNECTION_SCHEMA.md §6:
    // an explicit `aux.connections` entry names the service; otherwise the
    // connection IS its own default (`connection == service`).
    let service = state.resolve_connection_service(&vault_id, &connection);

    // Service lookup.
    let svc = state
        .services
        .get(&service)
        .ok_or(AppError::NotFound)?;
    let upstream = svc.upstream.first().ok_or_else(|| {
        AppError::Conflict(format!("service '{}' has no upstream defined", service))
    })?;

    // Host-literal guard (anti-SSRF). The scheme+authority of an upstream URL
    // must be a constant OR a declared `{{connection.<param>}}` slot (resolved to
    // a vetted host at forward time): a `{{secret.*}}` there could let a captured
    // request repoint the egress host. Templates are otherwise allowed only in
    // the path (e.g. Telegram's `/bot{{secret.telegram_bot_token}}`).
    if upstream_host_has_unsafe_template(upstream) {
        return Err(AppError::Conflict(format!(
            "service '{}' upstream host is templated with a non-connection token — refusing to forward",
            service
        )));
    }

    // The recipe's bare secret role + its namespaced vault address (§3): bare for
    // the default connection (`conn == service`), `<conn>:<ROLE>` for a named one.
    // `target` is the vault item the op resolves; `role` (bare) keys the render
    // map so `{{secret.<role>}}` matches.
    let role = resolve_vault_target(upstream).unwrap_or_else(|| "unknown".to_string());
    let target = crate::storage::plaintext::secret_address(&connection, &service, &role);

    // Honesty: the full set of `{{secret.*}}` items this operation will release,
    // so the approval UI and audit show every secret. Bare role names — the
    // render map is keyed by bare name, namespaced per-connection at resolve.
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

    // Per-request policy evaluation (PROTOCOL.md §6.4). Merges the service
    // recipe's built-in rules with this connection's user rules
    // (`aux.policy.connections.<conn>.rules`), resolves each rule's risk
    // through the live risk map, and takes the most-restrictive match
    // (deny-override), then falls back to the connection / category / global
    // default floor. `None` only when the vault entry is gone between the lock
    // check and here — should never happen but treat as locked.
    let path_for_eval = format!("/{}", rest);
    let body_text = std::str::from_utf8(&body).ok();
    let (level, matched_rule_id, level_ask_ttl) = state
        .evaluate_request_policy(
            &vault_id,
            &connection,
            &service,
            method.as_str(),
            &path_for_eval,
            body_text,
        )
        .ok_or(AppError::VaultLocked)?;

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
        if let Some(cached_secret) = state.cache_lookup(&vault_id, &connection) {
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
            .map(|a| state.services.auth_is_oauth2(a))
            .unwrap_or(false);
        let (secrets_map, oauth_token) = if is_oauth {
            let access = crate::server::broker::resolve_auth_value(
                &state,
                &vault_id,
                &connection,
                &service,
                &cached_secret,
            )
            .await?;
            let token = String::from_utf8(access)
                .map_err(|_| AppError::Internal("oauth access_token not utf8".into()))?;
            (std::collections::HashMap::new(), Some(token))
        } else {
            let map = state
                .cache_lookup_secrets(&vault_id, &connection)
                .unwrap_or_else(|| {
                    // Fallback (single-secret recipe, no bootstrap map): key by the
                    // BARE role so `{{secret.<role>}}` matches; the bytes are the
                    // namespaced primary the cache already resolved.
                    let mut m = std::collections::HashMap::new();
                    m.insert(role.clone(), cached_secret.clone());
                    m
                });
            (map, None)
        };
        let conn_config = state.connection_config(&vault_id, &connection);
        let inputs = crate::server::broker::RenderInputs {
            secrets: &secrets_map,
            oauth_access_token: oauth_token.as_deref(),
            connection: conn_config.as_ref(),
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
        // The routing/cache/audit unit (CONNECTION_SCHEMA.md §6). `service` is
        // the resolved recipe; for the default connection the two are equal.
        "connection_id": connection,
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
        // Pending TTL — kept in sync with the ApprovalStore's DEFAULT_TTL.
        valid: Valid::single_use(now, Some(now + crate::approval::store::DEFAULT_TTL.as_secs())),
    };

    // Stamp the policy decision on the pending op so the approve handler can
    // populate the secrets_cache per PROTOCOL.md §6.2:
    //   - Ask: cache the resolved s_o for `ttl_seconds` after forward.
    //   - Allow: cache forever (until lock). This branch only fires for Allow +
    //     cache MISS (the fast-path above already covered hits).
    //   - AskAlways: explicit None → no cache write (fresh-decrypt per request).
    let policy_context = match level {
        AccessLevel::Ask => Some(crate::approval::PolicyContext {
            level: AccessLevel::Ask,
            rule_id: matched_rule_id.clone(),
            ttl_seconds: level_ask_ttl.unwrap_or(300),
        }),
        AccessLevel::Allow => Some(crate::approval::PolicyContext {
            level: AccessLevel::Allow,
            rule_id: matched_rule_id.clone(),
            ttl_seconds: 0, // not used for Allow (caches forever)
        }),
        _ => None,
    };

    let (op_id, r, expires_at) =
        register_pending_use(&state, &vault_id, op, policy_context, addr.ip())?;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending_approval",
            "op_id": op_id,
            "r": r,
            "expires_at": expires_at,
            // Human taps their passkey here (cloud /grant page when paired;
            // relative local op-page for self-host). See active::grant_url.
            "approve_url": crate::cli::active::grant_url(&op_id),
            // Agent polls the LOCAL daemon (relative; resolves against VAULT_URL).
            "poll_url": format!("/op/{}", op_id),
        })),
    ))
}

/// Shared tail of the Use pending-op flow, used by BOTH the buffered `/use/`
/// handler and the streaming captive-portal (`/stream/` ask path): issue the
/// challenge `r`, create the `ApprovalRecord` (stamped with the policy context
/// the approve handler reads for its cache write), persist the `pending` audit
/// row, register with the cloud op-relay, and emit the `pending` SSE event the
/// agent watches. Returns `(op_id, r, expires_at)`.
///
/// Keeping this one function shared is what prevents the two planes' approval
/// logic from drifting (the gap that left `/stream/` allow-only): both compile
/// their own `Operation` (buffered carries the body; streaming sets
/// `scope.authorize_only`), then funnel through here.
pub(crate) fn register_pending_use(
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

    // Slice-2 web approval: register with the cloud op-relay (if configured) and
    // poll for the browser-deposited sealed grant. No-op when relay_url is unset.
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
/// Superseded at the call site by [`upstream_host_has_unsafe_template`] (which
/// permits a declared `{{connection.<param>}}` host); retained as the primitive
/// its unit tests exercise.
#[allow(dead_code)]
fn upstream_host_has_template(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    authority.contains("{{")
}

/// True if the upstream's host carries a `{{…}}` template that is NOT a declared
/// `{{connection.<param>}}` slot — i.e. an SSRF-risky host template
/// (CONNECTION_SCHEMA.md §4). A declared connection slot is the one allowed host
/// template (its resolved value is re-checked against the SSRF rules at forward
/// time); anything else (`{{secret.*}}`, an undeclared connection param, an
/// `{{oauth.*}}`) is rejected before any pending op is created.
pub(crate) fn upstream_host_has_unsafe_template(upstream: &UpstreamDef) -> bool {
    let after_scheme = upstream
        .url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(&upstream.url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    if !authority.contains("{{") {
        return false;
    }
    let declared: std::collections::HashSet<&str> = upstream
        .connection
        .as_ref()
        .map(|c| c.params.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();
    // Every `{{…}}` in the authority must be a declared `connection.<param>`.
    let mut rest = authority;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return true; // unterminated → treat as unsafe
        };
        let tok = after[..end].trim();
        let ok = tok
            .strip_prefix("connection.")
            .map(|p| declared.contains(p.trim()))
            .unwrap_or(false);
        if !ok {
            return true;
        }
        rest = &after[end + 2..];
    }
    false
}

fn resolve_vault_target(upstream: &UpstreamDef) -> Option<String> {
    let auth = upstream.auth.as_ref()?;
    // Preferred path: explicit `auth.secret = "key"` in service.toml (the
    // field formerly named `env`). The value IS the bare item name (no
    // `env.` prefix).
    if let Some(key) = auth.secret.as_deref() {
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
            connection: None,
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
            connection: None,
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
