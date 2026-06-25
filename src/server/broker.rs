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

use std::collections::HashMap;
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

    // Primary secret (op.act.target). For oauth2 services this is the
    // long-lived refresh_token; for API-key services it's the bearer/key
    // itself. Returned to the caller so the secrets_cache can fast-path
    // subsequent requests within the policy TTL.
    let s_o = view
        .resolve_value_async(&op.act.target)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!("secret '{}' not found in vault", op.act.target))
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

    // Look up the upstream config (header / query templates) from the
    // service registry. These carry the v3 `{{secret.NAME}}` /
    // `{{oauth.access_token}}` placeholders the engine renders.
    let service_id = scope.get("service").and_then(|v| v.as_str()).unwrap_or("");
    let upstream_id = scope
        .get("upstream_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let svc_def = services.get(service_id);
    let (tpl_headers, tpl_query) = svc_def
        .and_then(|svc| svc.upstream.iter().find(|u| u.id == upstream_id))
        .map(|u| (u.headers.clone(), u.query.clone()))
        .unwrap_or_default();

    // v3 multi-secret resolution: scan every template the recipe will
    // render (the upstream URL plus header / query values) for
    // `{{secret*.NAME}}` references, and resolve each NAME from the same
    // open vault view. Multi-secret is just "more than one name from one
    // open view" — no cryptographic change. An unresolvable reference is a
    // hard error (we never forward a literal `{{…}}`).
    let mut referenced = referenced_secrets(upstream_url);
    for v in tpl_headers.values().chain(tpl_query.values()) {
        for n in referenced_secrets(v) {
            if !referenced.contains(&n) {
                referenced.push(n);
            }
        }
    }
    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    for name in &referenced {
        let bytes = view
            .resolve_value_async(name)
            .await?
            .ok_or_else(|| AppError::BadRequest(format!("secret '{}' not found in vault", name)))?;
        secrets.insert(name.clone(), bytes);
    }

    // OAuth2 services: mint a fresh access_token from the refresh_token
    // (`s_o`) so templates can reference `{{oauth.access_token}}`. No-op
    // (and no minting cost) for non-oauth services.
    let is_oauth = svc_def
        .and_then(|s| s.upstream.first())
        .and_then(|u| u.auth.as_ref())
        .and_then(|a| a.auth_type.as_deref())
        == Some("oauth2");
    let oauth_token = if is_oauth {
        let access = resolve_auth_value(state, vault_id, service_id, &s_o).await?;
        Some(
            String::from_utf8(access)
                .map_err(|_| AppError::Internal("oauth access_token not utf8".into()))?,
        )
    } else {
        None
    };

    let inputs = RenderInputs {
        secrets: &secrets,
        oauth_access_token: oauth_token.as_deref(),
    };
    let response = forward_to_upstream_with_extras(
        &inputs,
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
    // Return the primary `s_o` (refresh_token for oauth2 services, the
    // bearer/key for others) so the caller can cache it per policy TTL —
    // the minted access_token is cached separately in `state.oauth_access`.
    Ok(UseForwardOutcome { response, s_o })
}

// ── v3 multi-secret template engine ──────────────────────────────────────────
//
// The grant's wrapping key opens the WHOLE vault into a plaintext view, so a
// single approved operation can resolve any number of named items. Multi-secret
// is therefore just "resolve more than one name from the same open view" — no
// cryptographic change. Every token is namespaced by its first segment so a
// vault item can never be confused with a builtin, and an unknown/unresolvable
// token is a HARD ERROR (we never forward a literal `{{…}}` as if it were auth).

/// Inputs for [`render_template`]: every secret the recipe references, plus an
/// optional minted OAuth access token (for `[upstream.auth]` upstreams).
pub struct RenderInputs<'a> {
    /// vault-item-name -> resolved secret bytes
    pub secrets: &'a std::collections::HashMap<String, Vec<u8>>,
    pub oauth_access_token: Option<&'a str>,
}

/// Names of vault items a template references via `{{secret*.NAME}}`. Used to
/// know which items to resolve from the open view, and to derive the set of
/// secrets a recipe requires (connect flow / required-items).
pub fn referenced_secrets(tpl: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = tpl.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if &bytes[i..i + 2] == b"{{" {
            if let Some(end) = tpl[i + 2..].find("}}") {
                let key = tpl[i + 2..i + 2 + end].trim();
                for prefix in ["secret.", "secret_b64.", "secret_basic."] {
                    if let Some(name) = key.strip_prefix(prefix) {
                        let name = name.trim();
                        if !name.is_empty() && !names.iter().any(|n: &String| n == name) {
                            names.push(name.to_string());
                        }
                    }
                }
                i += 2 + end + 2;
                continue;
            }
        }
        i += 1;
    }
    names
}

/// Substitute `{{…}}` tokens in an upstream template (header / query /
/// path-param value):
///   `{{secret.NAME}}`        raw bytes of vault item NAME (utf-8)
///   `{{secret_b64.NAME}}`    base64(item NAME)
///   `{{secret_basic.NAME}}`  base64(item NAME + ':')  — key-as-username basic
///   `{{oauth.access_token}}` the minted OAuth access token
///   `{{uuid_v4}}`            a fresh UUID v4
/// Unknown/unterminated/unresolvable token → hard error.
fn render_template(tpl: &str, inputs: &RenderInputs) -> Result<String> {
    let mut out = String::with_capacity(tpl.len());
    let bytes = tpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"{{" {
            let end = tpl[i + 2..]
                .find("}}")
                .ok_or_else(|| AppError::BadRequest("unterminated '{{' in upstream template".into()))?;
            let key = tpl[i + 2..i + 2 + end].trim();
            out.push_str(&resolve_token(key, inputs)?);
            i += 2 + end + 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

fn resolve_token(key: &str, inputs: &RenderInputs) -> Result<String> {
    if key == "uuid_v4" {
        return Ok(uuid::Uuid::new_v4().to_string());
    }
    let undeclared =
        |n: &str| AppError::BadRequest(format!("template references undeclared secret '{}'", n));
    let (ns, arg) = key
        .split_once('.')
        .ok_or_else(|| AppError::BadRequest(format!("unknown template token '{{{{{}}}}}'", key)))?;
    let arg = arg.trim();
    match ns {
        "secret" => {
            let b = inputs.secrets.get(arg).ok_or_else(|| undeclared(arg))?;
            String::from_utf8(b.clone())
                .map_err(|_| AppError::BadRequest(format!("secret '{}' is not valid UTF-8", arg)))
        }
        "secret_b64" => {
            let b = inputs.secrets.get(arg).ok_or_else(|| undeclared(arg))?;
            Ok(STANDARD.encode(b))
        }
        "secret_basic" => {
            let b = inputs.secrets.get(arg).ok_or_else(|| undeclared(arg))?;
            let mut buf = b.clone();
            buf.push(b':');
            Ok(STANDARD.encode(&buf))
        }
        "oauth" if arg == "access_token" => inputs
            .oauth_access_token
            .map(|t| t.to_string())
            .ok_or_else(|| AppError::BadRequest("{{oauth.access_token}} on a non-oauth upstream".into())),
        _ => Err(AppError::BadRequest(format!("unknown template token '{{{{{}}}}}'", key))),
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use std::collections::HashMap;

    fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, Vec<u8>> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect()
    }

    #[test]
    fn single_secret_substitutes() {
        let s = secrets(&[("github_token", "ghp_xyz")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None };
        assert_eq!(render_template("Bearer {{secret.github_token}}", &inp).unwrap(), "Bearer ghp_xyz");
    }

    #[test]
    fn multi_secret_substitutes_both() {
        let s = secrets(&[("twilio_sid", "AC123"), ("twilio_token", "tok")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None };
        assert_eq!(
            render_template("{{secret.twilio_sid}}:{{secret.twilio_token}}", &inp).unwrap(),
            "AC123:tok"
        );
    }

    #[test]
    fn b64_and_basic_variants() {
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None };
        assert_eq!(render_template("{{secret_b64.k}}", &inp).unwrap(), STANDARD.encode(b"user"));
        assert_eq!(render_template("{{secret_basic.k}}", &inp).unwrap(), STANDARD.encode(b"user:"));
    }

    #[test]
    fn oauth_access_token_substitutes() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: Some("at_live") };
        assert_eq!(render_template("Bearer {{oauth.access_token}}", &inp).unwrap(), "Bearer at_live");
    }

    #[test]
    fn unknown_token_hard_fails() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None };
        assert!(render_template("{{bogus}}", &inp).is_err());
        assert!(render_template("{{secret.missing}}", &inp).is_err());
    }

    #[test]
    fn missing_secret_never_leaks_literal() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None };
        // A typo'd reference must error, never forward the literal `{{…}}`.
        assert!(render_template("Bearer {{secret.typo}}", &inp).is_err());
    }

    #[test]
    fn static_text_unchanged() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None };
        assert_eq!(render_template("application/json", &inp).unwrap(), "application/json");
    }

    #[test]
    fn referenced_secrets_dedups_and_extracts() {
        let names = referenced_secrets(
            "{{secret.a}} {{secret_basic.b}} {{oauth.access_token}} {{secret.a}} {{uuid_v4}}",
        );
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
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

/// Forward an agent request to an upstream service, injecting the resolved
/// secrets according to the recipe's `[upstream.headers]` / `[upstream.query]`
/// templates (and any `{{secret*.NAME}}` / `{{oauth.access_token}}` in the
/// upstream URL itself). Every placeholder is rendered by the v3 engine
/// ([`render_template`]); an unresolvable reference is a hard error rather
/// than a silent literal `{{…}}` leak. Recipes with no auth template inject
/// no credential — there is no implicit bearer fallback. Runs after the
/// request-level hop-by-hop scrub.
#[allow(clippy::too_many_arguments)]
pub async fn forward_to_upstream_with_extras<'a>(
    inputs: &RenderInputs<'_>,
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
            let mut parts = Vec::with_capacity(q.len());
            for (k, v) in q {
                let rendered = render_template(v, inputs)?;
                parts.push(format!(
                    "{}={}",
                    urlencoding::encode(k),
                    urlencoding::encode(&rendered)
                ));
            }
            let extra = parts.join("&");
            if path.contains('?') {
                format!("{}&{}", path, extra)
            } else {
                format!("{}?{}", path, extra)
            }
        }
        _ => path.to_string(),
    };
    // URL itself may carry a template — e.g. Telegram's Bot API puts the
    // token in the URL path: `https://api.telegram.org/bot{{secret.telegram_bot_token}}`.
    // Render with the same engine that handles header/query templates so
    // the recipe author has one consistent placeholder vocabulary.
    let url_rendered = render_template(upstream_url, inputs)?;
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

    // Auth injection. The recipe's `[upstream.headers]` templates carry the
    // credential placeholders; each value is rendered by the v3 engine. No
    // implicit bearer fallback — a recipe with no auth header (e.g. Telegram,
    // which carries its token in the URL, or Google AI, which uses a query
    // param) simply injects no header here.
    if let Some(tpl_headers) = extra_headers.filter(|m| !m.is_empty()) {
        for (k, v) in tpl_headers {
            let rendered = render_template(v, inputs)?;
            if let (Ok(hn), Ok(hv)) = (
                reqwest::header::HeaderName::from_str(k),
                reqwest::header::HeaderValue::from_str(&rendered),
            ) {
                headers.insert(hn, hv);
            }
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
