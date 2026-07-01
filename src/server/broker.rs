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
    // PER-ITEM read seam: fold the item rows (if the per-item store exists) or
    // fall back to the whole-blob open. One call site so both formats resolve a
    // grant identically (metadata::open_view_for_grant).
    let view = crate::server::handlers::metadata::open_view_for_grant(
        state,
        vault_id,
        op,
        wrapping_key,
        credential_id_bytes,
        vault,
    )?;

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
    // The connection this op belongs to (CONNECTION_SCHEMA.md §6). Falls back to
    // the service for the default connection (conn == service) / legacy ops.
    let connection_id = scope
        .get("connection_id")
        .and_then(|v| v.as_str())
        .unwrap_or(service_id);
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
        // Resolve at the §3 namespaced address (`[<conn>:]<name>`) but key the
        // render map by the BARE name so `{{secret.<name>}}` matches.
        let addr = crate::storage::plaintext::secret_address(connection_id, service_id, name);
        let bytes = view
            .resolve_value_async(&addr)
            .await?
            .ok_or_else(|| AppError::BadRequest(format!("secret '{}' not found in vault", addr)))?;
        secrets.insert(name.clone(), bytes);
    }

    // OAuth2 services: mint a fresh access_token from the refresh_token
    // (`s_o`) so templates can reference `{{oauth.access_token}}`. No-op
    // (and no minting cost) for non-oauth services.
    let is_oauth = svc_def
        .and_then(|s| s.upstream.first())
        .and_then(|u| u.auth.as_ref())
        .map(|a| state.services.auth_is_oauth2(a))
        .unwrap_or(false);
    let oauth_token = if is_oauth {
        let access = resolve_auth_value(state, vault_id, connection_id, service_id, &s_o).await?;
        Some(
            String::from_utf8(access)
                .map_err(|_| AppError::Internal("oauth access_token not utf8".into()))?,
        )
    } else {
        None
    };

    // Per-connection config slots (`{{connection.<param>}}`) from the open vault
    // view's `aux.connections` (CONNECTION_SCHEMA.md §4).
    let conn_config = view.aux.connections.get(connection_id).map(|c| &c.config);
    let inputs = RenderInputs {
        secrets: &secrets,
        oauth_access_token: oauth_token.as_deref(),
        connection: conn_config,
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

/// Resolve a Use operation's primary secret WITHOUT forwarding — the streaming
/// captive-portal authorize path (`/stream/` ask policy). Opens the vault with
/// the already-verified grant, resolves `op.act.target`, and returns the bytes
/// for the caller to stash (cache) so the agent's *retried* stream can consume
/// them. No upstream call happens here: the real request rides the retry stream,
/// not this op (which carries no body). Mirrors the open+resolve preamble of
/// [`execute_use_forward`] minus the forward.
pub async fn resolve_use_primary(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &SealedVault,
    state: &crate::state::AppState,
    vault_id: &str,
) -> Result<Vec<u8>> {
    // PER-ITEM read seam (see execute_use_forward).
    let view = crate::server::handlers::metadata::open_view_for_grant(
        state,
        vault_id,
        op,
        wrapping_key,
        credential_id_bytes,
        vault,
    )?;
    view.resolve_value_async(&op.act.target)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!("secret '{}' not found in vault", op.act.target))
        })
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
    /// Per-connection config slot values (`{{connection.<param>}}`), from the
    /// active connection's `config` (CONNECTION_SCHEMA.md §4). `None` for a
    /// default connection with no slots. The recipe may template the host ONLY
    /// with a declared slot; the resolved host is SSRF-rechecked before forward.
    pub connection: Option<&'a std::collections::BTreeMap<String, String>>,
}

/// The vault-item name a single `{{…}}` token body references, if it is a
/// secret token. Handles all three secret forms:
///   - the filter grammar `secret.NAME | b64` / `secret.NAME | basic` /
///     bare `secret.NAME` (whitespace-tolerant around the pipe);
///   - the deprecated prefix aliases `secret_b64.NAME` / `secret_basic.NAME`.
/// Returns `None` for non-secret tokens (`oauth.*`, `uuid_v4`, unknown).
fn secret_name_of(key: &str) -> Option<String> {
    // Strip an optional `| filter` suffix; the source.key is the part before
    // the pipe. (Only `secret.*` takes a filter; the bare-prefix aliases never
    // carry one, but stripping is harmless.)
    let source_key = key.split('|').next().unwrap_or(key).trim();
    for prefix in ["secret.", "secret_b64.", "secret_basic."] {
        if let Some(name) = source_key.strip_prefix(prefix) {
            let name = name.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Names of vault items a template references via `{{secret.NAME [| filter]}}`
/// (or the deprecated `{{secret_b64.NAME}}` / `{{secret_basic.NAME}}` aliases).
/// Used to know which items to resolve from the open view, and to derive the
/// set of secrets a recipe requires (connect flow / required-items).
pub fn referenced_secrets(tpl: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = tpl.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if &bytes[i..i + 2] == b"{{" {
            if let Some(end) = tpl[i + 2..].find("}}") {
                let key = tpl[i + 2..i + 2 + end].trim();
                if let Some(name) = secret_name_of(key) {
                    if !names.iter().any(|n: &String| n == &name) {
                        names.push(name);
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
///   `{{secret.NAME}}`          raw bytes of vault item NAME (utf-8)
///   `{{secret.NAME | b64}}`    base64(item NAME)
///   `{{secret.NAME | basic}}`  base64(item NAME + ':')  — key-as-username basic
///   `{{secret_b64.NAME}}`      DEPRECATED alias of `secret.NAME | b64`
///   `{{secret_basic.NAME}}`    DEPRECATED alias of `secret.NAME | basic`
///   `{{oauth.access_token}}`   the minted OAuth access token
///   `{{uuid_v4}}`              a fresh UUID v4
/// Unknown/unterminated/unresolvable token (or unknown filter) → hard error.
pub(crate) fn render_template(tpl: &str, inputs: &RenderInputs) -> Result<String> {
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

/// Apply a secret encoding filter to raw vault bytes. `None` = no filter
/// (raw UTF-8); `Some("b64")` = base64; `Some("basic")` = base64(value + ':')
/// (token-as-username, e.g. GitHub); `Some("basic:USER")` = base64("USER:" +
/// value) (token-as-password with a fixed username, e.g. GitLab's `oauth2`).
/// Unknown filter → hard error.
fn apply_secret_filter(name: &str, bytes: &[u8], filter: Option<&str>) -> Result<String> {
    match filter {
        None => String::from_utf8(bytes.to_vec())
            .map_err(|_| AppError::BadRequest(format!("secret '{}' is not valid UTF-8", name))),
        Some("b64") => Ok(STANDARD.encode(bytes)),
        // `basic` (no arg): base64(value + ':') — the token is the username and
        // the password is empty (GitHub git smart-HTTP, Stripe).
        Some("basic") => {
            let mut buf = bytes.to_vec();
            buf.push(b':');
            Ok(STANDARD.encode(&buf))
        }
        // `basic:USER`: base64("USER:" + value) — a fixed username with the token
        // as the password (GitLab uses `oauth2`; any forge that requires a
        // non-empty Basic username). USER must be non-empty and colon-free (a
        // colon would corrupt the user/pass split at the server).
        Some(f) if f.starts_with("basic:") => {
            let user = &f["basic:".len()..];
            if user.is_empty() || user.contains(':') {
                return Err(AppError::BadRequest(format!(
                    "invalid basic filter username in '{}' (must be non-empty, no colon)",
                    f
                )));
            }
            let mut buf = Vec::with_capacity(user.len() + 1 + bytes.len());
            buf.extend_from_slice(user.as_bytes());
            buf.push(b':');
            buf.extend_from_slice(bytes);
            Ok(STANDARD.encode(&buf))
        }
        Some(other) => Err(AppError::BadRequest(format!(
            "unknown template filter '{}' (expected b64 | basic | basic:<user>)",
            other
        ))),
    }
}

fn resolve_token(key: &str, inputs: &RenderInputs) -> Result<String> {
    if key == "uuid_v4" {
        return Ok(uuid::Uuid::new_v4().to_string());
    }
    let undeclared =
        |n: &str| AppError::BadRequest(format!("template references undeclared secret '{}'", n));

    // Split off an optional `| filter`. The part before the pipe is the
    // `source.key`; the part after (trimmed) is the filter name. Only the
    // `secret.*` source takes a filter; the deprecated `secret_b64`/
    // `secret_basic` prefixes carry their encoding in the source itself.
    let (source_key, pipe_filter) = match key.split_once('|') {
        Some((src, f)) => (src.trim(), Some(f.trim())),
        None => (key, None),
    };

    let (ns, arg) = source_key.split_once('.').ok_or_else(|| {
        AppError::BadRequest(format!("unknown template token '{{{{{}}}}}'", key))
    })?;
    let arg = arg.trim();
    match ns {
        // Canonical secret form with the pipe-filter grammar.
        "secret" => {
            let b = inputs.secrets.get(arg).ok_or_else(|| undeclared(arg))?;
            apply_secret_filter(arg, b, pipe_filter)
        }
        // DEPRECATED alias: `secret_b64.X` == `secret.X | b64`.
        "secret_b64" => {
            if pipe_filter.is_some() {
                return Err(AppError::BadRequest(
                    "deprecated 'secret_b64' alias does not take a filter — use 'secret.X | b64'".into(),
                ));
            }
            let b = inputs.secrets.get(arg).ok_or_else(|| undeclared(arg))?;
            apply_secret_filter(arg, b, Some("b64"))
        }
        // DEPRECATED alias: `secret_basic.X` == `secret.X | basic`.
        "secret_basic" => {
            if pipe_filter.is_some() {
                return Err(AppError::BadRequest(
                    "deprecated 'secret_basic' alias does not take a filter — use 'secret.X | basic'".into(),
                ));
            }
            let b = inputs.secrets.get(arg).ok_or_else(|| undeclared(arg))?;
            apply_secret_filter(arg, b, Some("basic"))
        }
        "oauth" if arg == "access_token" && pipe_filter.is_none() => inputs
            .oauth_access_token
            .map(|t| t.to_string())
            .ok_or_else(|| AppError::BadRequest("{{oauth.access_token}} on a non-oauth upstream".into())),
        // Per-connection config slot (`{{connection.<param>}}`, CONNECTION_SCHEMA.md
        // §4). Resolved from the active connection's `config`; an undeclared slot
        // is a hard error (never a literal leak). Takes no filter.
        "connection" if pipe_filter.is_none() => inputs
            .connection
            .and_then(|c| c.get(arg))
            .map(|v| v.to_string())
            .ok_or_else(|| {
                AppError::BadRequest(format!("template references undeclared connection slot '{}'", arg))
            }),
        _ => Err(AppError::BadRequest(format!("unknown template token '{{{{{}}}}}'", key))),
    }
}

// ── setup template context (agent-facing, NO vault secrets) ──────────────────
//
// CONNECTIONS_AND_AUTH.md §7, second row. The `setup` blurb (git `insteadOf`,
// runtime base_url hints, …) is rendered for the AGENT, in its own env. It must
// NOT touch any vault secret: `api_key` here is the agent's OWN broker key, not
// a vault item. The only tokens are `{{proxy_base}}`, `{{api_key}}`, `{{vault}}`
// — a strictly disjoint, builtin-only vocabulary from the auth engine above.
// Recipes inline the full route as `{{proxy_base}}/stream/<upstream>/` (the
// upstream service name can differ from the recipe id, so there is no computed
// `{{route}}` token). An unknown token is still a hard error (never forward `{{…}}`).

/// Builtin values for the setup template context. All agent-facing — none of
/// these is a vault secret.
pub struct SetupInputs<'a> {
    /// The daemon's broker base URL the agent calls (e.g. `http://127.0.0.1:8787`).
    pub proxy_base: &'a str,
    /// The agent's own broker API key (its bearer to the daemon — NOT a vault item).
    pub api_key: &'a str,
    /// The active vault id / slug.
    pub vault: &'a str,
}

/// Render the `setup` string for the agent. Tokens: `{{proxy_base}}`,
/// `{{api_key}}`, `{{vault}}`. This context has NO access to vault secrets —
/// using a `secret.*` / `oauth.*` token here is an unknown-token hard error by
/// construction.
pub fn render_setup_template(tpl: &str, inputs: &SetupInputs) -> Result<String> {
    let mut out = String::with_capacity(tpl.len());
    let bytes = tpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"{{" {
            let end = tpl[i + 2..]
                .find("}}")
                .ok_or_else(|| AppError::BadRequest("unterminated '{{' in setup template".into()))?;
            let key = tpl[i + 2..i + 2 + end].trim();
            let val = match key {
                "proxy_base" => inputs.proxy_base,
                "api_key" => inputs.api_key,
                "vault" => inputs.vault,
                _ => {
                    return Err(AppError::BadRequest(format!(
                        "unknown setup template token '{{{{{}}}}}'",
                        key
                    )))
                }
            };
            out.push_str(val);
            i += 2 + end + 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
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
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(render_template("Bearer {{secret.github_token}}", &inp).unwrap(), "Bearer ghp_xyz");
    }

    #[test]
    fn multi_secret_substitutes_both() {
        let s = secrets(&[("twilio_sid", "AC123"), ("twilio_token", "tok")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(
            render_template("{{secret.twilio_sid}}:{{secret.twilio_token}}", &inp).unwrap(),
            "AC123:tok"
        );
    }

    #[test]
    fn b64_and_basic_variants() {
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(render_template("{{secret_b64.k}}", &inp).unwrap(), STANDARD.encode(b"user"));
        assert_eq!(render_template("{{secret_basic.k}}", &inp).unwrap(), STANDARD.encode(b"user:"));
    }

    #[test]
    fn pipe_filter_b64() {
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        // whitespace-tolerant around the pipe
        assert_eq!(render_template("{{secret.k | b64}}", &inp).unwrap(), STANDARD.encode(b"user"));
        assert_eq!(render_template("{{ secret.k|b64 }}", &inp).unwrap(), STANDARD.encode(b"user"));
    }

    #[test]
    fn pipe_filter_basic() {
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(render_template("{{secret.k | basic}}", &inp).unwrap(), STANDARD.encode(b"user:"));
    }

    #[test]
    fn pipe_filter_basic_user() {
        // `basic:USER` = base64("USER:" + value) — token-as-password (GitLab's
        // `oauth2`), distinct from bare `basic` = base64(value + ':').
        let s = secrets(&[("tok", "glpat_xyz")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(
            render_template("{{secret.tok | basic:oauth2}}", &inp).unwrap(),
            STANDARD.encode(b"oauth2:glpat_xyz"),
        );
        // Whitespace around the pipe is tolerated.
        assert_eq!(
            render_template("{{ secret.tok|basic:oauth2 }}", &inp).unwrap(),
            STANDARD.encode(b"oauth2:glpat_xyz"),
        );
        // Empty or colon-bearing username is a hard error.
        assert!(render_template("{{secret.tok | basic:}}", &inp).is_err());
        assert!(render_template("{{secret.tok | basic:a:b}}", &inp).is_err());
    }

    #[test]
    fn pipe_filter_none_is_raw() {
        let s = secrets(&[("k", "ghp_xyz")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(render_template("{{secret.k}}", &inp).unwrap(), "ghp_xyz");
    }

    #[test]
    fn alias_equivalence_b64_and_basic() {
        // The deprecated prefix aliases must produce byte-identical output to
        // the canonical pipe form.
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(
            render_template("{{secret_b64.k}}", &inp).unwrap(),
            render_template("{{secret.k | b64}}", &inp).unwrap(),
        );
        assert_eq!(
            render_template("{{secret_basic.k}}", &inp).unwrap(),
            render_template("{{secret.k | basic}}", &inp).unwrap(),
        );
    }

    #[test]
    fn unknown_filter_hard_fails() {
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        let err = render_template("{{secret.k | urlenc}}", &inp).unwrap_err();
        assert!(format!("{:?}", err).contains("unknown template filter"), "{:?}", err);
        // A missing secret under a valid filter is still a hard error (never literal).
        assert!(render_template("{{secret.missing | b64}}", &inp).is_err());
    }

    #[test]
    fn deprecated_alias_rejects_filter() {
        // `secret_b64.X | basic` is incoherent — reject rather than silently
        // double-apply.
        let s = secrets(&[("k", "user")]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert!(render_template("{{secret_b64.k | basic}}", &inp).is_err());
    }

    #[test]
    fn oauth_access_token_substitutes() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: Some("at_live"), connection: None };
        assert_eq!(render_template("Bearer {{oauth.access_token}}", &inp).unwrap(), "Bearer at_live");
    }

    #[test]
    fn unknown_token_hard_fails() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert!(render_template("{{bogus}}", &inp).is_err());
        assert!(render_template("{{secret.missing}}", &inp).is_err());
    }

    #[test]
    fn missing_secret_never_leaks_literal() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        // A typo'd reference must error, never forward the literal `{{…}}`.
        assert!(render_template("Bearer {{secret.typo}}", &inp).is_err());
    }

    #[test]
    fn static_text_unchanged() {
        let s = secrets(&[]);
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert_eq!(render_template("application/json", &inp).unwrap(), "application/json");
    }

    #[test]
    fn connection_slot_substitutes_and_undeclared_fails() {
        let s = secrets(&[]);
        let mut cfg = std::collections::BTreeMap::new();
        cfg.insert("host".to_string(), "git.acme.com".to_string());
        let inp = RenderInputs { secrets: &s, oauth_access_token: None, connection: Some(&cfg) };
        assert_eq!(
            render_template("https://{{connection.host}}/api/v4", &inp).unwrap(),
            "https://git.acme.com/api/v4",
        );
        // An undeclared / missing slot is a hard error, never a literal leak.
        assert!(render_template("https://{{connection.region}}/x", &inp).is_err());
        // No connection config at all → also a hard error.
        let inp2 = RenderInputs { secrets: &s, oauth_access_token: None, connection: None };
        assert!(render_template("https://{{connection.host}}/x", &inp2).is_err());
    }

    #[test]
    fn referenced_secrets_dedups_and_extracts() {
        let names = referenced_secrets(
            "{{secret.a}} {{secret_basic.b}} {{oauth.access_token}} {{secret.a}} {{uuid_v4}}",
        );
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn referenced_secrets_sees_pipe_filter_form() {
        // `secret.X | filter` references the same vault item `X` as `secret.X`.
        let names = referenced_secrets("{{secret.a | b64}} {{ secret.c|basic }} {{secret.a}}");
        assert_eq!(names, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn setup_template_renders_builtins() {
        let inp = SetupInputs {
            proxy_base: "http://127.0.0.1:8787",
            api_key: "sk_agent_123",
            vault: "v_abc",
        };
        // Recipes inline the full route as `{{proxy_base}}/stream/<upstream>/`
        // (no computed `{{route}}` token — the upstream name can differ from id).
        assert_eq!(
            render_setup_template(
                r#"git config url."{{proxy_base}}/stream/github-git/".insteadOf "https://github.com/""#,
                &inp
            )
            .unwrap(),
            r#"git config url."http://127.0.0.1:8787/stream/github-git/".insteadOf "https://github.com/""#,
        );
        assert_eq!(
            render_setup_template("Authorization: Bearer {{api_key}}", &inp).unwrap(),
            "Authorization: Bearer sk_agent_123",
        );
        assert_eq!(
            render_setup_template("{{proxy_base}}/openai/v1 vault={{vault}}", &inp).unwrap(),
            "http://127.0.0.1:8787/openai/v1 vault=v_abc",
        );
    }

    #[test]
    fn setup_template_rejects_vault_secret_tokens() {
        // The setup context must NEVER resolve a vault secret — `secret.*` /
        // `oauth.*` are unknown tokens here, hard-erroring rather than leaking.
        // `{{route}}` was dropped too, so it now hard-errors like any other.
        let inp = SetupInputs {
            proxy_base: "http://127.0.0.1:8787",
            api_key: "sk_agent_123",
            vault: "v",
        };
        assert!(render_setup_template("{{secret.github_token}}", &inp).is_err());
        assert!(render_setup_template("{{oauth.access_token}}", &inp).is_err());
        assert!(render_setup_template("{{route}}", &inp).is_err());
        assert!(render_setup_template("{{bogus}}", &inp).is_err());
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
    conn_id: &str,
    service_id: &str,
    raw: &[u8],
) -> Result<Vec<u8>> {
    let svc = state.services.get(service_id);
    let auth = svc
        .and_then(|s| s.upstream.first())
        .and_then(|u| u.auth.as_ref());
    let is_oauth = auth.map(|a| state.services.auth_is_oauth2(a)).unwrap_or(false);
    if !is_oauth {
        return Ok(raw.to_vec());
    }
    let auth = auth.expect("oauth2 branch implies auth present");

    // Cache hit — return the cached access_token directly. Keyed by the
    // **connection** (not service) so two accounts of one service don't collide.
    if let Some(cached) = state.oauth_access_lookup(vault_id, conn_id) {
        return Ok(cached);
    }

    // Cache miss → call the provider's /token endpoint to mint a fresh
    // access_token from our refresh_token. Endpoints + client come from the
    // resolved provider (literal public Desktop client) when `auth.provider`
    // is set, falling back to the legacy env-var path for self-hosted
    // confidential clients.
    let oauth = state.services.resolve_oauth_config(auth);
    let token_url = oauth.token_url.as_deref().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but no token_url (provider or auth.token_url)",
            service_id
        ))
    })?;
    let client_id = oauth.client_id.clone().ok_or_else(|| {
        AppError::Internal(format!(
            "service '{}' is oauth2 but no client_id (provider or client_id_env)",
            service_id
        ))
    })?;
    // client_secret is optional — PKCE flows (OpenAI Codex / Anthropic)
    // omit it; public Desktop clients (Google) and confidential clients
    // supply it.
    let client_secret = oauth.client_secret.clone();

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
    // doesn't grab a near-expired token. Keyed by connection.
    let safe_expires_at = expires_at.saturating_sub(60);
    state.oauth_access_insert(
        vault_id,
        conn_id,
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
    // SSRF recheck: a `{{connection.host}}` slot may have resolved to a concrete
    // host above — re-validate the resolved authority before egress (defense in
    // depth over the connect-time check; CONNECTION_SCHEMA.md §4). A literal host
    // already passed the load-time validator, so this is a cheap no-op for it.
    if let Some(authority) = url_rendered
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
