//! Broker-plane auth — gates the agent BROKER plane (the four broker routes
//! `/v/{vid}/use/*`, `/v/{vid}/stream/*`, `/v/{vid}/export/*` on the daemon's
//! single port, scoped via `server::broker_router`).
//!
//! This is the agent→daemon credential (Token 1): it authenticates the local
//! AGENT to the daemon, so a random other process on the same machine can't
//! drive the broker (and exfiltrate credentials) just by reaching `127.0.0.1`.
//! Deliberately **distinct from the upstream OAuth bearer** (which injects a bearer
//! into the *upstream* request) and from the daemon→cloud `device-key` written
//! by `sc login`.
//!
//! Auth model (agent ≡ api-key, account-level): the only authority is the
//! cloud-synced set of agent-key HASHES
//! (`AppState.agent_key_hashes`, refreshed from `/api/vault/agents/hashes` by
//! `crate::sync`). A presented `Authorization: Bearer <key>` is valid iff
//! `sha256(key)` is a member of that set — so any of the account's agent keys
//! works on this daemon, and a dashboard revoke takes effect on the next sync.
//! An empty set rejects everything: a paired daemon requires an agent key, and
//! an unpaired/local-only daemon has no agent to broker for. There is NO
//! single-key file and NO auth-free fallback. See
//! [[project_vault_agent_architecture_2026_06_25]].

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::error::{AppError, Result};
use crate::state::AppState;

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Pull the agent key out of an `Authorization` header. Two transports carry the
/// same key:
///   - `Bearer <key>` — the agent's normal broker call.
///   - `Basic base64("<user>:<key>")` — git's credential helper hands git a
///     username/password, which git sends as Basic; the username is ignored and
///     the **password** is the key. This is what lets `git` authenticate to the
///     broker for the streaming (smart-HTTP) route without the key on disk.
fn extract_key(auth: Option<&str>) -> Option<String> {
    let auth = auth?;
    if let Some(t) = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
    {
        return Some(t.to_string());
    }
    if let Some(b64) = auth
        .strip_prefix("Basic ")
        .or_else(|| auth.strip_prefix("basic "))
    {
        let decoded = STANDARD.decode(b64.trim()).ok()?;
        let creds = String::from_utf8(decoded).ok()?;
        // The password is everything after the first ':' (a password may itself
        // contain ':', the username never does).
        return creds.split_once(':').map(|(_, pass)| pass.to_string());
    }
    None
}

/// Verify the `Authorization` header (Bearer or Basic) against the synced
/// agent-key hash-set.
pub fn check(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let provided = extract_key(headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()));
    let hashes = state.agent_key_hashes.lock().unwrap();
    check_token(&hashes, provided.as_deref())
}

/// Pure broker-auth decision (testable). Valid iff a Bearer token is present
/// and `sha256(token)` is a member of the synced hash-set. An empty set
/// (unpaired / not-yet-synced) rejects everything.
fn check_token(
    hashes: &std::collections::HashSet<String>,
    provided: Option<&str>,
) -> Result<()> {
    let token = provided.ok_or_else(|| {
        AppError::Unauthorized("missing or malformed Authorization: Bearer header".into())
    })?;
    if hashes.contains(&sha256_hex(token)) {
        Ok(())
    } else {
        Err(AppError::Unauthorized("invalid api key".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn broker_auth_hash_set_only() {
        // Empty set ⇒ reject everything (no auth-free, no single-key fallback).
        let empty = HashSet::new();
        assert!(check_token(&empty, None).is_err());
        assert!(check_token(&empty, Some("anything")).is_err());

        // Synced hash-set is the sole authority: sha256(key) must be a member.
        let mut hashes = HashSet::new();
        hashes.insert(sha256_hex("sc_agent_alice"));
        assert!(check_token(&hashes, Some("sc_agent_alice")).is_ok());
        assert!(check_token(&hashes, Some("sc_agent_eve")).is_err());
        assert!(check_token(&hashes, None).is_err());
    }

    #[test]
    fn extract_key_bearer_and_basic() {
        // Bearer: the token is the key.
        assert_eq!(extract_key(Some("Bearer sc_agent_x")).as_deref(), Some("sc_agent_x"));
        assert_eq!(extract_key(Some("bearer sc_agent_x")).as_deref(), Some("sc_agent_x"));
        // Basic: base64("<user>:<key>") — username ignored, password is the key.
        let basic = format!("Basic {}", STANDARD.encode(b"safeclaw:sc_agent_x"));
        assert_eq!(extract_key(Some(&basic)).as_deref(), Some("sc_agent_x"));
        // A key containing ':' survives (split on the FIRST colon only).
        let weird = format!("Basic {}", STANDARD.encode(b"git:sc:agent:x"));
        assert_eq!(extract_key(Some(&weird)).as_deref(), Some("sc:agent:x"));
        // Junk / absent → None.
        assert_eq!(extract_key(Some("Basic !!notb64")), None);
        assert_eq!(extract_key(None), None);
    }
}

/// Axum middleware gating the broker plane. Layered on `server::broker_router`
/// only (the four broker routes) — never on the control routes.
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if let Err(e) = check(&state, &headers) {
        let mut resp = e.into_response();
        // On the streaming route, advertise HTTP Basic so git's credential
        // machinery engages: git only consults a credential helper after a 401
        // carrying `WWW-Authenticate`. The helper then supplies the agent key as
        // the Basic password (see `extract_key`). Scoped to `/stream/` so the
        // `/use/` + `/export/` API surface keeps its plain JSON 401.
        if request.uri().path().contains("/stream/") {
            if let Ok(v) = axum::http::HeaderValue::from_str("Basic realm=\"safeclaw\"") {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, v);
            }
        }
        return resp;
    }
    next.run(request).await
}
