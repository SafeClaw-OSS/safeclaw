//! Broker-plane auth — gates the agent's `/v/{vid}/export/*` stub route on the
//! daemon's control plane (scoped via `server::broker_router`). Live credential
//! traffic no longer takes an HTTP route — it rides the resident phantom-only
//! proxy — so the disabled `/export` raw-exfil stub is the sole agent-facing
//! HTTP surface that carries this gate.
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

use crate::error::{AppError, Result};
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub(crate) fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Pull the agent key out of an `Authorization: Bearer <key>` header — the
/// agent's broker-plane credential.
fn extract_key(auth: Option<&str>) -> Option<String> {
    let auth = auth?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(|t| t.to_string())
}

/// Verify the `Authorization` header (Bearer or Basic) against the synced
/// agent-key hash-set.
pub fn check(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let provided = extract_key(headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()));
    let hashes = state.agent_key_hashes.lock().unwrap();
    check_token(&hashes, provided.as_deref())
}

/// Pure broker-auth decision (testable). Valid iff a token is present and
/// `sha256(token)` is a member of the synced hash-set. An empty set (unpaired /
/// not-yet-synced) rejects everything. Shared by the control-plane middleware
/// (Bearer, above) AND the 23294 proxy/API face (`proxy::api_face` reads the
/// Bearer header, the proxy pipeline reads the Proxy-Auth Basic password) — both
/// feed the extracted token here, so there is ONE membership check.
pub(crate) fn check_token(
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
    fn extract_key_bearer_only() {
        // Bearer: the token is the key (case-insensitive scheme).
        assert_eq!(
            extract_key(Some("Bearer sc_agent_x")).as_deref(),
            Some("sc_agent_x")
        );
        assert_eq!(
            extract_key(Some("bearer sc_agent_x")).as_deref(),
            Some("sc_agent_x")
        );
        // Non-Bearer / absent → None (the daemon gate takes Bearer only).
        assert_eq!(extract_key(Some("Basic Zm9vOmJhcg==")), None);
        assert_eq!(extract_key(None), None);
    }
}

/// Axum middleware gating the broker plane. Layered on `server::broker_router`
/// only (the `/export` stub) — never on the control routes. A missing/invalid
/// key yields a plain JSON 401.
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if let Err(e) = check(&state, &headers) {
        return e.into_response();
    }
    next.run(request).await
}
