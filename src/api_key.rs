//! Broker-plane auth — gates the agent BROKER plane (the proxy port,
//! `/v/{vid}/use/*` + `/v/{vid}/export/*`).
//!
//! This is the agent→daemon credential (Token 1): it authenticates the local
//! AGENT to the daemon, so a random other process on the same machine can't
//! drive the broker (and exfiltrate credentials) just by reaching `127.0.0.1`.
//! Deliberately **distinct from `crate::auth::bearer`** (which injects a bearer
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

use crate::error::{AppError, Result};
use crate::state::AppState;

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify `Authorization: Bearer <key>` against the synced agent-key hash-set.
pub fn check(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });
    let hashes = state.agent_key_hashes.lock().unwrap();
    check_token(&hashes, provided)
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
}

/// Axum middleware gating the broker plane. Apply to the proxy router only.
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
