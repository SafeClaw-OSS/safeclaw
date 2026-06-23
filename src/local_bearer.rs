//! Local bearer token — gates the agent BROKER plane (the proxy port,
//! `/v/{vid}/use/*` + `/v/{vid}/export/*`) on a self-hosted daemon.
//!
//! This is deliberately **distinct from `crate::auth::bearer`**, which
//! injects a bearer into the *upstream* request. Here the token
//! authenticates the local AGENT to the daemon, so that a random other
//! process on the same machine can't drive the broker (and exfiltrate
//! credentials) just by reaching `127.0.0.1`.
//!
//! Enforcement model: **enforce-only-if-provisioned.** When
//! `config.local_bearer` is `None` the broker plane is auth-free — the
//! historical self-host localhost default. When it is `Some(token)`, every
//! broker request must carry `Authorization: Bearer <token>` or it gets a
//! 401. The token is provisioned by `sc install` / `sc custodian start`
//! into `~/.safeclaw/bearer.token` (0600) and embedded into the generated
//! systemd unit as `SAFECLAW_LOCAL_BEARER`; the same value is printed to the
//! agent as `SAFECLAW_API_KEY`. The admin plane (registry / op / approve) is
//! intentionally NOT gated here — there the per-op `op_id` is the capability,
//! and approval is passkey-signed.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;

use crate::error::{AppError, Result};
use crate::state::AppState;

/// `~/.safeclaw/bearer.token` — the provisioned machine-local secret.
pub fn token_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".safeclaw").join("bearer.token"))
}

/// Read the local-bearer token, generating it (32 bytes of OS randomness,
/// hex-encoded) on first use. Idempotent; the file is chmod 0600. Called by
/// `sc install` and `sc custodian start` so the daemon and the local agent
/// share one secret. Never logged.
pub fn ensure_token() -> std::result::Result<String, String> {
    let path = token_path().ok_or("cannot locate home dir for bearer token")?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let token = existing.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }
    let token = generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    std::fs::write(&path, &token).map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: the token only protects a localhost broker; a failure
        // to tighten perms shouldn't abort install on exotic filesystems.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

/// 32 bytes of OS randomness, lowercase hex (64 chars; header/env-safe, no
/// `+/=` to escape).
fn generate() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify `Authorization: Bearer <token>` against the configured local
/// bearer. Returns `Ok(())` immediately when no bearer is provisioned
/// (auth-free mode). Constant-time compare mirrors the admin-key path.
pub fn check(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let expected = match state.config.local_bearer.as_deref() {
        None => return Ok(()),
        Some(e) => e,
    };
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .ok_or_else(|| {
            AppError::Unauthorized("missing or malformed Authorization: Bearer header".into())
        })?;
    let matched: bool = expected.as_bytes().ct_eq(provided.as_bytes()).into();
    if matched {
        Ok(())
    } else {
        Err(AppError::Unauthorized("invalid local bearer token".into()))
    }
}

/// Axum middleware gating the broker plane. Apply to the proxy router only.
pub async fn require_bearer(
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
