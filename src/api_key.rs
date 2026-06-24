//! API key — gates the agent BROKER plane (the proxy port,
//! `/v/{vid}/use/*` + `/v/{vid}/export/*`) on a self-hosted daemon.
//!
//! This is the agent→daemon credential (Token 1): it authenticates the
//! local AGENT to the daemon, so that a random other process on the same
//! machine can't drive the broker (and exfiltrate credentials) just by
//! reaching `127.0.0.1`. Deliberately **distinct from
//! `crate::auth::bearer`**, which injects a bearer into the *upstream*
//! request, and from the daemon→cloud `device-key` written by `sc login`.
//!
//! Storage + value: the key lives at `~/.safeclaw/api-key` (0600) as
//! `sc_api_<hex>` (the `sc_api_` prefix + 32 bytes of OS randomness, hex).
//! It is provisioned by `sc install` / `sc custodian start` and the **same
//! value is read by the daemon directly from that file at startup** (NOT
//! from an env var — `SAFECLAW_API_KEY` is the agent-facing name and must
//! not be adopted by the daemon, to avoid colliding with a stray
//! `SAFECLAW_API_KEY` in the operator's shell). `sc install` prints the
//! same value to the agent as `SAFECLAW_API_KEY`.
//!
//! Enforcement model: **enforce-only-if-provisioned.** When
//! `config.api_key` is `None` the broker plane is auth-free — the
//! historical self-host localhost default. When it is `Some(key)`, every
//! broker request must carry `Authorization: Bearer <key>` or it gets a
//! 401. The admin plane (registry / op / approve) is intentionally NOT
//! gated here — there the per-op `op_id` is the capability, and approval
//! is passkey-signed.

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

/// `sc_api_` — value prefix for the agent→daemon API key.
const API_KEY_PREFIX: &str = "sc_api_";

/// `~/.safeclaw/api-key` — the provisioned machine-local secret.
pub fn key_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".safeclaw").join("api-key"))
}

/// Read the api-key, generating it (`sc_api_` + 32 bytes of OS randomness,
/// hex-encoded) on first use. Idempotent; the file is chmod 0600. Called by
/// `sc install` and `sc custodian start` so the daemon and the local agent
/// share one secret, and read directly by the daemon at startup. Never
/// logged.
pub fn ensure_key() -> std::result::Result<String, String> {
    let path = key_path().ok_or("cannot locate home dir for api-key")?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let key = existing.trim().to_string();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    let key = generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    std::fs::write(&path, &key).map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: the key only protects a localhost broker; a failure
        // to tighten perms shouldn't abort install on exotic filesystems.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

/// Read the provisioned api-key from `~/.safeclaw/api-key` without
/// generating one. Returns `None` when the file is absent or empty —
/// auth-free self-host mode. The daemon calls this at startup to populate
/// `config.api_key` (file-read, never an env var; see module docs).
pub fn load_key() -> Option<String> {
    let path = key_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// `sc_api_` + 32 bytes of OS randomness, lowercase hex (64 chars;
/// header/env-safe, no `+/=` to escape).
fn generate() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}{}", API_KEY_PREFIX, hex)
}

/// Verify `Authorization: Bearer <key>` against the configured api-key.
/// Returns `Ok(())` immediately when no key is provisioned (auth-free
/// mode). Constant-time compare mirrors the admin-key path.
pub fn check(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let expected = match state.config.api_key.as_deref() {
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
        Err(AppError::Unauthorized("invalid api key".into()))
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
