//! `/admin/*` — operator-driven endpoints that bypass normal vault auth.
//!
//! Today:
//!   - `GET    /admin/vaults`       list all vault ids on this daemon
//!   - `DELETE /admin/vaults/{vid}` nuke a vault (SaaS demo-data cleanup;
//!                                  also lets OSS operator wipe a vault
//!                                  whose user lost their passkey)
//!
//! Each request must carry `X-Admin-Key: <secret>` matching the daemon's
//! `SAFECLAW_ADMIN_KEY` env. When the env is unset the whole surface
//! returns 403 — admin endpoints are off by default so an OSS deploy
//! that doesn't opt in is never exposed.
//!
//! NOTE: this is deliberately a "trust the holder of the shared secret"
//! design, not RBAC. The secret is a single shared value between
//! daemon and SaaS; rotation means redeploying both. Compromise of the
//! secret is equivalent to compromise of the SaaS service-role key,
//! which is the existing trust boundary for cleanup operations.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::error::{AppError, Result};
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;

const ADMIN_KEY_HEADER: &str = "x-admin-key";

fn check_admin_key(state: &AppState, headers: &HeaderMap) -> Result<()> {
    let expected = state.config.admin_key.as_deref().ok_or_else(|| {
        AppError::Forbidden("admin endpoints disabled (no SAFECLAW_ADMIN_KEY set)".into())
    })?;
    let provided = headers
        .get(ADMIN_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing X-Admin-Key header".into()))?;
    // Constant-time compare: a wrong key shouldn't reveal its length-prefix
    // via response timing. Pad both sides to a fixed width via subtle's
    // ct_eq, which handles unequal lengths by returning false without
    // short-circuiting.
    let matched: bool = expected.as_bytes().ct_eq(provided.as_bytes()).into();
    if matched {
        Ok(())
    } else {
        Err(AppError::Unauthorized("invalid admin key".into()))
    }
}

/// `GET /admin/vaults` — list all vault ids materialised on disk.
///
/// Returns just the ids; no contents, no sizes, no unlock state. Useful
/// for an OSS operator to enumerate what's on this daemon (e.g. for a
/// `sc admin vaults ls` view) and for SaaS cleanup tooling to reconcile
/// against the Supabase side. Vault list is alphabetised for stable
/// output.
pub async fn list_vaults(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    check_admin_key(&state, &headers)?;
    let mut vaults = state.vaults.list()?;
    vaults.sort();
    Ok(Json(json!({
        "vaults": vaults,
    })))
}

/// `DELETE /admin/vaults/{vid}` — nuke a vault's daemon-side state.
///
/// Idempotent — non-existent vault returns ok with `existed: false`.
/// Always returns 200 on auth + valid id; the body tells the caller
/// what actually happened.
pub async fn delete_vault(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<Value>> {
    check_admin_key(&state, &headers)?;
    validate_vault_id(&vault_id)?;

    // 1. Drop any cached unlocked state — releases zeroized secrets and
    //    ensures subsequent requests don't see ghost data after the dir
    //    is gone.
    {
        let mut states = state.vault_states.lock().unwrap();
        states.remove(&vault_id);
    }

    // 2. Close the audit SQLite handle (if any) before deleting its
    //    backing file. AuditRegistry::forget is a no-op for vaults
    //    that never opened.
    state.audits.forget(&vault_id);

    // 3. rm -rf the vault directory. `vaults.remove` is itself
    //    idempotent; existed is captured beforehand for diagnostics.
    let existed = state.vaults.dir_for(&vault_id)?.exists();
    state.vaults.remove(&vault_id)?;

    tracing::info!(vault = %vault_id, existed, "admin: vault deleted");

    Ok(Json(json!({
        "ok": true,
        "vault_id": vault_id,
        "existed": existed,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use crate::config::Config;
    use crate::state::AppState;
    use std::path::PathBuf;

    fn state_with_key(key: Option<&str>) -> AppState {
        let mut cfg = Config {
            state_dir: PathBuf::from("/tmp/safeclaw-admin-test"),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            admin_key: key.map(|s| s.to_string()),
            api_key: None,
            relay_url: None,
        };
        let _ = std::fs::create_dir_all(&cfg.state_dir);
        let _ = std::fs::create_dir_all(cfg.state_dir.join("vaults"));
        // Suppress unused warnings; the AppState constructor reads cfg fields.
        let _ = &mut cfg;
        AppState::new(cfg)
    }

    fn headers_with(key: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(k) = key {
            h.insert(ADMIN_KEY_HEADER, HeaderValue::from_str(k).unwrap());
        }
        h
    }

    #[test]
    fn disabled_when_env_unset() {
        let state = state_with_key(None);
        let r = check_admin_key(&state, &headers_with(Some("anything")));
        assert!(matches!(r, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn missing_header_when_enabled() {
        let state = state_with_key(Some("right"));
        let r = check_admin_key(&state, &headers_with(None));
        assert!(matches!(r, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn wrong_key_rejected() {
        let state = state_with_key(Some("right"));
        let r = check_admin_key(&state, &headers_with(Some("wrong")));
        assert!(matches!(r, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn correct_key_accepted() {
        let state = state_with_key(Some("right"));
        let r = check_admin_key(&state, &headers_with(Some("right")));
        assert!(r.is_ok());
    }

    #[test]
    fn different_length_keys_rejected_in_constant_time() {
        // Just confirms ct_eq handles different-length inputs without
        // panicking. Timing-channel claims would need a benchmark.
        let state = state_with_key(Some("right"));
        let r = check_admin_key(&state, &headers_with(Some("rig")));
        assert!(matches!(r, Err(AppError::Unauthorized(_))));
    }
}
