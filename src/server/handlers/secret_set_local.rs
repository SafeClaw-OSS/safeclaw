//! `POST /v/{vid}/secret` — local, unlocked-only secret write (no passkey).
//!
//! `sc set` normally mints a `secret-set` op and drives it through the passkey
//! grant ceremony (the grant delivers `W_c`, which recovers `K` to open + reseal
//! the vault). But the daemon already RETAINS `K` while a vault is unlocked
//! ("vault key resident while unlocked", state.rs `VaultState::Unlocked`), and
//! it already writes to the open vault under that `K` without a fresh passkey on
//! the OAuth connect-completion path (auth/connect.rs). This endpoint extends
//! that same resident-`K` write to `sc set`: while the vault is UNLOCKED, store
//! the value directly — no op, no passkey — so an owner who has unlocked once
//! isn't re-prompted on every `sc set`.
//!
//! Security posture: the value rides the LOCAL control plane in plaintext (like
//! `op-payload`), never the cloud. The gate is "vault is unlocked" instead of a
//! per-write passkey. That relaxes INTEGRITY only (a local process can add or
//! overwrite items while the vault is open); it does NOT weaken confidentiality
//! (this endpoint only writes — it can't read an existing secret, and anchoring
//! a host requires overwriting the value, so a stored credential can't be
//! re-pointed-then-exfiltrated). When the vault is LOCKED, `K` isn't resident:
//! the endpoint answers `{ "written": false, "locked": true }` and the CLI falls
//! back to the passkey ceremony (which unlocks + writes).
//!
//! Body: `{ "key": "FOO", "value": "…", "hosts": ["api.x.com"]?, "no_broker": bool? }`.
//! Response: `{ "written": true, "key", "conn", "hosts", "removed_prior_anchor" }`
//! or `{ "written": false, "locked": true }`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::state::AppState;

const MAX_VALUE_BYTES: usize = 64 * 1024;

pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>> {
    crate::server::handlers::op::validate_vault_id(&vault_id)?;

    let key_raw = body
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("body.key (string) required".into()))?;
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("body.value (string) required".into()))?;
    if value.is_empty() || value.len() > MAX_VALUE_BYTES {
        return Err(AppError::BadRequest(format!(
            "value must be 1..={} bytes",
            MAX_VALUE_BYTES
        )));
    }
    let no_broker = body
        .get("no_broker")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let hosts: Vec<String> = body
        .get("hosts")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let (key, hosts) =
        crate::server::handlers::approve::validate_secret_set(key_raw, &hosts, no_broker)?;
    let conn = key.to_ascii_lowercase();

    // The gate: `K` is resident only while the vault is unlocked. Locked → tell
    // the CLI to fall back to the passkey ceremony (which unlocks + writes).
    let Some(k) = state.cloned_state_key(&vault_id) else {
        return Ok(Json(json!({ "written": false, "locked": true })));
    };

    // Serialize with every other writer that reseals this vault body (connect
    // exchange, oauth rotation, grant-approve writes) — same lock those use.
    let removed_prior_anchor = {
        let lock = state.vault_write_lock(&vault_id);
        let _guard = lock.lock().await;
        let mut view =
            crate::server::handlers::metadata::open_view_with_state_key(&state, &vault_id, &k)?;
        let removed = crate::server::handlers::approve::apply_secret_set_to_view(
            &mut view,
            &key,
            value.as_bytes().to_vec(),
            &hosts,
            no_broker,
        );
        crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
            .map_err(AppError::Internal)?;
        removed
    };

    // Push AFTER the write guard drops — the push path re-takes the (non-
    // reentrant) per-vault write lock, exactly as the grant-approve path does.
    {
        let state = state.clone();
        let vid = vault_id.clone();
        tokio::spawn(async move {
            crate::sync::push_keys_best_effort(&state, &vid).await;
            crate::sync::push_items_best_effort(&state, &vid).await;
        });
    }

    tracing::info!(vault = %vault_id, key = %key, "secret set (unlocked, no passkey)");
    Ok(Json(json!({
        "written": true,
        "key": key,
        "conn": if hosts.is_empty() { Value::Null } else { json!(conn) },
        "hosts": hosts,
        "removed_prior_anchor": removed_prior_anchor,
    })))
}
