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
//! Security posture — the passkey gates TRUST-SURFACE CHANGE, not data entry:
//!
//!   - **A NEW egress host never rides this path.** Anchoring a host this
//!     connection doesn't already anchor verbatim widens the egress allowlist —
//!     the exact act `widen-host` passkey-gates — so a local rogue process must
//!     not be able to mint itself an exfil destination while the vault happens
//!     to be open. Any not-already-anchored host answers
//!     `{ "written": false, "needs_approval": true, "new_hosts": [...] }` and
//!     the CLI falls back to the grant ceremony. (A TTY confirm was considered
//!     and rejected: any process can drive a pty, so it gates nothing.)
//!   - What DOES ride free while unlocked: value-only rewrites (token
//!     rotation), `no_broker` human-only items, and host lists that are a
//!     verbatim subset of the existing anchor (narrowing is safe). Residual
//!     risk is integrity-shaped (a local process can overwrite a value); it
//!     can't read stored values and can't widen where they may be sent.
//!   - The value rides the LOCAL control plane in plaintext (like
//!     `op-payload`), never the cloud. When the vault is LOCKED, `K` isn't
//!     resident: the endpoint answers `{ "written": false, "locked": true }`
//!     and the CLI falls back to the passkey ceremony (which unlocks + writes).
//!
//! Body: `{ "key": "FOO", "value": "…", "hosts": ["api.x.com"]?, "no_broker": bool? }`.
//! Response: `{ "written": true, "key", "conn", "hosts", "removed_prior_anchor" }`,
//! `{ "written": false, "locked": true }`, or
//! `{ "written": false, "needs_approval": true, "new_hosts": [...] }`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::state::AppState;

const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Requested hosts NOT already anchored verbatim on the connection — the set
/// that would WIDEN egress and therefore needs the passkey ceremony. Literal
/// string compare on anchors (incl. wildcards): `api.x.com` under an existing
/// `*.x.com` still counts as new — conservative on purpose, ceremony decides.
fn hosts_not_already_anchored(
    existing: Option<&crate::storage::plaintext::Connection>,
    requested: &[String],
) -> Vec<String> {
    let have: std::collections::HashSet<&str> = existing
        .and_then(|c| c.hosts.as_ref())
        .map(|h| h.iter().map(String::as_str).collect())
        .unwrap_or_default();
    requested
        .iter()
        .filter(|h| !have.contains(h.as_str()))
        .cloned()
        .collect()
}

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
    let (removed_prior_anchor, current_anchors) = {
        let lock = state.vault_write_lock(&vault_id);
        let _guard = lock.lock().await;
        let mut view =
            crate::server::handlers::metadata::open_view_with_state_key(&state, &vault_id, &k)?;
        // Egress gate: a host this connection doesn't already anchor VERBATIM
        // is a trust-surface widening (same act as `widen-host`) — never free.
        // The check lives HERE, on the daemon against the just-opened view, so
        // a process talking to the endpoint directly can't skip it.
        if !hosts.is_empty() {
            let new_hosts = hosts_not_already_anchored(view.aux.connections.get(&conn), &hosts);
            if !new_hosts.is_empty() {
                return Ok(Json(json!({
                    "written": false,
                    "needs_approval": true,
                    "new_hosts": new_hosts,
                })));
            }
        }
        let removed = crate::server::handlers::approve::apply_secret_set_to_view(
            &mut view,
            &key,
            value.as_bytes().to_vec(),
            &hosts,
            no_broker,
        );
        // On a value-only write, echo the (untouched) anchors back to the CLI.
        let anchors: Vec<String> = if hosts.is_empty() && !no_broker {
            view.aux
                .connections
                .get(&conn)
                .and_then(|c| c.hosts.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
            .map_err(AppError::Internal)?;
        (removed, anchors)
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
        // A value-only write echoes the connection's CURRENT (untouched)
        // anchors so the CLI can show what the key still routes to.
        "hosts": if hosts.is_empty() { current_anchors } else { hosts },
        "removed_prior_anchor": removed_prior_anchor,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::plaintext::Connection;

    fn conn_with_hosts(hosts: &[&str]) -> Connection {
        Connection {
            hosts: Some(hosts.iter().map(|s| s.to_string()).collect()),
            ..Connection::default()
        }
    }

    #[test]
    fn new_host_detection_gates_widening_only() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // No existing connection: every requested host is new.
        assert_eq!(
            hosts_not_already_anchored(None, &v(&["api.x.com"])),
            v(&["api.x.com"])
        );
        // Verbatim subset (incl. narrowing): nothing new — rides free.
        let c = conn_with_hosts(&["api.x.com", "*.y.io"]);
        assert!(hosts_not_already_anchored(Some(&c), &v(&["api.x.com"])).is_empty());
        assert!(hosts_not_already_anchored(Some(&c), &v(&["*.y.io", "api.x.com"])).is_empty());
        // Any not-already-anchored host trips the gate.
        assert_eq!(
            hosts_not_already_anchored(Some(&c), &v(&["api.x.com", "evil.com"])),
            v(&["evil.com"])
        );
        // Literal compare: a concrete host under an existing wildcard still
        // counts as new (conservative — the ceremony decides).
        assert_eq!(
            hosts_not_already_anchored(Some(&c), &v(&["sub.y.io"])),
            v(&["sub.y.io"])
        );
    }
}
