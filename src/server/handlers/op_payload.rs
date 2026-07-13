//! `POST /v/{vid}/op-payload` — deposit the secret VALUES of an upcoming
//! write op (`connection-add` / `secret-set`) with the local daemon.
//!
//! Why this exists: a pending op's FULL JSON rides to the cloud op-relay as
//! `op_summary` (the grant page renders it and recomputes β over it), so
//! plaintext values must never live in `act.scope`. The CLI deposits them here
//! first; the daemon answers with a salted digest; the op carries only that
//! digest. The passkey gesture binds the digest via β, and the act consumes
//! the stash (single-use, op-TTL lifetime) after re-verifying it — the values
//! never leave this machine, and the cloud-visible digest can't be
//! brute-forced (the salt stays local).
//!
//! Body: `{ "values": { "KEY": "value", … } }` — env-valid UPPERCASE keys.
//! Response: `{ "values_digest": "<hex>" }`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::state::AppState;

/// Per-deposit caps — a connection carries a handful of keys, not a dataset.
const MAX_KEYS: usize = 32;
const MAX_VALUE_BYTES: usize = 64 * 1024;

pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>> {
    crate::server::handlers::op::validate_vault_id(&vault_id)?;
    let values_in = body
        .get("values")
        .and_then(|v| v.as_object())
        .ok_or_else(|| AppError::BadRequest("body.values (object) required".into()))?;
    if values_in.is_empty() || values_in.len() > MAX_KEYS {
        return Err(AppError::BadRequest(format!(
            "values must carry 1..={} keys",
            MAX_KEYS
        )));
    }
    let mut values = std::collections::BTreeMap::new();
    for (k, v) in values_in {
        if !crate::cli::conn::valid_role(k) || k.to_ascii_uppercase() != *k {
            return Err(AppError::BadRequest(format!(
                "'{}' is not a valid UPPERCASE env key",
                k
            )));
        }
        let val = v
            .as_str()
            .ok_or_else(|| AppError::BadRequest(format!("value for '{}' must be a string", k)))?;
        if val.is_empty() || val.len() > MAX_VALUE_BYTES {
            return Err(AppError::BadRequest(format!(
                "value for '{}' must be 1..={} bytes",
                k, MAX_VALUE_BYTES
            )));
        }
        values.insert(k.clone(), val.to_string());
    }
    let digest = state
        .op_payload_insert(values)
        .ok_or(AppError::TooManyRequests)?;
    Ok(Json(json!({ "values_digest": digest })))
}
