//! `GET /v/{vid}/keys-known` — what item names this vault can resolve.
//!
//! Returns the union of:
//!   * native-secrets item names (from the unlocked cache, no network)
//!   * each external store's `list()` output (live call per store, with
//!     a short timeout — partial success is fine)
//!
//! Frontend uses this to compute "is service X reachable" without having
//! to maintain per-service "connected" flags or guess from kv presence
//! alone (which would mis-report a service whose key lives in GCP).
//!
//! Response shape:
//! ```json
//! {
//!   "keys": ["openai_api_key", "github_token", ...],
//!   "store_errors": [
//!     { "store_id": "prod-gcp", "error": "listSecrets returned 403: ..." }
//!   ]
//! }
//! ```
//!
//! Errors at the *individual* store level are non-fatal — they only mean
//! that store's contribution is missing from the returned union. A
//! frontend showing "OpenAI: Not configured" when the SA lacks list
//! permission is a known limitation we surface explicitly via
//! `store_errors` rather than silently under-report.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::server::handlers::op::validate_vault_id;
use crate::state::{AppState, VaultState};
use crate::store::adapters::gcp::GcpSecretManagerAdapter;

/// Per-store live-list timeout. Short enough that a stalled GCP call
/// doesn't hang the page load, long enough that a normal cross-region
/// listSecrets completes (typical ~300-800ms).
const LIST_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn keys_known(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;

    // Snapshot what we need under the lock, then drop it before any
    // network work — list() is async and we don't want to hold the
    // vault-states mutex across an await.
    let (mut keys, external_stores) = {
        let states = state.vault_states.lock().unwrap();
        let cache = match states.get(&vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return Err(AppError::Conflict("vault locked — unlock first".into())),
        };
        let keys: HashSet<String> = cache.native_keys.iter().cloned().collect();
        let external = cache.external_stores.clone();
        (keys, external)
    };

    let mut store_errors: Vec<Value> = Vec::new();

    for (store_id, (store, sa_json)) in external_stores {
        // V1: only gcp-secret-manager is wired through here. Other kinds
        // remain `unsupported`; they'd never have been inserted into
        // `external_stores` in the first place (bootstrap filters by
        // kind), but we double-check for forward-compat.
        if store.kind != "gcp-secret-manager" {
            continue;
        }
        let project_id = match store
            .extra
            .get("project_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        {
            Some(p) => p,
            None => {
                store_errors.push(json!({
                    "store_id": store_id,
                    "error": "missing project_id"
                }));
                continue;
            }
        };
        let adapter = match GcpSecretManagerAdapter::new(project_id, sa_json) {
            Ok(a) => a,
            Err(e) => {
                store_errors.push(json!({ "store_id": store_id, "error": e.to_string() }));
                continue;
            }
        };
        match tokio::time::timeout(LIST_TIMEOUT, adapter.list()).await {
            Ok(Ok(names)) => keys.extend(names),
            Ok(Err(e)) => store_errors.push(json!({
                "store_id": store_id,
                "error": e.to_string(),
            })),
            Err(_) => store_errors.push(json!({
                "store_id": store_id,
                "error": format!("timed out after {}s", LIST_TIMEOUT.as_secs()),
            })),
        }
    }

    let mut keys: Vec<String> = keys.into_iter().collect();
    keys.sort();

    Ok(Json(json!({
        "keys": keys,
        "store_errors": store_errors,
    })))
}
