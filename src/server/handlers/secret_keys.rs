//! `GET /v/{vid}/secret-keys` — per-store breakdown of what this vault can resolve.
//!
//! Returns native-secrets item names + each external store's `list()` output
//! tagged with the store id. Frontend uses this to render the unified Entries
//! view (one row per effective key with a source badge + shadowed-by chip)
//! and to drive "is service X reachable" checks across Connections /
//! Permissions / Overview.
//!
//! Response shape:
//! ```json
//! {
//!   "native_keys": ["openai_api_key", "github_token", ...],
//!   "stores": [
//!     { "id": "prod-gcp", "kind": "gcp-secret-manager", "keys": ["openai_api_key", "stripe_key"] }
//!   ],
//!   "store_errors": [
//!     { "store_id": "prod-gcp", "error": "listSecrets returned 403: ..." }
//!   ]
//! }
//! ```
//!
//! Errors at the individual store level are non-fatal — they only mean
//! that store's keys are missing from the response. A frontend showing
//! "OpenAI: Not configured" when the SA lacks list permission is a
//! known limitation we surface explicitly via `store_errors`.

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

/// Per-store live-list timeout. Short enough that a stalled GCP call
/// doesn't hang the page load, long enough that a normal cross-region
/// listSecrets completes (typical ~300-800ms).
const LIST_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn secret_keys(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;

    // Snapshot what we need under the lock, then drop it before any
    // network work — list() is async and we don't want to hold the
    // vault-states mutex across an await.
    let (mut native_keys, external_stores, init_errors) = {
        let states = state.vault_states.lock().unwrap();
        let cache = match states.get(&vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return Err(AppError::VaultLocked),
        };
        let native: Vec<String> = cache.native_keys.iter().cloned().collect();
        let external = cache.external_stores.clone();
        (native, external, cache.external_store_errors.clone())
    };
    native_keys.sort();

    let mut stores: Vec<Value> = Vec::new();
    let mut store_errors: Vec<Value> = Vec::new();
    // Stores that never materialised at unlock (bad credentials/config)
    // stay visible as errors — a broken store must look broken, not absent.
    for (store_id, reason) in init_errors {
        store_errors.push(json!({ "store_id": store_id, "error": reason }));
    }

    for (store_id, (store, adapter)) in external_stores {
        // The session cache holds ONE live adapter per store (built at
        // unlock, OAuth token cached inside) — list through it instead of
        // constructing a throwaway instance per page load.
        match tokio::time::timeout(LIST_TIMEOUT, adapter.list()).await {
            Ok(Ok(mut names)) => {
                names.sort();
                stores.push(json!({
                    "id": store_id,
                    "kind": store.kind,
                    "keys": names,
                }));
            }
            Ok(Err(e)) => {
                // F-20: log the full error (may contain project id / GCP response body)
                // server-side only; return a sanitised summary to the caller so we
                // don't leak GCP project identifiers or raw API responses.
                tracing::warn!(store = %store_id, "secret-keys list error: {}", e);
                store_errors.push(json!({
                    "store_id": store_id,
                    "error": format!("store '{}' unavailable", store_id),
                }));
            }
            Err(_) => store_errors.push(json!({
                "store_id": store_id,
                "error": format!("timed out after {}s", LIST_TIMEOUT.as_secs()),
            })),
        }
    }

    Ok(Json(json!({
        "native_keys": native_keys,
        "stores": stores,
        "store_errors": store_errors,
    })))
}
