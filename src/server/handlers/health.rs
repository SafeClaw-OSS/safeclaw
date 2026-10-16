use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(health_value(&state))
}

/// The `/health` body as a plain `Value` — shared by the axum handler (above)
/// and the 23294 API face (`proxy::api_face`, unauthenticated liveness).
pub fn health_value(state: &AppState) -> Value {
    let vault_count = state.vaults.list().map(|v| v.len()).unwrap_or(0);
    let ledger = state.ledger.lock().unwrap().clone();
    let device = match ledger.device {
        crate::principal_ledger::DeviceGate::Open => "admitted",
        crate::principal_ledger::DeviceGate::NotAdmitted => "not_admitted",
        crate::principal_ledger::DeviceGate::AccountMissing => "account_missing",
        crate::principal_ledger::DeviceGate::Stale => "stale",
        crate::principal_ledger::DeviceGate::Revoked => "revoked",
    };
    json!({
        "ok": true,
        "version": crate::build_version(),
        "vault_count": vault_count,
        "device": {
            "standing": device,
            "checked_at": ledger.checked_at,
        },
        // Items the last fold of each vault had to skip. A total only: this
        // endpoint is unauthenticated, so which vault/item lives in the log.
        "unreadable_items": crate::storage::sealed_vault::unreadable_item_total(),
    })
}
