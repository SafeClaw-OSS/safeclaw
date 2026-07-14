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
    json!({
        "ok": true,
        "version": crate::build_version(),
        "vault_count": vault_count,
    })
}
