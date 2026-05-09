use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::json;

use crate::state::AppState;

pub async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let tenant_count = state.tenants.list().map(|v| v.len()).unwrap_or(0);
    Json(json!({
        "ok": true,
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "tenant_count": tenant_count,
    }))
}
