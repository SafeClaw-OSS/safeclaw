//! `POST /proxy/reload` — hot-reload the device egress proxy into the running
//! daemon's swappable clients after `sc proxy set/clear` rewrites the stored
//! value. It re-points BOTH egress paths — the shared reqwest client (OAuth
//! mint / GCP / snaplii, via [`crate::core::forward::reload_egress_proxy`]) and
//! the resident proxy's forward connector (the shared [`AppState::egress_proxy`]
//! cell) — with NO daemon restart, so the in-memory vault key survives and the
//! operator never re-unlocks.
//!
//! Takes NO parameters: it always re-reads the on-disk egress proxy (env >
//! file). So even if the control plane is bound beyond loopback, this can only
//! re-point the daemon at its OWN local config, never an attacker-chosen proxy —
//! it carries no gate of its own by design.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn reload(State(state): State<Arc<AppState>>) -> Json<Value> {
    crate::core::forward::reload_egress_proxy();
    crate::proxy::upstream::reload_cell(&state.egress_proxy);
    let proxy = crate::cli::egress_proxy::effective();
    tracing::info!(
        proxy = proxy.as_deref().unwrap_or("(direct)"),
        "egress proxy hot-reloaded"
    );
    Json(json!({ "ok": true, "proxy": proxy }))
}
