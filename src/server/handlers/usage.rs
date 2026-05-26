//! `GET /v/{vid}/usage` — billable-Use aggregate over a time window.
//!
//! Reads straight from the per-tenant audit log; no separate counter
//! state. Same SSoT used by the approvals listing and retention prune.
//!
//! Auth: this endpoint is *daemon-perimeter* (no token check here). In the
//! Pro deployment the SaaS proxy gates with the vault owner's Supabase
//! JWT before forwarding; OSS deployments terminate trust at the network
//! perimeter as elsewhere on `/v/{vid}/*`.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AppError, Result};
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    /// Inclusive lower bound, unix seconds. Required.
    pub since: i64,
    /// Exclusive upper bound, unix seconds. Defaults to "now" when omitted.
    #[serde(default)]
    pub until: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UsageResponse {
    pub since: i64,
    pub until: i64,
    /// Total billable Use ops (allowed + approved) in the window.
    pub total: i64,
    /// Per-service breakdown. Ordered for stable JSON output.
    pub by_service: BTreeMap<String, i64>,
}

pub async fn usage(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;
    let until = q.until.unwrap_or_else(now_secs);
    if q.since >= until {
        return Err(AppError::BadRequest(
            "since must be strictly less than until".into(),
        ));
    }
    let store = state.audits.for_tenant(&vault_id)?;
    let (total, by_service) = store.aggregate_usage(q.since, until)?;
    let body = UsageResponse {
        since: q.since,
        until,
        total,
        by_service,
    };
    Ok(Json(serde_json::to_value(body)?))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
