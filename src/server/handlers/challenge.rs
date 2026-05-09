use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use serde_json::json;

use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> Result<Json<serde_json::Value>> {
    let ip: IpAddr = addr.ip();
    let r = {
        let mut store = state.challenges.lock().unwrap();
        store
            .issue(ip)
            .ok_or(AppError::TooManyRequests)?
    };
    Ok(Json(json!({ "r": r })))
}
