//! `GET /c/registry` — public service catalog for the agent.
//!
//! Returns the daemon's loaded service definitions in a shape the agent's
//! skill template can consume directly. **No vault contents** — the daemon
//! cannot read sealed vault entries without a passkey-signed Export op, so
//! "is this service connected" is not knowable here. The agent calls a
//! service and handles the missing-entry case via the broker's error
//! response.
//!
//! Custodian-level path (no vault context): the catalog is currently the
//! same for every vault. If we ever need per-vault filtering (admin-locked
//! services per tenant), add `/v/{vid}/registry` as an override that takes
//! precedence — no protocol break.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;
use serde_json::Value;

use crate::error::Result;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct RegistryEndpoint {
    pub method: String,
    pub path: String,
    /// Approval level summarised in the service-level policy. "ask" by default
    /// when no explicit level is declared.
    pub approval: String,
}

#[derive(Debug, Serialize)]
pub struct RegistryService {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub endpoints: Vec<RegistryEndpoint>,
}

#[derive(Debug, Serialize)]
pub struct RegistryResponse {
    pub version: u32,
    pub proxy_base: String,
    pub services: Vec<RegistryService>,
}

pub async fn registry(State(state): State<Arc<AppState>>) -> Result<Json<Value>> {
    // proxy_base is derived from the deployment's configured origin so URLs
    // in the registry response work directly. Agents call through the SaaS
    // pro-backend's /api/use/ surface, not the daemon's /v/{vid}/use/.
    let proxy_base = format!("{}/api/use", state.config.origin.trim_end_matches('/'));

    let services: Vec<RegistryService> = state
        .services
        .iter_sorted()
        .into_iter()
        .map(|(id, def)| {
            let endpoints = def
                .api
                .iter()
                .map(|api| {
                    // api.path may be "*" (catch-all), "/sign", "/wallets/", etc.
                    // We always need a `/` between the service id and the
                    // path — service-relative paths sometimes omit the leading
                    // slash. Normalise to "/api/use/{id}/{rest}".
                    let rest = api.path.trim_start_matches('/');
                    RegistryEndpoint {
                        method: api.method.clone().unwrap_or_else(|| "ANY".to_string()),
                        path: format!("/api/use/{}/{}", id, rest),
                        // Per-endpoint policy resolution is a follow-up; declare
                        // "ask" uniformly so the agent doesn't pre-assume free
                        // passes. Policies still gate the actual broker call.
                        approval: "ask".to_string(),
                    }
                })
                .collect();
            RegistryService {
                id: id.to_string(),
                name: def.service.name.clone(),
                description: def.service.help.clone(),
                endpoints,
            }
        })
        .collect();

    let body = RegistryResponse {
        version: 1,
        proxy_base,
        services,
    };
    Ok(Json(serde_json::to_value(body)?))
}
