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
    /// True when `path` is the service root and any sub-path under it works
    /// (the daemon-side TOML used `path = "*"`). Agents can interpret this
    /// as "POST to `path` directly, or append whatever the upstream needs".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub wildcard: bool,
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
                    // For catch-alls we drop the `*` and emit the service root
                    // with `wildcard: true`, so the agent sees a real URL it
                    // can call directly instead of "/api/use/demo/*". For
                    // fixed paths we just normalise the slash.
                    let rest = api.path.trim_start_matches('/');
                    let (path, wildcard) = if rest == "*" {
                        (format!("/api/use/{}", id), true)
                    } else {
                        (format!("/api/use/{}/{}", id, rest), false)
                    };
                    RegistryEndpoint {
                        method: api.method.clone().unwrap_or_else(|| "ANY".to_string()),
                        path,
                        // Per-endpoint policy resolution is a follow-up; declare
                        // "ask" uniformly so the agent doesn't pre-assume free
                        // passes. Policies still gate the actual broker call.
                        approval: "ask".to_string(),
                        wildcard,
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
