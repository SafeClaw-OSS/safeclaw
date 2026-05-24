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
    /// One-line sub-title (e.g. "demo target", "REST API"). UI surfaces it
    /// in parentheses after `name` so users see what kind of service this
    /// is without reading the full description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Service category — drives global policy bucketing on the UI
    /// (`llm` / `channel` / `service` etc.). Always present; defaults to
    /// `"service"` if the toml didn't declare one.
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub endpoints: Vec<RegistryEndpoint>,
    /// Vault entries this service expects to be populated. Driven by:
    ///   1. Explicit `[[vault]]` blocks in service.toml — the schema source
    ///      of truth (name + kind + description, used for richer
    ///      multi-field services like wallets/configs).
    ///   2. Synthesized from `[upstream.auth].env` when the service didn't
    ///      declare `[[vault]]` blocks but does have a credential field —
    ///      lets the frontend show an "Add OpenAI key" picker for any
    ///      service with `auth.env = "openai_api_key"`, without forcing
    ///      every service.toml to redundantly declare the same field.
    /// Empty vec for oauth services (no vault entry — credentials come
    /// from the connect/OAuth flow) and for fully-internal services.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vault_fields: Vec<RegistryVaultField>,
    /// Built-in policy snapshot — global default levels for this service
    /// plus the explicit per-action rule list. Frontend uses this to
    /// render the per-app fine-tuning UI; user overrides come from
    /// `aux.service_state.<svc>.rule_overrides`. Absent when the service
    /// has no policy.toml AND no inline [policy] block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<RegistryServicePolicy>,
}

#[derive(Debug, Serialize)]
pub struct RegistryServicePolicy {
    /// Default read / write levels for the service. Either may be absent
    /// (defer to category-level global default in that case).
    pub defaults: RegistryPolicyDefaults,
    /// Ordered list of built-in rules. Empty when the service has no
    /// per-action rules (rare — most services declare at least one).
    pub rules: Vec<RegistryPolicyRule>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPolicyDefaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPolicyRule {
    pub id: String,
    pub label: String,
    #[serde(rename = "match")]
    pub match_pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegistryVaultField {
    /// Vault entry key (no `env.` prefix).
    pub name: String,
    /// "secret" → mask in UI / never log. "config" → plain text.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// UI input hint pulled from service.toml `auth.placeholder` when
    /// available (e.g. "sk-..."). Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryResponse {
    pub version: u32,
    pub proxy_base: String,
    pub services: Vec<RegistryService>,
    /// Per-category global default levels — what the UI shows in the top
    /// "What can your agent do without asking?" block. Read straight from
    /// `PolicyDefaults::default()` so the policy crate stays the source
    /// of truth for the safe defaults. Users override these via
    /// `aux.policy_defaults`.
    pub policy_defaults: serde_json::Value,
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
            // Vault field schema:
            //  - explicit [[vault]] blocks win
            //  - else, synthesize from the first upstream's auth.env (the
            //    common single-secret case)
            //  - oauth2 / no env / no [[vault]] → empty
            let vault_fields: Vec<RegistryVaultField> = if !def.vault.is_empty() {
                def.vault.iter().map(|vf| RegistryVaultField {
                    name: vf.name.clone(),
                    kind: vf.kind.clone(),
                    description: vf.description.clone(),
                    placeholder: None,
                }).collect()
            } else if let Some(env_name) = def
                .upstream
                .first()
                .and_then(|u| u.auth.as_ref())
                .and_then(|a| a.env.as_ref())
                .filter(|s| !s.trim().is_empty())
            {
                let placeholder = def
                    .upstream
                    .first()
                    .and_then(|u| u.auth.as_ref())
                    .and_then(|a| a.placeholder.clone())
                    // Templated placeholders like "{{ env.X }}" aren't UI
                    // hints — drop them so the frontend doesn't show that
                    // as the input ghost.
                    .filter(|p| !p.contains("{{"));
                vec![RegistryVaultField {
                    name: env_name.clone(),
                    kind: "secret".to_string(),
                    description: def
                        .service
                        .sub
                        .clone()
                        .or_else(|| Some(format!("{} credential", def.service.name))),
                    placeholder,
                }]
            } else {
                vec![]
            };

            // Policy snapshot: prefer the standalone policy.toml (has
            // explicit rule ids/labels) over the inline service.toml
            // [policy]. Absent → service has no per-action rules; the
            // category default still governs (handled by the frontend).
            let policy = state.services.policy_file(id).map(|p| {
                let defaults = p
                    .default
                    .as_ref()
                    .map(|m| RegistryPolicyDefaults {
                        read: m.get("read").cloned(),
                        write: m.get("write").cloned(),
                        ask_ttl: m.get("ask_ttl").and_then(|v| v.parse().ok()),
                    })
                    .unwrap_or(RegistryPolicyDefaults {
                        read: None,
                        write: None,
                        ask_ttl: None,
                    });
                let rules = p
                    .rule
                    .iter()
                    .map(|r| RegistryPolicyRule {
                        id: r.id.clone(),
                        label: r.label.clone(),
                        match_pattern: r.match_pattern.clone(),
                        body: r.body.clone(),
                        level: r.level.clone(),
                        ask_ttl: r.ask_ttl,
                    })
                    .collect();
                RegistryServicePolicy { defaults, rules }
            });

            RegistryService {
                id: id.to_string(),
                name: def.service.name.clone(),
                sub: def.service.sub.clone(),
                category: def.service.category.clone(),
                description: def.service.help.clone(),
                endpoints,
                vault_fields,
                policy,
            }
        })
        .collect();

    // Surface the compiled-in safe defaults so the UI can render globals
    // even when the vault aux doesn't carry user-set overrides yet.
    let policy_defaults = serde_json::to_value(crate::core::policy::PolicyDefaults::default())?;

    let body = RegistryResponse {
        version: 1,
        proxy_base,
        services,
        policy_defaults,
    };
    Ok(Json(serde_json::to_value(body)?))
}
