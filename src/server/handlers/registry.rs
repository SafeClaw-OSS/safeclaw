//! Service discovery — two endpoints, one shared catalog.
//!
//! - `GET /menu` — static service catalog. What SafeClaw *supports*,
//!   vault-agnostic. Drives /try landing, docs, public browse. No vault
//!   state — no `connected`, `vault_entries`, `console_url`.
//!
//! - `GET /v/{vid}/registry` — live, per-vault view. Same catalog with
//!   per-service `connected` flag (derived from `cache.native_keys`),
//!   plus top-level `vault_entries` (native-secrets item names; `null`
//!   when locked), `console_url`, `vault_locked`, `vault_id`. This is
//!   the endpoint the agent skill points at.
//!
//! Query: `?include=policy` adds the explicit `policy.rules` list back
//! into each service (console UI). Default response omits it — the
//! agent doesn't need rule details, only `policy.defaults` for a
//! coarse "will this need approval" signal.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::server::handlers::op::validate_vault_id;
use crate::service::ServiceDef;
use crate::state::{AppState, VaultState};

#[derive(Debug, Deserialize)]
pub struct RegistryQuery {
    /// Comma-separated extras. Today only `policy` is recognised — it
    /// expands `policy.rules` per service. Unknown values are ignored.
    #[serde(default)]
    pub include: Option<String>,
}

impl RegistryQuery {
    fn include_policy_rules(&self) -> bool {
        self.include
            .as_deref()
            .map(|s| s.split(',').any(|t| t.trim() == "policy"))
            .unwrap_or(false)
    }
}

#[derive(Debug, Serialize)]
pub struct RegistryEndpoint {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub wildcard: bool,
}

#[derive(Debug, Serialize)]
pub struct RegistryService {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub endpoints: Vec<RegistryEndpoint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vault_fields: Vec<RegistryVaultField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<RegistryServicePolicy>,
    /// Only present on the per-vault endpoint. `true` = every declared
    /// vault field is present in the vault's native-secrets (or the
    /// service has no vault_fields = no credential needed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    /// Public OAuth consent params (authorization_url / client_id / scopes /
    /// pkce) for an oauth2 service — what a frontend needs to START a
    /// cloud-blind connect. The confidential half (client_secret / token_url)
    /// is never exposed; the daemon does the exchange. Absent for non-oauth2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<crate::service::ConnectDescriptor>,
    /// Tool-config hint for a service that needs a **local tool** (a CLI/SDK)
    /// pointed at SafeClaw — one rendered blurb (goal + ready-to-run config),
    /// with `{{proxy_base}}` / `{{api_key}}` / `{{vault}}` filled in. The route
    /// is inlined by the recipe as `{{proxy_base}}/stream/<upstream>/`.
    /// `{{proxy_base}}` renders to the literal `$SAFECLAW_VAULT_URL` (the single
    /// broker base the agent already has in its env), so the hint is
    /// deployment-agnostic and the agent's shell expands it. Agent-facing only;
    /// carries NO vault secret. Present only on the per-vault registry (the route
    /// is vault-scoped). The generic counterpart to `connect`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryServicePolicy {
    pub defaults: RegistryPolicyDefaults,
    /// Explicit per-action rules. Omitted unless `?include=policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RegistryPolicyRule>>,
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
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryResponse {
    pub version: u32,
    pub services: Vec<RegistryService>,
    pub policy_defaults: serde_json::Value,
    // ── Per-vault overlay — only set by /v/{vid}/registry ────────────
    //
    // Deliberately no `vault_id` field. The agent's mental model is
    // "I have an apiKey that points to my vault"; exposing vid would
    // let the agent bypass the SaaS apiKey gate by hitting the
    // daemon's auth-free `/v/{vid}/*` endpoints directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_locked: Option<bool>,
    /// Native-secrets item names present in this vault. `Some([..])` when
    /// unlocked. `Some(null)` (JSON `null`) when locked so the agent can
    /// distinguish "vault has nothing" from "I can't see right now".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_entries: Option<Option<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_url: Option<String>,
}

/// Per-vault overlay fed into `build_service` so a single rendering path
/// covers both `/menu` (overlay=None) and `/v/{vid}/registry`.
struct VaultOverlay<'a> {
    /// Item names available to satisfy a service's vault_fields. Includes
    /// native-secrets only — external stores (GCP etc.) require an async
    /// list call we don't want to pay for on every registry hit.
    native_keys: &'a HashSet<String>,
}

fn endpoint_for_api(id: &str, api: &crate::service::ApiDef) -> RegistryEndpoint {
    // Paths are relative to the broker base the agent already holds
    // (`$SAFECLAW_VAULT_URL/use`) so the agent can prepend it uniformly.
    let rest = api.path.trim_start_matches('/');
    let (path, wildcard) = if rest == "*" {
        (format!("/{}", id), true)
    } else {
        (format!("/{}/{}", id, rest), false)
    };
    RegistryEndpoint {
        method: api.method.clone().unwrap_or_else(|| "ANY".to_string()),
        path,
        wildcard,
    }
}

fn vault_fields_for(def: &ServiceDef) -> Vec<RegistryVaultField> {
    if !def.vault.is_empty() {
        return def
            .vault
            .iter()
            .map(|vf| RegistryVaultField {
                name: vf.name.clone(),
                kind: vf.kind.clone(),
                description: vf.description.clone(),
                placeholder: None,
            })
            .collect();
    }
    // Single-field synthesis from `auth.secret` for the common API-key case.
    let Some(env_name) = def
        .upstream
        .first()
        .and_then(|u| u.auth.as_ref())
        .and_then(|a| a.secret.as_ref())
        .filter(|s| !s.trim().is_empty())
    else {
        return vec![];
    };
    let placeholder = def
        .upstream
        .first()
        .and_then(|u| u.auth.as_ref())
        .and_then(|a| a.placeholder.clone())
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
}

fn policy_for(
    state: &AppState,
    id: &str,
    include_rules: bool,
) -> Option<RegistryServicePolicy> {
    let p = state.services.policy_file(id)?;
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
    let rules = if include_rules {
        Some(
            p.rule
                .iter()
                .map(|r| RegistryPolicyRule {
                    id: r.id.clone(),
                    label: r.label.clone(),
                    match_pattern: r.match_pattern.clone(),
                    body: r.body.clone(),
                    level: r.level.clone(),
                    ask_ttl: r.ask_ttl,
                })
                .collect(),
        )
    } else {
        None
    };
    Some(RegistryServicePolicy { defaults, rules })
}

/// Render a service's `setup` hint for the registry, filling `{{proxy_base}}`
/// / `{{api_key}}` / `{{vault}}`. Agent-facing only — the setup context has no
/// access to vault secrets by construction. Returns `None` if the service
/// declares no `setup` string.
///
/// With the daemon collapsed to a single port, `{{proxy_base}}` renders to the
/// literal `$SAFECLAW_VAULT_URL` (the broker base the agent already has in its
/// env) — the agent's shell expands it. `{{api_key}}` (if any recipe uses it)
/// renders to the literal `$SAFECLAW_API_KEY` the same way. So a setup hint is
/// identical across deployments and never needs a request-derived host. The
/// route is inlined by the recipe as `{{proxy_base}}/stream/<upstream>/`.
fn render_setup(def: &ServiceDef) -> Option<String> {
    use crate::server::broker::{render_setup_template, SetupInputs};
    const PROXY_BASE: &str = "$SAFECLAW_VAULT_URL";
    let setup = def.setup.as_deref()?;
    let inputs = SetupInputs { proxy_base: PROXY_BASE, api_key: "$SAFECLAW_API_KEY", vault: "" };
    render_setup_template(setup, &inputs).ok()
}

fn build_service(
    state: &AppState,
    id: &str,
    def: &ServiceDef,
    overlay: Option<&VaultOverlay<'_>>,
    include_policy_rules: bool,
    render_setup_hint: bool,
) -> RegistryService {
    let endpoints: Vec<RegistryEndpoint> =
        def.api.iter().map(|api| endpoint_for_api(id, api)).collect();
    let vault_fields = vault_fields_for(def);
    let policy = policy_for(state, id, include_policy_rules);

    // `connected` = "ready for the agent to call": every credential the
    // service needs is present in the vault. With declared vault_fields,
    // that's "all present in native_keys". With NO derivable field we must
    // NOT blindly say connected — `.all([]) == true` would mark every
    // undeclared-credential service connected, which is how an unconfigured
    // oauth2 service (e.g. openai-codex: `auth.type = oauth2`, no `env`) showed
    // a false ✅. Empty fields is "connected" ONLY when the service genuinely
    // needs no credential (a usable upstream that declares no auth).
    let connected = overlay.map(|o| {
        if vault_fields.is_empty() {
            service_needs_no_auth(def)
        } else {
            vault_fields
                .iter()
                .all(|vf| o.native_keys.contains(&vf.name))
        }
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
        connected,
        connect: state.services.connect_descriptor(id),
        setup: if render_setup_hint { render_setup(def) } else { None },
    }
}

/// True iff "no declared vault_field" legitimately means "connected" — i.e.
/// the service requires NO credential at all. Two cases qualify: a callable
/// vault-native service with no upstream (e.g. encrypted files — usable the
/// moment the vault unlocks) and a public upstream that declares no auth. A
/// service whose upstream declares an auth block (env / oauth2 / …) does NOT
/// qualify: it needs a credential we couldn't resolve to a field, so an
/// unconfigured oauth2 service reads as not-connected (not a false ✅). Only
/// consulted when `vault_fields` is empty; non-callable markers never reach
/// here (filtered out of the registry by api-presence).
fn service_needs_no_auth(def: &ServiceDef) -> bool {
    def.upstream.iter().all(|u| u.auth.is_none())
}

fn console_url(state: &AppState, vault_id: &str) -> String {
    // Demo vaults minted by /try (`demo-<user.id>` prefix) live on the
    // /try page, not the full /vault console. Pointing the agent at
    // /vault for a demo user shows them a "create a vault" CTA instead
    // of the unlock surface they actually need.
    // Deep-link to THIS vault (not the bare /vault picker) so the agent can
    // hand the user a link that lands straight on their vault — append
    // `#connections` for the add-credential flow. Demo vaults live on /try.
    let origin = state.config.origin.trim_end_matches('/');
    if vault_id.starts_with("demo-") {
        format!("{}/try", origin)
    } else {
        format!("{}/vault/{}", origin, vault_id)
    }
}

/// `GET /menu` — static service catalog.
pub async fn menu(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RegistryQuery>,
) -> Result<Json<Value>> {
    let include_policy_rules = q.include_policy_rules();
    let services: Vec<RegistryService> = state
        .services
        .iter_sorted()
        .into_iter()
        .filter(|(_, def)| !def.service.hidden)
        // No setup rendering on /menu: the setup hint is vault-scoped (the agent
        // applies it against its own `$SAFECLAW_VAULT_URL`), and the catalog has
        // no vault context.
        .map(|(id, def)| build_service(&state, id, def, None, include_policy_rules, false))
        .collect();
    let body = RegistryResponse {
        version: 2,
        services,
        policy_defaults: serde_json::to_value(crate::core::policy::PolicyDefaults::default())?,
        vault_locked: None,
        vault_entries: None,
        console_url: None,
    };
    Ok(Json(serde_json::to_value(body)?))
}

/// `GET /v/{vid}/registry` — per-vault live view (catalog + connection state).
pub async fn vault_registry(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Query(q): Query<RegistryQuery>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;
    let include_policy_rules = q.include_policy_rules();

    // Snapshot native_keys + lock state under the mutex, then drop it
    // before doing per-service rendering. Cheap copy — typically <20
    // keys.
    let (native_keys, locked): (HashSet<String>, bool) = {
        let states = state.vault_states.lock().unwrap();
        match states.get(&vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => (cache.native_keys.clone(), false),
            _ => (HashSet::new(), true),
        }
    };

    let services: Vec<RegistryService> = state
        .services
        .iter_sorted()
        .into_iter()
        // Non-hidden catalog services. The catalog is curated to hold only
        // real, callable services — the agent-product markers that had no
        // endpoints were REMOVED from it (archived on the
        // `agent-product-services` branch), not papered over with a runtime
        // filter — and deliberate per-service hiding uses `hidden = true`
        // (e.g. files, nodpay). So `!hidden` is the whole rule.
        .filter(|(_, def)| !def.service.hidden)
        .map(|(id, def)| {
            let overlay = if locked {
                None
            } else {
                Some(VaultOverlay {
                    native_keys: &native_keys,
                })
            };
            build_service(&state, id, def, overlay.as_ref(), include_policy_rules, true)
        })
        .collect();

    let vault_entries = if locked {
        Some(None)
    } else {
        let mut entries: Vec<String> = native_keys.into_iter().collect();
        entries.sort();
        Some(Some(entries))
    };

    // vault_id intentionally NOT returned in the body (see RegistryResponse
    // comment) — but it IS used to pick the right console URL: /try for
    // demo vaults, /vault for everyone else.
    let body = RegistryResponse {
        version: 2,
        services,
        policy_defaults: serde_json::to_value(crate::core::policy::PolicyDefaults::default())?,
        vault_locked: Some(locked),
        vault_entries,
        console_url: Some(console_url(&state, &vault_id)),
    };
    Ok(Json(serde_json::to_value(body)?))
}


#[cfg(test)]
mod setup_tests {
    use super::*;

    #[test]
    fn render_setup_fills_proxy_base() {
        let toml = r#"
setup = '''
Route git through SafeClaw. credential.helper = !sc git-credential
git config --global url."{{proxy_base}}/stream/github/".insteadOf "https://github.com/"
'''

[service]
id = "github"
name = "GitHub"
category = "integration"
[[upstream]]
id = "git"
url = "https://github.com"
stream = true
auth = { secret = "github_token" }
[upstream.headers]
Authorization = "Basic {{secret.github_token | basic}}"
"#;
        let def: ServiceDef = toml::from_str(toml).unwrap();
        let s = render_setup(&def).expect("setup rendered");
        // {{proxy_base}} renders to the literal $SAFECLAW_VAULT_URL — the broker
        // base the agent already holds; its shell expands it at apply time. The
        // route is inlined by the recipe as `{{proxy_base}}/stream/<upstream>/`.
        assert!(s.contains("$SAFECLAW_VAULT_URL/stream/github/"), "{}", s);
        assert!(!s.contains("{{"), "no leftover template tokens: {}", s);

        // No `setup` → None.
        let no_setup: ServiceDef =
            toml::from_str("[service]\nid=\"x\"\nname=\"X\"\n[[upstream]]\nid=\"d\"\nurl=\"https://x.com\"\n")
                .unwrap();
        assert!(render_setup(&no_setup).is_none());
    }
}
