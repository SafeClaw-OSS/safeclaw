//! Service discovery — two endpoints, one shared catalog.
//!
//! - `GET /registry` — static service catalog. What SafeClaw *supports*,
//!   vault-agnostic. Drives /try landing, docs, public browse. No vault
//!   state — no `connected`, `vault_entries`, `console_url`. Also produced
//!   offline (no server) via `sc registry` / [`render_catalog`] for CI.
//!
//! - `GET /v/{vid}/registry` — live, per-vault view. Same catalog with
//!   per-service `connected` flag (derived from `cache.native_keys`),
//!   plus top-level `vault_entries` (native-secrets item names; `null`
//!   when locked), `console_url`, `vault_locked`, `vault_id`. This is
//!   the endpoint the agent skill points at.
//!
//! Query params (all optional, compose):
//! - `?include=policy` adds the explicit `policy.rules` list back into
//!   each service (console UI). Default omits it — the agent needs only
//!   `policy.defaults` for a coarse "will this need approval" signal.
//! - `?ids=a,b` keeps only those services (unknown ids drop silently).
//! - `?view=summary` returns thin rows (id/name/category/connected/
//!   needs_reauth) + top-level vault state, dropping the heavy fields.
//!   The agent's two-step: `?view=summary` to orient cheaply, then
//!   `?ids=<id>` for full detail on the one it's about to call.

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
use crate::core::host::phantoms_for;
use crate::service::{ServiceDef, ServiceRegistry};
use crate::state::{AppState, VaultState};

#[derive(Debug, Deserialize)]
pub struct RegistryQuery {
    /// Comma-separated extras. Today only `policy` is recognised — it
    /// expands `policy.rules` per service. Unknown values are ignored.
    #[serde(default)]
    pub include: Option<String>,
    /// Comma-separated service ids to keep. Absent = all. Unknown ids are
    /// silently dropped (asking for something that doesn't exist yields an
    /// empty match, not a 404). Lets an agent point at just the service it
    /// needs instead of paying for the whole catalog.
    #[serde(default)]
    pub ids: Option<String>,
    /// `summary` = thin per-service rows (id/name/category/connected/
    /// needs_reauth) + top-level vault state; drops the heavy fields
    /// (endpoints/vault_fields/policy/connect/setup). Anything else (incl.
    /// absent) = full. The agent's orient step: pull a cheap list, then
    /// `?ids=<id>` for full detail on the one it wants.
    #[serde(default)]
    pub view: Option<String>,
}

impl RegistryQuery {
    fn include_policy_rules(&self) -> bool {
        self.include
            .as_deref()
            .map(|s| s.split(',').any(|t| t.trim() == "policy"))
            .unwrap_or(false)
    }

    fn is_summary(&self) -> bool {
        self.view.as_deref() == Some("summary")
    }

    /// The `?ids=` allow-set, or `None` for "all". Blanks are trimmed out;
    /// an all-blank list (`?ids=`) reads as an empty set → matches nothing.
    fn ids_filter(&self) -> Option<HashSet<String>> {
        self.ids.as_deref().map(|s| {
            s.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .map(|t| t.to_string())
                .collect()
        })
    }
}

#[derive(Debug, Serialize)]
pub struct RegistryService {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Anchored egress hosts (service-declared exact FQDNs / `*.suffix`).
    /// Omitted in `?view=summary`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Injectable role → ready-made phantom string (`__sc__<conn>__[<role>__]`).
    /// The agent copies these verbatim, never constructs them. Omitted in
    /// `?view=summary`. Empty on the static catalog face (phantoms are per-vault).
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub phantoms: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<RegistryServicePolicy>,
    /// Only present on the per-vault endpoint. `true` = every declared
    /// vault field is present in the vault's native-secrets (or the
    /// service has no vault_fields = no credential needed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    /// Per-vault only. `true` = this OAuth connection's refresh_token was rejected
    /// (invalid_grant) at /use — user must reconnect. Absent for healthy / non-OAuth
    /// services. Distinct from `connected`: a dead refresh_token is still PRESENT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_reauth: Option<bool>,
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
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPolicyRule {
    pub id: String,
    pub label: String,
    #[serde(rename = "match")]
    pub match_pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Author-assigned risk tier (`low`/`medium`/`high`), if classified by
    /// risk. The console renders this as the (editable) risk column; `level`
    /// is what it currently resolves to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    /// Effective access level: an explicit pin, else the risk tier mapped
    /// through the *default* `risk_policy`. The live per-vault value (after a
    /// user `risk_policy` edit) is resolved by the daemon at request time and
    /// stamped on the approval record; this registry view shows the baseline.
    /// Absent only if the rule declares neither risk nor level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegistryResponse {
    pub version: u32,
    pub services: Vec<RegistryService>,
    /// The policy tree baseline (risk map + default floors + categories). The
    /// console reads the vault's live `aux.policy` client-side from the
    /// decrypted `M` (de-daemon), then writes edits via a `write` op.
    pub policy: serde_json::Value,
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
/// covers both `/registry` (overlay=None) and `/v/{vid}/registry`.
struct VaultOverlay<'a> {
    /// Item names available to satisfy a service's vault_fields. Includes
    /// native-secrets only — external stores (GCP etc.) require an async
    /// list call we don't want to pay for on every registry hit.
    native_keys: &'a HashSet<String>,
}

/// The secret roles that must be present in the vault for a service to be
/// "connected": the oauth2 refresh-token role, else every declared direct
/// secret. Empty ⇒ the service needs no credential.
fn required_keys(def: &ServiceDef) -> Vec<String> {
    if let Some(o) = &def.oauth2 {
        vec![o.secret.clone()]
    } else {
        def.service.secrets.clone()
    }
}

fn policy_for(
    services: &ServiceRegistry,
    id: &str,
    include_rules: bool,
) -> Option<RegistryServicePolicy> {
    let p = services.policy_file(id)?;
    let defaults = p
        .default
        .as_ref()
        .map(|m| RegistryPolicyDefaults {
            read: m.get("read").cloned(),
            write: m.get("write").cloned(),
            ttl: m.get("ttl").and_then(|v| v.parse().ok()),
        })
        .unwrap_or(RegistryPolicyDefaults {
            read: None,
            write: None,
            ttl: None,
        });
    let rules = if include_rules {
        Some(
            p.rule
                .iter()
                .map(|r| {
                    let risk = r.risk.as_deref().and_then(crate::core::policy::RiskTier::parse);
                    // Effective level shown to agents: the tier through the
                    // DEFAULT risk map. The live per-vault value (after a user
                    // risk-map edit) is computed by the daemon at request time;
                    // the console recomputes it from `risk` + the policy tree.
                    let level = risk
                        .map(|t| crate::core::policy::RiskMap::default().get(t).to_string());
                    RegistryPolicyRule {
                        id: r.id.clone(),
                        label: r.label.clone(),
                        match_pattern: r.match_pattern.clone(),
                        body: r.body.clone(),
                        risk: risk.map(|t| t.to_string()),
                        level,
                        ttl: r.ttl,
                    }
                })
                .collect(),
        )
    } else {
        None
    };
    Some(RegistryServicePolicy { defaults, rules })
}

/// A service's `setup` hint — plain agent-facing prose in v4 (routed ⇒ nothing
/// to configure; unrouted ⇒ `sc run -- <cmd>`). No template tokens.
fn render_setup(def: &ServiceDef) -> Option<String> {
    def.setup.clone()
}

fn build_service(
    services: &ServiceRegistry,
    id: &str,
    def: &ServiceDef,
    overlay: Option<&VaultOverlay<'_>>,
    include_policy_rules: bool,
    render_setup_hint: bool,
    summary: bool,
) -> RegistryService {
    let required = required_keys(def);

    // `connected` = "ready for the agent to call": every credential the service
    // needs is present in the vault (bare address for the default connection).
    // A service that needs no credential (empty `required`) is connected once
    // the vault unlocks.
    let connected = overlay.map(|o| {
        if required.is_empty() {
            service_needs_no_auth(def)
        } else {
            required.iter().all(|k| o.native_keys.contains(k))
        }
    });

    if summary {
        return RegistryService {
            id: id.to_string(),
            name: def.service.name.clone(),
            category: def.service.category.clone(),
            description: None,
            hosts: vec![],
            phantoms: std::collections::BTreeMap::new(),
            policy: None,
            connected,
            needs_reauth: None,
            connect: None,
            setup: None,
        };
    }

    let policy = policy_for(services, id, include_policy_rules);
    // Phantoms are meaningful per-vault (they name a connection). On the static
    // catalog face (`overlay: None`) we omit them; on the per-vault face we emit
    // the default connection's phantoms (conn == service id).
    let phantoms = if overlay.is_some() {
        phantoms_for(id, def)
    } else {
        std::collections::BTreeMap::new()
    };

    RegistryService {
        id: id.to_string(),
        name: def.service.name.clone(),
        category: def.service.category.clone(),
        description: def.service.help.clone(),
        hosts: def.service.hosts.clone(),
        phantoms,
        policy,
        connected,
        needs_reauth: None,
        connect: services.connect_descriptor(id),
        setup: if render_setup_hint { render_setup(def) } else { None },
    }
}

/// True iff the service requires NO credential at all (no `secrets`, no
/// `[oauth2]`) — so an empty `required_keys` legitimately reads as connected.
fn service_needs_no_auth(def: &ServiceDef) -> bool {
    def.service.secrets.is_empty() && def.oauth2.is_none()
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

/// Render the static, vault-agnostic service catalog from a `ServiceRegistry`.
///
/// Pure — no `AppState`, no vault, no I/O — so the exact catalog the daemon
/// serves at `GET /registry` can also be produced offline (`sc registry`, CI)
/// from `ServiceRegistry::compiled_only()`. No setup rendering: the setup hint
/// is vault-scoped (the agent applies it against its own `$SAFECLAW_VAULT_URL`),
/// and the catalog has no vault context.
pub fn render_catalog(
    services: &ServiceRegistry,
    include_policy_rules: bool,
    ids: Option<&HashSet<String>>,
    summary: bool,
) -> Result<RegistryResponse> {
    let rendered: Vec<RegistryService> = services
        .iter_sorted()
        .into_iter()
        .filter(|(_, def)| !def.service.hidden)
        .filter(|(id, _)| ids.map_or(true, |set| set.contains(*id)))
        .map(|(id, def)| build_service(services, id, def, None, include_policy_rules, false, summary))
        .collect();
    Ok(RegistryResponse {
        version: 3,
        services: rendered,
        policy: serde_json::to_value(crate::core::policy::Policy::default())?,
        vault_locked: None,
        vault_entries: None,
        console_url: None,
    })
}

/// `GET /registry` — static service catalog.
pub async fn catalog(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RegistryQuery>,
) -> Result<Json<Value>> {
    let body = render_catalog(
        &state.services,
        q.include_policy_rules(),
        q.ids_filter().as_ref(),
        q.is_summary(),
    )?;
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
    let ids_filter = q.ids_filter();
    let summary = q.is_summary();

    // Snapshot native_keys + lock state under the mutex, then drop it
    // before doing per-service rendering. Cheap copy — typically <20
    // keys.
    let (native_keys, custom_services, locked): (HashSet<String>, Vec<(String, ServiceDef)>, bool) = {
        let states = state.vault_states.lock().unwrap();
        match states.get(&vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                let mut custom: Vec<(String, ServiceDef)> =
                    cache.custom_services.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                custom.sort_by(|a, b| a.0.cmp(&b.0));
                (cache.native_keys.clone(), custom, false)
            }
            _ => (HashSet::new(), Vec::new(), true),
        }
    };

    let mut services: Vec<RegistryService> = state
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
        .filter(|(id, _)| ids_filter.as_ref().map_or(true, |set| set.contains(*id)))
        .map(|(id, def)| {
            let overlay = if locked {
                None
            } else {
                Some(VaultOverlay {
                    native_keys: &native_keys,
                })
            };
            let mut svc = build_service(&state.services, id, def, overlay.as_ref(), include_policy_rules, true, summary);
            // Surface a dead OAuth refresh_token (flagged at /use) so the console
            // shows "needs re-auth". Default connection: conn_id == service id.
            if !locked && svc.connected == Some(true) && state.oauth_needs_reauth(&vault_id, id) {
                svc.needs_reauth = Some(true);
            }
            svc
        })
        .collect();

    // Custom (aux.services) definitions fold in exactly like a built-in — same
    // build_service path, an unlocked overlay, honoring ids/needs_reauth. Empty
    // when locked (custom defs live in the sealed blob, like the credentials).
    let overlay = VaultOverlay { native_keys: &native_keys };
    for (id, def) in &custom_services {
        if ids_filter.as_ref().map_or(false, |set| !set.contains(id)) {
            continue;
        }
        if def.service.hidden {
            continue;
        }
        let mut svc = build_service(&state.services, id, def, Some(&overlay), include_policy_rules, true, summary);
        if svc.connected == Some(true) && state.oauth_needs_reauth(&vault_id, id) {
            svc.needs_reauth = Some(true);
        }
        services.push(svc);
    }
    services.sort_by(|a, b| a.id.cmp(&b.id));

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
        version: 3,
        services,
        policy: serde_json::to_value(crate::core::policy::Policy::default())?,
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
    fn render_setup_is_plain_passthrough() {
        let toml = r#"
setup = """
Routed? Nothing to configure. Not routed? Prefix: sc run -- git clone ...
"""

[service]
id = "github"
name = "GitHub"
hosts = ["github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def: ServiceDef = toml::from_str(toml).unwrap();
        let s = render_setup(&def).expect("setup passthrough");
        assert!(s.contains("sc run --"), "{}", s);

        let no_setup: ServiceDef =
            toml::from_str("[service]\nid=\"x\"\nname=\"X\"\nhosts=[\"x.com\"]\n").unwrap();
        assert!(render_setup(&no_setup).is_none());
    }

    fn q(ids: Option<&str>, view: Option<&str>) -> RegistryQuery {
        RegistryQuery {
            include: None,
            ids: ids.map(|s| s.to_string()),
            view: view.map(|s| s.to_string()),
        }
    }

    #[test]
    fn ids_filter_parses_and_trims() {
        assert!(q(None, None).ids_filter().is_none());
        assert_eq!(
            q(Some("gmail,github"), None).ids_filter().unwrap(),
            ["gmail", "github"].iter().map(|s| s.to_string()).collect()
        );
        // Whitespace + empties trimmed; `?ids=` alone → empty set (matches nothing).
        assert_eq!(
            q(Some(" gmail , "), None).ids_filter().unwrap(),
            ["gmail"].iter().map(|s| s.to_string()).collect()
        );
        assert!(q(Some(""), None).ids_filter().unwrap().is_empty());
    }

    #[test]
    fn view_summary_toggle() {
        assert!(!q(None, None).is_summary());
        assert!(!q(None, Some("full")).is_summary());
        assert!(q(None, Some("summary")).is_summary());
    }

    #[test]
    fn summary_drops_heavy_fields_keeps_state() {
        let reg = ServiceRegistry::compiled_only();
        let (id, def) = reg.iter_sorted().into_iter().next().expect("a compiled service");
        let native: HashSet<String> = required_keys(def).into_iter().collect();
        let overlay = VaultOverlay { native_keys: &native };

        let full = build_service(&reg, id, def, Some(&overlay), false, true, false);
        let sum = build_service(&reg, id, def, Some(&overlay), false, true, true);

        // Identity + connection state survive the trim.
        assert_eq!(sum.id, full.id);
        assert_eq!(sum.name, full.name);
        assert_eq!(sum.category, full.category);
        assert_eq!(sum.connected, full.connected);
        // Heavy fields are gone (skip_serializing_if drops them from the wire).
        assert!(sum.hosts.is_empty());
        assert!(sum.phantoms.is_empty());
        assert!(sum.policy.is_none());
        assert!(sum.connect.is_none());
        assert!(sum.setup.is_none());
        assert!(sum.description.is_none());
        // Full view carries the declared hosts.
        assert_eq!(full.hosts, def.service.hosts);
    }
}
