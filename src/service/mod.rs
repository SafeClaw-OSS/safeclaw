/// TOML-driven service registry (protocol v2).
///
/// Each service is defined by a `service.toml` in `services/{category}/{id}/`.
/// No Rust code is needed per service — upstream, API steps, and policies are declarative.

pub mod locked;
pub mod validate;

use std::collections::{BTreeMap, HashMap};
use axum::response::Response;
use crate::auth::AuthConfig;
use crate::auth::oauth2::OAuthStyle;

// ── ServiceDef: parsed from service.toml (v2) ───────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceDef {
    pub service: ServiceMeta,
    #[serde(default)]
    pub upstream: Vec<UpstreamDef>,
    #[serde(default)]
    pub api: Vec<ApiDef>,
    #[serde(default)]
    pub vault: Vec<VaultField>,
    pub policy: Option<PolicyDef>,
    /// Optional top-level `setup` string: the agent-facing tool/runtime config
    /// hint (CONNECTIONS_AND_AUTH.md §6). One free-form blurb the agent adapts
    /// to the user's real config (per the iron rule: goal + building blocks,
    /// not a rigid script), with inline `{{proxy_base}}` / `{{api_key}}` /
    /// `{{vault}}` tokens. Parsed only — never executed here.
    #[serde(default)]
    pub setup: Option<String>,
}

/// Declares a field stored in the vault for this service.
/// Used for schema validation, documentation, and frontend form generation.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct VaultField {
    /// Key name in the vault JSON (e.g. "gatewayToken").
    pub name: String,
    /// "secret" if the value should be masked in UI / never logged.
    /// Omit or use "config" for non-sensitive values.
    #[serde(default = "default_vault_kind")]
    pub kind: String,
    /// Human-readable description for docs and UI labels.
    #[serde(default)]
    pub description: Option<String>,
}

fn default_vault_kind() -> String { "config".to_string() }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default = "default_category")]
    pub category: String,
    /// If set, this service is grouped with the service whose id matches this value.
    /// Services sharing the same group are merged into one card in the UI.
    #[serde(default)]
    pub group: Option<String>,
    /// Help text returned by GET /{service}/help and rendered into safeclaw.md.
    /// Supports template variables: {{wallet.*}} resolved from vault service data.
    #[serde(default)]
    pub help: Option<String>,
    /// Activation mode: "auto" = starts automatically without credentials.
    /// Absent/None = requires user "connect" (provide API key / OAuth).
    #[serde(default)]
    pub activation: Option<String>,
    /// If true, exclude from /menu and /v/{vid}/registry. Use for services
    /// that are defined but not yet ready for agent discovery.
    #[serde(default)]
    pub hidden: bool,
}

fn default_category() -> String { "integration".to_string() }

/// Named upstream destination block.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UpstreamDef {
    pub id: String,
    pub url: String,
    /// Legacy auth block. When present, drives the daemon's hardcoded
    /// bearer-style injection: `Authorization: Bearer {{auth.env}}`.
    /// New services SHOULD prefer the explicit `[upstream.headers]` /
    /// `[upstream.query]` template blocks below — `auth` stays compiled
    /// for the existing 18+ services that still declare it.
    #[serde(default)]
    pub auth: Option<AuthDef>,
    /// Static header values to attach to every outbound request to this
    /// upstream. Values may reference `{{auth_value}}` which the daemon
    /// substitutes with the resolved secret bytes (via store_order
    /// lookup of `auth.env`). When the map is non-empty, it OVERRIDES
    /// the legacy auth-block's hardcoded `Authorization: Bearer …`
    /// injection — pick one or the other per upstream, not both.
    ///
    /// Example (Stripe-style basic auth — the canonical "weird case"):
    ///   ```toml
    ///   [[upstream]]
    ///   id  = "default"
    ///   url = "https://api.stripe.com"
    ///   auth = { type = "bearer", env = "stripe_secret_key" }
    ///
    ///   [upstream.headers]
    ///   Authorization = "Basic {{auth_value_basic}}"
    ///   ```
    /// `{{auth_value_basic}}` is `base64(s_o + ':')`, the Stripe shape.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Query-string params to attach to every outbound request. Same
    /// template semantics as `headers`.
    #[serde(default)]
    pub query: HashMap<String, String>,
    /// Opt into the generic **streaming passthrough** transport (the
    /// `/v/{vid}/stream/{service}/…` route): request and response bodies are
    /// proxied as byte streams with no buffering, for transports like git's
    /// smart-HTTP where a packfile can be hundreds of MB. The daemon does NOT
    /// interpret the protocol — it injects auth and forwards verbatim. This is
    /// the one recipe shape that is *not* OpenAPI-describable (git is a binary
    /// transport, not a REST API); normal `[[api]]` recipes stay OpenAPI-mappable.
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub locked: Option<LockedResponseDef>,
    /// Per-connection config slots this upstream exposes (CONNECTION_SCHEMA.md
    /// §4). A connection may fill ONLY these via its `config`, surfaced in
    /// templates as `{{connection.<param>}}`. Absent = no connection-fillable
    /// slots (the common case). The host SSRF guard grants `{{connection.host}}`
    /// its narrow exception only for a param declared here.
    #[serde(default)]
    pub connection: Option<ConnectionSlots>,
}

/// The per-connection re-map slots an upstream declares — the ONLY fields a
/// connection's `config` may fill (anti-SSRF; a connection can never re-point an
/// audited recipe's host or token endpoint). e.g. `params = ["host"]` lets a
/// self-hosted connection set `{{connection.host}}`; nothing else is fillable.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ConnectionSlots {
    #[serde(default)]
    pub params: Vec<String>,
}

/// API endpoint definition containing steps.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ApiDef {
    #[serde(default)]
    pub method: Option<String>,
    pub path: String,
    #[serde(default)]
    pub steps: Vec<ApiStep>,
}

/// A single step within an API endpoint.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ApiStep {
    pub target: String,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub read: Option<String>,
    #[serde(default)]
    pub returns: bool,
    #[serde(default)]
    pub retry: Option<RetryDef>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RetryDef {
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,
    #[serde(default = "default_retry_interval")]
    pub interval_ms: u64,
}

fn default_retry_attempts() -> u32 { 1 }
fn default_retry_interval() -> u64 { 500 }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthDef {
    /// Legacy auth-style discriminator (`bearer` / `header` / `query` /
    /// `basic` / `oauth2` / `path`). Optional in the new template-driven
    /// shape — services that declare `[upstream.headers]` / `[upstream.query]`
    /// instead drop this field; the daemon's injection logic reads the
    /// templates directly. Still required for `oauth2`-flow services.
    #[serde(rename = "type", default)]
    pub auth_type: Option<String>,
    /// Vault entry key feeding this credential (just the key name, no `env.`
    /// prefix). Replaces the older `placeholder = "{{ env.X }}"` templating
    /// convention. `placeholder` continues to mean "UI input hint" only.
    ///
    /// For oauth2 services, this names the native-secrets item holding the
    /// long-lived refresh_token. The short-lived access_token derived from
    /// it lives in-memory only (per the design: only the immutable refresh
    /// token enters the vault).
    ///
    /// Renamed from `env` (CONNECTIONS_AND_AUTH.md §1). The `env` alias keeps
    /// every existing in-tree recipe + already-stored connection parsing
    /// unchanged. A recipe never holds a secret VALUE — only the *key*.
    #[serde(alias = "env", default)]
    pub secret: Option<String>,
    /// Multi-secret form (rare): role → vault-entry key, e.g.
    /// `refresh_token = "gmail_refresh_token"`, `webhook_key = "gmail_webhook"`
    /// (CONNECTIONS_AND_AUTH.md §3). The single `secret` string stays the
    /// common case; this table is for services that inject more than one
    /// vault item.
    #[serde(default)]
    pub secrets: Option<BTreeMap<String, String>>,
    /// OAuth scopes requested at consent time (= Nango `default_scopes`).
    /// Audit/visibility only at the recipe layer; the consent screen is the
    /// provider's. (CONNECTIONS_AND_AUTH.md §3.)
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    /// oauth2: body style for the refresh /token call. `form` (default) or
    /// `json` (Anthropic). Reused by `auth::oauth2::refresh_token`.
    #[serde(default)]
    pub oauth_style: Option<String>,
    /// oauth2: identity-provider key (`google` / `openai` / `anthropic`).
    /// Used by the consent-flow side of the OAuth ceremony to pick the
    /// right provider config; daemon doesn't read it at refresh time.
    #[serde(default)]
    pub provider: Option<String>,
    /// oauth2: provider's token endpoint, e.g.
    /// `https://oauth2.googleapis.com/token`. Public info, baked into
    /// service.toml.
    #[serde(default)]
    pub token_url: Option<String>,
    /// oauth2: name of the daemon-startup env var holding the OAuth client_id
    /// (public but kept off the binary so self-hosters can register their own
    /// OAuth app). e.g. `SAFECLAW_GOOGLE_CLIENT_ID`.
    #[serde(default)]
    pub client_id_env: Option<String>,
    /// oauth2: name of the daemon-startup env var holding the OAuth
    /// client_secret. Required for confidential clients (Google) and absent
    /// for PKCE clients (OpenAI Codex / Anthropic). e.g.
    /// `SAFECLAW_GOOGLE_CLIENT_SECRET`.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// RFC 6749 §2.1 client type (`"public"` | `"confidential"`). Mirrors the
    /// provider's `client_type` for inline auth that declares a literal
    /// `client_id`/`client_secret` locally. Usually inherited from the
    /// referenced `[provider.<name>]` rather than set here.
    #[serde(default)]
    pub client_type: Option<String>,
    #[serde(default)]
    pub username_label: Option<String>,
}

// ── ProviderDef: parsed from services/_providers/<name>.toml ─────────────────

/// A `[provider.<name>]` block — the shared OAuth template reused by every
/// service on that provider (= Nango `providers.yaml`).
/// CONNECTIONS_AND_AUTH.md §2. Lives in `services/_providers/<name>.toml`.
///
/// A service's `[upstream.auth]` with `provider = "<name>"` inherits
/// `auth_mode` (= the service's `type`), the endpoints, and the client app
/// from here, declaring only what's unique (scopes, the secret slot, the
/// injection). Inline auth without a `provider` keeps declaring `type` +
/// endpoints locally.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProviderFileDef {
    /// Wraps the single `[provider.<name>]` table. The map key is the provider
    /// name (`google`), the value is the template.
    pub provider: HashMap<String, ProviderDef>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProviderDef {
    /// = Nango `auth_mode`; the service's `type` inherits this (`oauth2`).
    #[serde(default)]
    pub auth_mode: Option<String>,
    /// OAuth grant flow, e.g. `authorization_code`.
    #[serde(default)]
    pub flow: Option<String>,
    /// CONNECT step endpoint (user consent).
    #[serde(default)]
    pub authorization_url: Option<String>,
    /// REFRESH + code-exchange endpoint.
    #[serde(default)]
    pub token_url: Option<String>,
    /// Whether the connect flow uses PKCE (RFC 7636).
    #[serde(default)]
    pub pkce: bool,
    /// OAuth client_id (a public Desktop client may ship its id here).
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth client_secret. A LITERAL `client_secret` is allowed in a recipe
    /// ONLY for a `client_type = "public"` client (a confidential Web-app
    /// secret must never be committed). The validator enforces this.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// RFC 6749 §2.1: `"public"` | `"confidential"`.
    #[serde(default)]
    pub client_type: Option<String>,
    /// The OAuth client's fixed `redirect_uri` (CONNECTION_SCHEMA.md §5). A
    /// constant of the client, NOT part of each handshake — used in both the
    /// consent URL (frontend, via the connect descriptor) and the daemon's
    /// code→token exchange, so the two always match. Loopback for a Desktop
    /// client. Falls back to [`DEFAULT_LOOPBACK_REDIRECT`] when omitted.
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

/// The loopback redirect for desktop/PKCE OAuth clients when a provider doesn't
/// pin its own `redirect_uri`. Matches the frontend `DEFAULT_LOOPBACK_REDIRECT`
/// so the consent request and the code→token exchange always agree.
pub const DEFAULT_LOOPBACK_REDIRECT: &str = "http://127.0.0.1:8765/safeclaw/oauth/callback";

/// The OAuth client/endpoint config a service's auth resolves to after
/// provider inheritance — see `ServiceRegistry::resolve_oauth_config`.
#[derive(Debug, Clone)]
pub struct ResolvedOAuthConfig {
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// The OAuth client's fixed redirect_uri (provider literal, or the loopback
    /// default). Sent in the daemon's code→token exchange so it matches the
    /// consent request the browser made.
    pub redirect_uri: String,
}

/// The PUBLIC OAuth consent parameters a frontend needs to START a connect for
/// a service: where to send the user (authorization_url), as whom (client_id),
/// for what (scopes), and whether to use PKCE. CONNECTIONS_AND_AUTH.md §4a.
///
/// **Cloud-blind by construction:** the confidential half — `client_secret` and
/// `token_url` — is deliberately NOT here. The browser only drives consent and
/// seals the resulting `{code, verifier}` into the vault; the daemon holds the
/// secret and does the code→token exchange locally. So this struct is safe to
/// serialize into the public `/registry` response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectDescriptor {
    pub provider: String,
    pub auth_mode: String,
    pub authorization_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub pkce: bool,
    /// The OAuth client's fixed redirect_uri — the frontend builds the consent
    /// URL from this (not a hardcoded constant) so it always matches what the
    /// daemon sends at code→token exchange (CONNECTION_SCHEMA.md §5).
    pub redirect_uri: String,
}

/// Inline policy in service.toml (legacy, still supported as fallback).
/// Prefer standalone policy.toml for new services.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyDef {
    pub levels: Option<HashMap<String, String>>,
    #[serde(default)]
    pub rules: Vec<TomlPolicyRule>,
}

impl PolicyDef {
    pub fn to_service_levels(&self) -> Option<crate::core::policy::ServiceLevels> {
        let levels = self.levels.as_ref()?;
        Some(crate::core::policy::ServiceLevels {
            write: parse_access_level(levels.get("write")),
            read: parse_access_level(levels.get("read")),
            ask_ttl: None,
        })
    }

    pub fn to_policy_rules(&self) -> Vec<crate::core::policy::PolicyRule> {
        self.rules.iter().filter_map(|r| r.to_core_rule()).collect()
    }
}

/// Policy rule as it appears in legacy service.toml `[[policy.rules]]`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TomlPolicyRule {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path_exact: Option<String>,
    #[serde(default)]
    pub path_suffix: Option<String>,
    pub level: String,
}

impl TomlPolicyRule {
    /// Convert legacy method+path_exact+path_suffix to path pattern.
    fn to_core_rule(&self) -> Option<crate::core::policy::PolicyRule> {
        let level = parse_access_level(Some(&self.level))?;

        let path_part = if let Some(ref exact) = self.path_exact {
            exact.trim_end_matches('/').to_string()
        } else {
            // path_suffix rules can't cleanly map to path patterns; skip them
            return None;
        };
        let match_pattern = if let Some(ref m) = self.method {
            format!("{} {}", m, path_part)
        } else {
            path_part
        };

        Some(crate::core::policy::PolicyRule {
            id: None,
            label: None,
            match_pattern: Some(match_pattern),
            body: None,
            risk: None,
            level: Some(level),
            ask_ttl: None,
        })
    }
}

/// Standalone policy.toml file: `[default]` + `[[rule]]`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyFileDef {
    pub default: Option<HashMap<String, String>>,
    #[serde(default)]
    pub rule: Vec<PolicyFileRule>,
}

/// A rule in policy.toml.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyFileRule {
    pub id: String,
    pub label: String,
    /// Path pattern: "METHOD /path" or "/path" (any method). `*` = one segment.
    #[serde(rename = "match")]
    pub match_pattern: String,
    /// Regex matched against request body (optional).
    #[serde(default)]
    pub body: Option<String>,
    /// Author-assigned risk tier (`low` | `medium` | `high`). Resolved to an
    /// access level live via the vault's `risk_policy`. Prefer this over
    /// `level` so the user can re-tune all same-tier rules at once.
    #[serde(default)]
    pub risk: Option<String>,
    /// Explicit access level (pins, overriding `risk`). Optional: a risk-only
    /// rule omits it. A rule with neither is skipped (it can never decide).
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}

impl PolicyFileDef {
    pub fn to_service_levels(&self) -> Option<crate::core::policy::ServiceLevels> {
        let levels = self.default.as_ref()?;
        Some(crate::core::policy::ServiceLevels {
            write: parse_access_level(levels.get("write")),
            read: parse_access_level(levels.get("read")),
            ask_ttl: levels.get("ask_ttl").and_then(|v| v.parse().ok()),
        })
    }

    pub fn to_policy_rules(&self) -> Vec<crate::core::policy::PolicyRule> {
        self.rule.iter().filter_map(|r| {
            let level = r.level.as_ref().and_then(|l| parse_access_level(Some(l)));
            let risk = r.risk.as_deref().and_then(crate::core::policy::RiskTier::parse);
            // Skip a rule that can never decide (neither tier nor explicit
            // level) — it would only ever fall through, so it's noise.
            if level.is_none() && risk.is_none() {
                return None;
            }
            Some(crate::core::policy::PolicyRule {
                id: Some(r.id.clone()),
                label: Some(r.label.clone()),
                match_pattern: Some(r.match_pattern.clone()),
                body: r.body.clone(),
                risk,
                level,
                ask_ttl: r.ask_ttl,
            })
        }).collect()
    }
}

fn parse_access_level(s: Option<&String>) -> Option<crate::core::policy::AccessLevel> {
    match s?.as_str() {
        "allow" => Some(crate::core::policy::AccessLevel::Allow),
        "ask" => Some(crate::core::policy::AccessLevel::Ask),
        "ask-always" => Some(crate::core::policy::AccessLevel::AskAlways),
        "deny" => Some(crate::core::policy::AccessLevel::Deny),
        _ => None,
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct LockedResponseDef {
    /// Plain text message returned as the locked response.
    /// The proxy wraps it into the appropriate API format automatically.
    #[serde(default)]
    pub response: Option<String>,
}

// ── ServiceRegistry ───────────────────────────────────────────────────────────

pub struct ServiceRegistry {
    services: HashMap<String, ServiceDef>,
    /// Parsed policy.toml files (service_id → PolicyFileDef).
    policies: HashMap<String, PolicyFileDef>,
    /// Parsed `[provider.<name>]` blocks (provider name → ProviderDef), loaded
    /// from `services/_providers/*.toml`. A service's `auth.provider` inherits
    /// `auth_mode`/endpoints/client from here.
    providers: HashMap<String, ProviderDef>,
}

impl ServiceRegistry {
    /// Load all service definitions in priority layers:
    /// 1. Compiled-in defaults (always loaded as base)
    /// 2. $SAFECLAW_DATA/services/ (runtime override for dev/deployment)
    /// 3. ~/.safeclaw/services/ (user-installed services, highest priority)
    pub fn load() -> Self {
        let mut services = HashMap::new();
        let mut policies = HashMap::new();
        let mut providers = HashMap::new();

        // Layer 1: compiled-in defaults (always loaded as base)
        Self::load_compiled_defaults(&mut services, &mut policies, &mut providers);

        // Layer 2: $SAFECLAW_DATA/services/ override
        let dirs = Self::discover_service_dirs();
        if !dirs.is_empty() {
            for (id, service_toml, policy_toml) in dirs {
                match toml::from_str::<ServiceDef>(&service_toml) {
                    Ok(def) => { services.insert(id.clone(), def); }
                    Err(e) => {
                        tracing::warn!("Failed to parse service.toml for {}: {}", id, e);
                    }
                }
                if let Some(policy_str) = policy_toml {
                    match toml::from_str::<PolicyFileDef>(&policy_str) {
                        Ok(def) => { policies.insert(id, def); }
                        Err(e) => {
                            tracing::warn!("Failed to parse policy.toml for {}: {}", id, e);
                        }
                    }
                }
            }
        }

        // Layer 3: ~/.safeclaw/services/ (user-installed, overrides everything)
        Self::load_user_services(&mut services, &mut policies);

        // Providers: runtime `services/_providers/*.toml` override the
        // compiled-in defaults (same precedence intent as services).
        Self::load_runtime_providers(&mut providers);

        tracing::info!(
            "Loaded {} service definitions, {} policy files, {} providers",
            services.len(), policies.len(), providers.len()
        );
        Self { services, policies, providers }
    }

    /// Discover and parse `services/_providers/*.toml` from the same roots as
    /// `discover_service_dirs` ($SAFECLAW_DATA/services first, then beside the
    /// binary). Each file holds one or more `[provider.<name>]` blocks.
    fn load_runtime_providers(providers: &mut HashMap<String, ProviderDef>) {
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(data) = std::env::var("SAFECLAW_DATA") {
            roots.push(std::path::Path::new(&data).join("services"));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                roots.push(parent.join("services"));
            }
        }
        for root in roots {
            let dir = root.join("_providers");
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                    continue;
                }
                let Ok(content) = std::fs::read_to_string(&path) else { continue };
                match toml::from_str::<ProviderFileDef>(&content) {
                    Ok(def) => {
                        for (name, p) in def.provider {
                            providers.insert(name, p);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse provider {}: {}", path.display(), e);
                    }
                }
            }
        }
    }

    /// Returns (service_id, service_toml_content, optional_policy_toml_content).
    fn discover_service_dirs() -> Vec<(String, String, Option<String>)> {
        let mut results = vec![];

        // Check $SAFECLAW_DATA/services/ first (runtime override)
        if let Ok(data) = std::env::var("SAFECLAW_DATA") {
            let dir = std::path::Path::new(&data).join("services");
            if dir.is_dir() {
                Self::scan_dir(&dir, &mut results);
                if !results.is_empty() {
                    return results;
                }
            }
        }

        // Fallback: relative to binary (for dev / standalone installs)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let dir = parent.join("services");
                if dir.is_dir() {
                    Self::scan_dir(&dir, &mut results);
                    if !results.is_empty() {
                        return results;
                    }
                }
            }
        }

        results
    }

    /// Scan for service.toml and policy.toml files. Supports both flat and nested layouts.
    fn scan_dir(base: &std::path::Path, results: &mut Vec<(String, String, Option<String>)>) {
        let Ok(entries) = std::fs::read_dir(base) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }

            // Check if this directory itself has service.toml (flat layout)
            let toml_path = path.join("service.toml");
            if toml_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&toml_path) {
                    let id = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    if !id.is_empty() {
                        let policy = std::fs::read_to_string(path.join("policy.toml")).ok();
                        results.push((id, content, policy));
                    }
                }
                continue;
            }

            // Otherwise, scan one level deeper (category subfolder: llm/, channel/, integration/)
            let Ok(sub_entries) = std::fs::read_dir(&path) else { continue };
            for sub_entry in sub_entries.flatten() {
                let sub_path = sub_entry.path();
                if !sub_path.is_dir() { continue; }
                let sub_toml = sub_path.join("service.toml");
                if sub_toml.exists() {
                    if let Ok(content) = std::fs::read_to_string(&sub_toml) {
                        let id = sub_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("")
                            .to_string();
                        if !id.is_empty() {
                            let policy = std::fs::read_to_string(sub_path.join("policy.toml")).ok();
                            results.push((id, content, policy));
                        }
                    }
                }
            }
        }
    }

    /// Load user-installed services from ~/.safeclaw/services/.
    /// Skips directories with a `.disabled` marker file.
    fn load_user_services(services: &mut HashMap<String, ServiceDef>, policies: &mut HashMap<String, PolicyFileDef>) {
        let user_dir = match user_services_dir() {
            Some(d) if d.is_dir() => d,
            _ => return,
        };

        let Ok(entries) = std::fs::read_dir(&user_dir) else { return };
        let mut count = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }

            // Skip disabled services
            if path.join(".disabled").exists() { continue; }

            let id = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };

            let toml_path = path.join("service.toml");
            let Ok(content) = std::fs::read_to_string(&toml_path) else { continue };
            match toml::from_str::<ServiceDef>(&content) {
                Ok(def) => {
                    services.insert(id.clone(), def);
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to parse user service {}: {}", id, e);
                    continue;
                }
            }

            if let Ok(policy_str) = std::fs::read_to_string(path.join("policy.toml")) {
                if let Ok(def) = toml::from_str::<PolicyFileDef>(&policy_str) {
                    policies.insert(id, def);
                }
            }
        }
        if count > 0 {
            tracing::info!("Loaded {} user-installed services from {}", count, user_dir.display());
        }
    }

    /// Compiled-in service definitions for when filesystem discovery fails.
    /// Uses the auto-generated registry from build.rs.
    fn load_compiled_defaults(
        services: &mut HashMap<String, ServiceDef>,
        policies: &mut HashMap<String, PolicyFileDef>,
        providers: &mut HashMap<String, ProviderDef>,
    ) {
        let defaults = crate::generated_services::compiled_service_tomls();
        for (id, toml_str) in defaults {
            if let Ok(def) = toml::from_str::<ServiceDef>(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let policy_defaults = crate::generated_services::compiled_policy_tomls();
        for (id, toml_str) in policy_defaults {
            if let Ok(def) = toml::from_str::<PolicyFileDef>(toml_str) {
                policies.insert(id.to_string(), def);
            }
        }
        let provider_defaults = crate::generated_services::compiled_provider_tomls();
        for (_file, toml_str) in provider_defaults {
            if let Ok(def) = toml::from_str::<ProviderFileDef>(toml_str) {
                for (name, p) in def.provider {
                    providers.insert(name, p);
                }
            }
        }
    }

    /// Resolve a service by name. Returns None if not found.
    pub fn get(&self, service_name: &str) -> Option<&ServiceDef> {
        self.services.get(service_name)
    }

    /// Iterate all loaded service definitions, sorted by id for stable ordering.
    /// Used by the `/v/{vid}/registry` endpoint.
    pub fn iter_sorted(&self) -> Vec<(&str, &ServiceDef)> {
        let mut entries: Vec<(&str, &ServiceDef)> = self
            .services
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        entries.sort_by_key(|(k, _)| *k);
        entries
    }

    /// Get default category for a service, falling back to "service".
    pub fn default_category(&self, service_name: &str) -> &str {
        self.services.get(service_name)
            .map(|d| d.service.category.as_str())
            .unwrap_or("service")
    }

    /// Default-read AccessLevel for a service (H3 unlock bootstrap predicate).
    /// Priority: standalone policy.toml `[default] read` > service.toml inline
    /// `policy.levels.read` > safe default (AskAlways). Per-rule overrides
    /// (e.g. github's `delete-branch ask-always`) are NOT consulted here —
    /// they're evaluated per request at /use time. This helper answers only
    /// "is this service's bulk default `allow`?", i.e. "should its auth value
    /// be bootstrapped into secrets_cache at unlock?".
    pub fn default_read_level(&self, service_id: &str) -> crate::core::policy::AccessLevel {
        if let Some(policy) = self.policies.get(service_id) {
            if let Some(default) = policy.default.as_ref() {
                if let Some(read) = default.get("read") {
                    if let Some(level) = parse_access_level(Some(read)) {
                        return level;
                    }
                }
            }
        }
        if let Some(svc) = self.services.get(service_id) {
            if let Some(policy) = svc.policy.as_ref() {
                if let Some(levels) = policy.to_service_levels() {
                    if let Some(read) = levels.read {
                        return read;
                    }
                }
            }
        }
        crate::core::policy::AccessLevel::AskAlways
    }

    /// Resolve the env vault key that backs a service's first upstream's auth,
    /// if any. Preferred path: `auth.env = "key"`. Legacy fallback: parse
    /// `auth.placeholder = "{{ env.key }}"`. Returns `None` if the service has
    /// no upstream, no auth, or an unparseable placeholder.
    pub fn service_env_key(&self, service_id: &str) -> Option<String> {
        let svc = self.services.get(service_id)?;
        let upstream = svc.upstream.first()?;
        let auth = upstream.auth.as_ref()?;
        if let Some(k) = auth.secret.as_deref() {
            let trimmed = k.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        // Legacy `placeholder = "{{ env.X }}"` template.
        let placeholder = auth.placeholder.as_deref()?;
        let start = placeholder.find("{{")?;
        let end = placeholder[start..].find("}}")?;
        let inner = placeholder[start + 2..start + end].trim();
        let key = inner.strip_prefix("env.")?.trim();
        if key.is_empty() {
            return None;
        }
        Some(key.to_string())
    }

    /// Get OAuth style for a service (if oauth2 with custom style).
    pub fn oauth_style(&self, service_name: &str) -> Option<OAuthStyle> {
        let def = self.services.get(service_name)?;
        // Find the default upstream and check its auth
        let upstream = def.find_upstream("default")?;
        let auth = upstream.auth.as_ref()?;
        match auth.oauth_style.as_deref() {
            Some("json") => Some(OAuthStyle::Json),
            _ => None,
        }
    }

    /// Look up a `[provider.<name>]` template by name.
    pub fn provider(&self, name: &str) -> Option<&ProviderDef> {
        self.providers.get(name)
    }

    /// True if this auth resolves its `auth_mode` to `oauth2`, accounting for
    /// provider inheritance: a service may carry `provider = "google"` and omit
    /// `type` entirely, inheriting `auth_mode = "oauth2"` from the provider.
    pub fn auth_is_oauth2(&self, auth: &AuthDef) -> bool {
        if matches!(auth.auth_type.as_deref(), Some("oauth2")) {
            return true;
        }
        auth.provider
            .as_deref()
            .and_then(|p| self.providers.get(p))
            .and_then(|p| p.auth_mode.as_deref())
            == Some("oauth2")
    }

    /// Resolve the OAuth client/endpoint config for a service's auth, honoring
    /// `provider =` inheritance. When the auth references a provider, the
    /// literal `client_id`/`client_secret`/`token_url` come from the provider
    /// (public Desktop client). When no provider literal exists, falls back to
    /// the legacy env-var path (`client_id_env`/`client_secret_env`/`token_url`)
    /// so self-hosted confidential clients keep working.
    ///
    /// Returns `(token_url, client_id, client_secret)`. Any field the caller
    /// can't satisfy is `None` (caller decides whether it's fatal).
    pub fn resolve_oauth_config(&self, auth: &AuthDef) -> ResolvedOAuthConfig {
        let provider = auth
            .provider
            .as_deref()
            .and_then(|p| self.providers.get(p));

        // token_url: provider literal first, then the service's own literal.
        let token_url = provider
            .and_then(|p| p.token_url.clone())
            .or_else(|| auth.token_url.clone());

        // client_id: provider literal first, then env-var lookup.
        let client_id = provider
            .and_then(|p| p.client_id.clone())
            .or_else(|| auth.client_id_env.as_deref().and_then(|n| std::env::var(n).ok()));

        // client_secret: provider literal first, then env-var lookup (optional
        // for PKCE/public flows).
        let client_secret = provider
            .and_then(|p| p.client_secret.clone())
            .or_else(|| auth.client_secret_env.as_deref().and_then(|n| std::env::var(n).ok()));

        // redirect_uri: provider literal, else the loopback default. A constant
        // of the client (not per-handshake), so the exchange matches consent.
        let redirect_uri = provider
            .and_then(|p| p.redirect_uri.clone())
            .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string());

        ResolvedOAuthConfig { token_url, client_id, client_secret, redirect_uri }
    }

    /// The PUBLIC OAuth consent parameters for `service_id` — what a frontend
    /// needs to start a cloud-blind connect (CONNECTIONS_AND_AUTH.md §4a). The
    /// confidential half (client_secret/token_url) is intentionally omitted; the
    /// daemon does the exchange. Returns `None` when the service isn't oauth2,
    /// declares no `provider`, or the provider lacks an authorization_url/client_id.
    pub fn connect_descriptor(&self, service_id: &str) -> Option<ConnectDescriptor> {
        let def = self.services.get(service_id)?;
        let auth = def.upstream.first()?.auth.as_ref()?;
        if !self.auth_is_oauth2(auth) {
            return None;
        }
        let provider_name = auth.provider.as_deref()?;
        let p = self.providers.get(provider_name)?;
        Some(ConnectDescriptor {
            provider: provider_name.to_string(),
            auth_mode: p.auth_mode.clone().unwrap_or_else(|| "oauth2".to_string()),
            authorization_url: p.authorization_url.clone()?,
            client_id: p.client_id.clone()?,
            scopes: auth.scopes.clone(),
            pkce: p.pkce,
            redirect_uri: p
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
        })
    }

    /// Generate locked response for a service when vault is locked.
    /// In v2, locked response is a plain text string auto-formatted by the proxy.
    pub fn locked_response(
        &self,
        service_name: &str,
        is_stream: bool,
        admin_url: &str,
        path: &str,
    ) -> Option<Response> {
        let def = self.services.get(service_name)?;

        // Find the upstream that would handle this request
        let upstream = def.find_upstream_for_path(path)?;
        let lr = upstream.locked.as_ref()?;

        // v2: use service-defined locked message, or fall back to default
        let custom_message = lr.response.as_deref();

        // Auto-detect API format from upstream URL and generate appropriate response
        locked::render_for_upstream(&upstream.url, is_stream, admin_url, custom_message)
    }

    /// Check if a service is a local CLI bridge (not an HTTP proxy).
    /// In v2: a service is "local" if it has no upstream blocks and its API steps
    /// target safeclaw or openclaw (exec targets, not upstream).
    pub fn is_local(&self, service_name: &str) -> bool {
        let def = match self.services.get(service_name) {
            Some(d) => d,
            None => return false,
        };
        // If the service has upstream blocks, it's a proxy service
        if !def.upstream.is_empty() {
            // But check if the actual API steps target exec, not upstream
            // A service with upstreams and path="*" targeting upstream is a proxy
            for api in &def.api {
                for step in &api.steps {
                    if step.target.starts_with("upstream:") {
                        return false;
                    }
                }
            }
        }
        // If no API steps target upstream, it's a local/exec service
        // (or has no APIs at all, which we treat as non-local)
        !def.api.is_empty()
            && def.api.iter().all(|api| {
                api.steps.iter().all(|s| !s.target.starts_with("upstream:"))
            })
    }

    /// Get vault field declarations for a service.
    pub fn vault_fields(&self, service_name: &str) -> &[VaultField] {
        self.services.get(service_name)
            .map(|d| d.vault.as_slice())
            .unwrap_or(&[])
    }

    /// Find a matching local API definition for the given method + path.
    /// Returns the full API def (all steps will be executed sequentially).
    pub fn find_local_api(&self, service_name: &str, method: &str, path: &str) -> Option<&ApiDef> {
        let def = self.services.get(service_name)?;
        for api in &def.api {
            if let Some(ref m) = api.method {
                if !m.eq_ignore_ascii_case(method) {
                    continue;
                }
            }
            // Match path: "*" matches everything, otherwise prefix match
            if api.path != "*" && !path.starts_with(&api.path) {
                continue;
            }
            if !api.steps.is_empty() {
                return Some(api);
            }
        }
        None
    }

    /// Get default policy levels: policy.toml > service.toml [policy.levels].
    pub fn default_policy_levels(&self, service_name: &str) -> Option<crate::core::policy::ServiceLevels> {
        // Prefer policy.toml [default]
        if let Some(policy) = self.policies.get(service_name) {
            if let Some(levels) = policy.to_service_levels() {
                return Some(levels);
            }
        }
        // Fall back to service.toml [policy.levels]
        let def = self.services.get(service_name)?;
        def.policy.as_ref()?.to_service_levels()
    }

    /// Get default policy rules: policy.toml [[rule]] > service.toml [[policy.rules]].
    pub fn default_policy_rules(&self, service_name: &str) -> Option<Vec<crate::core::policy::PolicyRule>> {
        // Prefer policy.toml [[rule]]
        if let Some(policy) = self.policies.get(service_name) {
            let rules = policy.to_policy_rules();
            if !rules.is_empty() {
                return Some(rules);
            }
        }
        // Fall back to service.toml [[policy.rules]] (legacy, converted to regex)
        let def = self.services.get(service_name)?;
        let policy = def.policy.as_ref()?;
        let rules = policy.to_policy_rules();
        if rules.is_empty() { None } else { Some(rules) }
    }

    /// Get policy file definition (for console UI to show action labels).
    pub fn policy_file(&self, service_name: &str) -> Option<&PolicyFileDef> {
        self.policies.get(service_name)
    }

    /// Return all service definitions (for catalog/UI use).
    pub fn all(&self) -> &HashMap<String, ServiceDef> {
        &self.services
    }

    /// Check if a service has any upstream blocks.
    pub fn has_upstream(&self, service_name: &str) -> bool {
        self.services.get(service_name)
            .map(|d| !d.upstream.is_empty())
            .unwrap_or(false)
    }

    /// Check if a service auto-activates (no credentials needed).
    pub fn is_auto_activated(&self, service_name: &str) -> bool {
        self.services.get(service_name)
            .map(|d| d.service.activation.as_deref() == Some("auto"))
            .unwrap_or(false)
    }

    /// Check if a service is callable by the agent (has [[upstream]], [[api]], or help).
    pub fn is_agent_visible(&self, service_name: &str) -> bool {
        self.services.get(service_name)
            .map(|d| !d.upstream.is_empty() || !d.api.is_empty() || d.service.help.is_some())
            .unwrap_or(false)
    }
}

impl ServiceDef {
    /// Find an upstream block by id.
    pub fn find_upstream(&self, id: &str) -> Option<&UpstreamDef> {
        self.upstream.iter().find(|u| u.id == id)
    }

    /// Find the upstream block that would handle a given request path.
    /// Looks at [[api]] steps to find which upstream is targeted.
    /// Falls back to "default" upstream.
    pub fn find_upstream_for_path(&self, path: &str) -> Option<&UpstreamDef> {
        // Try to find an API that matches the path and has an upstream step
        for api in &self.api {
            if api.path == "*" || path.starts_with(&api.path) {
                for step in &api.steps {
                    if let Some(upstream_id) = step.target.strip_prefix("upstream:") {
                        return self.find_upstream(upstream_id);
                    }
                }
            }
        }
        // Fall back to default upstream
        self.find_upstream("default")
    }

    /// Get the upstream URL for this service (from the default upstream).
    pub fn upstream_url(&self) -> Option<&str> {
        self.find_upstream("default").map(|u| u.url.as_str())
    }

    /// Get the auth definition (from the default upstream).
    pub fn upstream_auth(&self) -> Option<&AuthDef> {
        self.find_upstream("default").and_then(|u| u.auth.as_ref())
    }
}

// ── User service directory ───────────────────────────────────────────────────

/// Returns ~/.safeclaw/services/ path, or None if home dir can't be resolved.
pub fn user_services_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".safeclaw").join("services"))
}

// ── Vault service helpers ────────────────────────────────────────────────────

/// A proxy service has an upstream URL and is visible to the agent.
/// Internal services (e.g. agent-identity, openclaw-dashboard) have no upstream
/// and exist only for recipe execution — they should be hidden from safeclaw.md and UI.
pub fn is_proxy_service(vault_entry: &serde_json::Value) -> bool {
    !vault_entry.is_null() && vault_entry.get("upstream").and_then(|u| u.as_str()).is_some()
}

// ── Header micro-resolver ─────────────────────────────────────────────────────

/// Context for resolving header template variables.
pub struct HeaderContext<'a> {
    pub auth: &'a AuthConfig,
    pub resolved_bearer: Option<&'a str>,
}

/// Resolve template variables in a header value string.
/// Supports: {{uuid_v4}}, {{auth.<field>}}, static strings.
fn resolve_header_value(template: &str, ctx: &HeaderContext) -> Option<String> {
    if !template.contains("{{") {
        // Static value, return as-is
        return Some(template.to_string());
    }

    match template.trim() {
        "{{uuid_v4}}" => Some(uuid::Uuid::new_v4().to_string()),
        s if s.starts_with("{{auth.") && s.ends_with("}}") => {
            let field = &s[7..s.len() - 2];
            match field {
                "account_id" => ctx.auth.account_id.clone(),
                "client_id" => ctx.auth.client_id.clone(),
                "secret" => ctx.auth.secret.clone(),
                _ => None,
            }
        }
        _ => {
            // Unknown template, skip this header
            tracing::debug!("Unknown header template: {}", template);
            None
        }
    }
}

/// Apply service-specific headers from TOML definitions.
/// In v2, headers come from [[upstream]] blocks.
pub fn apply_service_headers(
    auth: &AuthConfig,
    resolved_bearer: Option<&str>,
    headers: &mut reqwest::header::HeaderMap,
    registry: &ServiceRegistry,
    service_name: &str,
) {
    let def = match registry.get(service_name) {
        Some(d) => d,
        None => return,
    };

    // Find the default upstream and apply its headers
    let upstream = match def.find_upstream("default") {
        Some(u) => u,
        None => return,
    };

    if upstream.headers.is_empty() {
        return;
    }

    // Only apply custom headers for oauth2 services with a resolved token
    // (API-key services don't need extra headers — their auth is fully declarative)
    if auth.auth_type == "oauth2" && resolved_bearer.is_some() {
        let ctx = HeaderContext { auth, resolved_bearer };

        for (name, template) in &upstream.headers {
            if let Some(value) = resolve_header_value(template, &ctx) {
                if let (Ok(header_name), Ok(header_value)) = (
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                    reqwest::header::HeaderValue::from_str(&value),
                ) {
                    headers.insert(header_name, header_value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::AccessLevel;

    // ── PolicyDef::to_service_levels ────────────────────────────────────────

    #[test]
    fn policy_def_converts_allow_levels() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "allow".into());
        levels.insert("write".into(), "allow".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_service_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Allow));
        assert_eq!(sl.write, Some(AccessLevel::Allow));
    }

    #[test]
    fn policy_def_converts_mixed_levels() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "allow".into());
        levels.insert("write".into(), "ask".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_service_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Allow));
        assert_eq!(sl.write, Some(AccessLevel::Ask));
    }

    #[test]
    fn policy_def_handles_deny_and_ask_always() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "deny".into());
        levels.insert("write".into(), "ask-always".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_service_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Deny));
        assert_eq!(sl.write, Some(AccessLevel::AskAlways));
    }

    #[test]
    fn policy_def_none_levels_returns_none() {
        let def = PolicyDef { levels: None, rules: vec![] };
        assert!(def.to_service_levels().is_none());
    }

    #[test]
    fn policy_def_partial_levels_has_none_for_missing() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "allow".into());
        // No "write" key
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_service_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Allow));
        assert_eq!(sl.write, None); // missing → None, falls through to defaults
    }

    #[test]
    fn policy_def_unknown_level_value_is_none() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "invalid-value".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_service_levels().unwrap();
        assert_eq!(sl.read, None);
    }

    // ── Service.toml policy as fallback in evaluate_policy ──────────────────

    #[test]
    fn toml_policy_used_when_vault_has_none() {
        // Simulates: vault has no per-service levels, service.toml says allow
        let mut levels = HashMap::new();
        levels.insert("read".into(), "allow".into());
        levels.insert("write".into(), "allow".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let toml_levels = def.to_service_levels();

        // vault_levels = None, so effective = toml_levels
        let effective = None::<&crate::core::policy::ServiceLevels>
            .or(toml_levels.as_ref());

        let access = crate::core::policy::evaluate_policy(
            "POST", "/v1/chat",
            None,
            None,
            effective,
            &crate::core::policy::PolicyDefaults::default(),
            Some("integration"), // not llm, so type defaults = ask-always
        );
        // toml says allow → should win over type defaults
        assert_eq!(access, AccessLevel::Allow);
    }

    #[test]
    fn vault_policy_overrides_toml() {
        // vault explicitly sets ask, toml says allow → vault wins
        let vault_levels = crate::core::policy::ServiceLevels {
            write: Some(AccessLevel::Ask),
            read: Some(AccessLevel::Ask),
            ask_ttl: None,
        };

        let mut toml_map = HashMap::new();
        toml_map.insert("read".into(), "allow".into());
        toml_map.insert("write".into(), "allow".into());
        let toml_def = PolicyDef { levels: Some(toml_map), rules: vec![] };
        let toml_levels = toml_def.to_service_levels();

        let effective = Some(&vault_levels)
            .or(toml_levels.as_ref());

        let access = crate::core::policy::evaluate_policy(
            "POST", "/v1/chat",
            None,
            None,
            effective,
            &crate::core::policy::PolicyDefaults::default(),
            Some("llm"),
        );
        assert_eq!(access, AccessLevel::Ask);
    }

    // ── Service.toml parsing (v2 format) ───────────────────────────────────

    #[test]
    fn parse_upstream_service_toml() {
        let toml_str = r#"
[service]
id = "openai"
name = "OpenAI"
category = "llm"

[[upstream]]
id = "default"
url = "https://api.openai.com"
auth = { type = "bearer", placeholder = "sk-..." }
locked = { response = "Vault locked." }

[[api]]
path = "*"
  [[api.steps]]
  target = "upstream:default"
  returns = true

[policy.levels]
read = "allow"
write = "allow"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        assert_eq!(def.service.id, "openai");
        assert_eq!(def.upstream.len(), 1);
        assert_eq!(def.upstream[0].id, "default");
        assert_eq!(def.upstream[0].url, "https://api.openai.com");
        assert_eq!(def.upstream[0].locked.as_ref().unwrap().response.as_deref(), Some("Vault locked."));
        assert_eq!(def.api.len(), 1);
        assert_eq!(def.api[0].steps[0].target, "upstream:default");
        assert!(def.api[0].steps[0].returns);
        let sl = def.policy.unwrap().to_service_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Allow));
    }

    #[test]
    fn parse_local_service_toml_with_multi_step() {
        let toml_str = r#"
[service]
id = "openclaw-dashboard"
name = "OpenClaw Dashboard"
category = "integration"

[[api]]
method = "POST"
path = "/access"
  [[api.steps]]
  target = "safeclaw.vault"
  read = "services.openclaw-dashboard.gatewayToken"
  returns = true
  [[api.steps]]
  target = "openclaw"
  run = "openclaw devices approve --latest"
  retry = { attempts = 6, interval_ms = 500 }
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        assert_eq!(def.service.id, "openclaw-dashboard");
        assert!(def.upstream.is_empty());
        assert_eq!(def.api.len(), 1);
        let api = &def.api[0];
        assert_eq!(api.method.as_deref(), Some("POST"));
        assert_eq!(api.path, "/access");
        assert_eq!(api.steps.len(), 2);
        // Step 1: vault read
        assert_eq!(api.steps[0].target, "safeclaw.vault");
        assert_eq!(api.steps[0].read.as_deref(), Some("services.openclaw-dashboard.gatewayToken"));
        assert!(api.steps[0].returns);
        assert!(api.steps[0].retry.is_none());
        // Step 2: exec with retry
        assert_eq!(api.steps[1].target, "openclaw");
        assert_eq!(api.steps[1].run.as_deref(), Some("openclaw devices approve --latest"));
        assert!(!api.steps[1].returns);
        let retry = api.steps[1].retry.as_ref().unwrap();
        assert_eq!(retry.attempts, 6);
        assert_eq!(retry.interval_ms, 500);
    }

    // ── is_local / find_local_api ──────────────────────────────────────────

    #[test]
    fn is_local_for_upstream_service() {
        let toml_str = r#"
[service]
id = "openai"
name = "OpenAI"
category = "llm"
[[upstream]]
id = "default"
url = "https://api.openai.com"
[[api]]
path = "*"
  [[api.steps]]
  target = "upstream:default"
  returns = true
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("openai".into(), def);
        let reg = ServiceRegistry { services, policies: HashMap::new(), providers: HashMap::new() };
        assert!(!reg.is_local("openai"));
    }

    #[test]
    fn is_local_for_exec_service() {
        let toml_str = r#"
[service]
id = "dashboard"
name = "Dashboard"
[[api]]
method = "POST"
path = "/access"
  [[api.steps]]
  target = "safeclaw.vault"
  read = "foo.bar"
  returns = true
  [[api.steps]]
  target = "openclaw"
  run = "openclaw devices approve --latest"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("dashboard".into(), def);
        let reg = ServiceRegistry { services, policies: HashMap::new(), providers: HashMap::new() };
        assert!(reg.is_local("dashboard"));
    }

    #[test]
    fn find_local_api_returns_all_steps() {
        let toml_str = r#"
[service]
id = "dashboard"
name = "Dashboard"
[[api]]
method = "POST"
path = "/access"
  [[api.steps]]
  target = "safeclaw.vault"
  read = "x.y"
  returns = true
  [[api.steps]]
  target = "openclaw"
  run = "echo hi"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("dash".into(), def);
        let reg = ServiceRegistry { services, policies: HashMap::new(), providers: HashMap::new() };
        let api = reg.find_local_api("dash", "POST", "/access").unwrap();
        assert_eq!(api.steps.len(), 2);
    }

    #[test]
    fn find_local_api_method_mismatch_returns_none() {
        let toml_str = r#"
[service]
id = "x"
name = "X"
[[api]]
method = "POST"
path = "/do"
  [[api.steps]]
  target = "openclaw"
  run = "echo"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("x".into(), def);
        let reg = ServiceRegistry { services, policies: HashMap::new(), providers: HashMap::new() };
        assert!(reg.find_local_api("x", "GET", "/do").is_none());
    }

    // ── vault field parsing ──────────────────────────────────────────────────

    #[test]
    fn parse_vault_fields() {
        let toml_str = r#"
[service]
id = "dashboard"
name = "Dashboard"

[[vault]]
name = "gatewayToken"
kind = "secret"
description = "Auth token"

[[vault]]
name = "theme"
description = "UI theme preference"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        assert_eq!(def.vault.len(), 2);
        assert_eq!(def.vault[0].name, "gatewayToken");
        assert_eq!(def.vault[0].kind, "secret");
        assert_eq!(def.vault[0].description.as_deref(), Some("Auth token"));
        assert_eq!(def.vault[1].name, "theme");
        assert_eq!(def.vault[1].kind, "config"); // default
        assert_eq!(def.vault[1].description.as_deref(), Some("UI theme preference"));
    }

    #[test]
    fn vault_fields_empty_by_default() {
        let toml_str = r#"
[service]
id = "openai"
name = "OpenAI"
category = "llm"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        assert!(def.vault.is_empty());
    }

    #[test]
    fn vault_fields_accessor() {
        let toml_str = r#"
[service]
id = "dash"
name = "Dash"
[[vault]]
name = "token"
kind = "secret"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("dash".into(), def);
        let reg = ServiceRegistry { services, policies: HashMap::new(), providers: HashMap::new() };
        let fields = reg.vault_fields("dash");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "token");
        assert!(reg.vault_fields("nonexistent").is_empty());
    }

    // ── Compiled-in recipe sanity (v3 token vocabulary) ────────────────────

    /// Every compiled-in service.toml must parse, and every `{{…}}` token in
    /// its upstream URL / headers / query must be a token the broker engine
    /// actually understands. Guards against a recipe shipping a typo'd or
    /// stale (`{{auth_value}}`) placeholder that would only fail at runtime.
    #[test]
    fn compiled_recipes_parse_and_use_known_tokens() {
        // openai-codex is a legacy ChatGPT-oauth proxy carrying `{{auth.*}}`
        // account-bundle tokens; it is non-functional via the broker path
        // (no `auth.env`) and intentionally exempt from the v3 vocabulary.
        const LEGACY_EXEMPT: &[&str] = &["openai-codex"];

        fn token_is_known(tok: &str) -> bool {
            let tok = tok.trim();
            if tok == "uuid_v4" || tok == "oauth.access_token" {
                return true;
            }
            // Secret tokens may carry a pipe filter: `secret.X | b64` /
            // `secret.X | basic`. Parse `source.key | filter` and validate the
            // namespace + filter independently (mirrors
            // `crate::service::validate::token_is_known`).
            let (source_key, filter) = match tok.split_once('|') {
                Some((src, f)) => (src.trim(), Some(f.trim())),
                None => (tok, None),
            };
            match source_key.split_once('.').map(|(ns, _)| ns) {
                Some("secret") => match filter {
                    None | Some("b64") | Some("basic") => true,
                    // `basic:<user>` — non-empty, colon-free username (GitLab `oauth2`).
                    Some(f) => f
                        .strip_prefix("basic:")
                        .map_or(false, |u| !u.is_empty() && !u.contains(':')),
                },
                Some("secret_b64") | Some("secret_basic") => filter.is_none(),
                _ => false,
            }
        }

        fn tokens(s: &str) -> Vec<String> {
            let mut out = Vec::new();
            let mut rest = s;
            while let Some(start) = rest.find("{{") {
                let after = &rest[start + 2..];
                if let Some(end) = after.find("}}") {
                    out.push(after[..end].trim().to_string());
                    rest = &after[end + 2..];
                } else {
                    break;
                }
            }
            out
        }

        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            let def: ServiceDef = toml::from_str(toml_str)
                .unwrap_or_else(|e| panic!("service '{}' failed to parse: {}", id, e));
            if LEGACY_EXEMPT.contains(id) {
                continue;
            }
            for u in &def.upstream {
                let mut surfaces: Vec<&str> = vec![u.url.as_str()];
                surfaces.extend(u.headers.values().map(|v| v.as_str()));
                surfaces.extend(u.query.values().map(|v| v.as_str()));
                for surface in surfaces {
                    for tok in tokens(surface) {
                        assert!(
                            token_is_known(&tok),
                            "service '{}' uses unknown template token '{{{{{}}}}}' in '{}'",
                            id,
                            tok,
                            surface
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn oauth2_secret_field_drives_service_env_key() {
        // OAuth services declare their refresh_token vault item via
        // `auth.secret` (renamed from `env`), same as API-key services.
        // service_env_key must pick this up so registry surfaces a vault_field
        // and the unlock-time cache bootstrap loads the refresh_token (when
        // policy is allow). This is the new provider-inheriting shape: no
        // `type`/endpoints/client on the service — they come from the provider.
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"
category = "integration"

[[upstream]]
id = "default"
url = "https://gmail.googleapis.com"

[upstream.auth]
provider = "google"
scopes = [
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
]
secret = "gmail_refresh_token"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let upstream = def.upstream.first().unwrap();
        let auth = upstream.auth.as_ref().unwrap();
        // No inline `type` — auth_mode is inherited from the provider.
        assert_eq!(auth.auth_type, None);
        assert_eq!(auth.provider.as_deref(), Some("google"));
        assert_eq!(auth.secret.as_deref(), Some("gmail_refresh_token"));
        assert_eq!(auth.scopes.len(), 3);

        // service_env_key uses auth.secret first, so OAuth services resolve to
        // their refresh_token item — exactly like API-key services.
        let mut services = HashMap::new();
        services.insert("gmail".into(), def);
        let reg = ServiceRegistry {
            services,
            policies: HashMap::new(),
            providers: HashMap::new(),
        };
        assert_eq!(
            reg.service_env_key("gmail").as_deref(),
            Some("gmail_refresh_token"),
        );
    }

    #[test]
    fn secret_field_accepts_env_alias_for_backcompat() {
        // Existing recipes (and stored connections) still write `env = "..."`.
        // The serde alias keeps them parsing into `secret` unchanged.
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"
category = "integration"
[[upstream]]
id = "default"
url = "https://api.github.com"
auth = { env = "github_token" }
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let auth = def.upstream[0].auth.as_ref().unwrap();
        assert_eq!(auth.secret.as_deref(), Some("github_token"));
    }

    #[test]
    fn multi_secret_table_parses() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"
category = "integration"
[[upstream]]
id = "default"
url = "https://gmail.googleapis.com"
[upstream.auth]
provider = "google"
[upstream.auth.secrets]
refresh_token = "gmail_refresh_token"
webhook_key = "gmail_webhook"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let auth = def.upstream[0].auth.as_ref().unwrap();
        let secrets = auth.secrets.as_ref().unwrap();
        assert_eq!(secrets.get("refresh_token").map(String::as_str), Some("gmail_refresh_token"));
        assert_eq!(secrets.get("webhook_key").map(String::as_str), Some("gmail_webhook"));
    }

    #[test]
    fn setup_block_parses() {
        // Top-level bare `setup` string (sibling to [service]/[[upstream]]/…),
        // placed before any [section] as TOML requires for bare keys.
        let toml_str = r#"
setup = """
Route the user's git remotes through SafeClaw so the PAT never enters git.
git config --global url."{{proxy_base}}/stream/github-git/".insteadOf "https://github.com/"
"""

[service]
id = "github-git"
name = "GitHub Git"
category = "integration"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let setup = def.setup.as_deref().unwrap();
        assert!(setup.contains("Route the user's git remotes through SafeClaw"));
        assert!(setup.contains("{{proxy_base}}/stream/github-git/"));
        assert!(setup.contains("insteadOf"));
    }

    #[test]
    fn provider_file_parses() {
        let toml_str = r#"
[provider.google]
auth_mode = "oauth2"
flow = "authorization_code"
authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
pkce = true
client_id = "499410884315-x.apps.googleusercontent.com"
client_secret = "GOCSPX-public"
client_type = "public"
"#;
        let file: ProviderFileDef = toml::from_str(toml_str).unwrap();
        let p = file.provider.get("google").unwrap();
        assert_eq!(p.auth_mode.as_deref(), Some("oauth2"));
        assert_eq!(p.flow.as_deref(), Some("authorization_code"));
        assert!(p.pkce);
        assert_eq!(p.client_type.as_deref(), Some("public"));
        assert_eq!(p.token_url.as_deref(), Some("https://oauth2.googleapis.com/token"));
    }

    #[test]
    fn provider_inheritance_resolves_oauth_config() {
        // A service with `provider = "google"` and no inline type/endpoints
        // inherits auth_mode + token_url + client from the provider literal.
        let svc_toml = r#"
[service]
id = "gmail"
name = "Gmail"
category = "integration"
[[upstream]]
id = "default"
url = "https://gmail.googleapis.com"
[upstream.auth]
provider = "google"
secret = "gmail_refresh_token"
"#;
        let prov_toml = r#"
[provider.google]
auth_mode = "oauth2"
token_url = "https://oauth2.googleapis.com/token"
client_id = "public-client-id"
client_secret = "public-secret"
client_type = "public"
"#;
        let def: ServiceDef = toml::from_str(svc_toml).unwrap();
        let pfile: ProviderFileDef = toml::from_str(prov_toml).unwrap();

        let mut services = HashMap::new();
        services.insert("gmail".into(), def);
        let mut providers = HashMap::new();
        for (name, p) in pfile.provider {
            providers.insert(name, p);
        }
        let reg = ServiceRegistry {
            services,
            policies: HashMap::new(),
            providers,
        };

        let auth = reg.get("gmail").unwrap().upstream[0].auth.as_ref().unwrap();
        // Inherited auth_mode → recognized as oauth2 despite no inline `type`.
        assert!(reg.auth_is_oauth2(auth));
        let cfg = reg.resolve_oauth_config(auth);
        assert_eq!(cfg.token_url.as_deref(), Some("https://oauth2.googleapis.com/token"));
        assert_eq!(cfg.client_id.as_deref(), Some("public-client-id"));
        assert_eq!(cfg.client_secret.as_deref(), Some("public-secret"));
    }

    #[test]
    fn inline_auth_without_provider_still_oauth2() {
        // Self-hosted confidential clients keep declaring type + endpoints
        // locally with env-var client refs (no provider literal).
        let toml_str = r#"
[service]
id = "selfhosted"
name = "Self Hosted"
category = "integration"
[[upstream]]
id = "default"
url = "https://api.example.com"
[upstream.auth]
type = "oauth2"
secret = "selfhosted_refresh_token"
token_url = "https://api.example.com/token"
client_id_env = "SELFHOSTED_CLIENT_ID"
client_secret_env = "SELFHOSTED_CLIENT_SECRET"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let reg = ServiceRegistry {
            services: HashMap::new(),
            policies: HashMap::new(),
            providers: HashMap::new(),
        };
        let auth = def.upstream[0].auth.as_ref().unwrap();
        assert!(reg.auth_is_oauth2(auth));
        // No provider literal → falls back to the env-var path. token_url is
        // the service's own literal.
        let cfg = reg.resolve_oauth_config(auth);
        assert_eq!(cfg.token_url.as_deref(), Some("https://api.example.com/token"));
    }

    #[test]
    fn compiled_google_services_inherit_provider() {
        // The shipped gmail/gdrive/gcalendar recipes must resolve oauth2 via
        // the compiled-in google provider after the recipe rewrite.
        let mut providers = HashMap::new();
        for (_f, toml_str) in crate::generated_services::compiled_provider_tomls() {
            let pfile: ProviderFileDef = toml::from_str(toml_str).unwrap();
            for (name, p) in pfile.provider {
                providers.insert(name, p);
            }
        }
        assert!(providers.contains_key("google"), "google provider must be compiled in");

        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = toml::from_str::<ServiceDef>(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let reg = ServiceRegistry {
            services,
            policies: HashMap::new(),
            providers,
        };
        for id in ["gmail", "gdrive", "gcalendar"] {
            let auth = reg.get(id).unwrap().upstream[0].auth.as_ref()
                .unwrap_or_else(|| panic!("{} missing auth", id));
            assert_eq!(auth.provider.as_deref(), Some("google"), "{}", id);
            assert!(reg.auth_is_oauth2(auth), "{} should be oauth2 via provider", id);
            let cfg = reg.resolve_oauth_config(auth);
            assert_eq!(
                cfg.token_url.as_deref(),
                Some("https://oauth2.googleapis.com/token"),
                "{}", id
            );
            assert!(cfg.client_id.is_some(), "{} client_id", id);
            assert!(!auth.scopes.is_empty(), "{} scopes", id);
        }
    }

    #[test]
    fn connect_descriptor_for_gmail_exposes_public_consent_only() {
        let reg = ServiceRegistry::load();
        let d = reg
            .connect_descriptor("gmail")
            .expect("gmail is oauth2 with a google provider");
        assert_eq!(d.provider, "google");
        assert_eq!(d.auth_mode, "oauth2");
        assert!(d.authorization_url.starts_with("https://accounts.google.com/"));
        assert!(d.client_id.ends_with(".apps.googleusercontent.com"));
        assert!(d.pkce);
        assert!(d.scopes.iter().any(|s| s.contains("gmail.send")));

        // CLOUD-BLIND: the descriptor that ships to the browser must NEVER carry
        // the confidential half — no client_secret, no token endpoint.
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("GOCSPX"), "client_secret leaked: {json}");
        assert!(
            !json.contains("oauth2.googleapis.com/token"),
            "token_url leaked: {json}"
        );
    }

    #[test]
    fn connect_descriptor_none_for_non_oauth_service() {
        let reg = ServiceRegistry::load();
        // openai is a bearer/api-key service — no oauth2 consent to start.
        assert!(reg.connect_descriptor("openai").is_none());
    }

    /// End-to-end guard for the risk-tier rewrite of the gmail recipe: the
    /// compiled-in `gmail/policy.toml` must PARSE (the loader silently drops a
    /// policy that fails `toml::from_str`, so a typo wouldn't fail the build —
    /// only this test would) AND each rule must resolve to the intended access
    /// level through the default `risk_policy`. Also pins the headline win:
    /// list (low→allow) + read (medium→ask) = one approval to read an email,
    /// not two.
    #[test]
    fn compiled_gmail_policy_resolves_risk_tiers() {
        use crate::core::policy::{evaluate_policy, AccessLevel, PolicyDefaults};
        let reg = ServiceRegistry::load();
        let rules = reg
            .default_policy_rules("gmail")
            .expect("gmail policy.toml must parse and yield rules");
        let defaults = PolicyDefaults::default();
        let eval = |m: &str, p: &str| {
            evaluate_policy(m, p, None, Some(&rules), None, &defaults, Some("integration"))
        };
        // low → allow (listing, no private body)
        assert_eq!(eval("GET", "/gmail/v1/users/me/messages"), AccessLevel::Allow);
        assert_eq!(eval("GET", "/gmail/v1/users/me/labels"), AccessLevel::Allow);
        // medium → ask (reads private content, once per TTL)
        assert_eq!(eval("GET", "/gmail/v1/users/me/messages/abc123"), AccessLevel::Ask);
        // high → ask-always (outbound / mutating)
        assert_eq!(eval("POST", "/gmail/v1/users/me/messages/send"), AccessLevel::AskAlways);
        assert_eq!(eval("POST", "/gmail/v1/users/me/messages/abc123/modify"), AccessLevel::AskAlways);
        // pinned deny (escape hatch, ignores risk_policy)
        assert_eq!(eval("DELETE", "/gmail/v1/users/me/messages/abc123"), AccessLevel::Deny);
    }
}
