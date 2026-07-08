/// TOML-driven service registry (v4, phantom-only broker).
///
/// Each service is defined by a `service.toml` in `services/{id}/` (flat — the
/// dir name is the id; classification lives in the `tags` field, not layout).
/// A service declares what a minimal connection has — `hosts` + `secrets` —
/// plus the one non-direct production (`[oauth2]`) and cosmetic helpers. No
/// routing/transport is declared: the phantom is the sole intent carrier and
/// the request already carries the real upstream URL.

pub mod validate;

use std::collections::HashMap;
use crate::auth::oauth2::OAuthStyle;

// ── ServiceDef: parsed from service.toml (v4) ───────────────────────────────

/// A service TYPE. `deny_unknown_fields` rejects stale v3 sections and any
/// tool-named section (`[git]`, `[docker]`) at parse — auth is a MECHANISM,
/// never a tool, and the only named auth section is `[oauth2]`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDef {
    pub service: ServiceMeta,
    /// The sole non-direct production. When present, the phantom resolves to a
    /// minted OAuth access token; the refresh token named by `oauth2.refresh_token`
    /// is internal by construction and never injectable.
    #[serde(default)]
    pub oauth2: Option<OAuth2Def>,
    /// Optional agent-facing `setup` prose: service-specific guidance on where a
    /// phantom goes for this service's tools (a header, an env var, a URL) when
    /// run under `sc run --`. Plain text — no template tokens.
    #[serde(default)]
    pub setup: Option<String>,
    /// Optional inline policy fallback (`[policy.levels]` / `[[policy.rules]]`).
    /// Standalone `policy.toml` is preferred; kept for back-compat with tests
    /// and any service that inlines its floor.
    #[serde(default)]
    pub policy: Option<PolicyDef>,
}

impl ServiceDef {
    /// The stored secret role that backs this service's credential: the oauth2
    /// refresh-token role for an `[oauth2]` service, else its first `secrets`
    /// entry. `None` when it declares neither. A pure projection over the def —
    /// the SINGLE source of truth for "which vault role holds this service's
    /// secret", so a registry service and a vault-custom service resolve
    /// identically. Callers that only have a `service_id` and a registry go
    /// through [`service_env_key`]; callers that may face a custom service
    /// resolve the `ServiceDef` first (registry `.or_else(custom_service)`) and
    /// call this directly.
    pub fn env_role(&self) -> Option<String> {
        if let Some(o) = self.oauth2.as_ref() {
            let s = o.refresh_token.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
        self.service
            .secrets
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
    }
}

/// The one named auth MECHANISM. The `[oauth2]` section is SELF-SUFFICIENT: it
/// declares the endpoints + public client inline (`authorization_url`,
/// `token_url`, `client_id`, …) — the same shape whether it ships in-tree or is
/// user-authored (`aux.services`). There is no template/inheritance layer;
/// services sharing an OAuth client (the Google trio) simply repeat it.
/// `provider` is a pure display label ("Connect with Google").
///
/// Token slots use the RFC 6749 response field names: `refresh_token` maps the
/// durable refresh token to the vault secret KEY it is stored under (internal —
/// the mint reads it, no phantom exposes it); optional `id_token` maps a stored
/// OIDC id token likewise. The minted `access_token` is ephemeral (never
/// stored, never named) — it is what the default phantom resolves to. `exposes`
/// lists extra minted/derived roles surfaced as role-qualified phantoms (e.g.
/// openai-codex's `account_id`); `claims` maps such a role to its id_token
/// claim path (array of nested keys — a segment may itself contain dots or
/// slashes, e.g. a namespaced `https://api.openai.com/auth` claim). The flow
/// temps `code`/`code_verifier` are standard, not per-service — they live in
/// `aux.connecting.oauth2`, never here.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Def {
    /// Pure display label for the frontend's connect button ("Connect with
    /// Google"). Carries NO configuration; absent reads as "custom".
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RFC 6749 `refresh_token` → the vault secret KEY the durable refresh token
    /// is stored under (e.g. `GMAIL_REFRESH_TOKEN`). Named explicitly (not
    /// derived) so a service declaring more than one secret is unambiguous.
    pub refresh_token: String,
    /// RFC 6749 `id_token` → the vault secret KEY a stored OIDC id token is
    /// written under. Only for providers that return a durable id token; absent
    /// for the common access+refresh flow.
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub exposes: Vec<String>,
    /// `exposes` role → its claim path in the exchange's id_token payload, as an
    /// ARRAY of nested object keys (a plain string path would be ambiguous —
    /// OIDC namespace keys contain `.`/`/` themselves). A role with no mapping
    /// falls back to a top-level claim of the same name.
    #[serde(default)]
    pub claims: HashMap<String, Vec<String>>,

    // ── Inline endpoints + public client ──
    /// CONNECT step endpoint (user consent).
    #[serde(default)]
    pub authorization_url: Option<String>,
    /// REFRESH + code-exchange endpoint.
    #[serde(default)]
    pub token_url: Option<String>,
    /// OAuth client_id (a PUBLIC client's id — safe to declare in a recipe).
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth client_secret. A literal secret in a definition is BY CONVENTION a
    /// PUBLIC client's (RFC 6749 §2.1) — non-confidential by the vendor's own
    /// design, like Google's Desktop client. A confidential secret must never
    /// sit in a recipe; that line is review-enforced (there is no client_type
    /// field to assert it — tooling stamped it automatically, so it proved
    /// nothing).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Whether the connect flow uses PKCE (RFC 7636). Defaults to `true`
    /// (every public client should).
    #[serde(default)]
    pub pkce: Option<bool>,
    /// The OAuth client's fixed redirect_uri. Falls back to
    /// [`DEFAULT_LOOPBACK_REDIRECT`].
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Body style for the `/token` call: `form` (default) or `json` (Anthropic).
    #[serde(default)]
    pub oauth_style: Option<String>,
    /// Extra static query params for the consent URL — the per-vendor quirks
    /// (Google's `access_type=offline`/`prompt=consent`, codex's
    /// `codex_cli_simplified_flow=true`). Reserved protocol params (client_id,
    /// redirect_uri, scope, state, response_type, code_challenge*) are rejected
    /// by the validator — these are ADDITIONS, never overrides.
    #[serde(default)]
    pub authorize_params: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceMeta {
    pub id: String,
    pub name: String,
    /// Classification tags (lowercase-kebab, multiple allowed) — e.g. "ai",
    /// "app", "messaging", "wallet". Replaces the old directory-derived single
    /// category. Dual use: browse/filter metadata on the registry wire, and
    /// policy tag-floor matching (`Policy.categories` keys; when several tags
    /// hit floors the most restrictive wins). Absent (per-vault custom
    /// services) = untagged: no tag floor applies, console buckets it as an
    /// app.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Anchored egress hosts — exact FQDNs or `*.suffix` wildcards (leftmost
    /// single label). The runtime anchor validates the destination against the
    /// exact entries (and pinned instances of the wildcards). Declared under the
    /// `[service]` table.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Stored secret role keys (`[A-Z0-9_]`). A phantom resolves to the value
    /// as-is; the injection SITE is the agent's (header/query/URL/Basic).
    /// Declared under the `[service]` table.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// If set, this service is grouped with the service whose id matches this value.
    /// Services sharing the same group are merged into one card in the UI.
    #[serde(default)]
    pub group: Option<String>,
    /// Optional, purely auxiliary: the page where a HUMAN mints/manages this
    /// service's secret (e.g. `https://crates.io/settings/tokens`). Pairs with
    /// `secrets` above. Display-only — consumers render it as a helper link
    /// (console "Open ... -> API tokens", CLI "Get a token: ..."); nothing ever
    /// FETCHES a secret from it, and it never participates in routing or
    /// policy. Must be http(s) when present (it is rendered as a link).
    #[serde(default)]
    pub secret_url: Option<String>,
    /// Help text returned by GET /{service}/help and rendered into safeclaw.md.
    /// Supports template variables: {{wallet.*}} resolved from vault service data.
    #[serde(default)]
    pub help: Option<String>,
    /// Activation mode: "auto" = starts automatically without credentials.
    /// Absent/None = requires user "connect" (provide API key / OAuth).
    #[serde(default)]
    pub activation: Option<String>,
    /// If true, exclude from `/registry` and `/v/{vid}/registry`. Use for
    /// services that are defined but not yet ready for agent discovery.
    #[serde(default)]
    pub hidden: bool,
}

/// The loopback redirect for desktop/PKCE OAuth clients when an `[oauth2]`
/// section doesn't pin its own `redirect_uri`. Matches the frontend
/// `DEFAULT_LOOPBACK_REDIRECT` so the consent request and the code→token
/// exchange always agree.
pub const DEFAULT_LOOPBACK_REDIRECT: &str = "http://127.0.0.1:8765/safeclaw/oauth/callback";

/// A service's `[oauth2]` client/endpoint config with the defaults applied —
/// see `ServiceRegistry::resolve_oauth_config`.
#[derive(Debug, Clone)]
pub struct ResolvedOAuthConfig {
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// The OAuth client's fixed redirect_uri (inline literal, or the loopback
    /// default). Sent in the daemon's code→token exchange so it matches the
    /// consent request the browser made.
    pub redirect_uri: String,
}

/// The OAuth wiring of a service's `[oauth2]` section, as broadcast on the
/// public `/registry` response — everything a frontend needs to START a
/// connect (consent URL) and to DISPLAY the wiring faithfully.
/// CONNECTIONS_AND_AUTH.md §4a.
///
/// This mirrors the definition 1:1 on purpose: a definition may only ever
/// contain PUBLIC-client material (a literal `client_secret` in a def is a
/// public client's by convention — see `OAuth2Def::client_secret`), so there
/// is nothing confidential to withhold — hiding fields here would only make
/// the console lie about what the toml says. The daemon still does the
/// code→token exchange locally; the browser only drives consent and seals the
/// resulting `{code, verifier}` into the vault.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectDescriptor {
    /// Display label ("Connect with Google"); "custom" when the def names none.
    pub provider: String,
    pub authorization_url: String,
    /// REFRESH + code-exchange endpoint (display/reference — the daemon uses it,
    /// the frontend never calls it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    pub client_id: String,
    /// The PUBLIC client's secret, when the def ships one (e.g. Google's
    /// Desktop client, non-confidential by design).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub pkce: bool,
    /// The OAuth client's fixed redirect_uri — the frontend builds the consent
    /// URL from this (not a hardcoded constant) so it always matches what the
    /// daemon sends at code→token exchange (CONNECTION_SCHEMA.md §5).
    pub redirect_uri: String,
    /// `/token` body style: `form` (default) or `json`.
    pub oauth_style: String,
    /// Extra static consent-URL query params (vendor quirks: Google's
    /// `access_type=offline`, codex's `codex_cli_simplified_flow=true`). The
    /// frontend appends these BEFORE setting the reserved protocol params, so
    /// they can never override client_id/redirect_uri/state/….
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub authorize_params: HashMap<String, String>,
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
    pub fn to_levels(&self) -> Option<crate::core::policy::Levels> {
        let levels = self.levels.as_ref()?;
        Some(crate::core::policy::Levels {
            write: parse_access_level(levels.get("write")),
            read: parse_access_level(levels.get("read")),
            ttl: None,
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
    /// Convert legacy method+path_exact+path_suffix to a core rule. The legacy
    /// `level` is the access decision directly.
    fn to_core_rule(&self) -> Option<crate::core::policy::PolicyRule> {
        let level = crate::core::policy::AccessLevel::parse(&self.level)?;

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
            level: Some(level),
            ttl: None,
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
    /// Access decision (`allow` | `ask` | `ask-always` | `deny`) when this rule
    /// matches. A rule with no parseable `level` is skipped.
    #[serde(default)]
    pub level: Option<String>,
    /// `ask`-cache TTL in seconds (PROTOCOL.md §6.1 `policy.rules[].ttl`).
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl PolicyFileDef {
    pub fn to_levels(&self) -> Option<crate::core::policy::Levels> {
        let levels = self.default.as_ref()?;
        Some(crate::core::policy::Levels {
            write: parse_access_level(levels.get("write")),
            read: parse_access_level(levels.get("read")),
            ttl: levels.get("ttl").and_then(|v| v.parse().ok()),
        })
    }

    pub fn to_policy_rules(&self) -> Vec<crate::core::policy::PolicyRule> {
        self.rule.iter().filter_map(|r| {
            // A rule decides via its `level`; one with no parseable level is
            // skipped (it could never decide).
            let level = r.level.as_deref().and_then(crate::core::policy::AccessLevel::parse)?;
            Some(crate::core::policy::PolicyRule {
                id: Some(r.id.clone()),
                label: Some(r.label.clone()),
                match_pattern: Some(r.match_pattern.clone()),
                body: r.body.clone(),
                level: Some(level),
                ttl: r.ttl,
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

// ── ServiceRegistry ───────────────────────────────────────────────────────────

pub struct ServiceRegistry {
    services: HashMap<String, ServiceDef>,
    /// Parsed policy.toml files (service_id → PolicyFileDef).
    policies: HashMap<String, PolicyFileDef>,
}

impl ServiceRegistry {
    /// Load all service definitions in priority layers:
    /// 1. Compiled-in defaults (always loaded as base)
    /// 2. $SAFECLAW_DATA/services/ (runtime override for dev/deployment)
    /// 3. ~/.safeclaw/services/ (user-installed services, highest priority)
    pub fn load() -> Self {
        let mut services = HashMap::new();
        let mut policies = HashMap::new();

        // Layer 1: compiled-in defaults (always loaded as base)
        Self::load_compiled_defaults(&mut services, &mut policies);

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

        tracing::info!(
            "Loaded {} service definitions, {} policy files",
            services.len(), policies.len()
        );
        Self { services, policies }
    }

    /// Build a registry from ONLY the compiled-in (in-tree) services — no
    /// `$SAFECLAW_DATA` / user-installed overrides, no filesystem I/O. Used by
    /// offline tooling (`sc registry`) and CI to render the exact catalog a
    /// freshly-built daemon serves, without booting a server or reading any
    /// deployment state.
    pub fn compiled_only() -> Self {
        let mut services = HashMap::new();
        let mut policies = HashMap::new();
        Self::load_compiled_defaults(&mut services, &mut policies);
        Self { services, policies }
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

            // Otherwise, scan one level deeper — tolerant reader for the
            // retired nested services/{category}/{id}/ layout (pre-tags
            // user-installed dirs may still carry it).
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

    /// Classification tags for a service; empty for unknown ids and untagged
    /// (custom) services — no tag floor applies then, only the global floor.
    pub fn service_tags(&self, service_name: &str) -> &[String] {
        self.services.get(service_name)
            .map(|d| d.service.tags.as_slice())
            .unwrap_or(&[])
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
                if let Some(levels) = policy.to_levels() {
                    if let Some(read) = levels.read {
                        return read;
                    }
                }
            }
        }
        crate::core::policy::AccessLevel::AskAlways
    }

    /// The stored secret role that backs a **registry** service's credential.
    /// Thin wrapper over [`ServiceDef::env_role`] — a registry-only lookup.
    /// A connection may reference a vault-custom service (`aux.services`) that
    /// is NOT in the compiled registry; such a caller must resolve the
    /// `ServiceDef` custom-awarely (registry `.or_else(custom_service)`) and
    /// call `def.env_role()` directly, or it will miss the custom def and fall
    /// back to the connection id — the bug this split removes.
    pub fn service_env_key(&self, service_id: &str) -> Option<String> {
        self.services.get(service_id).and_then(|d| d.env_role())
    }

    /// The `/token` body style for a service's `[oauth2]`: `oauth_style`,
    /// defaulting to `form`.
    pub fn oauth_style(&self, oauth: &OAuth2Def) -> OAuthStyle {
        match oauth.oauth_style.as_deref() {
            Some("json") => OAuthStyle::Json,
            _ => OAuthStyle::Form,
        }
    }

    /// A service's `[oauth2]` client/endpoint config with the defaults applied
    /// (loopback redirect_uri). A missing field is `None` (caller decides
    /// whether it's fatal).
    pub fn resolve_oauth_config(&self, oauth: &OAuth2Def) -> ResolvedOAuthConfig {
        ResolvedOAuthConfig {
            token_url: oauth.token_url.clone(),
            client_id: oauth.client_id.clone(),
            client_secret: oauth.client_secret.clone(),
            redirect_uri: oauth
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
        }
    }

    /// The public OAuth wiring broadcast for `service_id` — see
    /// [`ConnectDescriptor`]. `None` when the service isn't oauth2 or its
    /// section lacks an authorization_url + client_id.
    pub fn connect_descriptor(&self, service_id: &str) -> Option<ConnectDescriptor> {
        let def = self.services.get(service_id)?;
        let oauth = def.oauth2.as_ref()?;
        self.connect_descriptor_for(oauth)
    }

    /// [`Self::connect_descriptor`] for an `[oauth2]` section directly — shared
    /// with per-vault custom services that don't live in `self.services`.
    pub fn connect_descriptor_for(&self, oauth: &OAuth2Def) -> Option<ConnectDescriptor> {
        Some(ConnectDescriptor {
            provider: oauth
                .provider
                .clone()
                .unwrap_or_else(|| "custom".to_string()),
            authorization_url: oauth.authorization_url.clone()?,
            token_url: oauth.token_url.clone(),
            client_id: oauth.client_id.clone()?,
            client_secret: oauth.client_secret.clone(),
            scopes: oauth.scopes.clone(),
            pkce: oauth.pkce.unwrap_or(true),
            redirect_uri: oauth
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
            oauth_style: match oauth.oauth_style.as_deref() {
                Some("json") => "json".to_string(),
                _ => "form".to_string(),
            },
            authorize_params: oauth.authorize_params.clone(),
        })
    }

    /// Get default policy levels: policy.toml > service.toml [policy.levels].
    pub fn default_policy_levels(&self, service_name: &str) -> Option<crate::core::policy::Levels> {
        // Prefer policy.toml [default]
        if let Some(policy) = self.policies.get(service_name) {
            if let Some(levels) = policy.to_levels() {
                return Some(levels);
            }
        }
        // Fall back to service.toml [policy.levels]
        let def = self.services.get(service_name)?;
        def.policy.as_ref()?.to_levels()
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

}

// ── User service directory ───────────────────────────────────────────────────

/// Returns ~/.safeclaw/services/ path, or None if home dir can't be resolved.
pub fn user_services_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".safeclaw").join("services"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::AccessLevel;

    fn reg(services: HashMap<String, ServiceDef>) -> ServiceRegistry {
        ServiceRegistry { services, policies: HashMap::new() }
    }

    // ── PolicyDef::to_levels (inline policy fallback kept) ───────────────────

    #[test]
    fn policy_def_converts_allow_levels() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "allow".into());
        levels.insert("write".into(), "allow".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Allow));
        assert_eq!(sl.write, Some(AccessLevel::Allow));
    }

    #[test]
    fn policy_def_handles_deny_and_ask_always() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "deny".into());
        levels.insert("write".into(), "ask-always".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let sl = def.to_levels().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Deny));
        assert_eq!(sl.write, Some(AccessLevel::AskAlways));
    }

    #[test]
    fn toml_policy_used_when_vault_has_none() {
        let mut levels = HashMap::new();
        levels.insert("read".into(), "allow".into());
        levels.insert("write".into(), "allow".into());
        let def = PolicyDef { levels: Some(levels), rules: vec![] };
        let toml_levels = def.to_levels();
        let access = crate::core::policy::evaluate(
            "POST", "/v1/chat", None, None, toml_levels.as_ref(),
            &crate::core::policy::Policy::default(), &["app".into()],
        );
        assert_eq!(access, AccessLevel::Allow);
    }

    // ── v4 service.toml parsing ──────────────────────────────────────────────

    #[test]
    fn parse_direct_service_hosts_and_secrets() {
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        assert_eq!(def.service.id, "github");
        assert_eq!(def.service.hosts, vec!["api.github.com", "github.com"]);
        assert_eq!(def.service.secrets, vec!["GITHUB_TOKEN"]);
        assert!(def.oauth2.is_none());
    }

    #[test]
    fn parse_oauth2_service() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"

hosts = ["gmail.googleapis.com"]

[oauth2]
provider = "google"
scopes = ["https://www.googleapis.com/auth/gmail.send"]
refresh_token = "GMAIL_REFRESH_TOKEN"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let o = def.oauth2.as_ref().unwrap();
        assert_eq!(o.provider.as_deref(), Some("google"));
        assert_eq!(o.refresh_token, "GMAIL_REFRESH_TOKEN");
        assert_eq!(o.scopes.len(), 1);
        assert!(o.exposes.is_empty());
    }

    #[test]
    fn parse_oauth2_exposes() {
        let toml_str = r#"
[service]
id = "openai-codex"
name = "OpenAI Codex"

hosts = ["api.openai.com"]

[oauth2]
provider = "openai"
refresh_token = "OPENAI_CODEX_REFRESH_TOKEN"
exposes = ["account_id"]
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        assert_eq!(def.oauth2.as_ref().unwrap().exposes, vec!["account_id"]);
    }

    #[test]
    fn deny_unknown_fields_rejects_tool_and_v3_sections() {
        // A tool-named section is rejected — sections are auth MECHANISMS only.
        let git = r#"
[service]
id = "x"
name = "X"
hosts = ["x.com"]
[git]
helper = "sc"
"#;
        assert!(toml::from_str::<ServiceDef>(git).is_err(), "[git] must be rejected");
        // A stale v3 `[[upstream]]` is rejected too.
        let v3 = r#"
[service]
id = "x"
name = "X"
[[upstream]]
id = "default"
url = "https://x.com"
"#;
        assert!(toml::from_str::<ServiceDef>(v3).is_err(), "[[upstream]] must be rejected");
    }

    #[test]
    fn oauth2_secret_drives_service_env_key() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
[oauth2]
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("gmail".into(), def);
        let r = reg(services);
        assert_eq!(r.service_env_key("gmail").as_deref(), Some("GMAIL_REFRESH_TOKEN"));
    }

    #[test]
    fn direct_secret_drives_service_env_key() {
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"
hosts = ["api.github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let mut services = HashMap::new();
        services.insert("github".into(), def);
        let r = reg(services);
        assert_eq!(r.service_env_key("github").as_deref(), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn custom_def_env_role_resolves_when_registry_misses() {
        // A vault-custom `[oauth2]` service (e.g. a user-added "gcp"): NOT in the
        // compiled registry. `service_env_key(id)` is a registry-only lookup, so
        // it returns None and the ask/approve path would fall back to the
        // connection id as the op `target` — the "secret 'gcp' not found" bug.
        // Resolving the def and calling `env_role()` directly is source-agnostic
        // and names the real refresh key.
        let toml_str = r#"
[service]
id = "gcp"
name = "Google Cloud"
hosts = ["compute.googleapis.com"]
[oauth2]
provider = "google"
refresh_token = "GCP_REFRESH_TOKEN"
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        // The pure projection resolves regardless of where the def came from —
        // the single source of truth both the forward and approve paths share.
        assert_eq!(def.env_role().as_deref(), Some("GCP_REFRESH_TOKEN"));
        // A registry WITHOUT this custom service confirms the asymmetry the fix
        // removes: the id-based lookup misses, so a caller that may face a custom
        // service must go through the resolved def's `env_role`, never the
        // registry-only `service_env_key`.
        let r = reg(HashMap::new());
        assert_eq!(r.service_env_key("gcp"), None);
    }

    #[test]
    fn setup_block_parses_plain_prose() {
        let toml_str = r#"
setup = """
Put the phantom in the URL: sc run -- git clone https://x:__sc__github__@github.com/o/r
"""

[service]
id = "github"
name = "GitHub"
hosts = ["github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def: ServiceDef = toml::from_str(toml_str).unwrap();
        let setup = def.setup.as_deref().unwrap();
        assert!(setup.contains("sc run --"));
    }

    // ── [oauth2] inline resolution ────────────────────────────────────────────

    #[test]
    fn oauth_style_defaults_form_inline_json_wins() {
        let r = reg(HashMap::new());
        let oauth = |style: Option<&str>| OAuth2Def {
            provider: None,
            scopes: vec![],
            refresh_token: "RT".into(),
            id_token: None,
            exposes: vec![],
            claims: HashMap::new(),
            authorization_url: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            pkce: None,
            redirect_uri: None,
            oauth_style: style.map(|s| s.to_string()),
            authorize_params: HashMap::new(),
        };
        assert!(matches!(r.oauth_style(&oauth(None)), OAuthStyle::Form));
        assert!(matches!(r.oauth_style(&oauth(Some("form"))), OAuthStyle::Form));
        assert!(matches!(r.oauth_style(&oauth(Some("json"))), OAuthStyle::Json));
    }

    // ── compiled-in sanity (post-migration) ──────────────────────────────────

    #[test]
    fn compiled_services_parse_and_validate() {
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            let def: ServiceDef = toml::from_str(toml_str)
                .unwrap_or_else(|e| panic!("service '{}' failed to parse: {}", id, e));
            // Non-hidden services must anchor at least one host.
            if !def.service.hidden {
                assert!(!def.service.hosts.is_empty(), "service '{}' declares no hosts", id);
            }
            // [oauth2] is self-sufficient: every compiled oauth service must be
            // inline-complete (there is no template layer to fill gaps).
            if let Some(o) = &def.oauth2 {
                assert!(!o.refresh_token.is_empty(), "service '{}' oauth2 has empty refresh_token", id);
                assert!(o.authorization_url.is_some(), "service '{}' oauth2 missing authorization_url", id);
                assert!(o.token_url.is_some(), "service '{}' oauth2 missing token_url", id);
                assert!(o.client_id.is_some(), "service '{}' oauth2 missing client_id", id);
            }
        }
    }

    #[test]
    fn compiled_codex_resolves_fully_inline() {
        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = toml::from_str::<ServiceDef>(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let r = reg(services);
        let oauth = r.get("openai_codex").unwrap().oauth2.clone().expect("codex [oauth2]");
        let cfg = r.resolve_oauth_config(&oauth);
        assert_eq!(cfg.token_url.as_deref(), Some("https://auth.openai.com/oauth/token"));
        assert_eq!(cfg.client_id.as_deref(), Some("app_EMoamEEZ73f0CkXaXp7hrann"));
        assert!(cfg.client_secret.is_none(), "codex is pure PKCE");
        assert_eq!(cfg.redirect_uri, "http://localhost:1455/auth/callback");
        let d = r.connect_descriptor("openai_codex").expect("codex descriptor");
        assert!(d.pkce);
        assert_eq!(d.provider, "openai");
        assert_eq!(
            d.authorize_params.get("codex_cli_simplified_flow").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            oauth.claims.get("account_id").map(Vec::as_slice),
            Some(&["https://api.openai.com/auth".to_string(), "chatgpt_account_id".to_string()][..])
        );
    }

    #[test]
    fn descriptor_labels_custom_when_no_provider() {
        let r = reg(HashMap::new());
        let mut oauth: OAuth2Def = toml::from_str(
            "refresh_token=\"RT\"\nauthorization_url=\"https://b.example/auth\"\nclient_id=\"cid\"\n[authorize_params]\nprompt=\"login\"\n",
        ).unwrap();
        let d = r.connect_descriptor_for(&oauth).unwrap();
        assert_eq!(d.provider, "custom");
        assert_eq!(d.client_id, "cid");
        assert_eq!(d.authorize_params.get("prompt").map(String::as_str), Some("login"));
        // A provider name is a pure label — it changes nothing but the label.
        oauth.provider = Some("g".into());
        let d2 = r.connect_descriptor_for(&oauth).unwrap();
        assert_eq!(d2.provider, "g");
        assert_eq!(d2.client_id, "cid");
    }

    #[test]
    fn compiled_google_trio_is_inline_complete_and_shares_one_client() {
        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = toml::from_str::<ServiceDef>(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let r = reg(services);
        let mut client_ids = std::collections::HashSet::new();
        for id in ["gmail", "gdrive", "gcalendar"] {
            let oauth = r.get(id).unwrap().oauth2.clone()
                .unwrap_or_else(|| panic!("{} missing [oauth2]", id));
            assert_eq!(oauth.provider.as_deref(), Some("google"), "{}", id);
            let cfg = r.resolve_oauth_config(&oauth);
            assert_eq!(cfg.token_url.as_deref(), Some("https://oauth2.googleapis.com/token"), "{}", id);
            client_ids.insert(cfg.client_id.expect("client_id"));
            assert!(!oauth.scopes.is_empty(), "{} scopes", id);
        }
        assert_eq!(client_ids.len(), 1, "the trio must share ONE Desktop client (rotate together)");
    }

    #[test]
    fn connect_descriptor_for_gmail_mirrors_the_full_wiring() {
        // The descriptor is a 1:1 mirror of the def — a def can only hold
        // public-client material (validator), so nothing is withheld and the
        // console can display the wiring faithfully.
        let r = ServiceRegistry::load();
        let d = r.connect_descriptor("gmail").expect("gmail is oauth2");
        assert_eq!(d.provider, "google");
        assert!(d.authorization_url.starts_with("https://accounts.google.com/"));
        assert_eq!(d.token_url.as_deref(), Some("https://oauth2.googleapis.com/token"));
        assert!(d.client_id.ends_with(".apps.googleusercontent.com"));
        assert!(d.client_secret.as_deref().is_some_and(|s| s.starts_with("GOCSPX-")),
            "the public Desktop client_secret is part of the wiring");
        assert!(d.pkce);
        assert_eq!(d.oauth_style, "form");
        assert!(d.scopes.iter().any(|s| s.contains("gmail.send")));
        assert_eq!(d.authorize_params.get("access_type").map(String::as_str), Some("offline"));
    }

    #[test]
    fn connect_descriptor_none_for_non_oauth_service() {
        let r = ServiceRegistry::load();
        assert!(r.connect_descriptor("openai").is_none());
    }

    #[test]
    fn compiled_gmail_policy_resolves_risk_tiers() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r.default_policy_rules("gmail")
            .expect("gmail policy.toml must parse and yield rules");
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(m, p, None, Some(&rules), None, &policy, &["app".into()])
        };
        assert_eq!(eval("GET", "/gmail/v1/users/me/messages"), AccessLevel::Allow);
        assert_eq!(eval("GET", "/gmail/v1/users/me/messages/abc123"), AccessLevel::Ask);
        assert_eq!(eval("POST", "/gmail/v1/users/me/messages/send"), AccessLevel::AskAlways);
        assert_eq!(eval("DELETE", "/gmail/v1/users/me/messages/abc123"), AccessLevel::AskAlways);
    }

    #[test]
    fn compiled_cratesio_policy_gates_publish_surface() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r.default_policy_rules("cratesio")
            .expect("cratesio policy.toml must parse and yield rules");
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(m, p, None, Some(&rules), None, &policy, &["app".into()])
        };
        // Routine traffic rides the allow floor.
        assert_eq!(eval("GET", "/api/v1/me"), AccessLevel::Allow);
        assert_eq!(eval("GET", "/api/v1/crates"), AccessLevel::Allow);
        assert_eq!(eval("PUT", "/api/v1/crates/serde/follow"), AccessLevel::Allow);
        // Publish + version availability ask once per window.
        assert_eq!(eval("PUT", "/api/v1/crates/new"), AccessLevel::Ask);
        assert_eq!(eval("DELETE", "/api/v1/crates/serde/1.0.219/yank"), AccessLevel::Ask);
        assert_eq!(eval("PUT", "/api/v1/crates/serde/1.0.219/unyank"), AccessLevel::Ask);
        assert_eq!(eval("PATCH", "/api/v1/crates/serde/1.0.219"), AccessLevel::Ask);
        // Ownership + supply chain gate every time.
        assert_eq!(eval("PUT", "/api/v1/crates/serde/owners"), AccessLevel::AskAlways);
        assert_eq!(eval("DELETE", "/api/v1/crates/serde/owners"), AccessLevel::AskAlways);
        assert_eq!(eval("POST", "/api/v1/trusted_publishing/github_configs"), AccessLevel::AskAlways);
        assert_eq!(eval("PATCH", "/api/v1/crates/serde"), AccessLevel::AskAlways);
        // Publish approvals cover a workspace release train, not one crate.
        let publish = rules.iter().find(|ru| ru.id.as_deref() == Some("publish")).unwrap();
        assert_eq!(publish.ttl, Some(1800));
    }
}
