/// TOML-driven service registry (protocol v2).
///
/// Each service is defined by a `service.toml` in `services/{category}/{id}/`.
/// No Rust code is needed per service — upstream, API steps, and policies are declarative.

pub mod locked;

use std::collections::HashMap;
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
}

fn default_category() -> String { "integration".to_string() }

/// Named upstream destination block.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UpstreamDef {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub auth: Option<AuthDef>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub locked: Option<LockedResponseDef>,
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
    #[serde(rename = "type")]
    pub auth_type: String,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub oauth_style: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub username_label: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyDef {
    pub levels: Option<HashMap<String, String>>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl PolicyDef {
    /// Convert to the policy engine's ServiceLevels type.
    pub fn to_service_levels(&self) -> Option<crate::core::policy::ServiceLevels> {
        let levels = self.levels.as_ref()?;
        let parse = |key: &str| -> Option<crate::core::policy::AccessLevel> {
            match levels.get(key)?.as_str() {
                "allow" => Some(crate::core::policy::AccessLevel::Allow),
                "ask" => Some(crate::core::policy::AccessLevel::Ask),
                "ask-always" => Some(crate::core::policy::AccessLevel::AskAlways),
                "deny" => Some(crate::core::policy::AccessLevel::Deny),
                _ => None,
            }
        };
        Some(crate::core::policy::ServiceLevels {
            write: parse("write"),
            read: parse("read"),
        })
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyRule {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path_exact: Option<String>,
    #[serde(default)]
    pub path_suffix: Option<String>,
    pub level: String,
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
}

impl ServiceRegistry {
    /// Load all service definitions from `services/*/service.toml`.
    /// Falls back to compiled-in definitions if the directory is not found.
    pub fn load() -> Self {
        let mut services = HashMap::new();

        // Try runtime path first ($SAFECLAW_DATA/services/), then compiled-in
        let dirs = Self::discover_service_dirs();
        for (id, toml_str) in dirs {
            match toml::from_str::<ServiceDef>(&toml_str) {
                Ok(def) => { services.insert(id, def); }
                Err(e) => {
                    tracing::warn!("Failed to parse service.toml for {}: {}", id, e);
                }
            }
        }

        if services.is_empty() {
            tracing::warn!("No service definitions found, loading compiled-in defaults");
            Self::load_compiled_defaults(&mut services);
        }

        tracing::info!("Loaded {} service definitions", services.len());
        Self { services }
    }

    fn discover_service_dirs() -> Vec<(String, String)> {
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

    /// Scan for service.toml files. Supports both flat and nested layouts:
    ///   services/anthropic/service.toml          (flat)
    ///   services/llm/anthropic/service.toml      (nested by category)
    fn scan_dir(base: &std::path::Path, results: &mut Vec<(String, String)>) {
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
                        results.push((id, content));
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
                            results.push((id, content));
                        }
                    }
                }
            }
        }
    }

    /// Compiled-in service definitions for when filesystem discovery fails.
    /// Uses the auto-generated registry from build.rs.
    fn load_compiled_defaults(services: &mut HashMap<String, ServiceDef>) {
        let defaults = crate::generated_services::compiled_service_tomls();
        for (id, toml_str) in defaults {
            if let Ok(def) = toml::from_str::<ServiceDef>(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
    }

    /// Resolve a service by name. Returns None if not found.
    pub fn get(&self, service_name: &str) -> Option<&ServiceDef> {
        self.services.get(service_name)
    }

    /// Get default category for a service, falling back to "service".
    pub fn default_category(&self, service_name: &str) -> &str {
        self.services.get(service_name)
            .map(|d| d.service.category.as_str())
            .unwrap_or("service")
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

    /// Get the service.toml policy levels as a fallback when vault has none.
    pub fn default_policy_levels(&self, service_name: &str) -> Option<crate::core::policy::ServiceLevels> {
        let def = self.services.get(service_name)?;
        def.policy.as_ref()?.to_service_levels()
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

    /// Check if a service is callable by the agent (has [[upstream]] or [[api]]).
    pub fn is_agent_visible(&self, service_name: &str) -> bool {
        self.services.get(service_name)
            .map(|d| !d.upstream.is_empty() || !d.api.is_empty())
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
        let reg = ServiceRegistry { services };
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
        let reg = ServiceRegistry { services };
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
        let reg = ServiceRegistry { services };
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
        let reg = ServiceRegistry { services };
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
        let reg = ServiceRegistry { services };
        let fields = reg.vault_fields("dash");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "token");
        assert!(reg.vault_fields("nonexistent").is_empty());
    }
}
