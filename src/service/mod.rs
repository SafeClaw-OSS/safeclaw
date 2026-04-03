/// TOML-driven service registry.
///
/// Each service is defined by a `service.toml` in `services/{id}/`.
/// No Rust code is needed per service — headers, locked responses, and
/// categories are all declarative.

pub mod locked;

use std::collections::HashMap;
use axum::response::Response;
use crate::auth::AuthConfig;
use crate::auth::oauth2::OAuthStyle;

// ── ServiceDef: parsed from service.toml ──────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceDef {
    pub service: ServiceMeta,
    pub upstream: Option<UpstreamDef>,
    pub policy: Option<PolicyDef>,
}

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
}

fn default_category() -> String { "integration".to_string() }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct UpstreamDef {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(rename = "type", default = "default_upstream_type")]
    pub upstream_type: String,
    #[serde(default)]
    pub auth: Option<AuthDef>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub locked: Option<LockedResponseDef>,
    #[serde(default)]
    pub apis: Vec<LocalApiDef>,
}

fn default_upstream_type() -> String { "proxy".to_string() }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct LocalApiDef {
    pub method: String,
    pub path: String,
    pub command: String,
}

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
    pub key_placeholder: Option<String>,
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
    pub template: Option<String>,
    #[serde(default)]
    pub routes: HashMap<String, String>,
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
        let upstream = def.upstream.as_ref()?;
        let auth = upstream.auth.as_ref()?;
        match auth.oauth_style.as_deref() {
            Some("json") => Some(OAuthStyle::Json),
            _ => None,
        }
    }

    /// Generate locked response for a service when vault is locked.
    pub fn locked_response(
        &self,
        service_name: &str,
        is_stream: bool,
        admin_url: &str,
        path: &str,
    ) -> Option<Response> {
        let def = self.services.get(service_name)?;
        let upstream = def.upstream.as_ref()?;
        let lr = upstream.locked.as_ref()?;

        // Check path-specific routes first
        for (route_prefix, template_name) in &lr.routes {
            if path.contains(route_prefix) {
                return locked::render(template_name, is_stream, admin_url);
            }
        }

        // Fall back to default template
        lr.template.as_ref()
            .and_then(|t| locked::render(t, is_stream, admin_url))
    }

    /// Check if a service is a local CLI bridge (not an HTTP proxy).
    pub fn is_local(&self, service_name: &str) -> bool {
        self.services.get(service_name)
            .and_then(|d| d.upstream.as_ref())
            .map(|u| u.upstream_type == "local")
            .unwrap_or(false)
    }

    /// Find a matching local API definition for the given method + path.
    pub fn find_local_api(&self, service_name: &str, method: &str, path: &str) -> Option<&LocalApiDef> {
        let def = self.services.get(service_name)?;
        let upstream = def.upstream.as_ref()?;
        upstream.apis.iter().find(|api| {
            api.method.eq_ignore_ascii_case(method) && path.starts_with(&api.path)
        })
    }

    /// Return all service definitions (for catalog/UI use).
    pub fn all(&self) -> &HashMap<String, ServiceDef> {
        &self.services
    }
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
/// Called from core/forward.rs after standard auth injection.
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

    let upstream = match def.upstream.as_ref() {
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
