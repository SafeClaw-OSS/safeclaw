/// Service plugin system.
///
/// Each upstream service can optionally implement the `Service` trait
/// to customize headers, locked responses, OAuth refresh, etc.
/// Services without a custom implementation use `Default` (pure config).
pub mod default;
pub mod anthropic;
pub mod openai;
pub mod google;

use axum::response::Response;
use crate::auth::AuthConfig;
use crate::auth::oauth2::OAuthStyle;

// ── Service Trait ───────────────────────────────────────────────────────

/// Trait for service-specific behavior.
///
/// Most methods have default implementations (no-op), so services only need
/// to override what they customize. Adding a new service requires:
/// 1. Create a file in `service/` implementing this trait
/// 2. Register it in `ServiceRegistry::new()` below
pub trait Service: Send + Sync {
    /// Service name(s) this implementation matches.
    fn names(&self) -> &[&str];

    /// Default category if not set in vault config.
    fn default_category(&self) -> &str { "service" }

    /// Extra headers beyond standard auth injection.
    /// Called after generic auth (bearer/basic/header) is already applied.
    fn apply_headers(
        &self,
        _auth: &AuthConfig,
        _resolved_bearer: Option<&str>,
        _headers: &mut reqwest::header::HeaderMap,
    ) {}

    /// Custom OAuth2 refresh style. Return None to use the default form-urlencoded.
    fn oauth_style(&self) -> Option<OAuthStyle> { None }

    /// Locked vault response in this service's API format.
    /// Return None to use a generic JSON error.
    fn locked_response(
        &self,
        _is_stream: bool,
        _admin_url: &str,
        _path: &str,
    ) -> Option<Response> { None }
}

// ── Service Registry ─────────────────────────────────────────────────────────

pub struct ServiceRegistry {
    services: Vec<Box<dyn Service>>,
}

impl ServiceRegistry {
    /// Build the registry with all built-in services.
    pub fn new() -> Self {
        Self {
            services: vec![
                Box::new(anthropic::Anthropic),
                Box::new(openai::OpenAI),
                Box::new(google::Google),
                Box::new(default::GenericLlm { names: &["deepseek", "groq"] }),
            ],
        }
    }

    /// Resolve a service by name. Returns Default if none matches.
    pub fn resolve(&self, service_name: &str) -> &dyn Service {
        for s in &self.services {
            if s.names().contains(&service_name) {
                return s.as_ref();
            }
        }
        &default::Default
    }
}

// ── Convenience: apply_service_headers (used by forward.rs) ─────────────────

/// Inject service-specific headers. Called from core/forward.rs after auth injection.
pub fn apply_service_headers(
    auth: &AuthConfig,
    resolved_bearer: Option<&str>,
    headers: &mut reqwest::header::HeaderMap,
) {
    if auth.auth_type != "oauth2" || resolved_bearer.is_none() {
        return;
    }

    // Anthropic OAuth
    if let Some(token_url) = &auth.token_url {
        if token_url.contains("anthropic.com") || token_url.contains("platform.claude.com") {
            anthropic::Anthropic.apply_headers(auth, resolved_bearer, headers);
        }
    }

    // OpenAI Codex OAuth
    if auth.account_id.is_some() {
        openai::OpenAI.apply_headers(auth, resolved_bearer, headers);
    }
}
