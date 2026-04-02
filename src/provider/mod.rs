/// Service provider plugin system.
///
/// Each upstream service can optionally implement the `ServiceProvider` trait
/// to customize headers, locked responses, OAuth refresh, etc.
/// Services without a provider implementation use `DefaultProvider` (pure config).
pub mod default;
pub mod anthropic;
pub mod openai;
pub mod google;

use axum::response::Response;
use crate::auth::AuthConfig;
use crate::auth::oauth2::OAuthStyle;

// ── ServiceProvider Trait ───────────────────────────────────────────────────────

/// Trait for provider-specific behavior.
///
/// Most methods have default implementations (no-op), so providers only need
/// to override what they customize. Adding a new provider requires:
/// 1. Create a file in `provider/` implementing this trait
/// 2. Register it in `build_registry()` below
pub trait ServiceProvider: Send + Sync {
    /// Service name(s) this provider matches.
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

    /// Locked vault response in this provider's API format.
    /// Return None to use a generic JSON error.
    fn locked_response(
        &self,
        _is_stream: bool,
        _admin_url: &str,
        _path: &str,
    ) -> Option<Response> { None }
}

// ── Provider Registry ──────────────────────────────────────────────────────────

pub struct ProviderRegistry {
    providers: Vec<Box<dyn ServiceProvider>>,
}

impl ProviderRegistry {
    /// Build the registry with all built-in providers.
    pub fn new() -> Self {
        Self {
            providers: vec![
                Box::new(anthropic::Anthropic),
                Box::new(openai::OpenAI),
                Box::new(google::Google),
                Box::new(default::GenericLlm { names: &["deepseek", "groq"] }),
            ],
        }
    }

    /// Resolve a provider by service name. Returns the DefaultProvider if none matches.
    pub fn resolve(&self, service_name: &str) -> &dyn ServiceProvider {
        for p in &self.providers {
            if p.names().contains(&service_name) {
                return p.as_ref();
            }
        }
        &default::Default
    }
}

// ── Convenience: apply_provider_headers (used by forward.rs) ────────────────────

/// Inject provider-specific headers. Called from core/forward.rs after auth injection.
pub fn apply_provider_headers(
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
