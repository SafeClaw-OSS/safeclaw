// Default provider: pure vault-config-driven, no provider-specific behavior.

use super::ServiceProvider;

/// Fallback provider for services with no custom behavior.
/// All methods use the default (no-op) implementations.
pub struct Default;

impl ServiceProvider for Default {
    fn names(&self) -> &[&str] { &[] }
}

/// Generic LLM provider: no custom headers/locked responses, just category = "llm".
/// Used for providers that are OpenAI-compatible (deepseek, groq, etc.)
pub struct GenericLlm {
    pub names: &'static [&'static str],
}

impl ServiceProvider for GenericLlm {
    fn names(&self) -> &[&str] { self.names }
    fn default_category(&self) -> &str { "llm" }
}
