// Default service: pure vault-config-driven, no service-specific behavior.

use super::Service;

/// Fallback service for services with no custom behavior.
/// All methods use the default (no-op) implementations.
pub struct Default;

impl Service for Default {
    fn names(&self) -> &[&str] { &[] }
}

/// Generic LLM service: no custom headers/locked responses, just category = "llm".
/// Used for services that are OpenAI-compatible (deepseek, groq, etc.)
pub struct GenericLlm {
    pub names: &'static [&'static str],
}

impl Service for GenericLlm {
    fn names(&self) -> &[&str] { self.names }
    fn default_category(&self) -> &str { "llm" }
}
