// Anthropic Claude API provider.

use std::str::FromStr;
use axum::response::Response;
use crate::auth::AuthConfig;
use crate::auth::oauth2::OAuthStyle;
use super::Service;
use crate::core::locked::anthropic_locked;

pub struct Anthropic;

impl Service for Anthropic {
    fn names(&self) -> &[&str] { &["anthropic"] }

    fn default_category(&self) -> &str { "llm" }

    fn oauth_style(&self) -> Option<OAuthStyle> {
        Some(OAuthStyle::Json)
    }

    fn apply_headers(
        &self,
        _auth: &AuthConfig,
        _resolved_bearer: Option<&str>,
        headers: &mut reqwest::header::HeaderMap,
    ) {
        headers.insert(
            reqwest::header::HeaderName::from_static("anthropic-beta"),
            reqwest::header::HeaderValue::from_static(
                "oauth-2025-04-20,interleaved-thinking-2025-05-14",
            ),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(
                "claude-cli/2.1.87 (external, cli)",
            ),
        );
        let session_id = uuid::Uuid::new_v4().to_string();
        if let Ok(hv) = reqwest::header::HeaderValue::from_str(&session_id) {
            headers.insert(
                reqwest::header::HeaderName::from_static("x-claude-code-session-id"),
                hv,
            );
        }
    }

    fn locked_response(&self, is_stream: bool, admin_url: &str, _path: &str) -> Option<Response> {
        Some(anthropic_locked(is_stream, admin_url))
    }
}
