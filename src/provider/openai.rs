// OpenAI provider (Chat Completions + Responses API + Codex).

use std::str::FromStr;
use axum::response::Response;
use crate::auth::AuthConfig;
use super::ServiceProvider;
use crate::core::locked::{openai_locked, openai_responses_locked};

pub struct OpenAI;

impl ServiceProvider for OpenAI {
    fn names(&self) -> &[&str] { &["openai"] }

    fn default_category(&self) -> &str { "llm" }

    fn apply_headers(
        &self,
        auth: &AuthConfig,
        _resolved_bearer: Option<&str>,
        headers: &mut reqwest::header::HeaderMap,
    ) {
        if let Some(account_id) = &auth.account_id {
            if let Ok(hv) = reqwest::header::HeaderValue::from_str(account_id) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("chatgpt-account-id"),
                    hv,
                );
            }
            headers.insert(
                reqwest::header::HeaderName::from_static("openai-beta"),
                reqwest::header::HeaderValue::from_static("responses=experimental"),
            );
        }
    }

    fn locked_response(&self, is_stream: bool, admin_url: &str, path: &str) -> Option<Response> {
        if path.contains("/responses") {
            Some(openai_responses_locked(is_stream, admin_url))
        } else {
            Some(openai_locked(is_stream, admin_url))
        }
    }
}
