// Google Gemini provider.

use axum::response::Response;
use crate::auth::AuthConfig;
use super::Service;
use crate::core::locked::gemini_locked;

pub struct Google;

impl Service for Google {
    fn names(&self) -> &[&str] { &["google"] }

    fn default_category(&self) -> &str { "llm" }

    fn locked_response(&self, _is_stream: bool, admin_url: &str, _path: &str) -> Option<Response> {
        Some(gemini_locked(admin_url))
    }
}
