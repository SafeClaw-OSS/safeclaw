// Query parameter authentication: `?{name}={secret}`

use super::AuthConfig;
use crate::core::forward::urlencoding_encode;

/// Transform the query string to inject auth credentials.
pub fn transform(auth: &AuthConfig, original_query: &str) -> String {
    let name = auth.name.as_deref().unwrap_or("key");
    let val = auth.secret.as_deref().unwrap_or("");
    if original_query.is_empty() {
        format!("?{}={}", urlencoding_encode(name), urlencoding_encode(val))
    } else {
        format!(
            "{}&{}={}",
            original_query,
            urlencoding_encode(name),
            urlencoding_encode(val)
        )
    }
}
