// Basic authentication: `Authorization: Basic {base64(username:password)}`

use base64::{engine::general_purpose::STANDARD, Engine};
use super::AuthConfig;

pub fn inject(auth: &AuthConfig, headers: &mut reqwest::header::HeaderMap) {
    let user = auth.username.as_deref().unwrap_or("");
    let pass = auth.password.as_deref().unwrap_or(
        auth.secret.as_deref().unwrap_or(""),
    );
    let encoded = STANDARD.encode(format!("{}:{}", user, pass));
    let val = format!("Basic {}", encoded);
    if let Ok(hv) = reqwest::header::HeaderValue::from_str(&val) {
        headers.insert(reqwest::header::AUTHORIZATION, hv);
    }
}
