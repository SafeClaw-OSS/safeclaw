// Bearer token authentication: `Authorization: Bearer {secret}`

use super::AuthConfig;

/// Inject bearer token from service config.
pub fn inject(auth: &AuthConfig, headers: &mut reqwest::header::HeaderMap) {
    let secret = auth.secret.as_deref().unwrap_or("");
    let val = format!("Bearer {}", secret);
    if let Ok(hv) = reqwest::header::HeaderValue::from_str(&val) {
        headers.insert(reqwest::header::AUTHORIZATION, hv);
    }
}

/// Inject a pre-resolved bearer token (e.g. from OAuth2 refresh).
pub fn inject_resolved(token: &str, headers: &mut reqwest::header::HeaderMap) {
    let val = format!("Bearer {}", token);
    if let Ok(hv) = reqwest::header::HeaderValue::from_str(&val) {
        headers.insert(reqwest::header::AUTHORIZATION, hv);
    }
}
