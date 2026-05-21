// Custom header authentication: `{name}: {prefix} {secret}`

use std::str::FromStr;
use super::AuthConfig;

pub fn inject(auth: &AuthConfig, headers: &mut reqwest::header::HeaderMap) {
    let header_name = auth.name.as_deref().unwrap_or("authorization").to_lowercase();
    let secret = auth.secret.as_deref().unwrap_or("");
    let header_val = if let Some(prefix) = &auth.prefix {
        if prefix.is_empty() {
            secret.to_string()
        } else {
            format!("{} {}", prefix.trim_end(), secret)
        }
    } else {
        secret.to_string()
    };
    if let (Ok(hn), Ok(hv)) = (
        reqwest::header::HeaderName::from_str(&header_name),
        reqwest::header::HeaderValue::from_str(&header_val),
    ) {
        headers.insert(hn, hv);
    }
}
