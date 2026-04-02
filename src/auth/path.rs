// Path-based authentication: inject key into URL path (e.g. Google API style)

use super::AuthConfig;

/// Transform the URL path to inject auth credentials.
pub fn transform(auth: &AuthConfig, rest_path: &str) -> String {
    let key = auth.secret.as_deref().unwrap_or("");
    if let Some(tmpl) = &auth.path_template {
        tmpl.replace("{key}", key)
    } else {
        format!("/{}{}", key, rest_path)
    }
}
