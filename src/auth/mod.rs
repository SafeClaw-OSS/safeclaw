/// Service authentication: credential injection for upstream requests.
///
/// Each auth type (bearer, basic, header, query, path, oauth2) has its own
/// submodule. The `inject_auth()` function dispatches to the correct one.
pub mod bearer;
pub mod basic;
pub mod header;
pub mod query;
pub mod path;
pub mod oauth2;
pub mod connect;

// ── Vault Types ──────────────────────────────────────────────────────────────

/// Per-service data stored in vault.enc (secrets + runtime auth state).
/// Policy is NOT here — it lives in `aux.policy` (SSoT); this struct carries
/// only the upstream/auth/category needed to forward a request.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceVault {
    /// Upstream base URL. Required for proxy services; absent for local services.
    #[serde(default)]
    pub upstream: Option<String>,
    pub auth: Option<AuthConfig>,
    /// UI display category — "llm" | "channel" | "integration" (default: "integration").
    /// Pure metadata; not used by proxy routing or auth logic.
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthConfig {
    #[serde(rename = "type")]
    pub auth_type: String,

    // For header / bearer / query / path
    pub name: Option<String>,
    /// The credential secret.  Accepts both "secret" (new) and "value" (legacy).
    #[serde(alias = "value")]
    pub secret: Option<String>,
    pub prefix: Option<String>,

    // For path type
    #[serde(rename = "pathTemplate")]
    pub path_template: Option<String>,

    // For basic auth
    pub username: Option<String>,
    pub password: Option<String>,

    // For oauth2
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    /// Cached access token (in-memory only; never written back to vault)
    pub access_token: Option<String>,
    pub expires_at: Option<u64>,

    // For OpenAI Codex OAuth (chatgpt.com/backend-api)
    pub account_id: Option<String>,
}

// ── Auth injection dispatcher ──────────────────────────────────────────────────

/// Inject authentication credentials into the request headers.
/// Handles bearer, basic, and custom header types.
/// Query and path types are handled at the URL level by `transform_url()`.
pub fn inject_auth(
    auth: &AuthConfig,
    resolved_bearer: Option<&str>,
    headers: &mut reqwest::header::HeaderMap,
) {
    // Pre-resolved bearer (from oauth2 refresh) takes priority
    if let Some(bearer_token) = resolved_bearer {
        bearer::inject_resolved(bearer_token, headers);
        return;
    }

    match auth.auth_type.as_str() {
        "bearer" => bearer::inject(auth, headers),
        "basic" => basic::inject(auth, headers),
        "header" => header::inject(auth, headers),
        // query and path are handled at URL level, not header level
        _ => {}
    }
}

/// Transform the upstream URL for auth types that modify the URL (query, path).
/// Returns (modified_path, modified_query).
pub fn transform_url(
    auth: &AuthConfig,
    rest_path: &str,
    original_query: &str,
) -> (String, String) {
    match auth.auth_type.as_str() {
        "path" => (path::transform(auth, rest_path), original_query.to_string()),
        "query" => (rest_path.to_string(), query::transform(auth, original_query)),
        _ => (rest_path.to_string(), original_query.to_string()),
    }
}
