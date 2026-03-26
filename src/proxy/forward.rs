/// Upstream request forwarding via reqwest (supports HTTP and HTTPS).
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use axum::body::Bytes;
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use std::str::FromStr;

use crate::policy::{PolicyRule, ServiceLevels};

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
});

// ── Config Types ───────────────────────────────────────────────────────────────

/// Service configuration extracted from vault secrets
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceConfig {
    pub upstream: String,
    pub auth: Option<AuthConfig>,
    /// Per-service access levels (optional; falls back to policy defaults)
    pub levels: Option<ServiceLevels>,
    /// Per-request rule overrides (optional; most specific match wins)
    pub rules: Option<Vec<PolicyRule>>,
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
}

// ── Routing ────────────────────────────────────────────────────────────────────

/// Parse route: /service/rest/of/path?query → (service, path, query)
pub fn parse_route(req_path: &str) -> Option<(String, String, String)> {
    let (path_part, query_part) = if let Some(q) = req_path.find('?') {
        (&req_path[..q], req_path[q..].to_string())
    } else {
        (req_path, String::new())
    };

    let parts: Vec<&str> = path_part.splitn(3, '/').collect();
    if parts.len() < 2 || parts[1].is_empty() {
        return None;
    }
    let service = parts[1].to_string();
    let rest = if parts.len() >= 3 {
        format!("/{}", parts[2])
    } else {
        "/".to_string()
    };

    Some((service, rest, query_part))
}

// ── OAuth2 Refresh ─────────────────────────────────────────────────────────────

/// Attempt to refresh an OAuth2 access token using the refresh_token grant.
/// Returns (access_token, expires_at_unix_secs) on success.
pub async fn refresh_oauth2_token(
    auth: &AuthConfig,
) -> Result<(String, u64), String> {
    let token_url = auth
        .token_url
        .as_ref()
        .ok_or("oauth2: missing token_url")?;
    let client_id = auth
        .client_id
        .as_ref()
        .ok_or("oauth2: missing client_id")?;
    let client_secret = auth
        .client_secret
        .as_ref()
        .ok_or("oauth2: missing client_secret")?;
    let refresh_token = auth
        .refresh_token
        .as_ref()
        .ok_or("oauth2: missing refresh_token")?;

    let resp = HTTP_CLIENT
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .map_err(|e| format!("oauth2 refresh request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("oauth2 refresh returned HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("oauth2 refresh parse failed: {}", e))?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("oauth2 response missing access_token")?
        .to_string();

    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok((access_token, now_secs + expires_in))
}

// ── Forward ────────────────────────────────────────────────────────────────────

/// Forward a request to the upstream service.
/// `resolved_bearer` is set by the proxy layer for oauth2 (pre-refreshed token).
pub async fn forward_request(
    method: Method,
    uri_path: &str,
    headers: &HeaderMap,
    body_bytes: Bytes,
    service_config: &ServiceConfig,
    resolved_bearer: Option<&str>,
) -> Response {
    let upstream_url = &service_config.upstream;

    // Parse upstream base URL for host header
    let parsed_upstream = match upstream_url.parse::<url::Url>() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("Invalid upstream URL: {}", e) })),
            )
                .into_response();
        }
    };

    let host = match parsed_upstream.host_str() {
        Some(h) => h.to_string(),
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": "Upstream URL missing host" })),
            )
                .into_response();
        }
    };

    // Build the upstream path + query
    let (_service_name, rest_path, query) = match parse_route(uri_path) {
        Some(r) => r,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": "Invalid request path" })),
            )
                .into_response();
        }
    };

    let auth = service_config.auth.as_ref();

    // Handle path-type auth injection (e.g. Google API key in path)
    let upstream_path = if let Some(a) = auth {
        if a.auth_type == "path" {
            let key = a.secret.as_deref().unwrap_or("");
            if let Some(tmpl) = &a.path_template {
                // Template like "/{key}/v1" where {key} is replaced
                tmpl.replace("{key}", key)
            } else {
                format!("/{}{}", key, rest_path)
            }
        } else {
            rest_path.clone()
        }
    } else {
        rest_path.clone()
    };

    // Handle query-type auth injection
    let upstream_query = if let Some(a) = auth {
        if a.auth_type == "query" {
            let name = a.name.as_deref().unwrap_or("key");
            let val = a.secret.as_deref().unwrap_or("");
            if query.is_empty() {
                format!("?{}={}", urlencoding_encode(name), urlencoding_encode(val))
            } else {
                format!(
                    "{}&{}={}",
                    query,
                    urlencoding_encode(name),
                    urlencoding_encode(val)
                )
            }
        } else {
            query.clone()
        }
    } else {
        query.clone()
    };

    let full_url = format!(
        "{}{}{}",
        upstream_url.trim_end_matches('/'),
        upstream_path,
        upstream_query
    );

    // Build forwarded headers
    let mut fwd_headers = reqwest::header::HeaderMap::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_lowercase();
        if key == "host" || key == "content-length" || key == "transfer-encoding" {
            continue;
        }
        if let Ok(rk) = reqwest::header::HeaderName::from_str(k.as_str()) {
            if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
                fwd_headers.insert(rk, rv);
            }
        }
    }
    if let Ok(hv) = reqwest::header::HeaderValue::from_str(&host) {
        fwd_headers.insert(reqwest::header::HOST, hv);
    }

    // Inject auth headers
    if let Some(bearer) = resolved_bearer {
        // Pre-resolved bearer (from oauth2 refresh)
        let val = format!("Bearer {}", bearer);
        if let Ok(hv) = reqwest::header::HeaderValue::from_str(&val) {
            fwd_headers.insert(reqwest::header::AUTHORIZATION, hv);
        }
    } else if let Some(a) = auth {
        match a.auth_type.as_str() {
            "bearer" => {
                let secret = a.secret.as_deref().unwrap_or("");
                let val = format!("Bearer {}", secret);
                if let Ok(hv) = reqwest::header::HeaderValue::from_str(&val) {
                    fwd_headers.insert(reqwest::header::AUTHORIZATION, hv);
                }
            }
            "basic" => {
                let user = a.username.as_deref().unwrap_or("");
                let pass = a.password.as_deref().unwrap_or(
                    a.secret.as_deref().unwrap_or(""),
                );
                let encoded = STANDARD.encode(format!("{}:{}", user, pass));
                let val = format!("Basic {}", encoded);
                if let Ok(hv) = reqwest::header::HeaderValue::from_str(&val) {
                    fwd_headers.insert(reqwest::header::AUTHORIZATION, hv);
                }
            }
            "header" => {
                let header_name = a.name.as_deref().unwrap_or("authorization").to_lowercase();
                let secret = a.secret.as_deref().unwrap_or("");
                let header_val = if let Some(prefix) = &a.prefix {
                    if prefix.is_empty() {
                        secret.to_string()
                    } else {
                        format!("{} {}", prefix, secret)
                    }
                } else {
                    secret.to_string()
                };
                if let (Ok(hn), Ok(hv)) = (
                    reqwest::header::HeaderName::from_str(&header_name),
                    reqwest::header::HeaderValue::from_str(&header_val),
                ) {
                    fwd_headers.insert(hn, hv);
                }
            }
            _ => {}
        }
    }

    // Convert method
    let reqwest_method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(
                        serde_json::json!({ "error": format!("Unsupported method: {}", other) }),
                    ),
                )
                    .into_response();
            }
        },
    };

    // Send request
    let upstream_resp = match HTTP_CLIENT
        .request(reqwest_method, &full_url)
        .headers(fwd_headers)
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("Upstream error: {}", e) })),
            )
                .into_response();
        }
    };

    // Convert upstream response — stream body through without buffering
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = upstream_resp.headers().clone();

    let byte_stream = upstream_resp.bytes_stream().map(|result| {
        result.map_err(|e| axum::Error::new(std::io::Error::other(e)))
    });
    let body = Body::from_stream(byte_stream);

    let mut response = Response::new(body);
    *response.status_mut() = status;
    for (k, v) in &resp_headers {
        if let (Ok(ak), Ok(av)) = (
            HeaderName::from_str(k.as_str()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            response.headers_mut().insert(ak, av);
        }
    }
    response
}

pub fn urlencoding_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => encoded.push(c),
            _ => {
                for byte in c.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    encoded
}

// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_basic() {
        let (svc, path, query) = parse_route("/anthropic/v1/messages").unwrap();
        assert_eq!(svc, "anthropic");
        assert_eq!(path, "/v1/messages");
        assert!(query.is_empty());
    }

    #[test]
    fn parse_route_with_query() {
        let (svc, path, query) = parse_route("/google/v1/models?key=abc").unwrap();
        assert_eq!(svc, "google");
        assert_eq!(path, "/v1/models");
        assert_eq!(query, "?key=abc");
    }

    #[test]
    fn parse_route_no_subpath() {
        let (svc, path, _) = parse_route("/myservice").unwrap();
        assert_eq!(svc, "myservice");
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_route_empty_fails() {
        assert!(parse_route("/").is_none());
        assert!(parse_route("").is_none());
    }

    #[test]
    fn auth_config_value_alias_deserializes() {
        // Old format: "value" key
        let json = r#"{"type":"bearer","value":"tok123"}"#;
        let cfg: AuthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.secret.as_deref(), Some("tok123"));

        // New format: "secret" key
        let json2 = r#"{"type":"bearer","secret":"tok456"}"#;
        let cfg2: AuthConfig = serde_json::from_str(json2).unwrap();
        assert_eq!(cfg2.secret.as_deref(), Some("tok456"));
    }

    #[test]
    fn urlencoding_encode_special_chars() {
        let encoded = urlencoding_encode("hello world");
        assert_eq!(encoded, "hello%20world");
    }
}
