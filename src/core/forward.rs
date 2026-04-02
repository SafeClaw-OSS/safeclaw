/// Upstream request forwarding via reqwest (supports HTTP and HTTPS).
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use axum::body::Bytes;
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use std::str::FromStr;

use crate::auth::{self, AuthConfig, ServiceConfig};

pub static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
});

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

    let auth_cfg = service_config.auth.as_ref();

    // Transform URL for auth types that modify it (path, query)
    let (upstream_path, upstream_query) = if let Some(a) = auth_cfg {
        auth::transform_url(a, &rest_path, &query)
    } else {
        (rest_path.clone(), query.clone())
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
        // When proxy injects auth (oauth2 or key), strip incoming auth headers
        // to prevent conflicts (e.g. agent sends x-api-key, but we need Bearer)
        if (resolved_bearer.is_some() || auth_cfg.is_some())
            && (key == "authorization" || key == "x-api-key")
        {
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

    // Inject auth headers (dispatches to bearer/basic/header modules)
    if let Some(a) = auth_cfg {
        auth::inject_auth(a, resolved_bearer, &mut fwd_headers);
    }

    // ── Provider-specific header injection ──────────────────────────────────
    if let Some(a) = auth_cfg {
        crate::service::apply_service_headers(a, resolved_bearer, &mut fwd_headers);
    }

    // ── Request logging (all auth types) ─────────────────────────────────────
    let auth_type = auth_cfg.map(|a| a.auth_type.as_str()).unwrap_or("none");
    tracing::info!(
        "proxy forward: {} {} auth={}",
        method, full_url, auth_type,
    );

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

    // ── Response logging ────────────────────────────────────────────────────
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    if status.is_success() {
        tracing::debug!("proxy response: {} {}", status.as_u16(), full_url);
    } else {
        tracing::warn!("proxy response: {} {}", status.as_u16(), full_url);
    }
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
        let json = r#"{"type":"bearer","value":"tok123"}"#;
        let cfg: AuthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.secret.as_deref(), Some("tok123"));

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
