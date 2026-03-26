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

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
});

/// Service configuration extracted from vault secrets
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceConfig {
    pub upstream: String,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthConfig {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub name: Option<String>,
    pub value: String,
    pub prefix: Option<String>,
}

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

/// Forward a request to the upstream service
pub async fn forward_request(
    method: Method,
    uri_path: &str,
    headers: &HeaderMap,
    body_bytes: Bytes,
    service_config: &ServiceConfig,
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
            format!("/{}{}", a.value, rest_path)
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
            if query.is_empty() {
                format!("?{}={}", urlencoding_encode(name), urlencoding_encode(&a.value))
            } else {
                format!("{}&{}={}", query, urlencoding_encode(name), urlencoding_encode(&a.value))
            }
        } else {
            query.clone()
        }
    } else {
        query.clone()
    };

    let full_url = format!("{}{}{}", upstream_url.trim_end_matches('/'), upstream_path, upstream_query);

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

    // Handle header-type auth injection
    if let Some(a) = auth {
        if a.auth_type == "header" {
            let header_name = a.name.as_deref().unwrap_or("authorization").to_lowercase();
            let header_val = if let Some(prefix) = &a.prefix {
                if prefix.is_empty() {
                    a.value.clone()
                } else {
                    format!("{} {}", prefix, a.value)
                }
            } else {
                a.value.clone()
            };
            if let (Ok(hn), Ok(hv)) = (
                reqwest::header::HeaderName::from_str(&header_name),
                reqwest::header::HeaderValue::from_str(&header_val),
            ) {
                fwd_headers.insert(hn, hv);
            }
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
                    axum::Json(serde_json::json!({ "error": format!("Unsupported method: {}", other) })),
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

    // Stream the response body as chunks arrive from upstream
    let byte_stream = upstream_resp.bytes_stream().map(|result| {
        result.map_err(|e| {
            axum::Error::new(std::io::Error::new(std::io::ErrorKind::Other, e))
        })
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

fn urlencoding_encode(s: &str) -> String {
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
