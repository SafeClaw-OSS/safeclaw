/// Upstream request forwarding.
///
/// For HTTP upstreams: forwards the request using hyper's HTTP connector.
/// For HTTPS upstreams: returns 502 (TLS support requires adding a TLS connector crate).
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::str::FromStr;


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
    // parts[0] = "" (before first /), parts[1] = service, parts[2] = rest
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
    let is_https = upstream_url.starts_with("https://");

    if is_https {
        // TLS not supported without adding hyper-tls / tokio-rustls to Cargo.toml
        return (
            StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({
                "error": "HTTPS upstream forwarding requires TLS support (add hyper-tls to Cargo.toml)"
            })),
        )
            .into_response();
    }

    // Parse upstream base URL
    let parsed_upstream = match upstream_url.parse::<Uri>() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("Invalid upstream URL: {}", e) })),
            )
                .into_response();
        }
    };

    let host = match parsed_upstream.host() {
        Some(h) => h.to_string(),
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": "Upstream URL missing host" })),
            )
                .into_response();
        }
    };
    let port = parsed_upstream.port_u16().unwrap_or(80);

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

    // Handle path-type auth injection
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

    let full_path = format!("{}{}", upstream_path, upstream_query);
    let full_uri = format!("http://{}:{}{}", host, port, full_path);

    let upstream_uri = match full_uri.parse::<Uri>() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("Failed to build upstream URI: {}", e) })),
            )
                .into_response();
        }
    };

    // Build forwarded headers (drop Host, add auth header if needed)
    let mut fwd_headers = HeaderMap::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_lowercase();
        if key == "host" {
            continue;
        }
        fwd_headers.insert(k.clone(), v.clone());
    }
    fwd_headers.insert(
        HeaderName::from_static("host"),
        HeaderValue::from_str(&format!("{}:{}", host, port)).unwrap_or_else(|_| HeaderValue::from_static("localhost")),
    );

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
                HeaderName::from_str(&header_name),
                HeaderValue::from_str(&header_val),
            ) {
                fwd_headers.insert(hn, hv);
            }
        }
    }

    // Build the request
    let mut req_builder = hyper::Request::builder()
        .method(method)
        .uri(upstream_uri);
    let req_headers = req_builder.headers_mut().unwrap();
    for (k, v) in &fwd_headers {
        req_headers.insert(k, v.clone());
    }

    let upstream_req = match req_builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({ "error": format!("Failed to build upstream request: {}", e) })),
            )
                .into_response();
        }
    };

    // Send request
    let connector = HttpConnector::new();
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

    let upstream_resp = match client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("Upstream error: {}", e) })),
            )
                .into_response();
        }
    };

    // Convert upstream response
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let body_bytes = match upstream_resp.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("Failed to read upstream body: {}", e) })),
            )
                .into_response();
        }
    };

    let mut response = Response::new(Body::from(body_bytes));
    *response.status_mut() = status;
    for (k, v) in &resp_headers {
        response.headers_mut().insert(k, v.clone());
    }
    response
}

fn urlencoding_encode(s: &str) -> String {
    // Simple percent-encoding for query parameter values
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
