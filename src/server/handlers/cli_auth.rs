//! Embedded passkey-ceremony page for CLI ↔ browser flow.
//!
//! `GET /op/{op_id}` (Accept: text/html) → HTML page.
//! `/op-page/main.js` → JS asset.
//! All other assets are self-contained in main.js (no external deps).

use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;

const OP_PAGE_HTML: &str = include_str!("../../../static/op-page/index.html");
const OP_PAGE_JS: &str = include_str!("../../../static/op-page/main.js");

fn js_response(body: &'static str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/javascript; charset=utf-8"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, body)
}

fn html_response(body: &'static str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, body)
}

pub async fn op_page_html() -> impl IntoResponse {
    html_response(OP_PAGE_HTML)
}

pub async fn op_page_js() -> impl IntoResponse {
    js_response(OP_PAGE_JS)
}

pub fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|part| part.trim().starts_with("text/html")))
        .unwrap_or(false)
}
