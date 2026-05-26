//! `/cli/auth*` — embedded static page that drives the WebAuthn ceremony for
//! `safeclaw unlock` / `safeclaw lock` CLI commands.
//!
//! The daemon ships every JS/HTML asset baked into its binary via
//! `include_str!` so OSS users get a fully self-contained build with no
//! build step, CDN dependency, or sidecar frontend.
//!
//! The page does the same passkey ceremony as the pro-frontend's unlock
//! flow, narrowed to the two Custom ops (`vault-unlock` / `vault-lock`),
//! then redirects back to the CLI's localhost callback.

use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;

const INDEX_HTML: &str = include_str!("../../../static/cli-auth/index.html");
const MAIN_JS: &str = include_str!("../../../static/cli-auth/main.js");

// Vendored authorizer dist files. See `static/cli-auth/sudp/VENDOR.md`.
const SUDP_BYTES: &str = include_str!("../../../static/cli-auth/sudp/bytes.js");
const SUDP_CANONICAL: &str = include_str!("../../../static/cli-auth/sudp/canonical.js");
const SUDP_HASH: &str = include_str!("../../../static/cli-auth/sudp/hash.js");
const SUDP_AAD: &str = include_str!("../../../static/cli-auth/sudp/aad.js");
const SUDP_BINDING: &str = include_str!("../../../static/cli-auth/sudp/binding.js");
const SUDP_KDF: &str = include_str!("../../../static/cli-auth/sudp/kdf.js");
const SUDP_WEBAUTHN: &str = include_str!("../../../static/cli-auth/sudp/webauthn.js");

fn js_response(body: &'static str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, body)
}

fn html_response(body: &'static str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, body)
}

pub async fn index() -> impl IntoResponse {
    html_response(INDEX_HTML)
}

pub async fn main_js() -> impl IntoResponse {
    js_response(MAIN_JS)
}

pub async fn sudp_bytes() -> impl IntoResponse {
    js_response(SUDP_BYTES)
}
pub async fn sudp_canonical() -> impl IntoResponse {
    js_response(SUDP_CANONICAL)
}
pub async fn sudp_hash() -> impl IntoResponse {
    js_response(SUDP_HASH)
}
pub async fn sudp_aad() -> impl IntoResponse {
    js_response(SUDP_AAD)
}
pub async fn sudp_binding() -> impl IntoResponse {
    js_response(SUDP_BINDING)
}
pub async fn sudp_kdf() -> impl IntoResponse {
    js_response(SUDP_KDF)
}
pub async fn sudp_webauthn() -> impl IntoResponse {
    js_response(SUDP_WEBAUTHN)
}
