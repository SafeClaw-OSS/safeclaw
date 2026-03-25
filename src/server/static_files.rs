/// Static asset serving — all files are embedded at compile time via include_bytes!
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

const INDEX_HTML: &[u8] = include_bytes!("../../public/index.html");
const SETUP_HTML: &[u8] = include_bytes!("../../public/setup.html");
const UNLOCK_HTML: &[u8] = include_bytes!("../../public/unlock.html");
const ADMIN_HTML: &[u8] = include_bytes!("../../public/admin.html");
const SAFECLAW_CLIENT_JS: &[u8] = include_bytes!("../../public/safeclaw-client.js");

fn html_response(content: &'static [u8]) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        content,
    )
        .into_response()
}

fn js_response(content: &'static [u8]) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/javascript"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        content,
    )
        .into_response()
}

pub async fn serve_index() -> Response {
    html_response(INDEX_HTML)
}

pub async fn serve_setup() -> Response {
    html_response(SETUP_HTML)
}

pub async fn serve_unlock() -> Response {
    html_response(UNLOCK_HTML)
}

pub async fn serve_admin() -> Response {
    html_response(ADMIN_HTML)
}

pub async fn serve_client_js() -> Response {
    js_response(SAFECLAW_CLIENT_JS)
}
