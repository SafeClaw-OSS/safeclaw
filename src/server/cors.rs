//! Configurable CORS layer for cases where the daemon is fronted directly by
//! a browser (e.g. localhost development without a reverse proxy).
//!
//! Production deployments terminate TLS + CORS at a reverse proxy (Caddy) and
//! should leave `SAFECLAW_CORS_ALLOW_ORIGINS` unset — daemon then ships
//! responses without any `Access-Control-*` headers and Caddy adds them once.
//!
//! For localhost dev (no reverse proxy), set the env var to a comma-separated
//! list of explicit origins, e.g.
//!
//! ```text
//! SAFECLAW_CORS_ALLOW_ORIGINS=http://localhost:3000,http://localhost:3001
//! ```
//!
//! Wildcard `*` is intentionally unsupported: it is incompatible with
//! `Access-Control-Allow-Credentials: true`, which the SaaS frontend uses.

use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderName, HeaderValue, Method,
};
use tower_http::cors::CorsLayer;

const ENV_VAR: &str = "SAFECLAW_CORS_ALLOW_ORIGINS";

/// Read `SAFECLAW_CORS_ALLOW_ORIGINS` and build a `CorsLayer` if any origins
/// are configured. Returns `None` to mean "no CORS handling at all".
pub fn build_cors() -> Option<CorsLayer> {
    let raw = std::env::var(ENV_VAR).ok()?;
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(origins)
            .allow_credentials(true)
            .allow_headers([
                AUTHORIZATION,
                CONTENT_TYPE,
                HeaderName::from_static("x-safeclaw-tenant"),
            ])
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS]),
    )
}
