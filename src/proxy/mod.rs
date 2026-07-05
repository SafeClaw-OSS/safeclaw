//! Agent-facing broker plane — the resident phantom-only HTTPS proxy.
//!
//! Live credential traffic rides a localhost HTTPS MITM (HTTP CONNECT) owned by
//! the daemon on `PROXY_PORT`. It decrypts ONLY connections whose host a
//! connection anchors (everything else is a blind tunnel), substitutes a phantom
//! for the real credential at egress, and never returns the value to the agent.
//! The one HTTP route still on the control plane is the `/export` disabled stub.

pub mod api_face;
pub mod ca;
pub mod env;
pub mod handler;
pub mod resolver;

use std::net::SocketAddr;
use std::sync::Arc;

use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::Proxy;

use crate::state::AppState;

pub use handler::BrokerHandler;

/// Build and run the resident proxy forever. Errors are stringly-typed to match
/// the daemon bootstrap; the caller runs this on its own task and keeps serving
/// the control plane even if it returns (a proxy exit must not kill the daemon).
pub async fn serve(state: Arc<AppState>) -> Result<(), String> {
    let resident = ca::load_or_generate(&state.config.state_dir)?;
    // The proxy injects real credentials and carries no auth of its own, so it
    // MUST stay loopback-only — regardless of the control plane's `--listen`
    // (which may legitimately be 0.0.0.0 behind a trusted reverse proxy). Binding
    // it to config.listen would expose the auth-less injector on every interface.
    let addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        state.config.proxy_port,
    );

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(resident.authority)
        // The proxy's OWN upstream TLS client (webpki roots) — unrelated to the
        // daemon's reqwest clients, which target real hosts directly.
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(BrokerHandler::new(state.clone()))
        .build()
        .map_err(|e| format!("proxy build: {}", e))?;

    tracing::info!(
        listen = %addr,
        ca = %resident.cert_path.display(),
        "resident credential proxy listening"
    );
    proxy.start().await.map_err(|e| format!("proxy: {}", e))
}
