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
pub mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;

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
        // The proxy's OWN upstream TLS client (webpki roots). Unlike hudsucker's
        // built-in `with_rustls_connector` (which dials every host directly),
        // this connector routes the forward hop through the device egress proxy
        // (`sc proxy set`) when one is configured — so a host reachable only via
        // a corporate/on-demand proxy (e.g. Google APIs on a firewalled network)
        // forwards through it instead of timing out on a direct dial. See
        // proxy/upstream.rs.
        .with_http_connector(upstream::forward_connector())
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
