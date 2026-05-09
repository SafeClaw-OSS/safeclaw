use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use safeclaw::config::{Cli, Config};
use safeclaw::proxy::proxy_router;
use safeclaw::server::admin_router;
use safeclaw::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,safeclaw=debug,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_cli(cli);

    std::fs::create_dir_all(&config.state_dir)?;
    std::fs::create_dir_all(config.state_dir.join("tenants"))?;

    let state = Arc::new(AppState::new(config.clone()));

    let bind: std::net::IpAddr = config.bind.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    let admin_addr = SocketAddr::new(bind, config.port);
    let proxy_addr = SocketAddr::new(bind, config.proxy_port);

    let admin = admin_router(state.clone());
    let proxy = proxy_router(state.clone());

    tracing::info!(
        admin = %admin_addr,
        proxy = %proxy_addr,
        state_dir = %config.state_dir.display(),
        rp_id = %config.rp_id,
        origin = %config.origin,
        "safeclaw daemon starting"
    );

    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    let proxy_listener = tokio::net::TcpListener::bind(proxy_addr).await?;

    let admin_task = tokio::spawn(async move {
        axum::serve(
            admin_listener,
            admin.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let proxy_task = tokio::spawn(async move {
        axum::serve(
            proxy_listener,
            proxy.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    tokio::select! {
        r = admin_task => { r??; },
        r = proxy_task => { r??; },
    }
    Ok(())
}
