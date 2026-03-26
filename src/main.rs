mod approval;
mod audit;
mod auth;
mod config;
mod crypto;
mod error;
mod generate;
mod policy;
mod proxy;
mod server;
mod state;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::serve;
use tokio::net::TcpListener;
use tracing::{info, warn};

use approval::ApprovalManager;
use audit::AuditLog;
use config::Config;
use crypto::keys::load_or_create_keypair;
use state::{AppState, RateLimiter, VaultState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt::init();

    let config = Config::parse();

    info!(
        "SafeClaw v{} starting — data_dir={} port={} proxy_port={}",
        env!("CARGO_PKG_VERSION"),
        config.data_dir.display(),
        config.port,
        config.proxy_port,
    );

    // Warn if SAFECLAW_ORIGIN/SAFECLAW_RP_ID are not set
    if config.origin.is_none() {
        warn!(
            "SAFECLAW_ORIGIN not set — defaulting to http://localhost:{}. Set this for production.",
            config.port
        );
    }
    if config.rp_id.is_none() {
        warn!("SAFECLAW_RP_ID not set — defaulting to 'localhost'. Set this for production.");
    }

    // Load or create server keypair
    let keypair = load_or_create_keypair(&config.data_dir)?;
    info!(
        "Server keypair loaded (pk.x={}...)",
        &keypair.pk.x[..8.min(keypair.pk.x.len())]
    );

    // --init: generate keypair and exit (for deployment scripts)
    if config.init {
        info!(
            "--init: keypair ready at {}/sc_pk.jwk, exiting",
            config.data_dir.display()
        );
        return Ok(());
    }

    // Ensure data directory exists
    std::fs::create_dir_all(&config.data_dir)?;

    // Initialize audit log (SQLite)
    let audit_log = Arc::new(
        AuditLog::open(&config.data_dir.join("audit.db"))
            .map_err(|e| format!("Failed to open audit log: {}", e))?,
    );
    info!("Audit log open: {}", config.data_dir.join("audit.db").display());

    // Initialize approval manager
    let approval_manager = Arc::new(ApprovalManager::new(audit_log.clone()));

    // Build shared vault state
    let vault = Arc::new(VaultState::new());

    // Build app state
    let state = Arc::new(AppState {
        keypair,
        vault: vault.clone(),
        nonces: Arc::new(Mutex::new(auth::nonce::NonceStore::new())),
        start_time: Instant::now(),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.rate_limit))),
        config: config.clone(),
        approval_manager: approval_manager.clone(),
        audit_log: audit_log.clone(),
    });

    // Periodic rate-limiter cleanup
    {
        let state_clone = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                state_clone.rate_limiter.lock().unwrap().cleanup();
            }
        });
    }

    // Build proxy state and router
    let proxy_state = Arc::new(proxy::ProxyState {
        vault: vault.clone(),
        config: config.clone(),
        approval_manager: approval_manager.clone(),
        audit_log: audit_log.clone(),
    });
    let proxy_router = proxy::build_proxy_router(proxy_state);

    // Bind proxy first (127.0.0.1)
    let proxy_addr: SocketAddr = format!("{}:{}", config.proxy_bind, config.proxy_port)
        .parse()
        .map_err(|e| format!("Invalid proxy bind address: {}", e))?;
    let proxy_listener = TcpListener::bind(proxy_addr).await?;
    info!("Proxy listening on http://{}", proxy_addr);

    // Bind server
    let server_addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .map_err(|e| format!("Invalid server address: {}", e))?;
    let server_listener = TcpListener::bind(server_addr).await?;
    info!("Server listening on http://{}", server_addr);

    // Build server router
    let server_router = server::build_router(state);

    // Run both servers concurrently
    tokio::try_join!(
        serve(
            server_listener,
            server_router.into_make_service_with_connect_info::<SocketAddr>()
        ),
        serve(proxy_listener, proxy_router.into_make_service()),
    )?;

    Ok(())
}
