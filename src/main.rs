use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use safeclaw::cli;
use safeclaw::config::{Cli, Command, Config, CustodianSubcommand, ServeArgs};
use safeclaw::proxy::proxy_router;
use safeclaw::server::admin_router;
use safeclaw::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Status(args) => {
            // CLI commands log to stderr; don't initialise the tracing
            // subscriber here (it'd pollute the user-facing output of a
            // short-lived command). The daemon path enables it below.
            cli::status::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw status: {}", e);
                e.into()
            })
        }
        Command::Custodian(args) => {
            // `sc c run` is the foreground daemon entry — it bootstraps
            // tracing, owns the runtime, and runs forever, so handle it
            // here instead of threading it through the short-lived CLI
            // dispatcher.
            match args.sub {
                CustodianSubcommand::Run(serve) => run_daemon(serve).await,
                sub => cli::custodian::run(sub).await.map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw custodian: {}", e);
                    e.into()
                }),
            }
        }
        Command::Up => {
            // `sc up` = idempotent ensure-running. Reuses the custodian
            // dispatcher's EnsureRunning impl verbatim; the rename is a
            // surface-only promotion to a top-level verb (§13.4).
            cli::custodian::run(CustodianSubcommand::EnsureRunning).await.map_err(
                |e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw up: {}", e);
                    e.into()
                },
            )
        }
        Command::Unlock(args) => {
            cli::unlock::run_unlock(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw unlock: {}", e);
                e.into()
            })
        }
        Command::Lock(args) => {
            cli::unlock::run_lock(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw lock: {}", e);
                e.into()
            })
        }
        Command::Ls(args) => {
            cli::ls::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw ls: {}", e);
                e.into()
            })
        }
        Command::Get(args) => {
            cli::secret::run_get(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw get: {}", e);
                e.into()
            })
        }
        Command::Doctor(args) => {
            cli::doctor::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw doctor: {}", e);
                e.into()
            })
        }
        Command::Vault(args) => {
            cli::vault::run(args.sub).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw vault: {}", e);
                e.into()
            })
        }
        Command::Config(args) => {
            cli::config::run(args.sub).map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw config: {}", e);
                e.into()
            })
        }
        Command::Store(args) => {
            cli::store::run(args.sub).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw store: {}", e);
                e.into()
            })
        }
        Command::Passkey(args) => {
            cli::passkey::run(args.sub).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw passkey: {}", e);
                e.into()
            })
        }
        Command::Admin(args) => {
            cli::admin::run(args.sub).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw admin: {}", e);
                e.into()
            })
        }
        Command::Env => {
            cli::env::run().map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw env: {}", e);
                e.into()
            })
        }
        Command::Install(args) => {
            cli::install::run(args).map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw install: {}", e);
                e.into()
            })
        }
        Command::Login(args) => {
            cli::login::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw login: {}", e);
                e.into()
            })
        }
        Command::Secret(args) => {
            use safeclaw::config::SecretSubcommand;
            let r = match args.sub {
                SecretSubcommand::Set(a) => cli::secret::run_set(a).await,
                SecretSubcommand::Get(a) => cli::secret::run_get(a).await,
                SecretSubcommand::Rm(a) => cli::secret::run_rm(a).await,
                SecretSubcommand::Ls(a) => cli::ls::run(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw secret: {}", e);
                e.into()
            })
        }
        Command::Set(args) => {
            cli::secret::run_set(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw set: {}", e);
                e.into()
            })
        }
        Command::Rm(args) => {
            cli::secret::run_rm(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw rm: {}", e);
                e.into()
            })
        }
        Command::Version => {
            println!("safeclaw {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

async fn run_daemon(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,safeclaw=debug,tower_http=info".into()),
        )
        .init();

    let config = Config::from_serve_args(args);

    std::fs::create_dir_all(&config.state_dir)?;
    std::fs::create_dir_all(config.state_dir.join("vaults"))?;

    // Slice 3: pull the active vault's sealed blob from the cloud before
    // serving, so a freshly-paired device serves a vault sealed in the
    // browser. Best-effort — a local-only or offline daemon serves whatever
    // vault.dat is already on disk.
    safeclaw::cloud_sync::pull_on_start(&config.state_dir).await;

    let state = Arc::new(AppState::new(config.clone()));

    let listen_ip: std::net::IpAddr = config.listen.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    let admin_addr = SocketAddr::new(listen_ip, config.port);
    let proxy_addr = SocketAddr::new(listen_ip, config.proxy_port);

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
