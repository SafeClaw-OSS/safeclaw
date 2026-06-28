use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use safeclaw::cli;
use safeclaw::config::{Cli, Command, Config, ServeArgs};
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
        // `serve` is the foreground daemon entry — it bootstraps tracing, owns
        // the runtime, and runs forever, so handle it here, not through the
        // short-lived CLI dispatcher.
        Command::Serve(serve) => run_daemon(serve).await,
        Command::Down => cli::service::run_stop().map_err(daemon_err),
        // `sc restart` = bounce the daemon AND converge back to ready (re-unlock).
        // A process restart wipes the in-memory keys, so it routes through the
        // same `ensure_unlocked` chokepoint as `sc up` (see cli/up.rs::restart).
        Command::Restart => {
            cli::up::restart().await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw restart: {}", e);
                e.into()
            })
        }
        Command::Logs(args) => cli::service::run_logs(args).map_err(daemon_err),
        Command::Pubkey(args) => cli::custodian::pubkey(args).await.map_err(daemon_err),
        Command::Menu(args) => cli::custodian::menu(args).await.map_err(daemon_err),
        Command::Up => {
            // `sc up` = make SafeClaw ready: ensure the daemon is running, then
            // ensure the vault is unlocked (the single auto-unlock chokepoint;
            // see cli/up.rs). login / upgrade-restart / agent lazy-start all
            // route through here, so the user never runs a bare "unlock".
            cli::up::run().await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw up: {}", e);
                e.into()
            })
        }
        Command::Unlock(args) => cli::unlock::run_unlock(args).await.map_err(daemon_err),
        Command::Lock(args) => cli::unlock::run_lock(args).await.map_err(daemon_err),
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
        Command::Agent(args) => {
            cli::agent::run(args.sub).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw agent: {}", e);
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
        Command::GitCredential(args) => {
            // Invoked by git, not users. Never print to stderr on the happy path
            // (git reads stdout); surface only hard errors.
            cli::git_credential::run(args).map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw git-credential: {}", e);
                e.into()
            })
        }
        Command::Upgrade(args) => {
            cli::upgrade::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw upgrade: {}", e);
                e.into()
            })
        }
        Command::Login(args) => {
            cli::login::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw login: {}", e);
                e.into()
            })
        }
        Command::Logout(args) => {
            cli::logout::run(args).await.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw logout: {}", e);
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
        Command::Recipe(args) => {
            use safeclaw::config::RecipeSubcommand;
            let r = match args.sub {
                RecipeSubcommand::Validate(a) => cli::recipe::run_validate(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw recipe: {}", e);
                e.into()
            })
        }
        Command::Version => {
            println!("safeclaw {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

/// Shared error adapter for the daemon-lifecycle verbs (down/restart/logs/…):
/// print to stderr and box the error for `main`'s return.
fn daemon_err(e: String) -> Box<dyn std::error::Error> {
    eprintln!("safeclaw: {}", e);
    e.into()
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
    safeclaw::sync::pull_on_start(&config.state_dir).await;

    let state = Arc::new(AppState::new(config.clone()));

    // Agent-centric auth: sync the account-level agent-key hash-set once
    // before serving (so account agent-keys are accepted from the start),
    // then keep it fresh in the background (revokes/new agents land in ~30s).
    safeclaw::sync::sync_agent_keys_once(&state).await;
    tokio::spawn(safeclaw::sync::sync_agent_keys_loop(state.clone()));

    // Slice 3 realtime sync: one detached long-poll watcher PER synced vault
    // (active ∪ known_vaults — all vaults stay live, not just the active one).
    // Best-effort — NOT in the serve select!, so a sync-loop exit never takes
    // the daemon down.
    safeclaw::sync::spawn_watchers(state.clone());

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
