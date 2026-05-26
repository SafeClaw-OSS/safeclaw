use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

/// Top-level CLI shape. `safeclaw` is one binary in two modes:
///
///   - `safeclaw serve` — long-running daemon (HTTP server). Today's
///     production usage; what systemd executes.
///   - `safeclaw <cmd>` — short-lived CLI commands that talk to a
///     daemon over HTTP. Today: `status` and `version`. Future:
///     setup / unlock / read / write / run / …
///
/// Bare `safeclaw` (no subcommand) prints help. This matches mainstream
/// CLI conventions (git, docker, gh, kubectl). The systemd unit on
/// safeclaw-daemon-dev runs the explicit `safeclaw serve` form.
#[derive(Debug, Parser)]
#[command(name = "safeclaw", version, about = "SafeClaw — passkey-gated credential broker")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon (HTTP server on admin + proxy ports).
    Serve(ServeArgs),
    /// Print daemon health and version.
    Status(StatusArgs),
    /// Print the safeclaw binary version.
    Version,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Top-level state directory. Tenants live at <state-dir>/tenants/<id>/.
    #[arg(long, env = "SAFECLAW_STATE_DIR", default_value = "./state")]
    pub state_dir: PathBuf,

    /// Admin port (clients submit grants here).
    #[arg(long, env = "SAFECLAW_PORT", default_value = "23294")]
    pub port: u16,

    /// Proxy port (agent transparent HTTP for env virtual service).
    #[arg(long, env = "SAFECLAW_PROXY_PORT", default_value = "23295")]
    pub proxy_port: u16,

    /// Bind address for both ports.
    #[arg(long, env = "SAFECLAW_BIND", default_value = "127.0.0.1")]
    pub bind: String,

    /// Expected WebAuthn origin (e.g. "https://safeclaw.pro").
    #[arg(long, env = "SAFECLAW_ORIGIN", default_value = "http://localhost:3000")]
    pub origin: String,

    /// WebAuthn relying party ID (e.g. "safeclaw.pro").
    #[arg(long, env = "SAFECLAW_RP_ID", default_value = "localhost")]
    pub rp_id: String,

    /// Shared secret gating the `/admin/*` surface (today: tenant
    /// deletion for SaaS demo-cleanup). When unset, `/admin/*` is
    /// disabled and returns 403. Set on the daemon AND on any caller
    /// that needs admin access (the SaaS pro-backend); the values must
    /// match. Rotate by changing the env var and redeploying.
    #[arg(long, env = "SAFECLAW_ADMIN_KEY")]
    pub admin_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Daemon admin URL. Defaults to local development daemon. Override
    /// with `--daemon https://custodian.safeclaw.pro` for the Pro
    /// custodian, or a self-hosted URL.
    #[arg(long, env = "SAFECLAW_DAEMON", default_value = "http://127.0.0.1:23294")]
    pub daemon: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub state_dir: PathBuf,
    pub port: u16,
    pub proxy_port: u16,
    pub bind: String,
    pub origin: String,
    pub rp_id: String,
    pub admin_key: Option<String>,
}

impl Config {
    pub fn from_serve_args(args: ServeArgs) -> Self {
        Self {
            state_dir: args.state_dir,
            port: args.port,
            proxy_port: args.proxy_port,
            bind: args.bind,
            origin: args.origin,
            rp_id: args.rp_id,
            admin_key: args.admin_key,
        }
    }
}
