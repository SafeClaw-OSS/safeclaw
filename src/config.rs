use std::path::PathBuf;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "safeclaw", about = "SafeClaw multi-tenant daemon")]
pub struct Cli {
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
}

#[derive(Debug, Clone)]
pub struct Config {
    pub state_dir: PathBuf,
    pub port: u16,
    pub proxy_port: u16,
    pub bind: String,
    pub origin: String,
    pub rp_id: String,
}

impl Config {
    pub fn from_cli(cli: Cli) -> Self {
        Self {
            state_dir: cli.state_dir,
            port: cli.port,
            proxy_port: cli.proxy_port,
            bind: cli.bind,
            origin: cli.origin,
            rp_id: cli.rp_id,
        }
    }
}
