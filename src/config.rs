use std::path::PathBuf;
use clap::Parser;

/// CLI-only arguments (clap "env" feature not enabled; env vars handled manually)
#[derive(Debug, Parser)]
#[command(name = "safeclaw", about = "Passkey-encrypted credential vault and proxy for AI agents")]
struct CliArgs {
    /// Data directory for vault files [env: SAFECLAW_DATA]
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Server port [env: SAFECLAW_PORT]
    #[arg(long)]
    port: Option<u16>,
    /// Proxy port [env: SAFECLAW_PROXY_PORT]
    #[arg(long)]
    proxy_port: Option<u16>,
    /// Server bind address [env: SAFECLAW_BIND]
    #[arg(long)]
    bind: Option<String>,
    /// Proxy bind address [env: SAFECLAW_PROXY_BIND]
    #[arg(long)]
    proxy_bind: Option<String>,
    /// Expected WebAuthn origin [env: SAFECLAW_ORIGIN]
    #[arg(long)]
    origin: Option<String>,
    /// WebAuthn relying party ID [env: SAFECLAW_RP_ID]
    #[arg(long)]
    rp_id: Option<String>,
    /// Admin URL shown in locked proxy responses [env: SAFECLAW_ADMIN_URL]
    #[arg(long)]
    admin_url: Option<String>,
    /// Optional instance identifier [env: SAFECLAW_INSTANCE_ID]
    #[arg(long)]
    instance_id: Option<String>,
    /// Rate limit: requests per minute per IP (0 = disabled)
    #[arg(long)]
    rate_limit: Option<u32>,
    /// Comma-separated path prefixes exempt from rate limiting (e.g. /health,/notifications,/approve/)
    /// [env: SAFECLAW_RATE_LIMIT_EXEMPT]
    #[arg(long)]
    rate_limit_exempt: Option<String>,
    /// Generate server keypair and exit. Use for deployment scripts that need
    /// the public key before starting the server.
    #[arg(long)]
    init: bool,
}

/// Resolved configuration from CLI args + environment variables.
/// CLI args take priority over env vars; env vars take priority over defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub port: u16,
    pub bind: String,
    pub proxy_port: u16,
    pub proxy_bind: String,
    pub origin: Option<String>,
    pub rp_id: Option<String>,
    pub admin_url: Option<String>,
    pub instance_id: Option<String>,
    pub rate_limit: u32,
    /// Path prefixes exempt from rate limiting. Prefix match: /health matches /health and /health/foo.
    pub rate_limit_exempt: Vec<String>,
    pub init: bool,
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

impl Config {
    pub fn parse() -> Self {
        let cli = CliArgs::parse();

        let data_dir = cli.data_dir
            .or_else(|| env_str("SAFECLAW_DATA").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("./data"));

        let port = cli.port
            .or_else(|| env_str("SAFECLAW_PORT").and_then(|s| s.parse().ok()))
            .unwrap_or(23294);

        let proxy_port = cli.proxy_port
            .or_else(|| env_str("SAFECLAW_PROXY_PORT").and_then(|s| s.parse().ok()))
            .unwrap_or(23295);

        let bind = cli.bind
            .or_else(|| env_str("SAFECLAW_BIND"))
            .unwrap_or_else(|| "0.0.0.0".to_string());

        let proxy_bind = cli.proxy_bind
            .or_else(|| env_str("SAFECLAW_PROXY_BIND"))
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let origin = cli.origin.or_else(|| env_str("SAFECLAW_ORIGIN"));
        let rp_id = cli.rp_id.or_else(|| env_str("SAFECLAW_RP_ID"));
        let admin_url = cli.admin_url.or_else(|| env_str("SAFECLAW_ADMIN_URL"));
        let instance_id = cli.instance_id.or_else(|| env_str("SAFECLAW_INSTANCE_ID"));

        let rate_limit = cli.rate_limit
            .or_else(|| env_str("SAFECLAW_RATE_LIMIT").and_then(|s| s.parse().ok()))
            .unwrap_or(300);

        // Default exempt: polling endpoints that have no security value in rate limiting
        let rate_limit_exempt = cli.rate_limit_exempt
            .or_else(|| env_str("SAFECLAW_RATE_LIMIT_EXEMPT"))
            .unwrap_or_else(|| "/health,/notifications,/pk,/approve/".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let init = cli.init;

        Self { data_dir, port, bind, proxy_port, proxy_bind, origin, rp_id, admin_url, instance_id, rate_limit, rate_limit_exempt, init }
    }

    pub fn effective_origin(&self) -> String {
        self.origin.clone().unwrap_or_else(|| format!("http://localhost:{}", self.port))
    }

    pub fn effective_rp_id(&self) -> String {
        self.rp_id.clone().unwrap_or_else(|| "localhost".to_string())
    }

    pub fn effective_admin_url(&self) -> String {
        self.admin_url.clone().unwrap_or_else(|| format!("http://localhost:{}", self.port))
    }
}
