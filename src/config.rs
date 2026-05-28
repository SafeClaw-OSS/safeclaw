use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

/// Top-level CLI shape. `safeclaw` (short alias `sc`) is one binary
/// with two roles:
///
///   - **Daemon ops** live under `sc custodian` (alias `sc c`):
///     start / stop / restart / logs (Linux user-systemd lifecycle) and
///     status / pubkey / menu (read-only, local or remote). Run with
///     `sc c start --foreground` in Docker/dev/non-Linux.
///   - **Vault ops** are short-lived CLI commands talking to the daemon
///     over HTTP: `sc status`, `sc vault ...` (alias `sc v`), `sc unlock`,
///     `sc lock`, `sc ls / get / set / rm`, `sc passkey` (alias `sc p`),
///     `sc store`, `sc doctor`, …
///
/// Bare `safeclaw` (no subcommand) prints help.
#[derive(Debug, Parser)]
#[command(name = "safeclaw", version, about = "SafeClaw — passkey-gated credential broker")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the current vault's status: which one, locked/unlocked,
    /// key count. For daemon lifecycle use `sc custodian` (`sc c`).
    Status(StatusArgs),
    /// Daemon (custodian) ops: start / stop / restart / logs / status /
    /// pubkey / menu. Local daemon or any remote custodian — same
    /// commands. Short alias: `sc c`.
    #[command(alias = "c")]
    Custodian(CustodianArgs),
    /// Bring the vault from Locked → Unlocked. Opens a browser to the
    /// custodian's `/cli/auth` page; the page runs the passkey ceremony
    /// and redirects back to a localhost callback this command spawns.
    Unlock(UnlockArgs),
    /// Drop the custodian's in-memory secrets cache and flip back to
    /// Locked. Also a passkey-gated ceremony (PROTOCOL.md §6.3 — H3
    /// requires a fresh grant so a stolen session token can't DOS-lock
    /// the vault).
    Lock(UnlockArgs),
    /// Alias for `sc secret ls`.
    Ls(CommonArgs),
    /// Alias for `sc secret get`.
    Get(GetArgs),
    /// Per-vault lifecycle ops. Today: `vault delete` to nuke a vault's
    /// daemon-side state (irreversible, passkey-gated). Short: `sc v`.
    #[command(alias = "v")]
    Vault(VaultArgs),
    /// Manage the active vault's enrolled passkeys. `ls` is read-only;
    /// `add` / `remove` / `rename` need crypto ceremonies and are deferred
    /// to a later session. Short: `sc p`.
    #[command(alias = "p")]
    Passkey(PasskeyArgs),
    /// Operator-only commands. Each subcommand requires `$SAFECLAW_ADMIN_KEY`
    /// to be set on the CLI side AND match the daemon's `SAFECLAW_ADMIN_KEY`
    /// env. In SaaS deployments only the SafeClaw team holds this key.
    Admin(AdminArgs),
    /// Print the active vault as shell `export` lines so agents see
    /// `SAFECLAW_VAULT_URL` + `SAFECLAW_API_KEY` from the env. Run as
    /// `eval "$(safeclaw env)"`.
    Env,
    /// Manage external stores connected to the active vault. Today: list.
    /// Connect / disconnect are deferred until the Write op lands in the
    /// CLI (they rewrite vault.dat).
    Store(StoreArgs),
    /// Secrets in the active vault. Subcommands: set / get / rm / ls.
    /// Top-level shortcuts `sc set/get/rm/ls` are aliases for these.
    Secret(SecretArgs),
    /// Alias for `sc secret set`.
    Set(SetArgs),
    /// Alias for `sc secret rm`.
    Rm(RmArgs),
    /// Print the safeclaw binary version.
    Version,
    /// Health + reachability checks: custodian connectivity, active
    /// profile, API key presence. Read-only; no vault state mutation.
    Doctor(CommonArgs),
}

#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub sub: VaultSubcommand,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub sub: SecretSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretSubcommand {
    /// Write a native secret. Two passkey gestures (unlock + write).
    Set(SetArgs),
    /// Read a native secret to stdout. One passkey gesture.
    Get(GetArgs),
    /// Delete a native secret. Two passkey gestures.
    Rm(RmArgs),
    /// List secret names this vault can resolve.
    Ls(CommonArgs),
}

#[derive(Debug, Args)]
pub struct PasskeyArgs {
    #[command(subcommand)]
    pub sub: PasskeySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum PasskeySubcommand {
    /// List passkeys enrolled on the active vault (public metadata only:
    /// credential id, device name, transports, timestamps). No vault
    /// unlock or passkey gesture required.
    Ls(CommonArgs),
    /// Add a new passkey (cross-device or same-device). NOT YET
    /// IMPLEMENTED — needs the daemon-side `/cli/auth?op=enroll-passkey`
    /// page and the same crypto vendoring as `sc setup`.
    Add(CommonArgs),
    /// Remove an enrolled passkey by credential id. NOT YET IMPLEMENTED.
    Remove(PasskeyRemoveArgs),
    /// Rename an enrolled passkey's `device_name`. NOT YET IMPLEMENTED —
    /// daemon currently has no metadata-update endpoint.
    Rename(PasskeyRenameArgs),
}

#[derive(Debug, Args)]
pub struct PasskeyRemoveArgs {
    /// base64url credential id (as shown in `passkeys ls`).
    pub credential_id: String,
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct PasskeyRenameArgs {
    pub credential_id: String,
    pub new_name: String,
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub sub: AdminSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AdminSubcommand {
    /// Tail the daemon's audit log for a specific vault. Calls
    /// `GET /v/{vid}/approvals` with operator credentials.
    Audit(AdminAuditArgs),
}

#[derive(Debug, Args)]
pub struct AdminAuditArgs {
    #[command(subcommand)]
    pub sub: AdminAuditSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AdminAuditSubcommand {
    /// List approvals (op-history) for a vault. Default: last 50 rows.
    Ls(AdminAuditLsArgs),
}

#[derive(Debug, Args)]
pub struct AdminAuditLsArgs {
    /// Vault id to inspect. Defaults to the active vault from config.
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    /// Max rows to print. Daemon caps at 200 — bigger values silently
    /// truncate.
    #[arg(long, default_value = "50")]
    pub limit: u32,
}

#[derive(Debug, Subcommand)]
pub enum VaultSubcommand {
    /// Show current vault: URL, state (locked/unlocked/not-enrolled),
    /// passkey count, secret count. Top-level alias: `sc status`.
    Status(StatusArgs),
    /// List vaults this CLI has used (from local config) + mark the
    /// active one with `*`.
    Ls,
    /// Switch the active vault. Pass a SAFECLAW_VAULT_URL, an index
    /// from `sc vault ls`, --local for the localhost default vault,
    /// or nothing for an interactive prompt.
    Use(VaultUseArgs),
    /// Remove a vault from the local known list (does NOT touch the
    /// daemon — for that use `sc vault delete`). Pass URL or index.
    Forget(VaultForgetArgs),
    /// Create a new vault. Default = local (http://localhost:23294,
    /// vault id "default"). Pass --remote <URL> to create on a remote
    /// custodian (auto-generates a UUID). Saves to config and makes
    /// the new vault active.
    Create(VaultCreateArgs),
    /// Irreversibly delete a vault's daemon-side state. Passkey-gated
    /// via the standard `/op/{op_id}` browser-callback ceremony.
    Delete(VaultDeleteArgs),
}

#[derive(Debug, Args)]
pub struct VaultUseArgs {
    /// Either a SAFECLAW_VAULT_URL (`<custodian>/v/<vault_id>`) or a
    /// numeric index from `sc vault ls`. If omitted and `--local` is
    /// also omitted, an interactive prompt lists known vaults.
    pub url_or_idx: Option<String>,
    /// Shortcut for `http://localhost:23294/v/default`.
    #[arg(long, conflicts_with = "url_or_idx")]
    pub local: bool,
}

#[derive(Debug, Args)]
pub struct VaultForgetArgs {
    /// SAFECLAW_VAULT_URL or numeric index from `sc vault ls`. If
    /// omitted, an interactive prompt lists known vaults.
    pub url_or_idx: Option<String>,
}

#[derive(Debug, Args)]
pub struct VaultCreateArgs {
    /// Create on a remote custodian (default is local). Pass the
    /// custodian root URL like `https://custodian.dev.safeclaw.pro`.
    #[arg(long)]
    pub remote: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct VaultDeleteArgs {
    /// Vault id to delete. Required even when only one config exists —
    /// no implicit "current vault" for destructive ops.
    pub vault: String,

    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,

    /// Bypass the interactive confirmation. Without this flag the command
    /// refuses to proceed (since deletion is irreversible).
    #[arg(long)]
    pub yes_i_mean_it: bool,

    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server. When set, the CLI
    /// always binds to this port (useful for SSH port-forwarding).
    /// Default: random OS-assigned port.
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct StoreArgs {
    #[command(subcommand)]
    pub sub: StoreSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StoreSubcommand {
    /// List external stores connected to the active vault. Needs the
    /// vault unlocked (we read from daemon's cache snapshot).
    Ls(CommonArgs),
}

#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Follow new log lines (like `tail -f`).
    #[arg(long, short = 'f')]
    pub follow: bool,
    /// Show only the last N lines (passed to journalctl as -n).
    #[arg(long, short = 'n', default_value = "200")]
    pub lines: u32,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Top-level state directory. Vaults live at <state-dir>/vaults/<id>/.
    #[arg(long, env = "SAFECLAW_STATE_DIR", default_value = "./state")]
    pub state_dir: PathBuf,

    /// Main API port. CLI, browser approval pages, dashboard, and
    /// reverse proxies talk to the daemon here. (Not "admin port" — the
    /// admin surface is the `/admin/*` subset, gated by --admin-key.)
    #[arg(long, env = "SAFECLAW_PORT", default_value = "23294")]
    pub port: u16,

    /// HTTPS proxy port for AI agents. Configure your agent with
    /// `HTTPS_PROXY=http://localhost:<this-port>` and SafeClaw will
    /// transparently inject credentials into outbound requests.
    #[arg(long, env = "SAFECLAW_PROXY_PORT", default_value = "23295")]
    pub proxy_port: u16,

    /// Network interface to listen on for both ports. `127.0.0.1` =
    /// localhost only (default, safe). `0.0.0.0` = all interfaces;
    /// only do that behind a reverse proxy or inside a private network.
    #[arg(long, env = "SAFECLAW_LISTEN", default_value = "127.0.0.1")]
    pub listen: String,

    /// Expected WebAuthn origin — the full URL the browser sees, e.g.
    /// `https://custodian.example.com`. Defaults to `http://localhost:<port>`
    /// for local dev.
    #[arg(long, env = "SAFECLAW_ORIGIN")]
    pub origin: Option<String>,

    /// WebAuthn relying party ID. Defaults to the host part of --origin
    /// (e.g. `custodian.example.com`), which is what 99% of deployments
    /// want. Override only for eTLD+1 sharing across subdomains.
    #[arg(long, env = "SAFECLAW_RP_ID")]
    pub rp_id: Option<String>,

    /// Shared secret gating the `/admin/*` surface (today: vault
    /// deletion for SaaS demo-cleanup). When unset, `/admin/*` is
    /// disabled and returns 403. Set on the daemon AND on any caller
    /// that needs admin access (the SaaS pro-backend); the values must
    /// match. Rotate by changing the env var and redeploying.
    #[arg(long, env = "SAFECLAW_ADMIN_KEY")]
    pub admin_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Custodian URL. Falls back to the active config's custodian (then
    /// to the root parsed out of `$SAFECLAW_VAULT_URL`), then to
    /// `http://127.0.0.1:23294` if nothing is configured. Override with
    /// `--custodian https://custodian.safeclaw.pro` for the Pro
    /// custodian or any self-hosted URL.
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
}

#[derive(Debug, Args)]
pub struct CustodianArgs {
    #[command(subcommand)]
    pub sub: CustodianSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CustodianSubcommand {
    /// Run the daemon in the current process (foreground). Use this in
    /// Docker / dev / when you write your own systemd unit. Config via
    /// SAFECLAW_* env vars and flags. Ctrl-C to stop.
    Run(ServeArgs),
    /// Install + enable a user-level systemd unit (Linux) so the daemon
    /// survives logout/reboot, then start it. SAFECLAW_* env vars from
    /// the calling shell are embedded into the unit. Re-run to refresh
    /// config.
    Start,
    /// Stop the local daemon (user-level systemd unit). No effect on a
    /// `sc c run` foreground process; Ctrl-C to stop that.
    Stop,
    /// Restart the local daemon (user-level systemd unit).
    Restart,
    /// Tail the local daemon's logs via journalctl.
    Logs(LogsArgs),
    /// Custodian health + version + vault count (works on local or
    /// remote — pass --custodian for remote).
    Status(CommonArgs),
    /// HPKE outer-envelope public key.
    Pubkey(CommonArgs),
    /// Public service catalog.
    Menu(CommonArgs),
}

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Override the custodian URL (otherwise loaded from
    /// `$SAFECLAW_VAULT_URL` or `~/.safeclaw/config.toml`).
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,

    /// Override the vault id (otherwise loaded from
    /// `$SAFECLAW_VAULT_URL` or `~/.safeclaw/config.toml`).
    #[arg(long)]
    pub vault: Option<String>,

    /// Don't try to auto-launch a browser; just print the URL.
    #[arg(long)]
    pub no_browser: bool,

    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,

    /// How long (seconds) to wait for the browser-callback before giving up.
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

/// Reusable arg set for read-only short-lived commands that only need to
/// pick a daemon URL + vault id (from the active config or explicit
/// flags). No subcommand-specific options.
#[derive(Debug, Args)]
pub struct CommonArgs {
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Native-secrets key name to reveal (`safeclaw read OPENAI_API_KEY`).
    pub key: String,

    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,

    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server. When set, the CLI
    /// always binds to this port (useful for SSH port-forwarding).
    /// Default: random OS-assigned port.
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// Native-secrets key name to write (`safeclaw write OPENAI_API_KEY sk-...`).
    pub key: String,
    /// The secret value. Shell quoting recommended for special chars.
    pub value: String,
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server. When set, the CLI
    /// always binds to this port (useful for SSH port-forwarding).
    /// Default: random OS-assigned port.
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// Native-secrets key name to remove from the vault.
    pub key: String,
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server. When set, the CLI
    /// always binds to this port (useful for SSH port-forwarding).
    /// Default: random OS-assigned port.
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub state_dir: PathBuf,
    pub port: u16,
    pub proxy_port: u16,
    pub listen: String,
    pub origin: String,
    pub rp_id: String,
    pub admin_key: Option<String>,
}

impl Config {
    pub fn from_serve_args(args: ServeArgs) -> Self {
        let origin = args.origin.unwrap_or_else(|| format!("http://localhost:{}", args.port));
        // rp_id defaults to origin's host: cheaper than depending on a URL
        // crate, and we already require origin to be well-formed for WebAuthn
        // to work. Strips scheme, path, and :port. Falls back to "localhost"
        // if origin is somehow unparseable.
        let rp_id = args.rp_id.unwrap_or_else(|| host_from_origin(&origin).unwrap_or_else(|| "localhost".into()));
        Self {
            state_dir: args.state_dir,
            port: args.port,
            proxy_port: args.proxy_port,
            listen: args.listen,
            origin,
            rp_id,
            admin_key: args.admin_key,
        }
    }
}

fn host_from_origin(origin: &str) -> Option<String> {
    let after_scheme = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.split(':').next()?;
    if host.is_empty() { None } else { Some(host.to_string()) }
}
