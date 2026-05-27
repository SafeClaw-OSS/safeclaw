use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

/// Top-level CLI shape. `safeclaw` is one binary in two modes:
///
///   - `safeclaw serve` — long-running daemon (HTTP server). Today's
///     production usage; what systemd executes.
///   - `safeclaw <cmd>` — short-lived CLI commands that talk to a
///     daemon over HTTP. Today: login / status / unlock / lock / ls /
///     read / doctor / vault / stores / version.
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
    /// Print custodian health and version.
    Status(StatusArgs),
    /// Save a custodian URL + vault id to ~/.config/safeclaw/config.toml so
    /// later commands can omit `--custodian` / `--vault`. Does NOT unlock
    /// the vault — passkey gestures happen per-operation. For SaaS the
    /// apiKey lives in $SAFECLAW_API_KEY (never on disk).
    Login(LoginArgs),
    /// Bring the vault from Locked → Unlocked. Opens a browser to the
    /// custodian's `/cli/auth` page; the page runs the passkey ceremony
    /// and redirects back to a localhost callback this command spawns.
    Unlock(UnlockArgs),
    /// Drop the custodian's in-memory secrets cache and flip back to
    /// Locked. Also a passkey-gated ceremony (PROTOCOL.md §6.3 — H3
    /// requires a fresh grant so a stolen session token can't DOS-lock
    /// the vault).
    Lock(UnlockArgs),
    /// List secret names this vault can resolve (native + each external
    /// store). Does NOT print values — just names + their source. Requires
    /// the vault to be unlocked.
    Ls(ProfileSelectArgs),
    /// Read a single native secret to stdout. Drives the custodian's
    /// `/cli/auth` page for the passkey ceremony; the value comes back via
    /// GET `/op/{op_id}` (never via the browser URL).
    Read(ReadArgs),
    /// Per-vault lifecycle ops. Today: `vault delete` to nuke a vault's
    /// daemon-side state (irreversible, passkey-gated).
    Vault(VaultArgs),
    /// Manage the active vault's enrolled passkeys. `ls` is read-only;
    /// `add` / `remove` / `rename` need crypto ceremonies and are deferred
    /// to a later session.
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
    /// Write a native secret to the vault. Two passkey gestures: unlock
    /// (to read current state) then write (to seal modified state). All
    /// crypto happens locally; the browser page is a minimal passkey proxy.
    Write(WriteArgs),
    /// Delete a native secret from the vault. Same two-gesture flow as
    /// write — the deletion is a Write op with the key removed from the
    /// sealed protected state.
    Delete(DeleteArgs),
    /// Print the safeclaw binary version.
    Version,
    /// Health + reachability checks: custodian connectivity, active
    /// profile, API key presence. Read-only; no vault state mutation.
    Doctor(ProfileSelectArgs),
}

#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub sub: VaultSubcommand,
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
    Ls(ProfileSelectArgs),
    /// Add a new passkey (cross-device or same-device). NOT YET
    /// IMPLEMENTED — needs the daemon-side `/cli/auth?op=enroll-passkey`
    /// page and the same crypto vendoring as `sc setup`.
    Add(ProfileSelectArgs),
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
    /// List vaults known to the active custodian. Hits the admin
    /// endpoint `GET /admin/vaults` — requires `SAFECLAW_ADMIN_KEY` to
    /// be set on the daemon (typical OSS self-host) and exposed to the
    /// CLI via `$SAFECLAW_ADMIN_KEY`.
    Ls(ProfileSelectArgs),
    /// Create a new vault. Hits `POST /v/new` to bootstrap an Enroll op,
    /// then opens the browser for a WebAuthn `create()` ceremony
    /// (passkey registration). The CLI handles initial key generation
    /// and seal after the ceremony completes.
    Create(VaultCreateArgs),
    /// Irreversibly delete a vault's daemon-side state. Passkey-gated via
    /// the standard `/op/{op_id}` browser-callback ceremony. Requires a
    /// typed `--yes-i-mean-it` flag to bypass the confirmation prompt;
    /// without it, refuses to proceed.
    Delete(VaultDeleteArgs),
}

#[derive(Debug, Args)]
pub struct VaultCreateArgs {
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
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
    Ls(ProfileSelectArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Top-level state directory. Vaults live at <state-dir>/vaults/<id>/.
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
pub struct LoginArgs {
    /// Custodian URL to save. Defaults to local. For SaaS pass
    /// `https://api.safeclaw.pro`.
    #[arg(long, default_value = "http://127.0.0.1:23294")]
    pub custodian: String,

    /// Vault id to save as the active vault. Required. Self-hosted
    /// single-user setups conventionally use `default`.
    #[arg(long)]
    pub vault: String,

    /// Skip the `/health` probe before writing config. Useful when
    /// initialising against a custodian that's intentionally offline.
    #[arg(long)]
    pub no_probe: bool,
}

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Override the custodian URL (otherwise loaded from
    /// `$SAFECLAW_VAULT_URL` or `~/.config/safeclaw/config.toml`).
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,

    /// Override the vault id (otherwise loaded from
    /// `$SAFECLAW_VAULT_URL` or `~/.config/safeclaw/config.toml`).
    #[arg(long)]
    pub vault: Option<String>,

    /// Don't try to auto-launch a browser; just print the URL.
    #[arg(long)]
    pub no_browser: bool,

    /// How long (seconds) to wait for the browser-callback before giving up.
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

/// Reusable arg set for read-only short-lived commands that only need to
/// pick a daemon URL + vault id (from the active config or explicit
/// flags). No subcommand-specific options.
#[derive(Debug, Args)]
pub struct ProfileSelectArgs {
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// Native-secrets key name to reveal (`safeclaw read OPENAI_API_KEY`).
    pub key: String,

    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,

    #[arg(long)]
    pub no_browser: bool,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct WriteArgs {
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
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Native-secrets key name to remove from the vault.
    pub key: String,
    #[arg(long, env = "SAFECLAW_CUSTODIAN")]
    pub custodian: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
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
