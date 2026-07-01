use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

/// Top-level CLI shape. `safeclaw` (short alias `sc`) is one binary
/// with two roles:
///
///   - **Daemon + vault lifecycle** (Linux user-systemd): `sc up` (install +
///     start + unlock), `sc down`, `sc restart`, `sc unlock` / `sc lock` (the
///     active vault), `sc logs`, and `sc serve` to run it in the foreground
///     (Docker / dev / non-Linux).
///   - **Vault ops** are short-lived CLI commands talking to the daemon
///     over HTTP: `sc status`, `sc vault ...` (alias `sc v`, manage the set of
///     vaults), `sc ls / get / set / rm`, `sc passkey` (alias `sc p`),
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
    /// Print SafeClaw's status: the daemon (running? version) and the active
    /// vault (which one, locked/unlocked, key count).
    Status(StatusArgs),
    /// Get SafeClaw running and ready: install + start the daemon if needed,
    /// then unlock the vault (one passkey tap). Idempotent — the everyday
    /// "make sure it's up" command (the `tailscale up` idiom; the skill's
    /// lazy-start). This is the single setup entrypoint after `sc login`.
    Up,
    /// Stop the local daemon (user-level systemd unit).
    Down,
    /// Restart the local daemon, then re-unlock the vault (one passkey tap).
    /// A bounce wipes the in-memory keys, so `restart` converges back to the
    /// same running+unlocked state as `sc up` — never leaves you silently locked.
    Restart,
    /// Pull the latest vault state from the cloud now and finish any pending
    /// connect (e.g. a Gmail "Connect" sealed from the web that hasn't completed
    /// yet). Normally automatic via the background watcher; use this to force it.
    Sync(SyncArgs),
    /// Bring the active vault Locked → Unlocked (one passkey tap). Normally
    /// `sc up` does this for you; use this to unlock explicitly. A vault-level
    /// lifecycle op — sits next to `sc up`, not under `sc vault` (which manages
    /// the *set* of vaults). Pass `--vault` to target a non-active vault.
    Unlock(UnlockArgs),
    /// Drop the active vault's in-memory secrets cache and flip it back to
    /// Locked (passkey-gated per PROTOCOL.md §6.3 so a stolen session can't
    /// DOS-lock the vault). Pass `--vault` to target a non-active vault.
    Lock(UnlockArgs),
    /// Tail the local daemon's logs (journalctl).
    Logs(LogsArgs),
    /// Run the daemon in the FOREGROUND (this process). For Docker / dev / a
    /// hand-written systemd unit. Config via SAFECLAW_* env + flags; Ctrl-C to
    /// stop. The installed background service runs this under the hood.
    Serve(ServeArgs),
    /// HPKE outer-envelope public key (diagnostic).
    #[command(hide = true)]
    Pubkey(CommonArgs),
    /// Public service catalog. Renders the compiled-in recipes offline (no
    /// running daemon), the exact shape `GET /registry` serves. `--json` for CI.
    Registry(RegistryArgs),
    /// Alias for `sc secret ls`.
    Ls(CommonArgs),
    /// Alias for `sc secret get`.
    Get(GetArgs),
    /// Per-vault lifecycle ops. Today: `vault delete` to nuke a vault's
    /// daemon-side state (irreversible, passkey-gated). Short: `sc v`.
    #[command(alias = "v")]
    Vault(VaultArgs),
    /// Read/write persistent CLI preferences in `~/.safeclaw/config.toml`.
    /// Settings here are the lowest-priority fallback in the resolution
    /// chain (flag > env > config > default). Subs: set / get / unset /
    /// list.
    Config(ConfigArgs),
    /// Manage the active vault's enrolled passkeys. `ls` is read-only;
    /// `add` / `remove` / `rename` need crypto ceremonies and are deferred
    /// to a later session. Short: `sc p`.
    #[command(alias = "p")]
    Passkey(PasskeyArgs),
    /// Manage this account's agents (agent ≡ api-key). `add` mints a key
    /// (works on any paired device), `ls` lists them, `rm` revokes. Short: `sc a`.
    #[command(alias = "a")]
    Agent(AgentArgs),
    /// Operator-only commands. Each subcommand requires `$SAFECLAW_ADMIN_KEY`
    /// to be set on the CLI side AND match the daemon's `SAFECLAW_ADMIN_KEY`
    /// env. In SaaS deployments only the SafeClaw team holds this key.
    Admin(AdminArgs),
    /// Print the active vault as a shell `export` line so agents see
    /// `SAFECLAW_VAULT_URL` from the env. Run as `eval "$(safeclaw env)"`.
    /// The per-agent broker key (`SAFECLAW_API_KEY`) comes from `sc agent add`.
    Env,
    /// Self-update: download the latest release binary for this platform,
    /// verify its sha256, and replace the running binary in place. No-op when
    /// already current. This is also how the baked cloud domain changes ship.
    Upgrade(UpgradeArgs),
    /// Pair this host to your vault: exchange a one-shot pair-token (from
    /// safeclaw.pro's "Connect a new agent" modal) for this host's persistent
    /// cloud-side daemon credential. Writes `~/.safeclaw/device-key` (0600) and
    /// sets the active vault. Run once per host (re-run to repair/re-pair).
    /// `sc login` then brings the daemon up and unlocks for you; `sc up` is the
    /// everyday "make sure it's running" afterwards.
    Login(LoginArgs),
    /// Unpair this host: the inverse of `sc login`. Stops the daemon, clears the
    /// local pairing (active vault, cloud backend, known vaults), removes the
    /// `~/.safeclaw/device-key`, and revokes that device-key cloud-side (its
    /// plaintext is gone locally, so the server row is dead weight otherwise).
    /// `--keep-remote` skips the cloud revoke. Your agent's `SAFECLAW_*` shell
    /// env is yours to remove (we can't edit your profile).
    Logout(LogoutArgs),
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
    /// Health + reachability checks: daemon connectivity, active
    /// profile, API key presence. Read-only; no vault state mutation.
    Doctor(CommonArgs),
    /// Work with service.toml recipes. Today: `recipe validate <path>` runs
    /// the static safety checks the console upload editor enforces. Offline,
    /// no daemon needed.
    Recipe(RecipeArgs),
    /// git credential helper — **invoked by git, not users**. Registered via
    /// `git config credential.<broker>.helper "!sc git-credential"`. On `get`
    /// it returns the agent's `$SAFECLAW_API_KEY` as the Basic password so git
    /// can authenticate to the LOCAL broker for the streaming (smart-HTTP) git
    /// route — the key is read from the environment at call time and never
    /// written to disk. Only answers for the SafeClaw broker host.
    #[command(name = "git-credential", hide = true)]
    GitCredential(GitCredentialArgs),
}

#[derive(Debug, Args)]
pub struct GitCredentialArgs {
    /// The operation git passes: `get` | `store` | `erase`. Only `get` does
    /// anything (returns the key); `store`/`erase` are no-ops — we persist nothing.
    pub operation: String,
}

#[derive(Debug, Args)]
pub struct RegistryArgs {
    /// Emit the catalog as JSON (the same shape `GET /registry` serves) instead
    /// of a human-readable table. Used by CI to publish the catalog artifact.
    #[arg(long)]
    pub json: bool,
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
pub struct RecipeArgs {
    #[command(subcommand)]
    pub sub: RecipeSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RecipeSubcommand {
    /// Validate a service.toml recipe against the broker's safety rules.
    /// Prints each problem and exits non-zero on failure.
    Validate(RecipeValidateArgs),
}

#[derive(Debug, Args)]
pub struct RecipeValidateArgs {
    /// Path to the service.toml to validate.
    pub path: std::path::PathBuf,
    /// Validate as a first-party (trusted) recipe — allows exec / non-upstream
    /// steps. Default: validate as an UPLOADED recipe (exec forbidden), i.e.
    /// the same strict checks the console upload editor applies.
    #[arg(long)]
    pub first_party: bool,
}

#[derive(Debug, Args)]
pub struct PasskeyArgs {
    #[command(subcommand)]
    pub sub: PasskeySubcommand,
}

/// `sc agent` — manage this account's agent api-keys (agent ≡ api-key).
#[derive(Debug, Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub sub: AgentSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AgentSubcommand {
    /// Mint a new agent key (printed ONCE). Account-level: works on any of
    /// your paired devices. Put it in the agent's `SAFECLAW_API_KEY`.
    Add(AgentAddArgs),
    /// List this account's agents (name, key prefix, last-used).
    Ls,
    /// Revoke an agent by name (or key prefix / id). Stops working on every
    /// device after each device's next sync.
    Rm(AgentRmArgs),
}

#[derive(Debug, Args)]
pub struct AgentAddArgs {
    /// Friendly name for the agent (e.g. "Claude Code", "deploy-bot").
    pub name: String,
}

#[derive(Debug, Args)]
pub struct AgentRmArgs {
    /// Agent name, key prefix, or id (see `sc agent ls`).
    pub name: String,
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
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct PasskeyRenameArgs {
    pub credential_id: String,
    pub new_name: String,
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
    /// Back-compat alias for top-level `sc unlock`. Lock/unlock are vault-level
    /// lifecycle ops (they sit next to `sc up`), so the canonical spelling is
    /// top-level; this is kept hidden so existing `sc vault unlock` calls work.
    #[command(hide = true)]
    Unlock(UnlockArgs),
    /// Back-compat alias for top-level `sc lock`. See `Unlock` above.
    #[command(hide = true)]
    Lock(UnlockArgs),
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
    /// Reuse an existing registered passkey instead of registering a new one.
    /// Skips the create() ceremony; uses get() PRF from an already-enrolled
    /// vault. Saves a browser gesture when the hardware key is already set up.
    #[arg(long)]
    pub reuse_passkey: bool,
}

#[derive(Debug, Args)]
pub struct VaultDeleteArgs {
    /// Vault id to delete. Required even when only one config exists —
    /// no implicit "current vault" for destructive ops.
    pub vault: String,


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
pub struct ConfigArgs {
    #[command(subcommand)]
    pub sub: ConfigSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigSubcommand {
    /// Set a persistent CLI preference, e.g. `sc config set cb-port 23394`.
    /// Known keys: cb-port.
    Set { key: String, value: String },
    /// Print the value of one preference. Exit code is nonzero when unset.
    Get { key: String },
    /// Clear a preference.
    Unset { key: String },
    /// Print all preferences (key = value, one per line).
    List,
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
    /// Defaults to `~/.safeclaw/state` (parity with `~/.safeclaw/{crypto,
    /// config.toml,services}`). The old `./state` default was cwd-relative,
    /// which silently created a fresh empty state dir when the daemon was
    /// launched from an arbitrary working directory (e.g. a systemd unit
    /// with cwd=$HOME landed at `~/state`). Resolved in `from_serve_args`.
    #[arg(long, env = "SAFECLAW_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// The daemon's single port. The agent's broker calls (`/v/{vid}/use|
    /// stream|export`, agent-key gated), the CLI, op-approval polling, and any
    /// reverse proxy all talk to the daemon here. (Not "admin port" — the
    /// admin surface is just the `/admin/*` subset, gated by --admin-key.)
    /// The old separate agent proxy port (:23295) was folded in by the
    /// 2026-06-23 zero-inbound pivot.
    #[arg(long, env = "SAFECLAW_PORT", default_value = "23294")]
    pub port: u16,

    /// Network interface to listen on. `127.0.0.1` =
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

    /// Cloud op-relay base URL (e.g. `https://api.dev.safeclaw.pro`). When set,
    /// the daemon registers each pending op with the relay and polls for the
    /// browser-deposited (HPKE-sealed) grant — this is what enables web
    /// approval for a zero-inbound localhost daemon. When unset, the daemon is
    /// local-only (legacy embedded op-page). Auth uses `--admin-key`.
    #[arg(long, env = "SAFECLAW_RELAY_URL")]
    pub relay_url: Option<String>,
}

/// `sc status` takes no flags — the daemon URL comes from the active vault
/// (`$SAFECLAW_VAULT_URL` or `~/.safeclaw/config.toml`), defaulting to the
/// localhost daemon. Point at another device's daemon via `$SAFECLAW_VAULT_URL`.
#[derive(Debug, Args)]
pub struct StatusArgs {}

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// Vault id (defaults to the active vault).
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct UnlockArgs {
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

/// Args for `sc upgrade`.
#[derive(Debug, Args)]
pub struct UpgradeArgs {
    /// Re-download and reinstall even when the running binary already matches
    /// the latest release (otherwise `sc upgrade` is a no-op when current).
    #[arg(long)]
    pub force: bool,
}

/// Args for `sc login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// One-shot pair-token from safeclaw.pro → Connect-a-new-agent modal.
    /// 10-min TTL; single-use; format `spt_...`.
    #[arg(long)]
    pub pair_token: String,
    /// Friendly label shown for this host in the dashboard's device list.
    /// Defaults to `$HOSTNAME` / `$COMPUTERNAME`, else `agent-device`.
    #[arg(long)]
    pub device_name: Option<String>,
    /// Test-only: allow a plaintext `http://` custodian URL. Without this,
    /// `sc login` refuses non-HTTPS URLs to keep the pair-token off the wire
    /// in cleartext (a malicious skill prompt could otherwise smuggle in an
    /// attacker's device-key by suggesting an `http://` custodian).
    /// `http://localhost:*` and `http://127.0.0.1:*` are exempt — that's the
    /// common dev-loopback case and is on-host plaintext.
    #[arg(long)]
    pub insecure_http: bool,
}

/// Args for `sc logout`.
#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// Keep this host's device-key registered on the server (don't revoke it
    /// cloud-side). By default logout DELETES the cloud-side key too: once the
    /// local `device-key` file is gone its plaintext is unrecoverable, so the
    /// server row could never be used again — leaving it just clutters your
    /// dashboard's device list. Use `--keep-remote` only if something external
    /// still manages that key.
    #[arg(long)]
    pub keep_remote: bool,
}

/// Reusable arg set for read-only short-lived commands. The daemon URL comes
/// from `$SAFECLAW_VAULT_URL` / the active config; `--vault` only reselects the
/// vault id on that daemon.
#[derive(Debug, Args)]
pub struct CommonArgs {
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Native-secrets key name to reveal (`safeclaw read OPENAI_API_KEY`).
    pub key: String,

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
    pub listen: String,
    pub origin: String,
    pub rp_id: String,
    pub admin_key: Option<String>,
    pub relay_url: Option<String>,
}

impl Config {
    pub fn from_serve_args(args: ServeArgs) -> Self {
        // WebAuthn origin/rpId. When the daemon is cloud-paired, the vault's
        // passkeys were enrolled on the cloud FRONTEND (e.g. dev.safeclaw.pro)
        // and every web approval happens there — so the assertions the daemon
        // must verify carry the frontend origin/rpId, NOT localhost. Validate
        // against the frontend origin for a paired daemon; localhost for a
        // self-host / unpaired one. (The local op-page ceremony — the only
        // thing that'd want a localhost rpId — isn't used when paired: all
        // approvals route to the cloud /grant page.) An explicit --origin /
        // SAFECLAW_ORIGIN always wins.
        let origin = args.origin.unwrap_or_else(|| {
            crate::cli::active::frontend_origin()
                .unwrap_or_else(|| format!("http://localhost:{}", args.port))
        });
        // rp_id defaults to origin's host: cheaper than depending on a URL
        // crate, and we already require origin to be well-formed for WebAuthn
        // to work. Strips scheme, path, and :port. Falls back to "localhost"
        // if origin is somehow unparseable.
        let rp_id = args.rp_id.unwrap_or_else(|| host_from_origin(&origin).unwrap_or_else(|| "localhost".into()));
        // state_dir default = ~/.safeclaw/state. Single ~/.safeclaw tree so
        // the whole vault footprint is one dir to chmod/back up. Falls back
        // to cwd-relative ./state only if the home dir is somehow unknown.
        let state_dir = args.state_dir.unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join(".safeclaw").join("state"))
                .unwrap_or_else(|| PathBuf::from("./state"))
        });
        Self {
            state_dir,
            port: args.port,
            listen: args.listen,
            origin,
            rp_id,
            admin_key: args.admin_key,
            relay_url: args.relay_url,
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
