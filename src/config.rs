use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Control plane port (`0x5AFD`) — the axum Router (op / approve / ceremonies /
/// events). The `sc` CLI's target; the agent's own traffic never touches it (the
/// agent holds only `$SAFECLAW_BROKER_URL`, the proxy port's API face).
/// Sits just below the proxy's `0x5AFE`: both are below the OS ephemeral floor
/// and IANA-unregistered, so nothing should grab them by chance. Moved off the
/// former `23295` (`0x5AFF`), which some dev tools (e.g. a VS Code extension
/// host) deterministically squat — overridable via `$SAFECLAW_PORT`.
pub const CONTROL_PORT: u16 = 23293;

/// Credential-proxy plane port (`0x5AFE`) — the phantom-only local HTTPS MITM the
/// agent's tool traffic is routed through by `sc run`'s env bundle.
pub const PROXY_PORT: u16 = 23294;

/// Default cap on a brokered request's body (bytes) — the unified boundary:
/// what policy judges and what phantoms resolve against is ONE buffered view
/// of the body, so a phantom-bearing request whose body exceeds this is
/// REFUSED (413) rather than forwarded policy-blind. Generous by design (the
/// daemon runs user-side, authenticated, cost is local); the same convention
/// as nginx's `client_max_body_size`: hard limit + explained refusal +
/// user-adjustable knob (`--body-cap` / `SAFECLAW_BODY_CAP`).
pub const DEFAULT_BODY_CAP: u64 = 32 * 1024 * 1024;

/// Top-level CLI shape. `safeclaw` (short alias `sc`) is one binary
/// with two roles:
///
///   - **Daemon + vault lifecycle** (Linux user-systemd): `sc up` (install +
///     start + unlock), `sc down`, `sc restart`, `sc unlock` / `sc lock` (the
///     active vault), `sc log`, and `sc serve` to run it in the foreground
///     (Docker / dev / non-Linux).
///   - **Vault ops** are short-lived CLI commands talking to the daemon
///     over HTTP: `sc status`, `sc vault ...` (alias `sc v`, manage the set of
///     vaults), `sc ls / get / set / rm`, `sc passkey` (alias `sc p`),
///     `sc store`, `sc doctor`, …
///
/// Bare `safeclaw` (no subcommand) prints help.
#[derive(Debug, Parser)]
#[command(
    name = "safeclaw",
    // NOT bare `version` (= CARGO_PKG_VERSION): rc builds must self-report
    // their release tag here too, same as `sc status` / the custom prints.
    version = crate::build_version(),
    about = "SafeClaw — passkey-gated credential broker"
)]
pub struct Cli {
    /// Target vault for this invocation (any subcommand, any position): an id, a
    /// unique id prefix, or the exact name (`sc vault ls`; quote a name with
    /// spaces). An ambiguous name or prefix errors with the candidates. Overrides
    /// the shell's `$SAFECLAW_VAULT_ID` pin and the device default (top of the
    /// resolution chain, design/vault-addressing.md).
    #[arg(long, global = true, value_name = "VAULT")]
    pub vault: Option<String>,
    /// Emit machine-readable JSON instead of the human-readable output, on any
    /// subcommand that supports it (e.g. status, doctor, registry, and the `ls`
    /// listings). Commands with no JSON form ignore it.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Set up this machine and one agent without prompting. Re-run the command
    /// after completing each browser approval until it reports done.
    Setup(SetupArgs),
    /// Install or remove the SafeClaw agent skill.
    Skill(SkillArgs),
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
    Log(LogArgs),
    /// ADVANCED / self-host: run the daemon in the FOREGROUND (this process),
    /// for Docker / a hand-written systemd unit / non-systemd hosts. On a normal
    /// Linux box you never call this — `sc up` installs a background service
    /// whose entry-point IS `sc serve`. Config via SAFECLAW_* env + flags;
    /// Ctrl-C to stop.
    Serve(ServeArgs),
    /// HPKE outer-envelope public key (diagnostic).
    #[command(hide = true)]
    Pubkey(CommonArgs),
    /// Public service catalog. Renders the compiled-in services offline (no
    /// running daemon), the exact shape `GET /registry` serves. `--json` for CI.
    Registry(RegistryArgs),
    /// Alias for `sc secret ls`.
    Ls(CommonArgs),
    /// Alias for `sc secret get`.
    Get(GetArgs),
    /// Per-vault lifecycle ops. Today: `vault rm` to nuke a vault's
    /// daemon-side state (irreversible, passkey-gated). Short: `sc v`.
    #[command(alias = "v")]
    Vault(VaultArgs),
    /// Read/write persistent CLI preferences in `~/.safeclaw/config.toml`.
    /// Settings here are the lowest-priority fallback in the resolution
    /// chain (flag > env > config > default). Subs: set / get / unset /
    /// ls.
    Config(ConfigArgs),
    /// Manage this device's upstream egress proxy (the HTTP proxy the daemon uses
    /// to reach the internet). Subs: set / get / unset. Behind a corporate or
    /// on-demand proxy this is how the daemon completes OAuth connects and routes
    /// its forward hop, since the background daemon doesn't inherit your shell's
    /// `HTTPS_PROXY`.
    Proxy(ProxyArgs),
    /// Manage the active vault's enrolled passkeys. `ls` is read-only;
    /// `add` / `rm` / `rename` need crypto ceremonies and are deferred
    /// to a later session. Short: `sc p`.
    #[command(alias = "p")]
    Passkey(PasskeyArgs),
    /// Manage this account's agents (agent ≡ api-key). `add` mints a key
    /// (works on any paired device), `ls` lists them, `rm` revokes. Short: `sc a`.
    #[command(alias = "a")]
    Agent(AgentArgs),
    /// The DEVICE axis of the account plane: `sc device login/logout` are the
    /// canonical spellings of top-level `sc login`/`sc logout` (kept as
    /// shortcuts). Symmetric with `sc agent *` — both are account-level,
    /// device-key authed, cloud-backed.
    Device(DeviceArgs),
    /// Print `export` lines for the HUMAN's shell (`eval "$(sc env)"`):
    /// SAFECLAW_BROKER_URL projected from this device's config — never a key,
    /// never a vault pin (vault follows `sc vault use`; per-call override is
    /// `--vault`). An AGENT's env (incl. its key) is minted by `sc agent add`.
    Env,
    /// Self-update: download the latest release binary for this platform,
    /// verify its sha256, and replace the running binary in place. No-op when
    /// already current. This is also how the baked cloud domain changes ship.
    Upgrade(UpgradeArgs),
    /// Pair this host to your SafeClaw account: prints a short code and an
    /// approval link; you approve in the browser, then this host gets its
    /// cloud-side daemon credential. Writes `~/.safeclaw/device-key` (0600). Run once per host (re-run to repair/re-pair).
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
    /// Run a command with the resident credential proxy pasted into its
    /// environment — the everyday, zero-human way an agent routes one command's
    /// traffic through SafeClaw. `sc run -- <cmd…>` execs the child with the
    /// proxy + CA env bundle merged in; `sc run --export-env` prints the same
    /// bundle as shell `export` lines for `eval "$(sc run --export-env)"`. No
    /// plaintext secret ever enters the child's env — the agent writes the
    /// phantom (`__sc__<conn>__`) itself; the proxy substitutes at egress.
    Run(RunArgs),
    /// Manage the connections in the active vault (add / ls / rm). A connection
    /// is a secret (or several) bound to an egress host anchor; the agent reaches
    /// it via the phantom `__sc__<id>__`. The CLI twin of the console's
    /// "Connections". Short: `sc conn`.
    #[command(alias = "conn")]
    Connection(ConnectionArgs),
    /// Back-compat alias for `sc connection add`. The canonical spelling is
    /// `sc connection add <id>` (a noun-namespace, matching `sc secret`/`vault`/
    /// `agent`); kept hidden so existing `sc connect …` calls keep working.
    #[command(hide = true)]
    Connect(ConnectArgs),
    /// Print the safeclaw binary version.
    Version,
    /// Health + reachability checks: daemon connectivity, active
    /// profile, API key presence. Read-only; no vault state mutation.
    Doctor(CommonArgs),
    /// Service definitions in the active vault, added from sources: a local
    /// folder or a GitHub repository pinned to a commit (add / update / ls /
    /// rm), and `validate` to run the same checks offline.
    Service(ServiceArgs),
    /// git credential helper — **invoked by git, not users**. Registered
    /// per-process by `sc run` (`GIT_CONFIG_KEY_*=credential.helper`,
    /// `GIT_CONFIG_VALUE_*=!sc git-credential`; no gitconfig writes). On `get` it
    /// finds the connection anchored to git's request host and, when that
    /// connection has exactly one injectable secret, emits `username=x` +
    /// `password=<its phantom>`. The resident proxy substitutes the phantom for
    /// the real credential at egress; git never sees it. Ambiguous / unknown host
    /// → emits nothing (git falls through). Reads no vault secret — a phantom is
    /// the only thing it ever prints.
    #[command(name = "git-credential", hide = true)]
    GitCredential(GitCredentialArgs),
    /// Approval ops. `sc op wait <op_id>` blocks until the op resolves; its
    /// exit code is the outcome (`sc op wait --help`).
    Op(OpArgs),
}

/// `sc run` — paste the resident proxy + CA env bundle onto a child (or the
/// current shell) so its HTTPS traffic is brokered and phantoms substitute.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Print the env bundle as POSIX `export` lines instead of running a
    /// command — for `eval "$(sc run --export-env)"` to cover the whole shell.
    #[arg(long, conflicts_with = "cmd")]
    pub export_env: bool,
    /// The command to run, after `--`. Everything past `--` is the child's
    /// argv, passed through verbatim (`sc run -- git clone https://…`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}

/// `sc connection add` (alias `sc connect`) — create a connection (secret(s) +
/// host anchor) in one unlock+write cycle.
#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// A short id YOU choose for this connection (not picked from a list) —
    /// free text is slugified to `[a-z0-9_]` (e.g. "My Work" → `my_work`) and
    /// becomes the phantom `__sc__<id>__` the agent uses. Omit on a terminal to
    /// be prompted (with the rest of the wizard); required off a terminal.
    #[arg(value_name = "ID")]
    pub name: Option<String>,
    /// Back this connection with a catalog SERVICE: its id from `sc registry`
    /// (e.g. `github`), which supplies the hosts + declared secret slots. `--host`
    /// then only PINS an exact FQDN inside one of the service's `*.suffix`
    /// wildcards. Omit for a raw connection (you anchor your own `--host` and
    /// fill its keys with `--from-literal` / `--from-secret`).
    #[arg(long)]
    pub service: Option<String>,
    /// Anchored egress host (exact domain, repeatable). Required for a raw
    /// non-interactive create; prompted when omitted on a TTY. For a
    /// `--service` connection: optional, and each must be ⊆ the service's hosts.
    #[arg(long)]
    pub host: Vec<String>,
    /// Fill a slot with a NEW secret value, written to the vault when the
    /// connection is approved: `SLOT=VALUE`. With `--service`, SLOT is one of
    /// the service's declared secret roles (case-insensitive); for a raw
    /// connection SLOT is the vault KEY itself (stored UPPERCASE). A bare `SLOT`
    /// prompts for the value with hidden input on a terminal. Repeatable.
    #[arg(long = "from-literal", value_name = "SLOT=VALUE")]
    pub from_literal: Vec<String>,
    /// Fill a slot with a secret ALREADY in the vault, by its KEY; no value is
    /// written or shown: `SLOT=KEY`. With `--service`, SLOT is one of the
    /// service's declared secret roles and the `SLOT=KEY` form is required; for
    /// a raw connection SLOT is the KEY itself, so `--from-secret KEY` is the
    /// short form. KEY is matched as typed: native keys fold to their stored
    /// UPPERCASE form; an external store's key (e.g. a lowercase GCP secret id)
    /// is matched exactly. Repeatable. The service's primary credential slot
    /// (its token, or the refresh token it mints from) is required: named by
    /// neither flag, it is prompted for (hidden) on a terminal and is an error
    /// off one. Its other slots are optional: offered on a terminal (blank
    /// skips), left unfilled otherwise.
    #[arg(long = "from-secret", value_name = "SLOT=KEY")]
    pub from_secret: Vec<String>,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct ConnectionArgs {
    #[command(subcommand)]
    pub sub: ConnectionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ConnectionSubcommand {
    /// Create a connection (secret(s) + host anchor) in one approval. Each secret
    /// slot is filled from a new value (`--from-literal SLOT=VALUE`) or from a
    /// secret already in the vault (`--from-secret SLOT=KEY`). An agent may run
    /// this to propose a connection; it takes effect only after the vault
    /// owner approves it with a passkey, on a card that lists every bound key
    /// and every destination host. On a terminal, `sc connection add` with no
    /// args runs a short wizard (id → optional service → host(s) → secret(s));
    /// off a terminal, pass the `<id>` and the flags.
    Add(ConnectArgs),
    /// List the connections the agent can use (id, hosts, phantoms). Requires an
    /// unlocked vault. `--json` for scripts.
    Ls(ConnectionLsArgs),
    /// Remove a connection and its secret(s) from the vault (two passkey
    /// gestures: unlock + write). Mirrors the console's "Disconnect".
    Rm(ConnectionRmArgs),
    /// Propose adding a host to an existing connection's anchor — an exact FQDN
    /// or a leftmost `*.domain` wildcard (covers every subdomain). Passkey-gated:
    /// it mints an approval the vault owner confirms (an agent surfaces the
    /// link), then the host is added DURABLY. The self-service twin of the
    /// proxy's one-tap host widen — how an agent that hit a host it can't reach
    /// asks for access instead of a human editing the vault by hand.
    #[command(name = "add-host")]
    AddHost(ConnectionHostArgs),
    /// Propose REMOVING a host from a connection's anchor (tighten access) — the
    /// inverse of `add-host`. Same passkey approval; idempotent (a host not on
    /// the anchor reports nothing removed).
    #[command(name = "rm-host")]
    RmHost(ConnectionHostArgs),
}

#[derive(Debug, Args)]
pub struct ConnectionLsArgs {}

/// Args for `sc connection add-host` / `rm-host` — one passkey-approved host
/// edit on an existing connection's anchor.
#[derive(Debug, Args)]
pub struct ConnectionHostArgs {
    /// The connection to edit (see `sc connection ls`). Free text is slugified
    /// the same way `add` mints the id.
    #[arg(value_name = "ID")]
    pub id: String,
    /// The host: an exact FQDN (`api.example.com`) or a leftmost `*.domain`
    /// wildcard (`*.example.com`) covering every subdomain.
    #[arg(value_name = "HOST")]
    pub host: String,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct ConnectionRmArgs {
    /// The connection id to remove (see `sc connection ls`). Free text is
    /// slugified the same way `add` mints it.
    #[arg(value_name = "ID")]
    pub id: String,
    /// Skip the interactive confirmation (required off a terminal, since the
    /// delete of the connection + its secrets is irreversible without a re-add).
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Remove only the connection record and keep every secret value in the
    /// vault (unreference). Default deletes the keys this connection WROTE
    /// that no other connection references; a key it only bound
    /// (`--from-secret`), a key another connection references, and every key
    /// of a connection added before write tracking are always kept.
    #[arg(long)]
    pub keep_secrets: bool,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct OpArgs {
    #[command(subcommand)]
    pub sub: OpSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum OpSubcommand {
    /// Block until an approval op resolves; the exit code carries the outcome.
    ///
    /// Exit codes:
    ///   0  approved: re-run the original command
    ///   5  not approved: do not retry it unchanged
    ///   6  withdrawn or replaced by a newer request: re-run to ask again
    ///   3  expired or unknown: re-run for a fresh approval link
    ///   4  stopped waiting (--timeout): the op may still be pending; wait again
    #[command(verbatim_doc_comment)]
    Wait(OpWaitArgs),
}

#[derive(Debug, Args)]
pub struct OpWaitArgs {
    /// Op id from a pending-approval response (its `op_id` JSON field /
    /// `x-safeclaw-op-id` header).
    pub op_id: String,
    /// Max seconds to wait before giving up (the op's own expiry usually
    /// ends the wait first).
    #[arg(long, default_value = "1900")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct GitCredentialArgs {
    /// The operation git passes: `get` | `store` | `erase`. Only `get` does
    /// anything (returns the key); `store`/`erase` are no-ops — we persist nothing.
    pub operation: String,
}

#[derive(Debug, Args)]
pub struct RegistryArgs {}

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
pub struct ServiceArgs {
    #[command(subcommand)]
    pub sub: ServiceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServiceSubcommand {
    /// Add service definitions from a source to the active vault, with one
    /// passkey approval whose card lists each service, every host its
    /// credentials may be sent to, the rules it applies, and the source.
    /// SOURCE: `./path` or `/abs/path` (a service folder with service.toml
    /// and an optional policy.toml, or a collection folder with
    /// services/<id>/...), or `github:owner/repo[:sub/path]` (`git:` works
    /// too), pinned to a full commit. GitHub only for now.
    Add(ServiceAddArgs),
    /// Update definitions from their source. A GitHub source proposes the
    /// repository's default branch head (or `--ref`); a local source is re-read
    /// only when you pass its path again (`sc service update ./path`). Shows
    /// what changes, highlighting new hosts and loosened or removed rules,
    /// then asks for the passkey approval (always required).
    Update(ServiceUpdateArgs),
    /// List the vault's service definitions grouped by source, with the
    /// pinned commit and whether each is loaded or skipped (and why). Reads
    /// the unlocked vault; no network, no passkey.
    Ls(ServiceLsArgs),
    /// Remove one service, or every service of a source
    /// (`github:owner/repo[:path]` or `./path`). Connections that use them are
    /// kept but stop working; they are listed first. One passkey approval.
    Rm(ServiceRmArgs),
    /// Run the checks `add` runs on a source (the definition gate, and that no
    /// id is a built-in one), without a vault. Exits non-zero on any problem.
    Validate(ServiceValidateArgs),
}

#[derive(Debug, Args)]
pub struct ServiceAddArgs {
    /// `./path`, `/abs/path`, or `github:owner/repo[:sub/path]`.
    pub source: String,
    /// Store a single-service source under this id instead of its own (when
    /// it collides with a built-in service or another source's).
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,
    /// Branch or tag of a GitHub source (default: its default
    /// branch). Resolved to a full commit and pinned.
    #[arg(long = "ref", value_name = "REF")]
    pub git_ref: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct ServiceUpdateArgs {
    /// A service id or a source (`github:owner/repo[:path]`, `./path`).
    #[arg(required_unless_present = "all")]
    pub target: Option<String>,
    /// Update every GitHub source in the vault.
    #[arg(long, conflicts_with_all = ["target", "git_ref"])]
    pub all: bool,
    /// Show what would change; change nothing.
    #[arg(long)]
    pub check: bool,
    /// Skip the terminal confirmation (the passkey approval is still required).
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Update a GitHub source to this branch or tag instead of its
    /// default branch head.
    #[arg(long = "ref", value_name = "REF")]
    pub git_ref: Option<String>,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct ServiceLsArgs {
    /// Show one service in detail.
    pub id: Option<String>,
}

#[derive(Debug, Args)]
pub struct ServiceRmArgs {
    /// A service id, or a source (`github:owner/repo[:path]`, `./path`) to
    /// remove all of its services.
    pub target: String,
    #[arg(long)]
    pub no_browser: bool,
    /// Fixed port for the localhost callback server (for SSH port-forwarding).
    #[arg(long, env = "SAFECLAW_CB_PORT")]
    pub cb_port: Option<u16>,
    #[arg(long, default_value = "120")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct ServiceValidateArgs {
    /// `./path`, `/abs/path`, or `github:owner/repo[:sub/path]`.
    pub source: String,
    /// Branch or tag of a GitHub source.
    #[arg(long = "ref", value_name = "REF")]
    pub git_ref: Option<String>,
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
    /// Mint a new agent identity and print its env: two non-secret dotenv lines,
    /// SAFECLAW_BROKER_URL + SAFECLAW_AGENT_IDENTITY (a file path, not a secret),
    /// which the agent appends to its own `.env`. No vault line: vault is per-call,
    /// not identity (design/vault-addressing.md). Account-level: works on any of
    /// your paired devices.
    Add(AgentAddArgs),
    /// List this account's agents (name, key prefix, last-used).
    Ls,
    /// Remove an agent: prints the SafeClaw console page where the owner signs
    /// the removal. Every device refuses the agent at its next ledger pull.
    Rm(AgentRmArgs),
}

#[derive(Debug, Args)]
pub struct AgentAddArgs {
    /// A short name identifying THIS agent — use your own tool / agent name
    /// (e.g. "Claude Code", "Cursor", "deploy-bot"), not a generic one, so you
    /// can recognize it later in the console's Access list.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct AgentRmArgs {
    /// Agent name (see `sc agent ls`).
    pub name: String,
}

/// `sc setup` is an agent-driven, re-runnable state machine. `name` stays
/// optional at clap's boundary so the command can return its structured usage
/// error instead of clap writing a different shape to stderr.
#[derive(Debug, Args)]
pub struct SetupArgs {
    /// A short name identifying the agent being set up, such as claude-code.
    #[arg(long)]
    pub name: Option<String>,
    /// First-party environment selector: prod (default) or dev.
    #[arg(long)]
    pub profile: Option<String>,
    /// Wait briefly for an already-running setup worker.
    #[arg(long)]
    pub wait: bool,
    /// Internal detached-worker entrypoint.
    #[arg(long, hide = true)]
    pub worker: bool,
    /// Print the detected agent name and exit.
    #[arg(long, hide = true)]
    pub detect_agent: bool,
    /// Internal setup phase run by the detached worker.
    #[arg(long, hide = true, value_enum)]
    pub phase: Option<SetupPhase>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SetupPhase {
    Device,
    Agent,
    Unlock,
}

#[derive(Debug, Args)]
pub struct SkillArgs {
    #[command(subcommand)]
    pub sub: SkillSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SkillSubcommand {
    /// Install or update the SafeClaw skill for agents on this machine.
    Install(SkillInstallArgs),
    /// Remove the skill files previously written by SafeClaw.
    Remove(SkillRemoveArgs),
}

#[derive(Debug, Args)]
pub struct SkillInstallArgs {
    /// Replace a copy that was modified after SafeClaw installed it.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SkillRemoveArgs {
    /// Remove a copy that was modified after SafeClaw installed it.
    #[arg(long)]
    pub force: bool,
}

/// `sc device` — the device axis of the account plane.
#[derive(Debug, Args)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub sub: DeviceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum DeviceSubcommand {
    /// Pair this host to your vault (same as top-level `sc login`).
    Login(LoginArgs),
    /// Unpair this host (same as top-level `sc logout`).
    Logout(LogoutArgs),
}

#[derive(Debug, Subcommand)]
pub enum PasskeySubcommand {
    /// List passkeys enrolled on the active vault (public metadata only:
    /// credential id, device name, transports, timestamps). No vault
    /// unlock or passkey gesture required.
    Ls(CommonArgs),
    /// Add a passkey: prints the SafeClaw console page where passkeys are
    /// enrolled (in the browser, where the identity key lives).
    Add(CommonArgs),
    /// Remove an enrolled passkey by credential id. NOT YET IMPLEMENTED.
    Rm(PasskeyRemoveArgs),
    /// Rename an enrolled passkey's `device_name`. NOT YET IMPLEMENTED —
    /// daemon currently has no metadata-update endpoint.
    Rename(PasskeyRenameArgs),
}

#[derive(Debug, Args)]
pub struct PasskeyRemoveArgs {
    /// base64url credential id (as shown in `passkeys ls`).
    pub credential_id: String,
}

#[derive(Debug, Args)]
pub struct PasskeyRenameArgs {
    pub credential_id: String,
    pub new_name: String,
}

#[derive(Debug, Args)]
pub struct VaultLsArgs {}

#[derive(Debug, Subcommand)]
pub enum VaultSubcommand {
    /// Show current vault: URL, state (locked/unlocked/not-enrolled),
    /// passkey count, secret count. Top-level alias: `sc status`.
    Status(StatusArgs),
    /// List vaults this CLI has used (from local config) + mark the
    /// device default with `*`. `--json` for scripts/agents.
    Ls(VaultLsArgs),
    /// Switch the active vault. Pass an id, a unique id prefix, or the exact name
    /// (quote if it has spaces); also an `sc vault ls` index, a vault URL, --local
    /// for the localhost default, or nothing for an interactive prompt.
    Use(VaultUseArgs),
    /// Remove a vault from the local known list (does NOT touch the
    /// daemon, for that use `sc vault rm`). Pass URL or index.
    Forget(VaultForgetArgs),
    /// Create a new vault: prints the SafeClaw console page where vaults are
    /// created. The new vault syncs to this machine on its own.
    Create(VaultCreateArgs),
    /// Irreversibly delete a vault's daemon-side state. Passkey-gated
    /// via the standard `/op/{op_id}` browser-callback ceremony.
    Rm(VaultDeleteArgs),
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
    /// Either a vault URL (`<daemon>/v/<vault_id>`) or a numeric index
    /// from `sc vault ls`. If omitted and `--local` is also omitted, an
    /// interactive prompt lists known vaults.
    pub url_or_idx: Option<String>,
    /// Shortcut for the localhost control-plane vault (`/v/default`).
    #[arg(long, conflicts_with = "url_or_idx")]
    pub local: bool,
}

#[derive(Debug, Args)]
pub struct VaultForgetArgs {
    /// A vault URL (`<daemon>/v/<vault_id>`) or numeric index from
    /// `sc vault ls`. If omitted, an interactive prompt lists known vaults.
    pub url_or_idx: Option<String>,
}

#[derive(Debug, Args)]
pub struct VaultCreateArgs {}

#[derive(Debug, Args)]
pub struct VaultDeleteArgs {
    /// Vault id to delete. Required even when only one config exists —
    /// no implicit "current vault" for destructive ops.
    pub vault: String,

    /// Bypass the interactive confirmation. Without this flag the command
    /// refuses to proceed (since deletion is irreversible).
    #[arg(long, short = 'y')]
    pub yes: bool,

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
pub struct ProxyArgs {
    #[command(subcommand)]
    pub sub: ProxySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProxySubcommand {
    /// Set the device's upstream EGRESS proxy — the HTTP proxy the daemon uses to
    /// reach the internet (OAuth exchanges, the resident proxy's forward hop,
    /// `sc upgrade`). Persists it and bounces the daemon so it takes effect (one
    /// passkey tap to re-unlock). e.g. `sc proxy set http://127.0.0.1:7778`.
    Set { url: String },
    /// Print the configured egress proxy (and any shell `HTTPS_PROXY` that would
    /// override it). Exit nonzero when nothing is configured.
    Get,
    /// Remove the configured egress proxy and bounce the daemon back to direct.
    Unset,
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
    Ls,
}

#[derive(Debug, Args)]
pub struct LogArgs {
    /// Follow new log lines (like `tail -f`).
    #[arg(long, short = 'f')]
    pub follow: bool,
    /// Show only the last N lines (passed to journalctl as -n).
    #[arg(long, short = 'n', default_value = "200")]
    pub tail: u32,
    /// Keep journald's full format (local wall-clock, host, pid). Default output
    /// is `-o cat` — just the daemon's own already-timestamped line.
    #[arg(long)]
    pub raw: bool,
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

    /// The control plane port (`CONTROL_PORT`). The `sc` CLI, op-approval
    /// polling, ceremonies, `/events`, and any reverse proxy talk to the
    /// daemon here; the agent's own traffic uses only the proxy port
    /// (`$SAFECLAW_BROKER_URL`).
    #[arg(long, env = "SAFECLAW_PORT", default_value_t = CONTROL_PORT)]
    pub port: u16,

    /// The credential-proxy plane port (`PROXY_PORT`). The resident local HTTPS
    /// MITM the agent's tool traffic is routed through; addressed only by the
    /// env bundle `sc run` pastes, never by number in agent-facing config.
    #[arg(long, env = "SAFECLAW_PROXY_PORT", default_value_t = PROXY_PORT)]
    pub proxy_port: u16,

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
    /// want. Override only for eTLD+1 sharing across subdomains. With
    /// neither --origin nor --rp-id, a daemon paired with the SafeClaw
    /// console (safeclaw.pro, dev.safeclaw.pro) accepts its root, `app.` and
    /// `www.` origins under the root RP ID
    /// (`passkey::webauthn::RelyingParty::console`); any other console
    /// origin is matched exactly.
    #[arg(long, env = "SAFECLAW_RP_ID")]
    pub rp_id: Option<String>,

    /// Shared secret that authenticates this daemon to the cloud op-relay
    /// (see `--relay-url`): the daemon presents it as the bearer token when it
    /// registers a pending op and polls for the browser-deposited grant. When
    /// unset, the daemon can't reach the relay, so web approval is off (it
    /// falls back to local-only). Set on the daemon AND matched on the relay.
    /// Rotate by changing the env var and redeploying. (Named `admin_key` for
    /// historical reasons — the old `/admin/*` HTTP surface it also gated is
    /// gone; today it is purely the relay credential.)
    #[arg(long, env = "SAFECLAW_ADMIN_KEY")]
    pub admin_key: Option<String>,

    /// Cloud op-relay base URL (e.g. `https://api.dev.safeclaw.pro`). When set,
    /// the daemon registers each pending op with the relay and polls for the
    /// browser-deposited (HPKE-sealed) grant — this is what enables web
    /// approval for a zero-inbound localhost daemon. When unset, the daemon is
    /// local-only (legacy embedded op-page). Auth uses `--admin-key`.
    #[arg(long, env = "SAFECLAW_RELAY_URL")]
    pub relay_url: Option<String>,

    /// Max body size (bytes) the broker will buffer for a phantom-bearing
    /// request. Over the cap the request is refused with a clear 413 — the
    /// proxy never forwards a credential alongside a body policy couldn't
    /// inspect. Raise it if a legitimate brokered upload hits the limit.
    #[arg(long, env = "SAFECLAW_BODY_CAP", default_value_t = DEFAULT_BODY_CAP)]
    pub body_cap: u64,
}

/// `sc status` takes no flags — the daemon (control root) comes from
/// `~/.safeclaw/config.toml`; the active vault is `--vault` else
/// `$SAFECLAW_VAULT_ID` (env pin) else the config default (§5).
#[derive(Debug, Args)]
pub struct StatusArgs {}

#[derive(Debug, Args)]
pub struct SyncArgs {}

#[derive(Debug, Args)]
pub struct UnlockArgs {
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
    /// Force the PRE-RELEASE channel: install the newest release even if it's a
    /// `vX.Y.Z-rc.N` pre-release. Normally the channel is DERIVED from the cloud
    /// this host is paired to (a `dev.*` login tracks pre-releases, prod tracks
    /// stable), so a dogfood box needs no flag; plain `sc upgrade` already
    /// tracks rc. This override is for the rare case of pulling an rc while
    /// paired to prod. Mutually exclusive with `--stable`.
    #[arg(long, conflicts_with = "stable")]
    pub prerelease: bool,
    /// Force the STABLE channel: track only stable releases (GitHub's `latest`,
    /// which skips pre-releases) regardless of derivation. The escape hatch for a
    /// `dev.*`-paired box that wants to drop back to stable. Mutually exclusive
    /// with `--prerelease`.
    #[arg(long)]
    pub stable: bool,
}

/// Args for `sc login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Friendly label shown for this host in the dashboard's device list.
    /// Defaults to the machine's hostname, else `agent-device`.
    #[arg(long)]
    pub device_name: Option<String>,
    /// First-party environment selector: `prod` (default) or `dev`. Resolves
    /// only against a compiled-in allowlist, it is NOT a raw custodian URL, so
    /// a hostile install prompt can at worst flip between your own prod/dev,
    /// never to a third-party host. The prod console omits it; the dev console's
    /// install prompt appends `--profile dev`.
    #[arg(long)]
    pub profile: Option<String>,
    /// Test-only: allow a plaintext `http://` custodian URL. Without this,
    /// `sc login` refuses non-HTTPS URLs (a malicious skill prompt could
    /// otherwise smuggle in an attacker's device-key by suggesting an
    /// `http://` custodian).
    /// `http://localhost:*` and `http://127.0.0.1:*` are exempt, that's the
    /// common dev-loopback case and is on-host plaintext.
    #[arg(long)]
    pub insecure: bool,
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

/// Reusable arg set for read-only short-lived commands. The daemon control
/// root comes from the shared derivation (env `$SAFECLAW_BROKER_URL` host >
/// config > default); `--vault` only reselects the vault id on that daemon.
#[derive(Debug, Args)]
pub struct CommonArgs {}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Secret key to reveal, from any store (native or external), matched
    /// case-SENSITIVELY (`sc get OPENAI_API_KEY`; external keys verbatim).
    pub key: String,

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
    /// The secret value. When omitted on a TTY, `sc set` prompts for it hidden
    /// (keeps it out of shell history / `ps`). Required as an argument when
    /// stdin isn't a terminal.
    pub value: Option<String>,
    /// Anchor the secret to an egress host so the agent can broker it: creates a
    /// raw connection `__sc__<key>__` → this exact domain (repeatable). Pass
    /// `--host none` (or `--no-broker`) to store it for humans only. On a TTY a
    /// host is prompted when neither is given; off a TTY the command errors
    /// (naming both fixes) rather than storing an unusable item.
    #[arg(long)]
    pub host: Vec<String>,
    /// Store the secret WITHOUT a host anchor — human-only, invisible to the
    /// agent surface (`sc secret get` reveals it via the passkey ceremony).
    #[arg(long, conflicts_with = "host")]
    pub no_broker: bool,
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
    /// Remove the key even when connections still reference it. They are
    /// never deleted with it, they just turn unconfigured until the key is
    /// re-added. Required off a terminal; interactive runs prompt instead.
    #[arg(long, short = 'y')]
    pub yes: bool,
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
    /// Credential-proxy plane bind port (the hudsucker MITM). S2 binds it.
    pub proxy_port: u16,
    pub listen: String,
    /// The console origin links point at (`{origin}/vault/<id>`).
    pub origin: String,
    /// Whose WebAuthn assertions verify: the RP ID and the accepted origins.
    pub relying_party: crate::passkey::webauthn::RelyingParty,
    pub admin_key: Option<String>,
    pub relay_url: Option<String>,
    /// See `ServeArgs::body_cap` / [`DEFAULT_BODY_CAP`].
    pub body_cap: u64,
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
        let explicit = args.origin.is_some() || args.rp_id.is_some();
        let origin = args.origin.unwrap_or_else(|| {
            crate::cli::active::frontend_origin()
                .unwrap_or_else(|| format!("http://localhost:{}", args.port))
        });
        // A paired daemon's console origin (stored at `sc login`, either the
        // root or its `app.` host) gives the console relying party: the root
        // RP ID and its root / `app.` / `www.` origins. Explicit --origin /
        // --rp-id, and a localhost or self-host origin, match exactly; the
        // rp_id then defaults to the origin's host (scheme, path and :port
        // stripped; "localhost" if it does not parse).
        let relying_party = relying_party_for(&origin, explicit, args.rp_id);
        // state_dir default = ~/.safeclaw/state (see `default_state_dir`).
        let state_dir = args.state_dir.unwrap_or_else(default_state_dir);
        Self {
            state_dir,
            port: args.port,
            proxy_port: args.proxy_port,
            listen: args.listen,
            origin,
            relying_party,
            admin_key: args.admin_key,
            relay_url: args.relay_url,
            body_cap: args.body_cap,
        }
    }
}

/// The daemon's state directory, resolved the SAME way `from_serve_args` does:
/// `$SAFECLAW_STATE_DIR` else `~/.safeclaw/state` (single `~/.safeclaw` tree so
/// the whole footprint is one dir to chmod/back up; cwd-relative `./state` only
/// if the home dir is somehow unknown). Short-lived CLI verbs that need the
/// resident CA path (`sc run`, `sc status`) share this so they never drift from
/// where the daemon actually wrote `ca.pem`.
pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SAFECLAW_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .map(|h| h.join(".safeclaw").join("state"))
        .unwrap_or_else(|| PathBuf::from("./state"))
}

/// The WebAuthn relying party for `origin`: the SafeClaw console's (root RP
/// ID, root / `app.` / `www.` origins) when `origin` is one of its hosts and
/// neither the origin nor the RP ID was given explicitly. Every other origin
/// (a self-hosted console, localhost) is matched exactly under `rp_id`
/// (default: the origin's host).
fn relying_party_for(
    origin: &str,
    explicit: bool,
    rp_id: Option<String>,
) -> crate::passkey::webauthn::RelyingParty {
    use crate::passkey::webauthn::RelyingParty;
    match RelyingParty::console(origin).filter(|_| !explicit) {
        Some(rp) => rp,
        None => {
            let rp_id = rp_id
                .unwrap_or_else(|| host_from_origin(origin).unwrap_or_else(|| "localhost".into()));
            RelyingParty::exact(origin, &rp_id)
        }
    }
}

fn host_from_origin(origin: &str) -> Option<String> {
    let after_scheme = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod relying_party_tests {
    use super::*;

    #[test]
    fn stored_console_origin_gives_the_root_party_explicit_flags_stay_exact() {
        for stored in ["https://safeclaw.pro", "https://app.safeclaw.pro"] {
            let rp = relying_party_for(stored, false, None);
            assert_eq!(rp.rp_id, "safeclaw.pro");
            assert!(rp.allows("https://safeclaw.pro"));
            assert!(rp.allows("https://app.safeclaw.pro"));
            assert!(rp.allows("https://www.safeclaw.pro"));
            assert!(!rp.allows("https://evil.safeclaw.pro"));
        }
        let dev = relying_party_for("https://app.dev.safeclaw.pro", false, None);
        assert_eq!(dev.rp_id, "dev.safeclaw.pro");
        // --origin / --rp-id: exactly as given.
        let explicit = relying_party_for("https://app.safeclaw.pro", true, None);
        assert_eq!(explicit.rp_id, "app.safeclaw.pro");
        assert_eq!(
            explicit.origins,
            vec!["https://app.safeclaw.pro".to_string()]
        );
        let rp_only = relying_party_for("https://safeclaw.pro", true, Some("safeclaw.pro".into()));
        assert_eq!(rp_only.origins, vec!["https://safeclaw.pro".to_string()]);
        // Unpaired localhost.
        let local = relying_party_for("http://localhost:23293", false, None);
        assert_eq!(local.rp_id, "localhost");
        assert_eq!(local.origins, vec!["http://localhost:23293".to_string()]);
        // A self-hosted console: its own hostname is the RP ID and its origin
        // the only one, whatever its labels.
        for (stored, host) in [
            ("https://vault.corp.example", "vault.corp.example"),
            ("https://app.corp.example", "app.corp.example"),
            ("https://www.corp.example", "www.corp.example"),
        ] {
            let rp = relying_party_for(stored, false, None);
            assert_eq!(rp.rp_id, host, "{stored}");
            assert_eq!(rp.origins, vec![stored.to_string()], "{stored}");
            assert!(!rp.allows(&format!("https://app.{host}")));
            assert!(!rp.allows(&format!("https://www.{host}")));
        }
    }
}
