//! `sc login` — pair this machine to a SafeClaw account.
//!
//! Pairing is the PAKE short-code ceremony (grant-v3 contract C2,
//! `cli::pair_flow`): `sc` prints a code and a link it builds itself from the
//! pinned console origin, the owner approves in the browser, and `sc` verifies
//! the owner-signed admit of this device's own keys (`dev_…` ‖ `sc_pk`) before
//! it pins that owner as `account_uik`. Then:
//!
//!   1. Persist `device_key` (a `sc_device_<rand>` token) to
//!      `~/.safeclaw/device-key` (mode 0600): the daemon→cloud credential,
//!      distinct from any agent credential. The agent never sees it.
//!   2. Persist the cloud coordinates and the verified owner (`account_uik` +
//!      its key) in config.
//!
//! `sc up` reads the credential at start time.

use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::cli::active::put_cloud_coords;
use crate::config::LoginArgs;

/// Default daemon control-plane port (matches `ServeArgs` `SAFECLAW_PORT`).
const DEFAULT_DAEMON_PORT: u16 = crate::config::CONTROL_PORT;

/// Resolve which cloud this machine pairs with. Precedence:
///   1. `SAFECLAW_CLOUD_URL` — runtime self-host escape hatch (any URL; HTTPS
///      enforced below). Undocumented; for people running their own custodian.
///   2. `--profile {prod,dev}` — the FIRST-PARTY selector the console's install
///      prompt uses. It is a SYMBOL, not a URL: it resolves only against the
///      compiled-in allowlist below. This is deliberate, `sc login` has no
///      `--custodian <url>` flag, because a malicious skill prompt could
///      otherwise redirect pairing to an attacker host. A symbol bounded to
///      first-party domains means a hostile prompt can at worst flip you
///      between your OWN prod/dev, never to a third party. The prod console
///      omits the flag (→ default prod); the dev console appends `--profile dev`.
///   3. `SAFECLAW_BAKED_CLOUD_URL` — compile-time self-host bake.
///   4. Default: prod. Every real user only ever deals with prod.
/// The resolved value is only the target at `sc login` time; once paired, the
/// machine is pinned to the backend persisted in config.toml, so this never
/// matters again for that machine.
pub(crate) fn resolve_custodian(env_flag: Option<&str>) -> Result<String, String> {
    if let Ok(u) = std::env::var("SAFECLAW_CLOUD_URL") {
        if !u.is_empty() {
            return Ok(u);
        }
    }
    if let Some(env) = env_flag {
        return env_selector_to_url(env);
    }
    if let Some(u) = option_env!("SAFECLAW_BAKED_CLOUD_URL") {
        if !u.is_empty() {
            return Ok(u.to_string());
        }
    }
    Ok("https://safeclaw.pro".to_string())
}

/// The `--profile` allowlist. A SYMBOL → first-party URL only; anything else is a
/// hard error. This is the gate that keeps a hostile install prompt from
/// steering pairing off first-party domains; do not widen it to accept URLs.
pub(crate) fn env_selector_to_url(env: &str) -> Result<String, String> {
    match env {
        "prod" => Ok("https://safeclaw.pro".to_string()),
        "dev" => Ok("https://dev.safeclaw.pro".to_string()),
        other => Err(format!(
            "unknown --profile '{}': expected 'prod' or 'dev'",
            other
        )),
    }
}

pub(crate) fn device_name(requested: Option<String>) -> String {
    requested
        .or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "agent-device".to_string())
}

#[cfg(test)]
mod tests {
    use super::env_selector_to_url;

    #[test]
    fn env_selector_allowlist_maps_first_party_only() {
        assert_eq!(env_selector_to_url("prod").unwrap(), "https://safeclaw.pro");
        assert_eq!(
            env_selector_to_url("dev").unwrap(),
            "https://dev.safeclaw.pro"
        );
        // Anything that is not an exact first-party symbol is rejected — a
        // hostile prompt cannot smuggle a custodian URL through `--profile`.
        assert!(env_selector_to_url("https://attacker.com").is_err());
        assert!(env_selector_to_url("staging").is_err());
        assert!(env_selector_to_url("").is_err());
    }
}

/// What a completed pairing hands back (the approval body of `/api/pair/poll`).
#[derive(Debug, Deserialize)]
struct ExchangeResp {
    account_id: String,
    device_key: String,
    pro_backend_url: Option<String>,
    /// Cloud FRONTEND origin (web approval page host). Optional; the daemon
    /// derives it from `pro_backend_url` when absent.
    #[serde(default)]
    console_url: Option<String>,
}

/// Device material prepared in memory for a pairing. The DIK is not written
/// until the complete approval has verified.
pub(crate) struct PreparedDevice {
    pub path: std::path::PathBuf,
    pub seed: Zeroizing<[u8; 32]>,
    pub id: String,
    pub signer: crate::identity::SigningIdentity,
    pub sc_pk: [u8; 32],
}

pub(crate) fn prepare_device() -> Result<PreparedDevice, String> {
    let path = crate::identity_file::device_identity_path()?;
    let (seed, id) = match crate::identity_file::load(&path) {
        Ok(loaded) if loaded.kind == crate::identity::IdKind::Device => (loaded.seed, loaded.id),
        _ => crate::identity_file::mint(crate::identity::IdKind::Device),
    };
    let (signer, _) = crate::identity_file::resolve(crate::identity::IdKind::Device, &seed);
    let sc = crate::crypto::envelope::ScKeyPair::load_or_generate()
        .map_err(|e| format!("load this machine's daemon key: {}", e))?;
    let sc_pk = sc
        .pk_bytes()
        .try_into()
        .map_err(|_| "daemon key is not 32 bytes".to_string())?;
    Ok(PreparedDevice {
        path,
        seed,
        id,
        signer,
        sc_pk,
    })
}

pub async fn run(args: LoginArgs) -> Result<(), String> {
    pair_and_persist(args, true).await?;
    eprintln!("Starting SafeClaw…");
    if let Err(e) = bring_up(true).await {
        if let Some(e) = e.strip_prefix("auto-start: ") {
            eprintln!("  couldn't auto-start the daemon ({e}); run sc up to finish.");
        } else if let Some(e) = e.strip_prefix("auto-unlock: ") {
            eprintln!("  couldn't auto-unlock ({e}); run sc up to finish.");
        } else {
            eprintln!("  couldn't finish bring-up ({e}); run sc up to finish.");
        }
    }
    Ok(())
}

/// Run the existing device pairing ceremony and persist its result, but do not
/// start or unlock the daemon. `sc setup --background` uses this in-process so
/// the PAKE session remains in one long-lived background process.
pub async fn pair_and_persist(args: LoginArgs, allow_account_switch: bool) -> Result<(), String> {
    // ── Resolve cloud endpoint: env override > --profile selector > baked ─────
    let custodian = resolve_custodian(args.profile.as_deref())?;
    let custodian = custodian.trim_end_matches('/').to_string();

    // ── Enforce HTTPS for the custodian URL ──────────────────────────────
    // The response carries `pro_backend_url` + `device_key`, which we persist
    // and trust on subsequent runs; an on-path attacker on `http://` could
    // swap them. Reject by default; the only legitimate cleartext case is
    // dev-loopback.
    if !args.insecure && !custodian.starts_with("https://") && !is_localhost_http(&custodian) {
        return Err(format!(
            "custodian URL must use HTTPS ({} is plaintext); \
             pass --insecure to override (test-only)",
            custodian
        ));
    }

    // ── Resolve device name: flag > OS hostname > $HOSTNAME / $COMPUTERNAME
    //    env > literal. The hostname syscall is the reliable source — the env
    //    vars are unset in most non-login / non-interactive shells, which is
    //    what used to strand a device on the "agent-device" fallback. ──
    let device_name = device_name(args.device_name.clone());

    // Dedicated 10s timeout per request (each pairing call is one round-trip).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;

    // ── Device identity (DIK): reuse this machine's keypair or mint a fresh one
    // (identity wave §5). Stable across re-logins so a device keeps one `dev_…`
    // id. The private SEED stays on disk (0600, `~/.safeclaw/device/identity`);
    // only the PUBLIC key is registered with the cloud (authorized-devices set),
    // additive to the legacy device-key bearer that still authenticates
    // daemon↔cloud during the dual-auth window (§7).
    let device = prepare_device()?;

    // ── Pair (PAKE short code). The link's origin is the console of the
    // custodian resolved above (first-party allowlist / self-host env), never
    // a URL the server returns.
    let origin = crate::cli::active::console_origin_for_backend(&custodian);
    let paired = crate::cli::pair_flow::pair(
        &client,
        &crate::cli::pair_flow::PairRequest {
            entries: vec![crate::cli::pair_flow::PairPrincipal {
                kind: "device",
                name: &device_name,
                id: &device.id,
                signer: &device.signer,
                sc_pk: Some(device.sc_pk),
            }],
            cloud: &custodian,
            origin: &origin,
            restart: "sc login",
        },
    )
    .await?;
    persist_device_approval(
        &paired,
        &device,
        &custodian,
        allow_account_switch,
        Vec::new(),
    )
}

/// Persist a fully verified approval that contains a device. This is shared by
/// `sc login` and the one-code `sc setup` device+agent flow.
pub(crate) fn persist_device_approval(
    paired: &crate::cli::pair_flow::Paired,
    device: &PreparedDevice,
    custodian: &str,
    allow_account_switch: bool,
    admitted_agents: Vec<String>,
) -> Result<(), String> {
    let parsed: ExchangeResp = serde_json::from_value(paired.body.clone())
        .map_err(|e| format!("approved, but the server's response is incomplete: {}", e))?;
    if parsed.account_id.is_empty() {
        return Err("approved, but the server's response is incomplete: no account_id".into());
    }
    // The VERIFIED owner (admit signer, owner_mac), never the poll's label.
    let account_uik = paired.uik_id.clone();

    // ── Pairing a DIFFERENT account switches this machine to it ──────────
    // A machine's `sc` is paired to exactly one account. Nothing of the old one
    // may carry over: stop the daemon (it holds the old account's unlocked keys
    // and would write its state back), then drop the old account's local state
    // exactly as `sc logout` does. The bring-up below starts the daemon clean on
    // the new pairing; `put_cloud_coords` drops the old account id / pinned UIK.
    // Re-pairing the same account skips all of this.
    if crate::cli::active::paired_to_other_account(
        parsed.account_id.as_str(),
        account_uik.as_str(),
    ) {
        if !allow_account_switch {
            return Err(
                "the approval belongs to a different account than this machine's existing pairing"
                    .to_string(),
            );
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if crate::cli::service::unit_installed() {
                let _ = crate::cli::service::run_stop();
            }
        }
        crate::cli::logout::wipe_local_account_state()
            .map_err(|e| format!("clear the previous account's local state: {}", e))?;
    }

    // ── Persist the device-key to ~/.safeclaw/device-key (0600) ──────────
    let key_path = device_key_path()?;
    write_device_key(&key_path, &parsed.device_key)?;

    // ── Persist the DIK identity file (0600) after a successful exchange ──
    // Idempotent when reused. The daemon reads this for the daemon↔cloud mTLS /
    // signed-request path once hop-B ships; until then the device-key bearer
    // above stays the active transport.
    if let Err(e) =
        crate::identity_file::write(&device.path, crate::identity::IdKind::Device, &device.seed)
    {
        // Non-fatal: pairing succeeded; the DIK is an additive upgrade. Warn but
        // don't strand the device on a write hiccup.
        eprintln!(
            "warning: could not persist device identity ({e}); device-key pairing still succeeded"
        );
    }

    // ── Persist active vault + cloud sync coordinates ────────────────────
    // The AGENT talks to the LOCAL daemon (active `custodian`), not the
    // cloud — the daemon brokers locally and only the daemon reaches the
    // cloud, for sealed-blob sync (Slice 3). So active custodian = the
    // localhost daemon URL, and we record `pro_backend_url` separately as
    // `cloud_backend` for the daemon's pull/push. Use the server-returned
    // pro_backend_url (source of truth) over the request custodian — they
    // normally match, but the server can canonicalize the host.
    let pro_backend_url = parsed
        .pro_backend_url
        .as_deref()
        .unwrap_or(&custodian)
        .trim_end_matches('/')
        .to_string();
    let daemon_port = std::env::var("SAFECLAW_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_DAEMON_PORT);
    let local_custodian = format!("http://127.0.0.1:{}", daemon_port);
    put_cloud_coords(
        &local_custodian,
        &pro_backend_url,
        parsed.console_url.as_deref(),
        // §15: persist the account UUID (for reference) AND the owner-UIK us_ (the
        // real principal-ledger anchor). Both pairing paths converge here.
        parsed.account_id.as_str(),
        account_uik.as_str(),
    )
    .map_err(|e| format!("save active config: {}", e))?;
    crate::cli::active::put_account_uik_key(&paired.uik_pub)
        .map_err(|e| format!("save the account key: {}", e))?;
    // §15 W2: the daemon serves only while the ledger admits this device. Write
    // its standing fresh from the admit just verified (admitted at that seq, no
    // revoke, lease from now), so it serves at once and an old revoke of this
    // device never wipes the new pairing before the first pull.
    let admit_seq = paired
        .entries
        .iter()
        .find(|entry| entry.kind == "device")
        .map(|entry| entry.admit_seq)
        .ok_or("approved, but the device admit is missing")?;
    crate::principal_ledger::write_pairing_floor(
        &crate::config::default_state_dir(),
        admit_seq,
        paired.head_max_seq,
        admitted_agents,
        crate::util::now_unix(),
    )
    .map_err(|e| format!("save this device's standing: {}", e))?;

    eprintln!(
        "Paired to {}; your agent talks to {}.",
        pro_backend_url, local_custodian
    );
    // Show the user's IDENTITY (the us_ UIK) as the account line; the Supabase UUID rides
    // as a secondary `id:` for support / console matching (debug only, never an anchor).
    eprintln!("  account: {}", account_uik);
    eprintln!("  id:      {}", parsed.account_id);

    Ok(())
}

/// Bring up the daemon after pairing. With `unlock=false`, used only by the
/// setup device background process, no approval operation is created.
pub async fn bring_up(unlock: bool) -> Result<(), String> {
    if crate::cli::service::unit_installed() {
        if unlock {
            return crate::cli::up::restart().await;
        }
        crate::cli::service::restart_with_fallback().await?;
    } else {
        // Keep the ordinary terminal path exactly as before: attempt the
        // platform service install first. Only a service-manager failure enters
        // the detached fallback shared with `sc up`.
        if let Err(manager) = crate::cli::service::run_start_systemd(false).await {
            crate::cli::service::ensure_running_with_fallback()
                .await
                .map_err(|fallback| {
                    format!("auto-start: {}; detached fallback: {}", manager, fallback)
                })?;
        }
    }
    if unlock {
        crate::cli::up::ensure_unlocked()
            .await
            .map_err(|e| format!("auto-unlock: {}", e))?;
    }
    Ok(())
}

/// Loopback-exemption check for the HTTPS gate: `http://localhost[:PORT]`
/// and `http://127.0.0.1[:PORT]` (with optional trailing path) are allowed
/// without `--insecure` because the traffic never leaves the host. We
/// intentionally do NOT exempt `0.0.0.0`, `[::1]`, or arbitrary RFC1918
/// addresses — those can be reachable from off-host on misconfigured nets,
/// and the gate is the conservative call.
fn is_localhost_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    // host[:port] is everything before the first '/'
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

/// `~/.safeclaw/device-key` — the cloud-side device key (Token 2,
/// a `sc_device_...` token) persisted after `sc login`. Distinct from
/// `~/.safeclaw/api-key` (the local agent→daemon broker key, Token 1):
/// this one is used by the daemon itself to authenticate against the SaaS
/// op-relay once Slice C wires daemon→cloud registration. The agent never
/// sees it.
fn device_key_path() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot locate home dir".to_string())?;
    Ok(home.join(".safeclaw").join("device-key"))
}

fn write_device_key(path: &std::path::Path, device_key: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    std::fs::write(path, device_key).map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort chmod — we don't fail the login if perms can't be
        // tightened on exotic filesystems.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
