//! `sc login --pair-token <X>` — exchange a one-shot pair-token (minted by
//! safeclaw.pro's "Connect a new agent" modal) for this host's persistent
//! cloud-side daemon credential.
//!
//! The CLI POSTs the token to `<custodian>/api/pair-token/exchange`. The
//! pro-backend validates+single-uses the token (10-min TTL) and returns
//! `{ account_id, vault_id, device_key, pro_backend_url }`. We then:
//!
//!   1. Persist `device_key` (a `sc_device_<rand>` token) to
//!      `~/.safeclaw/device-key` (mode 0600). This is the daemon→cloud auth
//!      token — Token 2 — distinct from `~/.safeclaw/api-key`, which is the
//!      local agent→daemon broker key (Token 1). The agent never sees the
//!      device-key.
//!   2. Persist `(pro_backend_url, account_id)` as the active CLI vault via
//!      `active::put_active(...)`. account_id doubles as the vault id under
//!      the V1 §12.2 account-bound model.
//!
//! Idempotent: re-running with a fresh token simply overwrites both files.
//! `sc up` reads the credential at start time.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::cli::active::put_active_with_cloud;
use crate::config::LoginArgs;

/// Default daemon admin port (matches `ServeArgs` `SAFECLAW_PORT`).
const DEFAULT_DAEMON_PORT: u16 = 23294;

/// The baked cloud endpoint the daemon pairs with. Device→cloud is FIXED (not
/// user config): `SAFECLAW_CLOUD_URL` (undocumented runtime override, for
/// self-host) > `SAFECLAW_BAKED_CLOUD_URL` (CI-pinned at build time) > the
/// hardcoded default below. Domain changes ship via `sc upgrade`, not config.
///
/// PRE-LAUNCH: prod (`https://safeclaw.pro`) is NOT deployed — it's a marketing
/// page with no pairing API — so EVERY build (debug AND release) pairs with dev
/// for now. When prod goes live, switch the default to the build-profile split:
///   `if cfg!(debug_assertions) { dev } else { "https://safeclaw.pro" }`
/// (and bump + re-release so install.sh serves a prod-pointing binary).
fn baked_cloud_url() -> String {
    if let Ok(u) = std::env::var("SAFECLAW_CLOUD_URL") {
        if !u.is_empty() {
            return u;
        }
    }
    if let Some(u) = option_env!("SAFECLAW_BAKED_CLOUD_URL") {
        if !u.is_empty() {
            return u.to_string();
        }
    }
    "https://dev.safeclaw.pro".to_string()
}

#[derive(Debug, Deserialize)]
struct ExchangeResp {
    account_id: String,
    vault_id: String,
    device_key: String,
    pro_backend_url: String,
    /// Cloud FRONTEND origin (web approval page host). Optional for forward-
    /// compat with older backends; the daemon derives it from
    /// `pro_backend_url` when absent.
    #[serde(default)]
    console_url: Option<String>,
}

pub async fn run(args: LoginArgs) -> Result<(), String> {
    // ── Cloud endpoint is baked (device→cloud is fixed .pro) ─────────────
    let custodian = baked_cloud_url();
    let custodian = custodian.trim_end_matches('/').to_string();

    // ── Enforce HTTPS for the custodian URL ──────────────────────────────
    // The pair-token is single-use but high-value (POSTing it returns the
    // device_key), and the response carries `pro_backend_url` +
    // `device_key` which we persist and trust on subsequent runs. An
    // `http://` custodian leaks the token on the wire AND lets an on-path
    // attacker swap the response for an attacker-controlled daemon. Reject
    // by default; the only legitimate cleartext case is dev-loopback.
    if !args.insecure_http
        && !custodian.starts_with("https://")
        && !is_localhost_http(&custodian)
    {
        return Err(format!(
            "custodian URL must use HTTPS ({} is plaintext); \
             pass --insecure-http to override (test-only)",
            custodian
        ));
    }

    // ── Resolve device name: flag > $HOSTNAME / $COMPUTERNAME > literal ──
    let device_name = args
        .device_name
        .clone()
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "agent-device".to_string());

    // ── POST <custodian>/api/pair-token/exchange ─────────────────────────
    // Dedicated 10s timeout; this is a single round-trip and we don't want
    // it to inherit the longer browser-gesture timeouts other CLI calls use.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;

    let body = json!({
        "pair_token": args.pair_token,
        "device_name": device_name,
    });

    let url = format!("{}/api/pair-token/exchange", custodian);
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", custodian, e))?;

    let status = resp.status();
    if !status.is_success() {
        let detail = resp.text().await.unwrap_or_default();
        let detail_trimmed = detail.trim();
        return Err(match status.as_u16() {
            401 => format!(
                "pair-token invalid or unknown. Generate a new one at {}/dashboard (\"Connect a new agent\").",
                custodian
            ),
            409 => format!(
                "pair-token already used. Generate a new one at {}/dashboard (\"Connect a new agent\").",
                custodian
            ),
            410 => format!(
                "pair-token expired (10-min TTL). Generate a new one at {}/dashboard (\"Connect a new agent\").",
                custodian
            ),
            other => {
                if detail_trimmed.is_empty() {
                    format!("custodian returned HTTP {}", other)
                } else {
                    format!("custodian returned HTTP {}: {}", other, detail_trimmed)
                }
            }
        });
    }

    let parsed: ExchangeResp = resp
        .json()
        .await
        .map_err(|e| format!("parse exchange response: {}", e))?;

    // ── Persist the device-key to ~/.safeclaw/device-key (0600) ──────────
    let key_path = device_key_path()?;
    write_device_key(&key_path, &parsed.device_key)?;

    // ── Persist active vault + cloud sync coordinates ────────────────────
    // The AGENT talks to the LOCAL daemon (active `custodian`), not the
    // cloud — the daemon brokers locally and only the daemon reaches the
    // cloud, for sealed-blob sync (Slice 3). So active custodian = the
    // localhost daemon URL, and we record `pro_backend_url` separately as
    // `cloud_backend` for the daemon's pull/push. Use the server-returned
    // pro_backend_url (source of truth) over the request custodian — they
    // normally match, but the server can canonicalize the host.
    let pro_backend_url = parsed.pro_backend_url.trim_end_matches('/').to_string();
    let daemon_port = std::env::var("SAFECLAW_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_DAEMON_PORT);
    let local_custodian = format!("http://127.0.0.1:{}", daemon_port);
    put_active_with_cloud(
        &local_custodian,
        &parsed.vault_id,
        &pro_backend_url,
        parsed.console_url.as_deref(),
    )
    .map_err(|e| format!("save active config: {}", e))?;

    eprintln!(
        "Paired to {} (vault {}); your agent talks to {}.",
        pro_backend_url, parsed.vault_id, local_custodian
    );
    if parsed.account_id != parsed.vault_id {
        eprintln!("  account: {}", parsed.account_id);
    }

    // Bring SafeClaw to a ready state right after pairing: start the daemon (so
    // it pulls this vault), then unlock via the single chokepoint — so the agent
    // never has to run a separate up/unlock and the user just taps a passkey.
    // Best-effort: pairing already succeeded; if bring-up can't run here (e.g. a
    // non-Linux host with no service manager), point the user at `sc up`.
    eprintln!("Starting SafeClaw and unlocking your vault…");
    if let Err(e) = crate::cli::service::run_start_systemd(false).await {
        eprintln!("  couldn't auto-start the daemon ({e}); run `sc up` to finish.");
        return Ok(());
    }
    if let Err(e) = crate::cli::up::ensure_unlocked().await {
        eprintln!("  couldn't auto-unlock ({e}); run `sc up` to finish.");
    }

    Ok(())
}

/// Loopback-exemption check for the HTTPS gate: `http://localhost[:PORT]`
/// and `http://127.0.0.1[:PORT]` (with optional trailing path) are allowed
/// without `--insecure-http` because the traffic never leaves the host. We
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
    std::fs::write(path, device_key)
        .map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort chmod — we don't fail the login if perms can't be
        // tightened on exotic filesystems.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
