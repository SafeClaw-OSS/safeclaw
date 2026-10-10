//! `sc login` — pair this machine by admit-by-code (trust-reset design D2,
//! contract 5 / 8.1).
//!
//!   1. Mint a fresh device pair: DIK (`dv_`) + enc key. A machine already
//!      paired (its DIK still recognized by the server) is refused: run
//!      `sc logout` first. A pre-trust-reset `dev_` identity counts as absent.
//!   2. Mint the code, `POST /admit`, print `{console}/admit` and the code.
//!   3. Poll; verify the approval's mac under the code and that its effect is
//!      the ledger admit of THIS pair ([`crate::cli::admit`]).
//!   4. Ask "Pair to <email> (<us_>)? [y/N]" (warning if the person differs
//!      from the previous pairing), then persist the keys and pin the person
//!      anchor (`us_` + UIK sign pub). Nothing is written before the confirm.

use crate::cli::active::put_cloud_coords;
use crate::cli::admit::{
    confirm, device_fields, person_change_warning, post_and_wait, require_confirmable,
    require_https, resolve_target,
};
use crate::config::LoginArgs;
use crate::crypto::admission::AdmitCode;

/// Default daemon control-plane port (matches `ServeArgs` `SAFECLAW_PORT`).
const DEFAULT_DAEMON_PORT: u16 = crate::config::CONTROL_PORT;

pub async fn run(args: LoginArgs) -> Result<(), String> {
    // Fail fast when the account can't be confirmed (no terminal, no --yes):
    // before any key is minted or any admission is posted.
    require_confirmable("sc login", args.yes)?;
    let target = resolve_target(args.profile.as_deref())?;
    require_https(&target.backend, args.insecure)?;

    refuse_if_already_paired().await?;

    let device_name = args
        .device_name
        .clone()
        .or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "agent-device".to_string());

    // Fresh keys every pairing: a device is its key pair, and re-pairing makes
    // a new one (design D4). Persisted only after the confirm below.
    let minted = crate::device::MintedDevice::generate();
    let fields = device_fields(minted.sig_pub(), minted.enc_pub(), &device_name);
    let code = AdmitCode::generate();
    let approved = post_and_wait(&target, &fields, &code, "this machine").await?;

    let previous = crate::cli::active::load()
        .ok()
        .and_then(|c| c.last_paired_person);
    if let Some(w) = person_change_warning(previous.as_deref(), &approved.us) {
        eprintln!();
        eprintln!("{}", w);
    }
    eprintln!();
    if !confirm(
        &format!("Pair to {} ({})?", approved.email, approved.us),
        args.yes,
    )? {
        return Err(
            "not paired: you declined the account. Nothing was saved; revoke the \
             new device in the console if it shows up there."
                .into(),
        );
    }

    minted.persist()?;
    let daemon_port = std::env::var("SAFECLAW_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_DAEMON_PORT);
    let local_daemon = format!("http://127.0.0.1:{}", daemon_port);
    put_cloud_coords(
        &local_daemon,
        &target.backend,
        Some(&target.console),
        &approved.us,
        &approved.uik_sign_pub,
        &approved.email,
    )
    .map_err(|e| format!("save config: {}", e))?;

    eprintln!(
        "Paired this machine ({}) to {} ({}).",
        minted.id(),
        approved.email,
        approved.us
    );

    // Bring SafeClaw to a ready state: restart (a running daemon must reload the
    // new identity and pairing) or install + start, then unlock.
    eprintln!("Starting SafeClaw…");
    if crate::cli::service::unit_installed() {
        if let Err(e) = crate::cli::up::restart().await {
            eprintln!("  couldn't finish bring-up ({e}); run `sc up` to finish.");
        }
    } else {
        if let Err(e) = crate::cli::service::run_start_systemd(false).await {
            eprintln!("  couldn't auto-start the daemon ({e}); run `sc up` to finish.");
            return Ok(());
        }
        if let Err(e) = crate::cli::up::ensure_unlocked().await {
            eprintln!("  couldn't auto-unlock ({e}); run `sc up` to finish.");
        }
    }
    Ok(())
}

/// A machine whose device identity the server still recognizes (not revoked)
/// is already paired: pairing again would need a fresh device, so say how.
async fn refuse_if_already_paired() -> Result<(), String> {
    let Some(device) = crate::device::load_optional()? else {
        return Ok(());
    };
    let Ok(base) = crate::cloud::configured_backend() else {
        return Ok(());
    };
    let client = crate::cloud::DeviceClient::new(base, device);
    let Ok(resp) = client
        .get("/device/me", std::time::Duration::from_secs(10))
        .await
    else {
        return Ok(()); // unreachable: pairing will surface the network error
    };
    if !resp.status().is_success() {
        return Ok(()); // unknown / revoked / signed out: pair fresh
    }
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if body
        .get("revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(());
    }
    Err(format!(
        "this machine is already paired to {} ({}). Run `sc logout` first to pair it again.",
        body.get("account_email")
            .and_then(|v| v.as_str())
            .unwrap_or("your account"),
        body.get("person").and_then(|v| v.as_str()).unwrap_or("?"),
    ))
}
