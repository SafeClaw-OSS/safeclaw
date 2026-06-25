//! `sc up` — bring SafeClaw to a ready state: ensure the local daemon is
//! running, then make sure the vault is unlocked.
//!
//! Unlock is invisible by design. `ensure_unlocked` below is the ONLY place
//! `run_unlock` is invoked — `sc up` and `sc login` both route through it, and
//! everything else (an `sc upgrade` restart, the agent's lazy-start `sc up`)
//! goes through `sc up`. So the user never runs a separate "unlock" command and
//! never confuses the local vault state with the web console's unlock — they
//! just tap their passkey when SafeClaw asks.

use std::time::Duration;

use crate::cli::active::{resolve_active, settings_cb_port};
use crate::cli::status::{fetch_status, VaultState};
use crate::cli::{service, unlock};
use crate::config::UnlockArgs;

/// `sc up`: ensure the daemon is running, then ensure the vault is unlocked.
pub async fn run() -> Result<(), String> {
    service::run_ensure_running()?;
    ensure_unlocked().await
}

/// The single unlock chokepoint. If the active vault is Locked, run the passkey
/// unlock; otherwise no-op (already unlocked, or no vault selected). Waits
/// briefly for the daemon to finish pulling the vault on a fresh start.
/// Best-effort: an unreachable daemon just isn't unlocked here.
pub async fn ensure_unlocked() -> Result<(), String> {
    let (custodian, vault) = match resolve_active(None) {
        Ok(v) => v,
        Err(_) => return Ok(()), // nothing paired yet — nothing to unlock
    };

    // The daemon pulls the sealed vault on start; give it a moment to serve.
    let mut status = fetch_status(&custodian, &vault).await;
    for _ in 0..15 {
        if !matches!(status.state, VaultState::Unreachable | VaultState::NotFound) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        status = fetch_status(&custodian, &vault).await;
    }

    if matches!(status.state, VaultState::Locked { .. }) {
        let args = UnlockArgs {
            vault: None,
            no_browser: false,
            cb_port: settings_cb_port(),
            timeout: 120,
        };
        unlock::run_unlock(args).await?;
    }
    Ok(())
}
