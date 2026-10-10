//! `sc logout` — unpair this machine (trust-reset contract 5).
//!
//!   1. `POST /device/self-revoke`, signed by the DIK, FIRST: it needs the key
//!      we are about to delete. The server stops serving this device; the
//!      device stays in the person's ledger until a passkey signs its revoke in
//!      the console (only the person's UIK can write the ledger).
//!   2. Delete the DIK and the enc key (the device pair).
//!   3. Stop the daemon (it drops K and stops syncing), wipe the local sealed
//!      vault state, and clear the pairing from the config.
//!   4. Say how to finish: "Revoke it in the console to remove it from your
//!      ledger".
//!
//! The self-revoke is best-effort: offline, or a device the server no longer
//! knows, must not leave the keys on disk. The local wipe always happens.
//!
//! Not touched: an agent's `SAFECLAW_*` env in the user's own files (theirs to
//! edit), and the agent identities under `~/.safeclaw/agents/`.

use crate::config::LogoutArgs;

/// Outcome of the server-side self-revoke.
#[derive(Debug, PartialEq, Eq)]
pub enum SelfRevoke {
    Done,
    NotPaired,
    Failed(String),
}

pub async fn run(_args: LogoutArgs) -> Result<(), String> {
    let device = crate::device::load_optional().unwrap_or(None);
    let device_id = device.as_ref().map(|d| d.id().to_string());

    // 1. Self-revoke while we still hold the DIK.
    let revoke = match device {
        None => SelfRevoke::NotPaired,
        Some(device) => match crate::cloud::configured_backend() {
            Err(_) => SelfRevoke::NotPaired,
            Ok(base) => self_revoke(&crate::cloud::DeviceClient::new(base, device)).await,
        },
    };
    match &revoke {
        SelfRevoke::Done => eprintln!("Signed this device out of SafeClaw."),
        SelfRevoke::NotPaired => {}
        SelfRevoke::Failed(e) => {
            eprintln!("  couldn't reach SafeClaw to sign this device out ({e}); deleting its keys anyway.")
        }
    }

    // 2. Delete the device pair.
    crate::device::wipe()?;

    // 3. Stop the daemon, wipe local vault state, clear the pairing.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = crate::cli::service::run_stop();
    }
    let vaults_dir = crate::config::default_state_dir().join("vaults");
    if vaults_dir.exists() {
        let _ = std::fs::remove_dir_all(&vaults_dir);
    }
    crate::cli::active::clear_pairing()?;

    // 4. How to finish.
    match device_id {
        Some(id) => {
            eprintln!("Deleted this device's keys ({id}) and stopped SafeClaw here.");
            eprintln!("Revoke it in the console to remove it from your ledger.");
        }
        None => eprintln!("This machine had no device identity; cleared any local pairing."),
    }
    eprintln!();
    eprintln!("  Agents on this machine keep their identity files; remove one with");
    eprintln!("  `sc agent rm <name>`. Pair again with `sc login`.");
    Ok(())
}

/// `POST /device/self-revoke` (contract 8.4).
pub async fn self_revoke(client: &crate::cloud::DeviceClient) -> SelfRevoke {
    let resp = match client
        .post(
            "/device/self-revoke",
            &serde_json::json!({}),
            std::time::Duration::from_secs(15),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return SelfRevoke::Failed(e),
    };
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        return SelfRevoke::Done;
    }
    // Unknown to the server (401) or already revoked (403): nothing to sign out.
    if status == 401 || status == 403 {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        return match crate::cloud::refusal(status, &body) {
            Some(crate::cloud::Refusal::UpgradeRequired) => {
                SelfRevoke::Failed(crate::cloud::Refusal::UpgradeRequired.message())
            }
            _ => SelfRevoke::NotPaired,
        };
    }
    SelfRevoke::Failed(crate::cloud::error_text(resp, "self-revoke").await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::HeaderMap, http::StatusCode, routing::post, Json, Router};

    /// A fake backend answering `POST /device/self-revoke` with `status` and
    /// `body`; it 400s a request that is not DIK-signed by `dv`.
    async fn backend(status: u16, body: serde_json::Value, dv: String) -> String {
        let app = Router::new().route(
            "/device/self-revoke",
            post(move |h: HeaderMap| {
                let body = body.clone();
                let dv = dv.clone();
                async move {
                    let signed = h
                        .get(crate::device_auth::HDR_DEVICE_ID)
                        .map(|v| v.as_bytes())
                        == Some(dv.as_bytes())
                        && h.contains_key(crate::device_auth::HDR_DEVICE_SIG)
                        && h.contains_key(crate::device_auth::HDR_DEVICE_TS)
                        && h.contains_key(crate::cloud::HDR_VERSION);
                    if !signed {
                        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
                    }
                    (StatusCode::from_u16(status).unwrap(), Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{}", addr)
    }

    fn client(base: String) -> crate::cloud::DeviceClient {
        crate::cloud::DeviceClient::new(base, crate::device::tests_support::device(0x61))
    }

    /// `sc logout` signs the self-revoke with the DIK it is about to delete;
    /// an unknown or already revoked device has nothing to sign out, and an
    /// upgrade refusal is reported (the keys are deleted either way).
    #[tokio::test]
    async fn self_revoke_is_signed_and_its_refusals_classified() {
        let dv = crate::device::tests_support::device(0x61).id().to_string();
        let ok = backend(200, serde_json::json!({"ok": true}), dv.clone()).await;
        assert_eq!(self_revoke(&client(ok)).await, SelfRevoke::Done);

        let unknown = backend(
            401,
            serde_json::json!({"error": "unknown_device"}),
            dv.clone(),
        )
        .await;
        assert_eq!(self_revoke(&client(unknown)).await, SelfRevoke::NotPaired);

        let revoked = backend(
            403,
            serde_json::json!({"code": "SC_DEVICE_REVOKED"}),
            dv.clone(),
        )
        .await;
        assert_eq!(self_revoke(&client(revoked)).await, SelfRevoke::NotPaired);

        let old = backend(
            403,
            serde_json::json!({"code": "SC_UPGRADE_REQUIRED"}),
            dv.clone(),
        )
        .await;
        match self_revoke(&client(old)).await {
            SelfRevoke::Failed(m) => assert!(m.contains("sc upgrade"), "{m}"),
            other => panic!("{other:?}"),
        }

        let down = backend(500, serde_json::json!({"message": "boom"}), dv).await;
        assert!(matches!(
            self_revoke(&client(down)).await,
            SelfRevoke::Failed(_)
        ));
    }
}
