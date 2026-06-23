//! op-relay egress client: register an op, poll for the deposited grant, and
//! apply it locally. See `relay/mod.rs` for the why.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use serde_json::{json, Value};

use crate::state::AppState;

/// Poll cadence + safety cap. The relay also enforces a TTL; this is the
/// daemon-side bound so a never-approved op's task can't run forever.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_POLLS: u32 = 200; // 200 × 2s ≈ 400s, just past the 300s op TTL

/// Fire-and-forget: register `op_id` with the relay and drive it to
/// completion in a background task. No-op (returns immediately) when no relay
/// is configured. Never blocks op creation; all failures are logged, not
/// propagated — the local path still works without the relay.
pub fn spawn_register_and_poll(
    state: Arc<AppState>,
    vault_id: String,
    op_id: String,
    op: Value,
    r: String,
    expires_at: u64,
) {
    let relay_url = match state.config.relay_url.clone() {
        Some(u) if !u.is_empty() => u,
        _ => return, // local-only daemon; nothing to do
    };
    let admin_key = match state.config.admin_key.clone() {
        Some(k) if !k.is_empty() => k,
        _ => {
            tracing::warn!(op = %op_id, "relay configured but SAFECLAW_ADMIN_KEY unset — skipping relay registration");
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = run(state, &relay_url, &admin_key, &vault_id, &op_id, &op, &r, expires_at).await {
            tracing::warn!(op = %op_id, "relay register/poll ended: {}", e);
        }
    });
}

async fn run(
    state: Arc<AppState>,
    relay_url: &str,
    admin_key: &str,
    vault_id: &str,
    op_id: &str,
    op: &Value,
    r: &str,
    expires_at: u64,
) -> Result<(), String> {
    let base = relay_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(35))
        .build()
        .map_err(|e| format!("relay client init: {}", e))?;

    // 1. Register the pending op. op_summary is the full op JSON (the page
    //    renders it AND uses it + r to recompute the WebAuthn binding β).
    let daemon_pubkey = URL_SAFE_NO_PAD.encode(state.sc.pk_bytes());
    let op_summary = STANDARD.encode(serde_json::to_vec(op).unwrap_or_default());
    let reg_url = format!("{}/v/{}/op/relay/register", base, vault_id);
    let reg = client
        .post(&reg_url)
        .bearer_auth(admin_key)
        .json(&json!({
            "op_id": op_id,
            "daemon_pubkey": daemon_pubkey,
            "op_summary": op_summary,
            "r": r,
            "expires_at": expires_at,
        }))
        .send()
        .await
        .map_err(|e| format!("relay register: {}", e))?;
    if !reg.status().is_success() {
        return Err(format!("relay register HTTP {}", reg.status()));
    }
    tracing::info!(op = %op_id, "registered with op-relay");

    // 2. Poll for the deposited grant.
    let poll_url = format!("{}/v/{}/op/relay/{}", base, vault_id, op_id);
    for _ in 0..MAX_POLLS {
        if now() > expires_at + 5 {
            return Ok(()); // op expired; stop quietly
        }
        let resp = match client.get(&poll_url).bearer_auth(admin_key).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(op = %op_id, "relay poll transient error: {}", e);
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };
        match resp.status().as_u16() {
            200 => {
                // Approved: body carries the browser-deposited grant JSON.
                let body: Value = resp.json().await.map_err(|e| format!("relay poll parse: {}", e))?;
                let grant = body.get("sealed_grant").cloned().unwrap_or(body);
                apply_grant(state.clone(), op_id, grant).await?;
                return Ok(());
            }
            403 => {
                // Rejected by the user.
                apply_reject(state.clone(), op_id).await;
                return Ok(());
            }
            202 => {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            404 => return Ok(()), // unknown/expired on the relay side
            other => {
                tracing::debug!(op = %op_id, "relay poll HTTP {}", other);
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }
    Ok(())
}

/// Apply a relay-fetched grant by replaying it through the daemon's own
/// `/op/{id}/approve` endpoint over localhost. This reuses the full approve
/// path (incl. the §4.2 W_c unseal) verbatim — no logic is duplicated.
async fn apply_grant(state: Arc<AppState>, op_id: &str, grant: Value) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("loopback client init: {}", e))?;
    let url = format!("http://127.0.0.1:{}/op/{}/approve", state.config.port, op_id);
    let resp = client
        .post(&url)
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("loopback approve: {}", e))?;
    let status = resp.status();
    if status.is_success() {
        tracing::info!(op = %op_id, "relay grant applied via loopback approve");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("loopback approve HTTP {}: {}", status, body))
    }
}

async fn apply_reject(state: Arc<AppState>, op_id: &str) {
    let url = format!("http://127.0.0.1:{}/op/{}/reject", state.config.port, op_id);
    if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
        let _ = client.post(&url).send().await;
        tracing::info!(op = %op_id, "relay grant rejected via loopback");
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
