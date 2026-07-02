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
    let (relay_url, auth_token) = match resolve_relay(&state) {
        Some(v) => v,
        None => return, // local-only daemon (no cloud pairing); nothing to do
    };
    tokio::spawn(async move {
        if let Err(e) = run(state, &relay_url, &auth_token, &vault_id, &op_id, &op, &r, expires_at).await {
            tracing::warn!(op = %op_id, "relay register/poll ended: {}", e);
        }
    });
}

/// Fire-and-forget: withdraw a still-pending op from the relay (device-key
/// auth). Called when a new ceremony op supersedes a stale one — the requester
/// voids its OWN prior request. No passkey/W_c involved (nothing was granted).
/// The backend only flips `pending → cancelled`, so an already-approved op is
/// untouched. No-op when there's no cloud relay configured.
pub fn spawn_cancel(state: Arc<AppState>, vault_id: String, op_id: String) {
    let (base, auth_token) = match resolve_relay(&state) {
        Some(v) => v,
        None => return,
    };
    let daemon_pubkey = URL_SAFE_NO_PAD.encode(state.sc.pk_bytes());
    tokio::spawn(async move {
        let url = format!("{}/v/{}/op/relay/{}/cancel", base, vault_id, op_id);
        let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
            Ok(c) => c,
            Err(_) => return,
        };
        match client
            .post(&url)
            .bearer_auth(&auth_token)
            .json(&json!({ "daemon_pubkey": daemon_pubkey }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                tracing::info!(op = %op_id, "superseded op withdrawn from relay");
            }
            Ok(r) => tracing::debug!(op = %op_id, "relay cancel HTTP {}", r.status()),
            Err(e) => tracing::debug!(op = %op_id, "relay cancel error: {}", e),
        }
    });
}

/// Resolve `(relay_base, auth_token)` for op-relay registration.
///
/// Primary (the local-daemon pivot): a paired daemon dials its cloud backend
/// (`cloud_backend`, persisted at `sc login`) and authenticates as itself with
/// the `sc_device_` device-key — exactly the channel the Slice-3 blob sync
/// already uses. Backend gate: `resolveAuth` + `isOwnedVaultId`.
///
/// Fallback: an operator-supplied `SAFECLAW_RELAY_URL` + `SAFECLAW_ADMIN_KEY`
/// (self-host / SaaS-custodian deployments that pre-date pairing).
///
/// `None` ⇒ no relay ⇒ purely local daemon; the local op-page ceremony stands.
fn resolve_relay(state: &AppState) -> Option<(String, String)> {
    if let Ok(cfg) = crate::cli::active::load() {
        if let Some(base) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) {
            if let Some(dk) = crate::sync::device_key() {
                return Some((base.trim_end_matches('/').to_string(), dk));
            }
        }
    }
    let base = state.config.relay_url.clone().filter(|s| !s.is_empty())?;
    let key = state.config.admin_key.clone().filter(|s| !s.is_empty())?;
    Some((base.trim_end_matches('/').to_string(), key))
}

async fn run(
    state: Arc<AppState>,
    relay_url: &str,
    auth_token: &str,
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
    //    We also include the vault's passkey public material (cid + prf_salt)
    //    so the browser — which can't reach this localhost daemon's
    //    /v/{vid}/passkeys — can pick the credential and derive W_c. cid and
    //    prf_salt are public per PROTOCOL.md §4.3.
    let daemon_pubkey = URL_SAFE_NO_PAD.encode(state.sc.pk_bytes());
    let op_summary = STANDARD.encode(serde_json::to_vec(op).unwrap_or_default());
    let passkeys = fetch_passkeys(&client, state.config.port, vault_id).await;
    let reg_url = format!("{}/v/{}/op/relay/register", base, vault_id);
    let reg = client
        .post(&reg_url)
        .bearer_auth(auth_token)
        .json(&json!({
            "op_id": op_id,
            "daemon_pubkey": daemon_pubkey,
            "op_summary": op_summary,
            "passkeys": passkeys,
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
        let resp = match client.get(&poll_url).bearer_auth(auth_token).send().await {
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
            409 => {
                // Cancelled: the requester (this daemon, via a superseding op)
                // withdrew it. Stop polling — nothing more will arrive.
                tracing::info!(op = %op_id, "relay op cancelled by requester; poll stopping");
                return Ok(());
            }
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

/// Loopback-fetch the vault's passkey public material (cid + prf_salt + pubkey)
/// so the relay can hand it to the browser. Returns `[]` on any failure — the
/// page then reports "no passkeys" rather than the whole op failing.
async fn fetch_passkeys(client: &reqwest::Client, port: u16, vault_id: &str) -> Value {
    let url = format!("http://127.0.0.1:{}/v/{}/passkeys", port, vault_id);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => v.get("passkeys").cloned().unwrap_or_else(|| json!([])),
            Err(_) => json!([]),
        },
        _ => json!([]),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
