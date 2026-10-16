//! op-relay egress client: register an op, poll for the deposited grant, and
//! apply it locally. See `relay/mod.rs` for the why.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::device_auth::DikRequestExt;
use crate::state::AppState;

/// Poll cadence (v1.1, mode-dependent). The wait between polls is
/// `timeout(interval, op-event notify)`: the SSE `op` event ACCELERATES the
/// next poll, it never replaces it — the poll response stays the source of
/// truth for status. 15s only with PROOF the event can reach us —
/// `op_events_for(vid)`: this vid is on the live stream AND the backend
/// declared the `op` cap in hello. Anything short of proof (stream down,
/// vault born after daemon start, over the vid cap, v1-only backend) keeps
/// the legacy 2s cadence — an approval must never silently wait out a
/// relaxed poll for an event that cannot arrive.
const POLL_STREAMED: Duration = Duration::from_secs(15);
const POLL_FALLBACK: Duration = Duration::from_secs(2);
/// ★ Storm floor: an event wake never polls sooner than this after the
/// previous poll — events accelerate the poll, they don't replace its
/// pacing (a buggy emitter must cost ≤1 poll/s, not RTT-speed; same rule
/// as the ledger's on-miss re-pull debounce).
const POLL_FLOOR: Duration = Duration::from_secs(1);
/// Daemon-side safety cap so a never-approved op's task can't run forever
/// (the relay also enforces a TTL). Derived per-op from the op's own expiry
/// (SSOT: aux.policy.timeout stamps every pending op) + slack past the
/// in-loop `expires_at + 5` precise stop; clamped so a pathological expiry
/// can neither stop the poll instantly nor pin a task for days.
fn poll_budget(expires_at: u64) -> Duration {
    Duration::from_secs(expires_at.saturating_sub(now()).clamp(60, 86_400) + 60)
}

/// Interval selection, factored for the unit test.
fn poll_interval(op_events_reach_us: bool) -> Duration {
    if op_events_reach_us {
        POLL_STREAMED
    } else {
        POLL_FALLBACK
    }
}

/// Park until the next poll is due: an `op` stream event for OUR op_id or
/// the mode-sized interval, whichever first — then honor the storm floor
/// relative to the LAST poll. `notify_one` parks a permit, so an event that
/// fires while a poll response is in flight completes the next wait
/// instantly instead of being lost.
async fn next_poll_due(
    op_wait: &crate::sync_stream::OpWaitGuard<'_>,
    vault_id: &str,
    last_poll: tokio::time::Instant,
) {
    let interval = poll_interval(crate::sync_stream::op_events_for(vault_id));
    let _ = tokio::time::timeout(interval, op_wait.notified()).await;
    // Past deadlines return immediately — the floor only bites event storms.
    tokio::time::sleep_until(last_poll + POLL_FLOOR).await;
}

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
    // The triggering agent's id (api-key prefix / AIK id), forwarded to the
    // relay so the approve page can name WHO asked. None for user-initiated
    // lifecycle ceremonies (unlock/lock/delete).
    agent_id: Option<String>,
    // The live ops this op just superseded in its intent chain
    // (design/approvals-inbox.md D1). The backend marks exactly these ids;
    // it never supersedes by key match. Empty for everything but `use`.
    supersedes: Vec<String>,
) {
    let (relay_url, auth_token) = match resolve_relay(&state) {
        Some(v) => v,
        None => return, // local-only daemon (no cloud pairing); nothing to do
    };
    tokio::spawn(async move {
        if let Err(e) = run(
            state,
            &relay_url,
            &auth_token,
            &vault_id,
            &op_id,
            &op,
            &r,
            expires_at,
            agent_id.as_deref(),
            &supersedes,
        )
        .await
        {
            tracing::warn!(op = %op_id, "relay register/poll ended: {}", e);
        }
    });
}

/// Why a relay row is withdrawn (contract §2 cancel body `reason`). `None` at
/// the call site = the legacy reason-less cancel (lifecycle supersede).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelReason {
    /// Another op of the same intent chain applied.
    Satisfied { by: String },
    /// The user rejected another op of the same intent chain.
    Rejected,
    /// The requester withdrew its own op (`POST /op/{id}/cancel`).
    Withdrawn,
    /// The Export waiter stopped polling (E1 liveness backstop).
    Abandoned,
}

impl CancelReason {
    fn as_str(&self) -> &'static str {
        match self {
            CancelReason::Satisfied { .. } => "satisfied",
            CancelReason::Rejected => "rejected",
            CancelReason::Withdrawn => "withdrawn",
            CancelReason::Abandoned => "abandoned",
        }
    }
}

/// The relay cancel body: `daemon_pubkey` as before, plus `reason` and (for
/// `satisfied`) `satisfied_by`. A reason-less cancel sends neither, so the
/// backend stores null and behaves as today.
fn cancel_body(daemon_pubkey: &str, reason: Option<&CancelReason>) -> Value {
    let mut body = json!({ "daemon_pubkey": daemon_pubkey });
    if let Some(r) = reason {
        body["reason"] = json!(r.as_str());
        if let CancelReason::Satisfied { by } = r {
            body["satisfied_by"] = json!(by);
        }
    }
    body
}

/// Fire-and-forget: withdraw a still-pending op from the relay (device-key
/// auth). Called when the requester voids its OWN request (a superseding
/// ceremony, `POST /op/{id}/cancel`, an abandoned Export) or when an intent
/// chain resolves its siblings. No passkey/W_c involved (nothing was granted).
/// The backend only flips `pending → cancelled`, so an already-approved op is
/// untouched. No-op when there's no cloud relay configured.
pub fn spawn_cancel(
    state: Arc<AppState>,
    vault_id: String,
    op_id: String,
    reason: Option<CancelReason>,
) {
    let (base, auth_token) = match resolve_relay(&state) {
        Some(v) => v,
        None => return,
    };
    let daemon_pubkey = URL_SAFE_NO_PAD.encode(state.sc.pk_bytes());
    tokio::spawn(async move {
        let url = format!("{}/v/{}/op/relay/{}/cancel", base, vault_id, op_id);
        let client = match crate::cli::egress_proxy::client(Duration::from_secs(10)) {
            Ok(c) => c,
            Err(_) => return,
        };
        let cancel_body = cancel_body(&daemon_pubkey, reason.as_ref());
        match client
            .post(&url)
            .bearer_auth(&auth_token)
            .dik_pop(
                "POST",
                &url,
                &serde_json::to_vec(&cancel_body).unwrap_or_default(),
            )
            .json(&cancel_body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                tracing::info!(op = %op_id, "op withdrawn from relay");
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
    agent_id: Option<&str>,
    supersedes: &[String],
) -> Result<(), String> {
    let base = relay_url.trim_end_matches('/');
    // v1.1: register for `op` stream events before anything can flip the
    // op's status. The guard IS the registration — Drop deregisters — so
    // EVERY exit path out of this function (the early error returns below
    // included) removes the entry; a leak here would grow the daemon-global
    // map for the daemon's lifetime.
    let op_wait = crate::sync_stream::op_events().register(op_id);
    let client = crate::cli::egress_proxy::client(Duration::from_secs(35))
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
    let base_body = json!({
        "op_id": op_id,
        "daemon_pubkey": daemon_pubkey,
        "op_summary": op_summary,
        "passkeys": passkeys,
        "r": r,
        "expires_at": expires_at,
        // Batch-approve capability advertisement (design/batch-approve.md
        // §Version gating): the console offers "Approve all xN" only when
        // every op in a group carries a supporting version. Relay-asserted
        // and deliberately UNAUTHENTICATED - forging it down forces per-op
        // fallback (UX cost only); forging it up buys nothing the relay's
        // existing bare-403 reject power doesn't already have.
        "daemon_version": env!("CARGO_PKG_VERSION"),
        // WHO triggered this op — the agent the local broker authenticated.
        // Advisory attribution for the approve page (the backend resolves it to
        // a label); null for user-initiated lifecycle ceremonies.
        "agent_id": agent_id,
    });
    let reg_body = register_body(&state, &base_body, op_id, supersedes);
    let reg = client
        .post(&reg_url)
        .bearer_auth(auth_token)
        .dik_pop(
            "POST",
            &reg_url,
            &serde_json::to_vec(&reg_body).unwrap_or_default(),
        )
        .json(&reg_body)
        .send()
        .await
        .map_err(|e| format!("relay register: {}", e))?;
    if !reg.status().is_success() {
        let status = reg.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            crate::sync_stream::notify_device_auth_rejected();
        }
        let body = reg.bytes().await.unwrap_or_default();
        if let Some(crate::sync::VaultRefusal::AccessRevoked { membership }) =
            crate::sync::vault_refusal(status, &body)
        {
            crate::sync::revoke_vault_access(&state, vault_id, membership).await;
            apply_reject(
                state.clone(),
                op_id,
                Some(crate::error::VAULT_ACCESS_REVOKED_MSG),
            )
            .await;
            return Ok(());
        }
        return Err(format!("relay register HTTP {}", status));
    }
    tracing::info!(op = %op_id, "registered with op-relay");

    // 2. Poll for the deposited grant. Status semantics are UNCHANGED from
    //    the pre-event loop — only the wait between polls is event-aware.
    let poll_url = format!("{}/v/{}/op/relay/{}", base, vault_id, op_id);
    let deadline = tokio::time::Instant::now() + poll_budget(expires_at);
    // Full-body hash of the last grant refused RECOVERABLY (it failed BATCH
    // verification, or its signer may not approve this op): skip
    // re-applying a byte-identical redelivery in the gap before our
    // re-register flips the relay row back to pending. Full body, not the
    // assertion: a same-set retry has the same root and a deterministic
    // authenticator may repeat the assertion byte-for-byte — what guarantees
    // an honest retry differs is the fresh HPKE ephemeral in wk_enc/wk_ct
    // (or k_enc/k_ct, an admin's delivered vault key).
    let mut last_batch_failed: Option<[u8; 32]> = None;
    while tokio::time::Instant::now() < deadline {
        if now() > expires_at + 5 {
            return Ok(()); // op expired; stop quietly
        }
        let last_poll = tokio::time::Instant::now();
        let resp = match client
            .get(&poll_url)
            .bearer_auth(auth_token)
            .dik_pop("GET", &poll_url, &[])
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(op = %op_id, "relay poll transient error: {}", e);
                next_poll_due(&op_wait, vault_id, last_poll).await;
                continue;
            }
        };
        match resp.status().as_u16() {
            200 => {
                // Approved: body carries the browser-deposited grant JSON.
                let body: Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("relay poll parse: {}", e))?;
                let grant = body.get("sealed_grant").cloned().unwrap_or(body);
                let grant_hash: [u8; 32] =
                    Sha256::digest(serde_json::to_vec(&grant).unwrap_or_default()).into();
                if last_batch_failed == Some(grant_hash) {
                    // Same bad batch grant re-served before our re-register
                    // landed — wait, don't spin (and don't march fail_count).
                    next_poll_due(&op_wait, vault_id, last_poll).await;
                    continue;
                }
                // Already resolved locally (an intent-chain sibling applied or
                // the user rejected the chain, design/approvals-inbox.md D1):
                // a late grant for it ends the poll quietly — no reject, no
                // "approved but apply failed" audit row.
                if resolved_locally(&state, op_id) {
                    tracing::info!(op = %op_id, "grant arrived for an op already resolved locally; poll ending");
                    return Ok(());
                }
                if let Err(e) = apply_grant(state.clone(), op_id, grant).await {
                    // Lost the race (a second grant for one chain, or a
                    // sibling resolved it mid-apply): the 409 is not a
                    // failure of THIS approval — end quietly.
                    if resolved_locally(&state, op_id) {
                        tracing::info!(op = %op_id, "op resolved locally while its grant applied; poll ending");
                        return Ok(());
                    }
                    if e.batch_verify_failed || e.approver_not_authorized {
                        // RECOVERABLE (design/batch-approve.md §Daemon verify
                        // 7): never reject a user-approved op over a failed
                        // BATCH rebuild (daemon restart, version skew,
                        // tampered rows). Re-register the op — the register
                        // upsert resets the relay row to `pending`, making a
                        // fresh per-op deposit possible again (deposits are
                        // first-write-wins, so without this reset no retry
                        // could ever land) — and keep polling until the op's
                        // own expiry.
                        // Same recovery for a grant whose signer is neither the
                        // requester nor a vault admin: another member's tap must
                        // never resolve (or burn) the op; reset it to pending so
                        // the requester or an admin can still approve it.
                        last_batch_failed = Some(grant_hash);
                        if e.approver_not_authorized {
                            tracing::warn!(op = %op_id, "grant refused, approver not authorized ({}); re-registering op so the requester or a vault admin can approve", e.detail);
                        } else {
                            tracing::warn!(op = %op_id, "batch grant failed verification ({}); re-registering op so per-op approval works again", e.detail);
                        }
                        // Recovery re-register: `supersedes: []` (nothing was
                        // just marked), the op's CURRENT superseded_by.
                        let reg_body = register_body(&state, &base_body, op_id, &[]);
                        let rr = client
                            .post(&reg_url)
                            .bearer_auth(auth_token)
                            .dik_pop(
                                "POST",
                                &reg_url,
                                &serde_json::to_vec(&reg_body).unwrap_or_default(),
                            )
                            .json(&reg_body)
                            .send()
                            .await;
                        match rr {
                            Ok(r) if r.status().is_success() => {
                                tracing::info!(op = %op_id, "op re-registered as pending after a recoverable grant refusal");
                            }
                            Ok(r) => {
                                tracing::warn!(op = %op_id, "re-register after a refused grant: HTTP {}", r.status());
                            }
                            Err(err) => {
                                tracing::warn!(op = %op_id, "re-register after a refused grant: {}", err);
                            }
                        }
                        next_poll_due(&op_wait, vault_id, last_poll).await;
                        continue;
                    }
                    let e = e.detail;
                    // The human APPROVED but the daemon can't apply this grant.
                    // The canonical cause now is a tapped passkey that isn't in
                    // THIS vault's keyset ("unknown credential"), after the approve
                    // path's self-heal re-pull still couldn't resolve it. Record the
                    // reason locally, then REJECT the op so `sc unlock` / `sc op
                    // wait` returns a definitive, actionable error. Ending the poll
                    // with Err instead (the old behavior) left the relay op
                    // 'approved' and hung the CLI forever on "Waiting for approval".
                    if let Ok(audit) = state.audits.for_vault(vault_id) {
                        let _ = audit.finalize(
                            op_id,
                            crate::audit::STATUS_EXPIRED,
                            now() as i64,
                            None,
                            Some(&format!("approved but apply failed: {}", e)),
                            None,
                        );
                    }
                    tracing::warn!(op = %op_id, "approved grant could not be applied ({}); rejecting so the CLI fails clearly instead of hanging", e);
                    // Carry the REAL cause: this is an apply failure after a
                    // genuine user approval, and must never read back as
                    // a human "no" (it did, and misled approver and agent).
                    apply_reject(
                        state.clone(),
                        op_id,
                        Some(&format!("approved, but applying it failed: {}", e)),
                    )
                    .await;
                    return Ok(());
                }
                return Ok(());
            }
            403 => {
                // ONLY the backend's explicit user-rejection body is a human
                // "no" — and a user rejection now resolves the whole intent
                // chain (design/approvals-inbox.md D1). Any other 403 (tier
                // gate, vault mismatch, key binding, …) is an auth/routing
                // refusal of THIS poll: end it without rejecting anything; the
                // op stays pending locally until its own expiry.
                let body = resp.text().await.unwrap_or_default();
                if let Some(crate::sync::VaultRefusal::AccessRevoked { membership }) =
                    crate::sync::vault_refusal(reqwest::StatusCode::FORBIDDEN, body.as_bytes())
                {
                    crate::sync::revoke_vault_access(&state, vault_id, membership).await;
                    apply_reject(
                        state.clone(),
                        op_id,
                        Some(crate::error::VAULT_ACCESS_REVOKED_MSG),
                    )
                    .await;
                } else if is_user_rejection(&body) {
                    apply_reject(state.clone(), op_id, None).await;
                } else {
                    tracing::warn!(op = %op_id, "relay poll refused (HTTP 403, not a user rejection): {}; poll ending, op left pending", body.chars().take(200).collect::<String>());
                }
                return Ok(());
            }
            202 => {
                next_poll_due(&op_wait, vault_id, last_poll).await;
            }
            401 => {
                crate::sync_stream::notify_device_auth_rejected();
                return Ok(());
            }
            404 => return Ok(()), // unknown/expired on the relay side
            409 => {
                // Cancelled: this daemon withdrew it (a superseding ceremony, a
                // requester cancel, an abandoned Export, or its intent chain
                // resolved). Stop polling — nothing more will arrive.
                tracing::info!(op = %op_id, "relay op cancelled by requester; poll stopping");
                return Ok(());
            }
            other => {
                tracing::debug!(op = %op_id, "relay poll HTTP {}", other);
                next_poll_due(&op_wait, vault_id, last_poll).await;
            }
        }
    }
    Ok(())
}

/// The register body: the op's static fields plus the intent-chain state the
/// backend mirrors (design/approvals-inbox.md D1, contract §2): this
/// process's `boot_id`, the ids this op just superseded, and the op's CURRENT
/// `superseded_by` + `retry_count` read from the store at send time (register
/// tasks can land out of order; the backend applies pointers monotonically).
fn register_body(state: &AppState, base: &Value, op_id: &str, supersedes: &[String]) -> Value {
    let (superseded_by, retry_count) = {
        let store = state.approvals.lock().unwrap();
        store
            .get_any(op_id)
            .map(|r| (r.superseded_by.clone(), r.retry_count))
            .unwrap_or((None, 1))
    };
    let mut body = base.clone();
    body["boot_id"] = json!(state.boot_id);
    body["supersedes"] = json!(supersedes);
    body["superseded_by"] = json!(superseded_by);
    body["retry_count"] = json!(retry_count.max(1));
    body
}

/// Is a relay poll's 403 body the backend's USER rejection
/// (`{"error":"rejected"}`)? Anything else — other error codes, non-JSON, an
/// empty body — is not.
fn is_user_rejection(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.as_str())
                .map(|e| e == "rejected")
        })
        .unwrap_or(false)
}

/// True when the local op record exists and is no longer pending (approved,
/// satisfied by a chain sibling, rejected, withdrawn, consumed).
fn resolved_locally(state: &AppState, op_id: &str) -> bool {
    state
        .approvals
        .lock()
        .unwrap()
        .get_any(op_id)
        .map(|r| !matches!(r.status, crate::approval::ApprovalStatus::Pending))
        .unwrap_or(false)
}

/// Apply a relay-fetched grant by replaying it through the daemon's own
/// `/op/{id}/approve` endpoint over localhost. This reuses the full approve
/// path (incl. the §4.2 W_c unseal) verbatim — no logic is duplicated.
/// Why a loopback approve failed. `batch_verify_failed` is switched on by
/// the poll loop's recovery arm — detected via the RFC-9457 `code` member,
/// NEVER by matching message text (design/batch-approve.md §Daemon verify 7).
struct ApplyFailure {
    batch_verify_failed: bool,
    /// `approver_not_authorized` / `grant_id_invalid` / `wk_refused_v2`: the
    /// signer may not (or could not be proven to) approve this op, or the grant
    /// delivered an unlock secret; it stays pending (recovered like
    /// `batch_verify_failed`).
    approver_not_authorized: bool,
    detail: String,
}

impl ApplyFailure {
    fn transport(detail: String) -> Self {
        ApplyFailure {
            batch_verify_failed: false,
            approver_not_authorized: false,
            detail,
        }
    }
}

async fn apply_grant(state: Arc<AppState>, op_id: &str, grant: Value) -> Result<(), ApplyFailure> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ApplyFailure::transport(format!("loopback client init: {}", e)))?;
    let url = format!(
        "http://127.0.0.1:{}/op/{}/approve",
        state.config.port, op_id
    );
    let resp = client
        .post(&url)
        .json(&grant)
        .send()
        .await
        .map_err(|e| ApplyFailure::transport(format!("loopback approve: {}", e)))?;
    let status = resp.status();
    if status.is_success() {
        tracing::info!(op = %op_id, "relay grant applied via loopback approve");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        let code = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(String::from));
        Err(ApplyFailure {
            batch_verify_failed: code.as_deref() == Some("batch_verify_failed"),
            // Every refusal of WHO approved or HOW the key was delivered leaves
            // the op pending (grant v3): a forged or mis-shaped grant must never
            // resolve an op someone may still approve.
            approver_not_authorized: refusal_keeps_op_pending(code.as_deref()),
            detail: format!("loopback approve HTTP {}: {}", status, body),
        })
    }
}

/// Refusals that leave the op pending instead of failing it: who approved or
/// how the key was delivered (a forged or mis-shaped grant must never resolve
/// an op someone may still approve), and this device being unable to serve
/// right now (parked, lease expired, revoked: the approval itself isn't wrong).
fn refusal_keeps_op_pending(code: Option<&str>) -> bool {
    matches!(
        code,
        Some(
            "approver_not_authorized"
                | "grant_id_invalid"
                | "wk_refused_v2"
                | "device_not_admitted"
                | "ledger_stale"
                | "ledger_device_revoked"
        )
    )
}

/// `reason: None` = a genuine user rejection (the endpoint's default). `Some` =
/// the true cause of a non-user rejection (apply failure), recorded verbatim
/// so `sc op wait` and the console never dress it up as "user rejected".
async fn apply_reject(state: Arc<AppState>, op_id: &str, reason: Option<&str>) {
    let url = format!("http://127.0.0.1:{}/op/{}/reject", state.config.port, op_id);
    if let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        let req = match reason {
            Some(r) => client.post(&url).json(&serde_json::json!({ "reason": r })),
            None => client.post(&url),
        };
        let _ = req.send().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.1 mode-dependent poll interval: 15s safety net behind the stream's
    /// `op` event, the legacy 2s when the poll is the only path.
    #[test]
    fn poll_interval_is_mode_dependent() {
        assert_eq!(poll_interval(true), Duration::from_secs(15));
        assert_eq!(poll_interval(false), Duration::from_secs(2));
    }

    #[test]
    fn a_device_that_cannot_serve_keeps_the_op_pending() {
        for c in [
            "approver_not_authorized",
            "grant_id_invalid",
            "wk_refused_v2",
            "device_not_admitted",
            "ledger_stale",
            "ledger_device_revoked",
        ] {
            assert!(refusal_keeps_op_pending(Some(c)), "{c}");
        }
        assert!(!refusal_keeps_op_pending(Some("bad_request")));
        assert!(!refusal_keeps_op_pending(None));
    }

    fn test_state() -> AppState {
        AppState::new(crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-relay-{}",
                std::process::id()
            )),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            relying_party: crate::passkey::webauthn::RelyingParty::exact(
                "http://localhost",
                "localhost",
            ),
            admin_key: None,
            relay_url: None,
            body_cap: crate::config::DEFAULT_BODY_CAP,
        })
    }

    /// Contract §2: reason + satisfied_by ride the cancel body; a legacy
    /// reason-less cancel sends neither (backend stores null, as today).
    #[test]
    fn cancel_body_carries_reason_and_pointer() {
        assert_eq!(cancel_body("pk", None), json!({ "daemon_pubkey": "pk" }));
        assert_eq!(
            cancel_body("pk", Some(&CancelReason::Satisfied { by: "op-b".into() })),
            json!({ "daemon_pubkey": "pk", "reason": "satisfied", "satisfied_by": "op-b" })
        );
        for (r, s) in [
            (CancelReason::Rejected, "rejected"),
            (CancelReason::Withdrawn, "withdrawn"),
            (CancelReason::Abandoned, "abandoned"),
        ] {
            let b = cancel_body("pk", Some(&r));
            assert_eq!(b["reason"], s);
            assert!(b.get("satisfied_by").is_none());
        }
    }

    /// Contract §2: the register body carries this process's boot_id, the ids
    /// just superseded, and the op's CURRENT pointer + retry_count read at
    /// send time; recovery re-register passes `supersedes: []`.
    #[test]
    fn register_body_carries_chain_state() {
        use crate::core::policy::AccessLevel;
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let state = test_state();
        let op = Operation {
            act: Act {
                kind: ActType::Use,
                target: "GITHUB_TOKEN".into(),
                scope: json!({ "method": "GET", "host": "h", "path": "/p", "level": "ask", "window_s": 60 }),
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        };
        let pc = crate::approval::PolicyContext {
            level: AccessLevel::Ask,
            decided_by: crate::core::policy::DecidedBy::Floor,
            ttl_seconds: 60,
            host: Some("h".into()),
        };
        let (a, b) = {
            let mut s = state.approvals.lock().unwrap();
            let a = s.create_chained("v1".into(), op.clone(), "r1".into(), Some(pc.clone()), None);
            let b = s.create_chained("v1".into(), op, "r2".into(), Some(pc), None);
            (a, b)
        };
        let base = json!({ "op_id": "x", "daemon_version": "v" });

        let head = register_body(&state, &base, &b.id, &b.supersedes);
        assert_eq!(head["boot_id"], json!(state.boot_id));
        assert_eq!(state.boot_id.len(), 32);
        assert_eq!(head["supersedes"], json!([a.id.clone()]));
        assert!(head["superseded_by"].is_null());
        assert_eq!(head["retry_count"], 2);
        assert_eq!(head["daemon_version"], "v", "static fields preserved");

        // A's (late) register / recovery re-register: no supersedes, but its
        // current pointer so the backend converges on one head.
        let old = register_body(&state, &base, &a.id, &[]);
        assert_eq!(old["supersedes"], json!([]));
        assert_eq!(old["superseded_by"], json!(b.id));
        assert_eq!(old["retry_count"], 1);
    }

    /// Only `{"error":"rejected"}` reads as a user rejection on a poll 403;
    /// tier / vault / binding refusals (or a bare 403) must never reject the
    /// op — that would now resolve its whole intent chain.
    #[test]
    fn only_explicit_rejection_body_is_user_rejection() {
        assert!(is_user_rejection(r#"{"error":"rejected"}"#));
        assert!(is_user_rejection(
            r#"{"error":"rejected","grant_status":"rejected"}"#
        ));
        for other in [
            r#"{"error":"forbidden_tier"}"#,
            r#"{"error":"vault_mismatch"}"#,
            r#"{"error":"op_relay_immutable"}"#,
            r#"{"status":"rejected"}"#,
            r#"{"error":{"code":"rejected"}}"#,
            "rejected",
            "",
        ] {
            assert!(!is_user_rejection(other), "{other}");
        }
    }

    /// A late grant for an op the chain already resolved ends the relay poll
    /// quietly (no reject, no apply-failure audit).
    #[test]
    fn resolved_locally_tracks_status() {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let state = test_state();
        let op = Operation {
            act: Act {
                kind: ActType::Export,
                target: "K".into(),
                scope: Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        };
        let id = state
            .approvals
            .lock()
            .unwrap()
            .create("v1".into(), op, "r".into());
        assert!(!resolved_locally(&state, &id));
        assert!(!resolved_locally(&state, "unknown"));
        state.approvals.lock().unwrap().approve(&id, None);
        assert!(resolved_locally(&state, &id));
    }
}
