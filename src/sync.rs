//! Cloud sync over the DIK-signed `/device/*` routes (trust-reset contract 8.4).
//!
//! Per vault the daemon holds ONE local store (`vault.per-item.json`): the
//! member record (verified against this person's own pin, see [`crate::trust`])
//! and N sealed item rows. Sync moves only ciphertext and signed records: the
//! backend never sees K, and nothing it serves is trusted unless it verifies.
//!
//!   - `GET /device/vaults` — the vaults this person is a member of (discovery);
//!   - `GET /device/vaults/{vid}/state[?wait=1&since=]` — lifecycle: status, an
//!     owner-signed tombstone, `member_seq`, `items_seq`;
//!   - `GET /device/vaults/{vid}/member-record` — the member record;
//!   - `GET|PUT /device/vaults/{vid}/items[/{id}]`, `GET …/items/wait` — content;
//!   - `POST /device/vaults/{vid}/audit` — the local audit outbox;
//!   - `GET /device/ledger/{us}` — the own person's ledger (pins, self-revoke);
//!   - `GET /device/stream` — wake hints (see [`crate::sync_stream`]).
//!
//! Only an OWNER-SIGNED tombstone that verifies against the stored record
//! destroys local vault state; a server flipping a status field never does. A
//! verified `revoke{device}` of this device in its own ledger wipes the DIK and
//! the enc key and every local vault, then exits.
//!
//! Best-effort by design: a failure logs and leaves local state untouched; a
//! machine without a device identity simply doesn't sync.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::cli::active;
use crate::cloud::{DeviceClient, Refusal};
use crate::state::AppState;
use crate::storage::sealed_vault::{self as pv_store, PerItemVault};
use crate::sync_stream::{Mode, StreamHealth, WakeCell, Work};
use crate::trust::{AdoptError, RecordAdopt, SelfStatus, TrustError};

/// How long an auth-refused sync path parks before retrying. Shared with the
/// SSE dispatcher's park so the two shapes recover at the same speed.
pub(crate) const AUTH_RETRY: Duration = Duration::from_secs(600);

const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

// ── local store ──────────────────────────────────────────────────────────────

/// Load the per-item store for a vault, or `None` if it doesn't exist yet.
pub(crate) fn read_per_item_store(state_dir: &Path, vault: &str) -> Option<PerItemVault> {
    let path = state_dir
        .join("vaults")
        .join(vault)
        .join("vault.per-item.json");
    pv_store::read_per_item(&path).ok().flatten()
}

pub(crate) fn write_per_item_store(
    state_dir: &Path,
    vault: &str,
    pv: &PerItemVault,
) -> Result<(), String> {
    let path = state_dir
        .join("vaults")
        .join(vault)
        .join("vault.per-item.json");
    pv_store::write_per_item_atomic(&path, pv).map_err(|e| format!("write per-item store: {}", e))
}

// ── the vault set ────────────────────────────────────────────────────────────

/// Vault ids this device keeps synced: the active vault plus every vault in the
/// known-vaults catalog, deduped. A personal build leaves SHARED (team) vaults
/// to the official build (team-edition §9).
fn synced_vault_ids(cfg: &crate::cli::active::CliConfig) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    if let Some(v) = cfg.vault.as_deref().filter(|s| !s.is_empty()) {
        if !leave_shared_to_official(v) {
            ids.push(v.to_string());
        }
    }
    for kv in crate::cli::active::known_vaults() {
        if !kv.vault.is_empty()
            && !leave_shared_to_official(&kv.vault)
            && !ids.iter().any(|x| x == &kv.vault)
        {
            ids.push(kv.vault.clone());
        }
    }
    ids
}

/// A personal build (open source) never syncs a SHARED (team) vault's material:
/// `true` iff this build does not serve team AND the catalog says `vid` is
/// shared (unknown kind is NOT shared). The single guard every pull shares.
fn leave_shared_to_official(vid: &str) -> bool {
    if crate::team_hooks::build_serves_shared() {
        return false;
    }
    crate::cli::active::known_vaults()
        .iter()
        .find(|kv| kv.vault == vid)
        .map(|kv| crate::state::AppState::kind_str_is_shared(kv.kind.as_deref()))
        .unwrap_or(false)
}

/// One vault as `GET /device/vaults` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscoveredVault {
    id: String,
    label: Option<String>,
    kind: Option<String>,
}

/// Parse `GET /device/vaults` (`[{vault_id, label?, kind, role}]`; an object
/// `{vaults: [...]}` is accepted too).
fn parse_vault_list(body: &Value) -> Vec<DiscoveredVault> {
    let arr = body
        .as_array()
        .or_else(|| body.get("vaults").and_then(|v| v.as_array()));
    let Some(arr) = arr else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| {
            let id = v
                .get("vault_id")
                .or_else(|| v.get("id"))
                .and_then(|i| i.as_str())?
                .to_string();
            let s = |k: &str| {
                v.get(k)
                    .and_then(|i| i.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            };
            Some(DiscoveredVault {
                id,
                label: s("label"),
                kind: s("kind"),
            })
        })
        .collect()
}

async fn discover_account_vaults(client: &DeviceClient) -> Result<Vec<DiscoveredVault>, String> {
    let resp = client.get("/device/vaults", FETCH_TIMEOUT).await?;
    if !resp.status().is_success() {
        return Err(crate::cloud::error_text(resp, "vault list").await);
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("parse vault list: {}", e))?;
    Ok(parse_vault_list(&body))
}

/// Upsert discovered vaults into the known-vaults catalog (label/kind refresh on
/// every discovery) and seed the server-authoritative sharedness. Returns the
/// ids that were NOT known before.
fn remember_discovered(
    state: &AppState,
    cfg: &crate::cli::active::CliConfig,
    discovered: &[DiscoveredVault],
) -> Vec<String> {
    let daemon = cfg
        .daemon
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", crate::config::CONTROL_PORT));
    let known: std::collections::HashSet<String> = crate::cli::active::known_vaults()
        .into_iter()
        .map(|kv| kv.vault)
        .collect();
    let mut fresh = Vec::new();
    for dv in discovered {
        if dv.kind.is_some() {
            state.set_vault_shared(&dv.id, AppState::kind_str_is_shared(dv.kind.as_deref()));
        }
        match crate::cli::active::remember_discovered_vault(
            &daemon,
            &dv.id,
            dv.label.clone(),
            dv.kind.clone(),
        ) {
            Ok(()) => {
                if !known.contains(&dv.id) {
                    fresh.push(dv.id.clone());
                }
            }
            Err(e) => tracing::debug!(vault = %dv.id, "vault discovery: remember failed: {}", e),
        }
    }
    fresh
}

// ── refusals ─────────────────────────────────────────────────────────────────

/// React to a device-wide refusal seen on any sync request. `UpgradeRequired`
/// flags the daemon so the broker answers agents with `sc upgrade`;
/// `DeviceRevoked` is only a HINT — the daemon re-reads its own ledger and acts
/// on a VERIFIED revoke only (a server can't make it wipe itself).
fn on_refusal(state: &Arc<AppState>, r: &Refusal) {
    match r {
        Refusal::UpgradeRequired => {
            if !state.upgrade_required() {
                tracing::warn!("cloud: SC_UPGRADE_REQUIRED — this SafeClaw is below the server's floor; run `sc upgrade`");
            }
            state.set_upgrade_required(true);
        }
        Refusal::DeviceRevoked => {
            tracing::warn!(
                "cloud: the server says this device is revoked; verifying against the ledger"
            );
            crate::sync_stream::notify_own_ledger();
        }
        Refusal::Unauthorized { .. } => {
            tracing::warn!("cloud: {}", r.message());
        }
    }
}

/// Read a non-2xx sync answer on `vault`'s routes: `(status, body,
/// device-wide refusal)`. A refusal is applied ([`on_refusal`]) and a `403
/// not_member` parks the vault ([`park_not_member`]) before it is returned.
async fn refused(
    state: &Arc<AppState>,
    vault: &str,
    resp: reqwest::Response,
) -> (u16, Value, Option<Refusal>) {
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    let r = crate::cloud::refusal(status, &body);
    if let Some(r) = &r {
        on_refusal(state, r);
    }
    if is_not_member(status, &body) {
        park_not_member(vault);
    }
    (status, body, r)
}

// ── parked vaults (403 not_member) ───────────────────────────────────────────

/// How long a vault whose routes answer `403 not_member` stays parked.
pub const NOT_MEMBER_PARK: Duration = Duration::from_secs(600);

static PARKED: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(Default::default);

/// The vault gate's `403 {error:"not_member"}` (contract 8.6).
fn is_not_member(status: u16, body: &Value) -> bool {
    status == 403 && body.get("error").and_then(|v| v.as_str()) == Some("not_member")
}

/// The server says this person is not a member of `vault`. That is a claim,
/// not a verified removal: only a verified member record that no longer seats
/// this person drops local state ([`RecordPull::Removed`]). So the local copy is
/// kept, and the vault's sync stops (its watcher makes no requests) for
/// [`NOT_MEMBER_PARK`], then probes once more.
fn park_not_member(vault: &str) {
    let until = std::time::Instant::now() + NOT_MEMBER_PARK;
    let fresh = PARKED
        .lock()
        .unwrap()
        .insert(vault.to_string(), until)
        .is_none_or(|prev| prev <= std::time::Instant::now());
    if fresh {
        tracing::warn!(
            vault = %vault,
            "cloud: the server says this account is not a member of this vault; its sync is \
             paused for {} min (the local copy is kept)",
            NOT_MEMBER_PARK.as_secs() / 60
        );
    }
}

/// How long `vault` stays parked; `None` when it is not (an expired park is
/// cleared).
pub(crate) fn parked_for(vault: &str) -> Option<Duration> {
    let mut parked = PARKED.lock().unwrap();
    let left = parked
        .get(vault)?
        .checked_duration_since(std::time::Instant::now())
        .filter(|d| !d.is_zero());
    if left.is_none() {
        parked.remove(vault);
    }
    left
}

/// The message `sc sync` shows for a parked vault.
fn parked_message(left: Duration) -> String {
    format!(
        "the server says this account is not a member of this vault; sync is paused for \
         another {} s and the local copy is kept",
        left.as_secs()
    )
}

// ── lifecycle (/state) ───────────────────────────────────────────────────────

/// `GET /device/vaults/{vid}/state` (contract 8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStateResp {
    pub deleted: bool,
    pub tombstone: Option<(String, String)>,
    pub member_seq: u64,
    pub items_seq: u64,
}

fn parse_state(body: &Value) -> VaultStateResp {
    let tombstone = body.get("tombstone").and_then(|t| {
        Some((
            t.get("sig")?.as_str()?.to_string(),
            t.get("signer")?.as_str()?.to_string(),
        ))
    });
    VaultStateResp {
        deleted: body.get("status").and_then(|v| v.as_str()) == Some("deleted"),
        tombstone,
        member_seq: body.get("member_seq").and_then(|v| v.as_u64()).unwrap_or(0),
        items_seq: body.get("items_seq").and_then(|v| v.as_u64()).unwrap_or(0),
    }
}

/// Does a deleted status come with an owner-signed tombstone that verifies
/// against the stored record? Only then is local state destroyed: an unsigned
/// or forged delete parks (a later valid one drops).
fn tombstone_verified(state_dir: &Path, vault: &str, s: &VaultStateResp) -> bool {
    let Some((sig, signer)) = s.tombstone.as_ref() else {
        tracing::warn!(vault = %vault, "cloud: vault reported deleted without an owner signature; NOT dropping");
        return false;
    };
    let Some(pv) = read_per_item_store(state_dir, vault) else {
        // Nothing local to protect (no store yet): nothing to drop either.
        return false;
    };
    if pv.tombstone_verified(vault, signer, sig) {
        true
    } else {
        tracing::warn!(vault = %vault, signer = %signer, "cloud: tombstone signature did NOT verify; NOT dropping");
        false
    }
}

/// Lock the vault (zeroizing the retained K and the cache), forget its audit
/// handle, remove its local directory and its catalog entry. The ONE path that
/// destroys local vault state; reached only on a verified tombstone, a
/// verified removal from the record, or a verified self-revoke.
fn drop_local_vault(state: &Arc<AppState>, vault: &str) {
    state.lock_vault(vault);
    state.trust.forget_record(vault);
    state.audits.forget(vault);
    if let Err(e) = state.vaults.remove(vault) {
        tracing::warn!(vault = %vault, "drop vault: remove local dir failed: {}", e);
    }
    state.last_host_unions.lock().unwrap().remove(vault);
    if let Err(e) = active::forget_vault(vault) {
        tracing::warn!(vault = %vault, "drop vault: forget from config failed: {}", e);
    }
}

/// [`drop_local_vault`] under the per-vault write lock, so the destroy can't race
/// a concurrent approve / connect write.
pub(crate) async fn drop_local_vault_locked(state: &Arc<AppState>, vault: &str) {
    let lock = state.vault_write_lock(vault);
    let _guard = lock.lock().await;
    drop_local_vault(state, vault);
}

/// Why a state fetch failed.
enum StateError {
    Refused,
    /// `403 not_member`: the vault is parked ([`park_not_member`]).
    NotMember,
    Other(String),
}

async fn fetch_state(
    state: &Arc<AppState>,
    client: &DeviceClient,
    http: &reqwest::Client,
    vault: &str,
    wait_since: Option<u64>,
) -> Result<Option<VaultStateResp>, StateError> {
    let path = match wait_since {
        Some(since) => format!("/device/vaults/{}/state?wait=1&since={}", vault, since),
        None => format!("/device/vaults/{}/state", vault),
    };
    let resp = client
        .request(http, reqwest::Method::GET, &path, None)
        .map_err(StateError::Other)?
        .send()
        .await
        .map_err(|e| StateError::Other(format!("state: {}", e)))?;
    match resp.status().as_u16() {
        200 => {
            state.set_upgrade_required(false);
            let body: Value = resp
                .json()
                .await
                .map_err(|e| StateError::Other(format!("parse state: {}", e)))?;
            Ok(Some(parse_state(&body)))
        }
        404 => Ok(None),
        _ => {
            let (status, body, r) = refused(state, vault, resp).await;
            if r.is_some() {
                Err(StateError::Refused)
            } else if is_not_member(status, &body) {
                Err(StateError::NotMember)
            } else {
                Err(StateError::Other(format!("state HTTP {}", status)))
            }
        }
    }
}

// ── member record ────────────────────────────────────────────────────────────

/// The outcome of a member-record pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordPull {
    Adopted,
    Unchanged,
    /// No record on the server yet (a vault the console hasn't upgraded).
    Missing,
    /// Refused (no pin, a bad record, equivocation, rollback): the vault stays
    /// closed; the reason is logged and kept for the broker.
    Refused(String),
    /// A verified record that no longer seats this person: an owner removed
    /// them. Local state was dropped.
    Removed,
}

/// Pull `GET /device/vaults/{vid}/member-record`, verify it against this
/// person's pin and latch it against the held record ([`crate::trust::adopt_record`]).
pub async fn pull_member_record(
    state: &Arc<AppState>,
    client: &DeviceClient,
    vault: &str,
) -> Result<RecordPull, String> {
    if leave_shared_to_official(vault) {
        return Ok(RecordPull::Unchanged);
    }
    let Some(own) = state.trust.own_ledger() else {
        return Err("the own ledger is not verified yet".into());
    };
    let resp = client
        .get(
            &format!("/device/vaults/{}/member-record", vault),
            FETCH_TIMEOUT,
        )
        .await?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(RecordPull::Missing),
        _ => {
            let (status, body, r) = refused(state, vault, resp).await;
            return Err(match r {
                Some(r) => r.message(),
                None => format!(
                    "member-record HTTP {}: {}",
                    status,
                    body.get("message").and_then(|m| m.as_str()).unwrap_or("")
                ),
            });
        }
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("parse member record: {}", e))?;
    // Adopt under the vault write lock: the store is shared with item writers.
    let lock = state.vault_write_lock(vault);
    let guard = lock.lock().await;
    let mut pv = read_per_item_store(&state.config.state_dir, vault).unwrap_or_default();
    let outcome = match crate::trust::adopt_record(&mut pv, vault, &body, &own) {
        Ok(RecordAdopt::Adopted) => {
            if let Err(e) = state.vaults.ensure_dir(vault) {
                return Err(format!("vault dir: {}", e));
            }
            write_per_item_store(&state.config.state_dir, vault, &pv)?;
            if let Some(r) = pv.record.as_ref() {
                state.trust.latch_record(vault, r);
            }
            state.trust.clear_refusal(vault);
            RecordPull::Adopted
        }
        Ok(RecordAdopt::Unchanged) => {
            if let Some(r) = pv.record.as_ref() {
                state.trust.latch_record(vault, r);
            }
            state.trust.clear_refusal(vault);
            RecordPull::Unchanged
        }
        Err(AdoptError::Record(pv_store::RecordError::NotAMember)) => {
            // Verified against our pin, folds, and does not seat us: an owner
            // removed this person. Close the vault.
            drop(guard);
            tracing::warn!(vault = %vault, "member record: this account is no longer a member; dropping local state");
            drop_local_vault_locked(state, vault).await;
            return Ok(RecordPull::Removed);
        }
        Err(e) => {
            let why = e.to_string();
            match &e {
                AdoptError::Equivocation { .. } | AdoptError::Rollback | AdoptError::Record(_) => {
                    tracing::error!(vault = %vault, "member record REFUSED: {}", why);
                    state.lock_vault(vault);
                }
                AdoptError::NoPin => tracing::info!(vault = %vault, "member record: {}", why),
            }
            state.trust.refuse_vault(vault, why.clone());
            RecordPull::Refused(why)
        }
    };
    Ok(outcome)
}

// ── own ledger (pins, self-revoke) ───────────────────────────────────────────

/// Refresh the own person's ledger (latched), store it, and act on a VERIFIED
/// revoke of this device: wipe and exit. Returns the folded ledger.
pub async fn refresh_own_ledger(
    state: &Arc<AppState>,
    client: &DeviceClient,
) -> Result<crate::crypto::ledger::LedgerState, TrustError> {
    let Some(anchor) = crate::trust::own_anchor() else {
        return Err(TrustError::Fetch(crate::device::NOT_PAIRED.into()));
    };
    let ledger = match crate::trust::refresh_ledger(
        client,
        &state.config.state_dir,
        &anchor.us,
        &anchor.sign_pub,
    )
    .await
    {
        Ok(l) => l,
        Err(TrustError::Refused(r)) => {
            on_refusal(state, &r);
            return Err(TrustError::Refused(r));
        }
        Err(e) => {
            if e.is_hard() {
                tracing::error!(
                    "own ledger REFUSED: {} — keeping the last verified ledger",
                    e
                );
            }
            return Err(e);
        }
    };
    match crate::trust::self_status(&ledger, client.device().id()) {
        SelfStatus::Revoked => self_wipe_and_exit(state).await,
        SelfStatus::Unknown => {
            tracing::warn!(device = %client.device().id(), "own ledger: this device is not admitted in it")
        }
        SelfStatus::Live => {}
    }
    state.trust.set_own_ledger(ledger.clone());
    Ok(ledger)
}

/// A VERIFIED revoke of THIS device in its own ledger (design D4): lock and
/// drop every local vault, delete the DIK and the enc key, clear the pairing,
/// exit. Does not return.
async fn self_wipe_and_exit(state: &Arc<AppState>) -> ! {
    tracing::warn!("own ledger: THIS DEVICE was revoked (verified) — wiping local vaults and the device identity");
    let mut vaults: Vec<String> = crate::cli::active::known_vaults()
        .into_iter()
        .map(|kv| kv.vault)
        .filter(|v| !v.is_empty())
        .collect();
    vaults.extend(state.vaults.list().unwrap_or_default());
    vaults.sort();
    vaults.dedup();
    // Evict K from every vault up front so no in-flight request can use it.
    for vid in &vaults {
        state.lock_vault(vid);
    }
    for vid in &vaults {
        drop_local_vault_locked(state, vid).await;
    }
    if let Err(e) = crate::device::wipe() {
        tracing::error!("self-revoke: device identity wipe failed: {}", e);
    }
    if let Err(e) = crate::cli::active::clear_pairing() {
        tracing::warn!("self-revoke: clear pairing failed: {}", e);
    }
    tracing::warn!("self-revoke: local state wiped; daemon exiting (pair again with `sc login`)");
    std::process::exit(0);
}

/// Keep the own ledger fresh: immediately, on every `ledger` stream hint for
/// this person (and on a `SC_DEVICE_REVOKED`), and at least every 10 minutes.
async fn own_ledger_loop(state: Arc<AppState>, client: DeviceClient) {
    const INTERVAL: Duration = Duration::from_secs(600);
    const FLOOR: Duration = Duration::from_secs(2);
    loop {
        let started = tokio::time::Instant::now();
        let _ = refresh_own_ledger(&state, &client).await;
        tokio::select! {
            _ = crate::sync_stream::own_ledger_notified() => {}
            _ = tokio::time::sleep(INTERVAL) => {}
        }
        tokio::time::sleep_until(started + FLOOR).await;
    }
}

// ── the pull block ───────────────────────────────────────────────────────────

/// After an item pull adopted new rows, refresh the in-memory cache for an
/// UNLOCKED vault by folding the store with the retained K — no passkey. A K
/// that no longer folds (the vault was re-keyed) leaves the cache as is.
fn refresh_after_item_pull(state: &Arc<AppState>, vault: &str) {
    let Some(k) = state.cloned_state_key(vault) else {
        return;
    };
    let Some(pv) = read_per_item_store(&state.config.state_dir, vault) else {
        return;
    };
    match crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(
        &state.trust,
        &k,
        &pv,
        vault,
    ) {
        Ok(view) => {
            let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
            state.unlock_vault(vault.to_string(), cache, k);
            tracing::info!(vault = %vault, "sync: cache refreshed from item rows");
        }
        Err(e) => {
            tracing::warn!(vault = %vault, "sync: the retained K no longer folds this vault ({}); lock and unlock to see new state", e);
        }
    }
}

/// The serial pull block one vault's watcher runs on every wake: the member
/// record first (so items fold against a fresh record), then the item rows,
/// then any pending OAuth connect. Returns `(ok, stopped)`: `ok` = both pulls
/// succeeded; `stopped` = the vault was dropped (the watcher exits).
/// What one pull block did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pulled {
    /// Both pulls reached the server.
    ok: bool,
    /// The vault was dropped (a verified removal): the watcher ends.
    stopped: bool,
    /// The served member record is held now (adopted or unchanged). `false`
    /// for a refused or missing record, no pin yet, or a transient failure:
    /// the held seq did not move, so the caller must not re-wait on it.
    record_settled: bool,
}

async fn pull_and_process(
    state: &Arc<AppState>,
    client: &DeviceClient,
    vault: &str,
    channel: &str,
) -> Pulled {
    let mut ok = true;
    let mut record_settled = false;
    match pull_member_record(state, client, vault).await {
        Ok(RecordPull::Removed) => {
            return Pulled {
                ok: true,
                stopped: true,
                record_settled: true,
            }
        }
        Ok(RecordPull::Adopted) => {
            record_settled = true;
            state.record_cloud_contact(vault);
            tracing::info!(vault = %vault, "sync: member record adopted");
            refresh_after_item_pull(state, vault);
        }
        Ok(RecordPull::Unchanged) => {
            record_settled = true;
            state.record_cloud_contact(vault);
        }
        Ok(RecordPull::Missing) => {
            tracing::debug!(vault = %vault, "sync: no member record yet ({})", pv_store::NO_RECORD)
        }
        Ok(RecordPull::Refused(_)) => {}
        Err(e) => {
            tracing::debug!(vault = %vault, "sync: member record pull failed: {}", e);
            ok = false;
        }
    }
    match pull_items(state, client, vault).await {
        Ok(n) if n > 0 => {
            state.record_cloud_contact(vault);
            tracing::info!(vault = %vault, adopted = n, "sync: pulled item rows");
            refresh_after_item_pull(state, vault);
        }
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(vault = %vault, "sync: item pull failed: {}", e);
            ok = false;
        }
    }
    crate::auth::connect::process_vault_connects(state, vault, None).await;
    tracing::debug!(vault = %vault, channel = channel, "sync: wake processed");
    Pulled {
        ok,
        stopped: false,
        record_settled,
    }
}

/// Probe `/state` (no wait) and act on it: a verified tombstone drops the vault
/// (`Ok(true)` = stopped); otherwise run the pull block.
async fn probe_state_and_pull(
    state: &Arc<AppState>,
    client: &DeviceClient,
    vault: &str,
    channel: &str,
) -> Result<bool, StateError> {
    let http = crate::cli::egress_proxy::client(FETCH_TIMEOUT)
        .map_err(|e| StateError::Other(format!("http client init: {}", e)))?;
    if let Some(s) = fetch_state(state, client, &http, vault, None).await? {
        if s.deleted && tombstone_verified(&state.config.state_dir, vault, &s) {
            drop_local_vault_locked(state, vault).await;
            tracing::info!(vault = %vault, "sync: vault deleted upstream (owner-signed); dropped local state");
            return Ok(true);
        }
    }
    Ok(pull_and_process(state, client, vault, channel)
        .await
        .stopped)
}

/// Result of an on-demand `sc sync`: whether new cloud state was pulled, plus
/// the pending-connect report so the CLI can surface it.
pub struct SyncOutcome {
    pub pulled: bool,
    pub connects: crate::auth::connect::ConnectReport,
}

/// One-shot sync of `vault_id` (`POST /v/{vid}/sync`, `sc sync`): verify the
/// lifecycle, pull the member record and items, complete pending connects,
/// push local-ahead rows.
pub async fn sync_vault_now(state: &Arc<AppState>, vault_id: &str) -> Result<SyncOutcome, String> {
    let client = state
        .cloud()
        .ok_or_else(|| crate::device::NOT_PAIRED.to_string())?;
    if let Some(left) = parked_for(vault_id) {
        return Err(parked_message(left));
    }
    if state.trust.own_ledger().is_none() {
        refresh_own_ledger(state, &client)
            .await
            .map_err(|e| format!("could not verify your account ledger: {}", e))?;
    }
    let http = crate::cli::egress_proxy::client(FETCH_TIMEOUT)
        .map_err(|e| format!("http client init: {}", e))?;
    match fetch_state(state, &client, &http, vault_id, None).await {
        Ok(Some(s)) if s.deleted && tombstone_verified(&state.config.state_dir, vault_id, &s) => {
            drop_local_vault_locked(state, vault_id).await;
            return Ok(SyncOutcome {
                pulled: false,
                connects: Default::default(),
            });
        }
        Ok(_) => {}
        Err(StateError::Refused) => {
            return Err(if state.upgrade_required() {
                Refusal::UpgradeRequired.message()
            } else {
                "the server refused this device (see `sc log`)".into()
            })
        }
        Err(StateError::NotMember) => return Err(parked_message(NOT_MEMBER_PARK)),
        Err(StateError::Other(e)) => return Err(e),
    }
    let record = pull_member_record(state, &client, vault_id).await?;
    if let RecordPull::Refused(why) = &record {
        return Err(why.clone());
    }
    if record == RecordPull::Removed {
        return Err("you are no longer a member of this vault; its local copy was removed".into());
    }
    let n = pull_items(state, &client, vault_id).await?;
    if n > 0 || record == RecordPull::Adopted {
        refresh_after_item_pull(state, vault_id);
    }
    state.record_cloud_contact(vault_id);
    let connects = crate::auth::connect::process_vault_connects(state, vault_id, None).await;
    push_items_best_effort(state, vault_id).await;
    Ok(SyncOutcome {
        pulled: n > 0 || record == RecordPull::Adopted,
        connects,
    })
}

// ── watchers ─────────────────────────────────────────────────────────────────

/// Start the cloud side of a paired daemon: the own-ledger loop, one watcher per
/// synced vault, the SSE dispatcher and live discovery. A machine without a
/// device identity or pairing starts nothing.
pub fn spawn_watchers(state: Arc<AppState>) {
    let Some(client) = state.cloud() else {
        tracing::info!(
            "cloud sync: not paired (no device identity); sync not started — run `sc login`"
        );
        return;
    };
    tokio::spawn(async move {
        // The own ledger first: every member record verifies against its pins.
        let mut backoff = Duration::from_secs(2);
        loop {
            match refresh_own_ledger(&state, &client).await {
                Ok(_) => break,
                Err(e) => {
                    // Offline start: fall back to the latched cache, keep retrying.
                    if let Some(anchor) = crate::trust::own_anchor() {
                        if state.trust.own_ledger().is_none() {
                            if let Some(l) = crate::trust::cached_ledger(
                                &state.config.state_dir,
                                &anchor.us,
                                &anchor.sign_pub,
                            ) {
                                state.trust.set_own_ledger(l);
                            }
                        }
                    }
                    tracing::warn!("cloud sync: own ledger not verified yet ({}); retrying", e);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                    if state.trust.own_ledger().is_some() {
                        break;
                    }
                }
            }
        }
        tokio::spawn(own_ledger_loop(state.clone(), client.clone()));
        if let Ok(cfg) = active::load() {
            match discover_account_vaults(&client).await {
                Ok(d) => {
                    let fresh = remember_discovered(&state, &cfg, &d);
                    if !fresh.is_empty() {
                        tracing::info!(
                            count = fresh.len(),
                            "cloud sync: adopted account vaults via discovery"
                        );
                    }
                }
                Err(e) => tracing::debug!("cloud sync: discovery failed: {}", e),
            }
        }
        let cfg = active::load().unwrap_or_default();
        let (health_tx, health_rx) = tokio::sync::watch::channel(StreamHealth::Down);
        crate::sync_stream::publish_stream_health(health_rx.clone());
        let mut cells: Vec<(String, std::sync::Weak<WakeCell>)> = Vec::new();
        let ids = synced_vault_ids(&cfg);
        for vault in &ids {
            let cell = Arc::new(WakeCell::new());
            cells.push((vault.clone(), Arc::downgrade(&cell)));
            tokio::spawn(watch_loop(
                state.clone(),
                vault.clone(),
                client.clone(),
                cell,
                health_rx.clone(),
            ));
        }
        let own_us = crate::trust::own_anchor().map(|a| a.us).unwrap_or_default();
        tokio::spawn(crate::sync_stream::dispatcher(
            client.clone(),
            own_us,
            cells,
            health_tx,
        ));
        let watched: std::collections::HashSet<String> = ids.into_iter().collect();
        discovery_reconcile_loop(state, client, watched).await;
    });
}

/// Adopt an account vault created after the daemon started: re-list on an
/// interval; a new one gets a long-poll watcher (the next restart folds it into
/// the stream).
async fn discovery_reconcile_loop(
    state: Arc<AppState>,
    client: DeviceClient,
    mut watched: std::collections::HashSet<String>,
) {
    const INTERVAL: Duration = Duration::from_secs(120);
    let (_health_tx, health_rx) = tokio::sync::watch::channel(StreamHealth::Down);
    loop {
        tokio::time::sleep(INTERVAL).await;
        let Ok(cfg) = active::load() else { continue };
        let discovered = match discover_account_vaults(&client).await {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("cloud sync: discovery failed: {}", e);
                continue;
            }
        };
        remember_discovered(&state, &cfg, &discovered);
        for dv in discovered {
            if leave_shared_to_official(&dv.id) || !watched.insert(dv.id.clone()) {
                continue;
            }
            tracing::info!(vault = %dv.id, "cloud sync: live-adopted a new account vault (long-poll until restart)");
            tokio::spawn(watch_loop(
                state.clone(),
                dv.id,
                client.clone(),
                Arc::new(WakeCell::new()),
                health_rx.clone(),
            ));
        }
    }
}

/// Park the select arm forever when the health channel is closed.
async fn health_changed(rx: &mut tokio::sync::watch::Receiver<StreamHealth>) {
    if rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// One vault's long-lived watcher. Two shapes, re-picked every round from the
/// cell's mode (set only by the SSE dispatcher):
///
///  - **Sse**: no long-polls; wake on the cell (merged `state` / `members` /
///    `items` hints), on a 300 s reconcile deadline independent of event
///    traffic, or on a health flip. A `state` hint re-reads `/state`; any other
///    hint runs the pull block.
///  - **Fallback**: two server-held long-polls — `state?wait=1&since=<record
///    seq>` (lifecycle + member record) and `items/wait?since=<items seq>`
///    (content) — whichever answers first, plus the reconcile deadline.
///
/// Every pull is cursor- or latch-gated, so a duplicated or stale hint is a
/// no-op. A verified tombstone or a verified removal ends the task.
pub async fn watch_loop(
    state: Arc<AppState>,
    vault: String,
    client: DeviceClient,
    cell: Arc<WakeCell>,
    mut health_rx: tokio::sync::watch::Receiver<StreamHealth>,
) {
    const WATCH_TIMEOUT: Duration = Duration::from_secs(40);
    const RECONCILE_INTERVAL: Duration = Duration::from_secs(300);
    let state_dir = state.config.state_dir.clone();
    let mut http = match crate::cli::egress_proxy::client(WATCH_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cloud sync watch: client init failed: {}", e);
            return;
        }
    };
    tracing::info!(vault = %vault, "cloud sync watch loop started");
    if let Ok(true) = probe_state_and_pull(&state, &client, &vault, "start").await {
        return;
    }
    let mut backoff = Duration::from_secs(2);
    let mut last_reconcile = std::time::Instant::now();
    let mut pacer = FallbackPacer::new();
    loop {
        // Parked (`403 not_member`): no requests until the park ends, then
        // probe again. Local state is never touched on that claim.
        if let Some(left) = parked_for(&vault) {
            tokio::time::sleep(left).await;
            continue;
        }
        if cell.mode() == Mode::Sse {
            let notified = cell.notified();
            if !cell.has_work() {
                let deadline = last_reconcile + RECONCILE_INTERVAL;
                let until = deadline.saturating_duration_since(std::time::Instant::now());
                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep(until) => {}
                    r = health_rx.changed() => {
                        if r.is_err() {
                            cell.set_mode(Mode::Fallback);
                        }
                        continue;
                    }
                }
            }
            let work = cell.take_work();
            let reconcile = last_reconcile.elapsed() >= RECONCILE_INTERVAL;
            let result = if work.state.is_some() || reconcile {
                probe_state_and_pull(&state, &client, &vault, "sse-state").await
            } else if work.members || work.items {
                Ok(pull_and_process(&state, &client, &vault, "sse-wake")
                    .await
                    .stopped)
            } else {
                continue;
            };
            match result {
                Ok(true) => return,
                Ok(false) => {
                    backoff = Duration::from_secs(2);
                    if reconcile || work.state.is_some() {
                        last_reconcile = std::time::Instant::now();
                    }
                }
                Err(StateError::Refused) => {
                    cell.reinject(work);
                    tokio::time::sleep(AUTH_RETRY).await;
                }
                Err(StateError::NotMember) => {}
                Err(StateError::Other(e)) => {
                    tracing::debug!(vault = %vault, "cloud sync watch: {}", e);
                    cell.reinject(Work {
                        state: work.state,
                        members: true,
                        items: true,
                    });
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
            continue;
        }

        // ── Fallback: the two long-polls ────────────────────────────────────
        let round = std::time::Instant::now();
        let pv = read_per_item_store(&state_dir, &vault);
        let member_seq = pv
            .as_ref()
            .and_then(|p| p.record.as_ref())
            .map(|r| r.seq)
            .unwrap_or(0);
        let items_seq = pv.as_ref().map(|p| p.items_seq).unwrap_or(0);
        enum Wake {
            State(Result<Option<VaultStateResp>, StateError>),
            Items(Result<reqwest::Response, String>),
            Reconcile,
            Health,
        }
        let items_req = client
            .request(
                &http,
                reqwest::Method::GET,
                &format!("/device/vaults/{}/items/wait?since={}", vault, items_seq),
                None,
            )
            .map(|rb| rb.send());
        let wake = match items_req {
            Ok(items_fut) => tokio::select! {
                r = fetch_state(&state, &client, &http, &vault, Some(pacer.since(member_seq))) => Wake::State(r),
                r = items_fut => Wake::Items(r.map_err(|e| e.to_string())),
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => Wake::Reconcile,
                _ = health_changed(&mut health_rx) => Wake::Health,
            },
            Err(e) => Wake::Items(Err(e)),
        };
        match wake {
            Wake::State(Ok(Some(s))) => {
                backoff = Duration::from_secs(2);
                if s.deleted && tombstone_verified(&state_dir, &vault, &s) {
                    drop_local_vault_locked(&state, &vault).await;
                    tracing::info!(vault = %vault, "sync: vault deleted upstream (owner-signed); dropped local state");
                    return;
                }
                if s.member_seq != member_seq || s.items_seq > items_seq {
                    let pulled = pull_and_process(&state, &client, &vault, "state").await;
                    if pulled.stopped {
                        return;
                    }
                    last_reconcile = std::time::Instant::now();
                    if let Some(wait) =
                        pacer.after_pull(s.member_seq, member_seq, pulled.record_settled)
                    {
                        tracing::debug!(vault = %vault, served = s.member_seq, held = member_seq,
                            "cloud sync watch: member record not adopted; retrying in {}s", wait.as_secs());
                        tokio::time::sleep(wait).await;
                    }
                }
            }
            Wake::State(Ok(None)) => tokio::time::sleep(Duration::from_secs(30)).await,
            Wake::State(Err(StateError::Refused)) => tokio::time::sleep(AUTH_RETRY).await,
            Wake::State(Err(StateError::NotMember)) => continue,
            Wake::State(Err(StateError::Other(e))) | Wake::Items(Err(e)) => {
                tracing::debug!(vault = %vault, "cloud sync watch: channel error: {}", e);
                if let Ok(c) = crate::cli::egress_proxy::client(WATCH_TIMEOUT) {
                    http = c;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            Wake::Items(Ok(resp)) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    backoff = Duration::from_secs(2);
                    let body: Value = resp.json().await.unwrap_or(Value::Null);
                    let unchanged = body
                        .get("unchanged")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !unchanged
                        && pull_and_process(&state, &client, &vault, "items")
                            .await
                            .stopped
                    {
                        return;
                    }
                } else {
                    let (_, _, r) = refused(&state, &vault, resp).await;
                    tokio::time::sleep(if r.is_some() { AUTH_RETRY } else { backoff }).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
            Wake::Reconcile => {
                tracing::info!(vault = %vault, "cloud sync watch: no wake for {}s — reconciling", RECONCILE_INTERVAL.as_secs());
                if let Ok(true) = probe_state_and_pull(&state, &client, &vault, "reconcile").await {
                    return;
                }
                last_reconcile = std::time::Instant::now();
            }
            Wake::Health => {}
        }
        // Never loop without a sleep: a round that came back faster than
        // MIN_ROUND (the server did not hold the poll, or a pull did not move
        // the cursor) is padded to it.
        let rest = pace_remaining(round.elapsed());
        if !rest.is_zero() {
            tokio::time::sleep(rest).await;
        }
    }
}

/// A fallback long-poll round that comes back sooner than this is padded to
/// it, so the loop never spins.
const MIN_ROUND: Duration = Duration::from_secs(5);
/// The longest wait between retries of a member record this daemon could not
/// adopt.
const UNSETTLED_MAX: Duration = Duration::from_secs(300);

/// How long to pad a fallback round that took `elapsed`.
fn pace_remaining(elapsed: Duration) -> Duration {
    MIN_ROUND.saturating_sub(elapsed)
}

/// Paces the fallback `state?wait=1&since=` long-poll. After a pull that did
/// not settle the record (refused, no pin yet, transient), the held seq did not
/// move, and the server answers a wait on it at once. So the next wait is on
/// the SERVER's `member_seq`, and the retry sleeps with backoff
/// ([`MIN_ROUND`] doubling to [`UNSETTLED_MAX`]).
#[derive(Debug)]
struct FallbackPacer {
    wait_floor: Option<u64>,
    backoff: Duration,
}

impl FallbackPacer {
    fn new() -> Self {
        Self {
            wait_floor: None,
            backoff: MIN_ROUND,
        }
    }

    /// The `since` of the next state long-poll for a held record at `held`.
    fn since(&self, held: u64) -> u64 {
        self.wait_floor.map_or(held, |f| f.max(held))
    }

    /// After a pull triggered by a state answer at `served`: the sleep before
    /// the next round, `None` when the record settled.
    fn after_pull(&mut self, served: u64, held: u64, settled: bool) -> Option<Duration> {
        if settled || served == held {
            self.wait_floor = None;
            self.backoff = MIN_ROUND;
            return None;
        }
        self.wait_floor = Some(served);
        let wait = self.backoff;
        self.backoff = (self.backoff * 2).min(UNSETTLED_MAX);
        Some(wait)
    }
}

// ── audit shipper ────────────────────────────────────────────────────────────

/// Max rows shipped per vault per round-trip.
const AUDIT_SHIP_BATCH: u32 = 200;

/// One audit event in the ingest wire shape (`POST /device/vaults/{vid}/audit`,
/// same body as before). The backend stamps `vault_id`, `account_id` and
/// `device_id` from the signed request. Secret values, query strings and bodies
/// are never included.
#[derive(serde::Serialize)]
struct AuditEventWire {
    event_id: String,
    ts: i64,
    decision: String,
    op_id: String,
    act_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// The agent's `ag_` id (agents authenticate by AIK only).
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
}

fn event_from_row(row: &crate::audit::ApprovalRow) -> AuditEventWire {
    let action = match (&row.method, &row.path) {
        (Some(m), Some(p)) => Some(format!("{} {}", m, p)),
        (Some(m), None) => Some(m.clone()),
        (None, Some(p)) => Some(p.clone()),
        (None, None) => None,
    };
    AuditEventWire {
        event_id: row.id.clone(),
        ts: row.decided_at.unwrap_or(row.created_at),
        decision: row.status.clone(),
        op_id: row.id.clone(),
        act_kind: row.act_kind.clone(),
        service: row.service.clone(),
        action,
        target: row.target.clone(),
        // Only an `ag_` id is an agent id now (historic rows may hold a key
        // prefix: those ship without attribution).
        agent_id: row
            .agent_prefix
            .clone()
            .filter(|a| crate::identity::parse_id(a) == Some(crate::identity::IdKind::Agent)),
    }
}

/// The `audit_ceremonies` switch: ship control-plane terminal outcomes
/// alongside Use ops? Default ON. `SAFECLAW_AUDIT_CEREMONIES` beats config.
fn audit_ceremonies_enabled(cfg: &crate::cli::active::CliConfig) -> bool {
    let v = std::env::var("SAFECLAW_AUDIT_CEREMONIES")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            cfg.audit_ceremonies
                .as_ref()
                .map(|s| s.trim().to_ascii_lowercase())
        });
    !matches!(
        v.as_deref(),
        Some("off" | "0" | "false" | "no" | "disabled")
    )
}

/// Periodically ship each synced vault's unshipped audit rows.
pub async fn ship_audit_loop(state: Arc<AppState>) {
    loop {
        ship_audit_once(&state).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// One sweep across all synced vaults.
pub async fn ship_audit_once(state: &Arc<AppState>) {
    let Ok(cfg) = active::load() else {
        return;
    };
    let Some(client) = state.cloud() else {
        return;
    };
    let ceremonies = audit_ceremonies_enabled(&cfg);
    for vault in synced_vault_ids(&cfg) {
        if parked_for(&vault).is_some() {
            continue;
        }
        ship_vault_audit(state, &client, &vault, ceremonies).await;
    }
}

async fn ship_vault_audit(
    state: &Arc<AppState>,
    client: &DeviceClient,
    vault: &str,
    ship_ceremonies: bool,
) {
    let store = match state.audits.for_vault(vault) {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Some(days) = state.audit_retention_days(vault) {
        if let Some(cutoff) = retention_cutoff(days) {
            let _ = store.prune_older_than(cutoff);
        }
    }
    loop {
        let rows = match store.list_unsynced(AUDIT_SHIP_BATCH, ship_ceremonies) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(vault = %vault, "audit ship: list_unsynced failed: {}", e);
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        let events: Vec<AuditEventWire> = rows.iter().map(event_from_row).collect();
        let body = serde_json::json!({ "events": events });
        match client
            .post(
                &format!("/device/vaults/{}/audit", vault),
                &body,
                FETCH_TIMEOUT,
            )
            .await
        {
            Ok(r) if r.status().is_success() => {
                let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
                let n = ids.len();
                if let Err(e) = store.mark_synced(&ids) {
                    tracing::warn!(vault = %vault, "audit ship: mark_synced failed: {}", e);
                    return;
                }
                if (n as u32) < AUDIT_SHIP_BATCH {
                    return;
                }
            }
            Ok(r) => {
                let (status, _, _) = refused(state, vault, r).await;
                tracing::debug!(vault = %vault, status, "audit ship: backend rejected batch; retrying next tick");
                return;
            }
            Err(e) => {
                tracing::debug!(vault = %vault, "audit ship: unreachable backend: {}", e);
                return;
            }
        }
    }
}

fn retention_cutoff(days: u32) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(now - (days as i64) * 86_400)
}

// ── items ────────────────────────────────────────────────────────────────────
//
// The CONTENT sync: N sealed item rows against `/device/vaults/{vid}/items`
// (contract 8.4, same bodies as before):
//
//   GET  …/items?since=<seq>  → { items:[{item_id,version,seq,ct,sig?,signer?}], seq }
//   PUT  …/items/{item_id}    { base_version?, version, ct } → 200 {version,seq} | 409
//   GET  …/items/wait?since=<seq>  (long-poll)
//
// PULL adopts server truth (a newer version replaces a CLEAN local row; the
// cursor advances to max(seq)). PUSH is per-item CAS; a 409 reconciles under K
// (never last-writer-wins): secret/connection keep both, other ns re-apply
// ours, a delete wins over an edit.

use crate::storage::item as item_layer;

/// One row of a `/items` pull.
#[derive(Debug, Clone, serde::Deserialize)]
struct ItemRow {
    item_id: String,
    version: u64,
    #[allow(dead_code)]
    seq: u64,
    /// base64url-nopad of `suite‖nonce‖ct‖tag`.
    ct: String,
    /// A1.2 per-record signature (base64url, over the ciphertext) + the signer's
    /// self-id. Absent on unsigned (content) rows.
    #[serde(default)]
    sig: Option<String>,
    #[serde(default)]
    signer: Option<String>,
}

/// Adopt a batch of pulled item rows into the local store (server-authoritative,
/// §5): a strictly-newer `version` replaces a CLEAN local row (a dirty one is
/// left for the push-side 409 reconcile); the cursor advances
/// to the max `seq` seen. Tombstones are stored like any other row — `fold_view`
/// drops them at read time, and a later GC hard-deletes them. Returns the number
/// of rows adopted.
fn adopt_item_rows(pv: &mut PerItemVault, rows: &[ItemRow], max_seq: u64) -> Result<usize, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut adopted = 0usize;
    for row in rows {
        // Only adopt a strictly-newer version (server is authoritative, but a
        // stale replay must not clobber a fresher local row we already pushed).
        // NEVER adopt over a DIRTY local row (a local write not yet confirmed on
        // the cloud): that would silently drop our edit. A dirty row is owned by
        // the push side, whose 409 reconcile (`push_items_best_effort`) compares
        // ours with theirs and keeps both / re-applies; while the vault is locked
        // it stays dirty and is reconciled on the first push after unlock.
        let keep = pv
            .get_item(&row.item_id)
            .map(|s| row.version > s.version && s.version <= s.synced_version)
            .unwrap_or(true);
        if !keep {
            continue;
        }
        let ct = URL_SAFE_NO_PAD
            .decode(row.ct.as_bytes())
            .map_err(|e| format!("item ct not base64url: {}", e))?;
        pv.put_raw_signed(
            row.item_id.clone(),
            row.version,
            ct,
            row.sig.clone(),
            row.signer.clone(),
        );
        adopted += 1;
    }
    if max_seq > pv.items_seq {
        pv.items_seq = max_seq;
    }
    Ok(adopted)
}

/// GET `/device/vaults/{vault}/items?since=<since>` → `Ok(Some((rows, max_seq)))`,
/// or `Ok(None)` when the route answers 404. `max_seq` is the cursor the caller
/// should hold next. `since = 0` is a full snapshot (the 409 reconcile reads
/// THEIR current row from it, independent of the local cursor).
async fn fetch_item_rows(
    client: &DeviceClient,
    vault: &str,
    since: u64,
) -> Result<Option<(Vec<ItemRow>, u64)>, String> {
    let resp = client
        .get(
            &format!("/device/vaults/{}/items?since={}", vault, since),
            FETCH_TIMEOUT,
        )
        .await?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(None),
        status => {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if is_not_member(status, &body) {
                park_not_member(vault);
                return Err(parked_message(NOT_MEMBER_PARK));
            }
            if let Some(r) = crate::cloud::refusal(status, &body) {
                return Err(r.message());
            }
            return Err(format!(
                "items GET HTTP {}: {}",
                status,
                body.get("message").and_then(|m| m.as_str()).unwrap_or("")
            ));
        }
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse items response: {}", e))?;
    let rows: Vec<ItemRow> = body
        .get("items")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse items array: {}", e))?
        .unwrap_or_default();
    let max_seq = body.get("seq").and_then(|v| v.as_u64()).unwrap_or(since);
    Ok(Some((rows, max_seq)))
}

/// Pull item rows changed since the local `items_seq` cursor and adopt them.
/// No store yet (the vault has no verified record here) → nothing to adopt
/// into. Returns the number of rows adopted. Runs under the vault write lock
/// for the read-modify-write of the store.
pub async fn pull_items(
    state: &Arc<AppState>,
    client: &DeviceClient,
    vault: &str,
) -> Result<usize, String> {
    if leave_shared_to_official(vault) {
        return Ok(0);
    }
    let state_dir = &state.config.state_dir;
    let Some(since) = read_per_item_store(state_dir, vault).map(|pv| pv.items_seq) else {
        return Ok(0);
    };
    let Some((rows, max_seq)) = fetch_item_rows(client, vault, since).await? else {
        return Ok(0);
    };
    let lock = state.vault_write_lock(vault);
    let _guard = lock.lock().await;
    let Some(mut pv) = read_per_item_store(state_dir, vault) else {
        return Ok(0);
    };
    let adopted = adopt_item_rows(&mut pv, &rows, max_seq)?;
    if adopted > 0 || max_seq > since {
        write_per_item_store(state_dir, vault, &pv)?;
    }
    Ok(adopted)
}

/// Push a single item to the cloud with per-item CAS (§4). `base_version` is the
/// version the writer last read (absent → create). On `200` returns the cloud-
/// stamped `{version, seq}`; on `409` returns the conflict's `currentVersion` so
/// the caller can reconcile (re-apply on fresh, or conflict-copy — NEVER LWW).
///
/// `PushOutcome::EndpointMissing` (a 404) means the backend `/items` route isn't
/// live yet — the caller treats it as a no-op (stubbed[]).
/// `PushOutcome::Rejected` is a TERMINAL refusal ([`is_terminal_put_status`]):
/// the same bytes can never land, so retrying them is pointless.
pub enum PushOutcome {
    Ok { version: u64, seq: u64 },
    Conflict { current_version: u64 },
    EndpointMissing,
    Rejected { status: u16, error: String },
}

/// A non-2xx item PUT status the server returns for the write ITSELF (bad
/// request, plan freeze 402, owner-only / agent / record-signature gates 403,
/// too large, unprocessable): retrying the same bytes never lands. Everything
/// else non-2xx (5xx, 503 `agent_authz_unavailable`, 429 …) is transient.
fn is_terminal_put_status(status: u16) -> bool {
    matches!(status, 400 | 402 | 403 | 413 | 422)
}

pub async fn push_item(
    client: &DeviceClient,
    vault: &str,
    item_id: &str,
    base_version: Option<u64>,
    version: u64,
    ct_b64: &str,
) -> Result<PushOutcome, String> {
    // CREATE omits base_version entirely (sending 0 → 409); only include it on
    // update.
    let mut body = serde_json::json!({ "version": version, "ct": ct_b64 });
    if let Some(bv) = base_version {
        body["base_version"] = serde_json::json!(bv);
    }
    let resp = client
        .send(
            reqwest::Method::PUT,
            &format!("/device/vaults/{}/items/{}", vault, item_id),
            Some(&body),
            FETCH_TIMEOUT,
        )
        .await?;
    let status = resp.status().as_u16();
    let b: serde_json::Value = resp.json().await.unwrap_or_default();
    // A device-wide refusal is never a verdict on THIS item; neither is a
    // `not_member` claim (the vault parks, the row stays local).
    if let Some(r) = crate::cloud::refusal(status, &b) {
        return Err(r.message());
    }
    if is_not_member(status, &b) {
        park_not_member(vault);
        return Err(parked_message(NOT_MEMBER_PARK));
    }
    match status {
        200 => Ok(PushOutcome::Ok {
            version: b.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
            seq: b.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
        }),
        409 => {
            // `{conflict, currentVersion}` (0 = the row is gone).
            let current = b
                .get("currentVersion")
                .and_then(|v| v.as_u64())
                .or_else(|| b.get("version").and_then(|v| v.as_u64()))
                .unwrap_or(version);
            Ok(PushOutcome::Conflict {
                current_version: current,
            })
        }
        404 => Ok(PushOutcome::EndpointMissing),
        other if is_terminal_put_status(other) => Ok(PushOutcome::Rejected {
            status: other,
            error: b
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }),
        other => Err(format!("item PUT HTTP {}", other)),
    }
}

/// One DIRTY local row (`version > synced_version`) snapshotted for a push, so
/// the store isn't held across awaits.
struct DirtyRow {
    id: String,
    version: u64,
    synced_version: u64,
    ct: Vec<u8>,
    tombstone: bool,
}

/// `base_version` to push a dirty row with: the last version KNOWN to be on the
/// cloud (`synced_version`), so several local bumps between pushes still CAS
/// against the row the cloud actually holds instead of 409ing on themselves.
/// `synced_version == 0` ("never confirmed": a fresh local create, or a row from
/// a store that predates the tracking) is a CREATE: if the cloud has the row,
/// that 409s into the reconcile. Guessing `version - 1` instead could CAS-match
/// another device's row and silently overwrite its content.
fn push_base_version(synced_version: u64) -> Option<u64> {
    (synced_version > 0).then_some(synced_version)
}

/// How a same-item 409 resolves (§4). Never last-writer-wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictAction {
    /// Theirs already says what ours says (same live body, or both deleted):
    /// adopt theirs, write nothing.
    Adopt,
    /// Keep both: theirs stays at the canonical id, ours is written as a
    /// conflict copy; the local store converges to theirs + the copy.
    KeepBoth,
    /// Re-apply ours on top of theirs (CAS on their version), or re-create it
    /// when their row is gone.
    Reapply,
}

/// Namespaces whose same-item conflicts keep both: user-visible items a person
/// can compare and resolve. Everything else (singletons, `connecting`, legacy
/// aux …) re-applies ours, where a "(conflict copy)" row would be invisible to
/// the fold and undeletable. Console parity: `KEEP_BOTH_NS` in
/// `lib/vault-grant.ts`.
fn is_keep_both_ns(ns: item_layer::ItemNs) -> bool {
    ns.keeps_both_on_conflict()
}

/// The §4 decision for OUR dirty row vs THEIR current row (`None` = gone).
/// Delete wins over a concurrent edit (our tombstone is re-applied); an equal
/// live body is a no-op adopt; otherwise keep-both for [`is_keep_both_ns`] and
/// re-apply for the rest (incl. their tombstone vs our edit in a keep-both ns:
/// the copy keeps our value, their delete stands, as in the console).
fn decide_conflict(
    ours: &item_layer::ItemPayload,
    theirs: Option<&item_layer::ItemPayload>,
) -> ConflictAction {
    let Some(theirs) = theirs else {
        return ConflictAction::Reapply;
    };
    if ours.is_tombstone() {
        return if theirs.is_tombstone() {
            ConflictAction::Adopt
        } else {
            ConflictAction::Reapply
        };
    }
    if !theirs.is_tombstone()
        && theirs.ns == ours.ns
        && theirs.name == ours.name
        && theirs.body == ours.body
    {
        return ConflictAction::Adopt;
    }
    if is_keep_both_ns(ours.ns) {
        ConflictAction::KeepBoth
    } else {
        ConflictAction::Reapply
    }
}

/// A local-store change produced by the push loop, applied after it to a
/// FRESHLY re-read store (see [`apply_local_fixes`]).
enum LocalFix {
    /// Our push landed at `version` → the row is clean.
    Synced { id: String, version: u64 },
    /// Replace the row at `id` with `row` iff it is still at version `expect`
    /// (theirs adopted, or ours re-sealed at a fresh version and landed).
    Replace {
        id: String,
        expect: u64,
        row: pv_store::StoredItem,
    },
    /// A row known to be on the cloud (a conflict copy) → insert iff absent.
    InsertIfAbsent {
        id: String,
        row: pv_store::StoredItem,
    },
}

/// A clean row exactly as the cloud holds it (`synced_version == version`).
fn clean_row(
    version: u64,
    ct: Vec<u8>,
    tombstone: bool,
    sig: Option<String>,
    signer: Option<String>,
) -> pv_store::StoredItem {
    pv_store::StoredItem {
        version,
        ct,
        synced_version: version,
        tombstone,
        sig,
        signer,
    }
}

/// Apply the push loop's [`LocalFix`]es. Every change is version-guarded so a
/// writer that raced the push (bumped a row meanwhile) is never clobbered: its
/// newer row stays dirty and goes out on the next push. Returns `(changed,
/// content_changed)`; `content_changed` = a row's sealed content was replaced or
/// added (the unlocked cache needs a refresh).
fn apply_local_fixes(pv: &mut PerItemVault, fixes: Vec<LocalFix>) -> (bool, bool) {
    let mut changed = false;
    let mut content_changed = false;
    for fix in fixes {
        match fix {
            LocalFix::Synced { id, version } => {
                if let Some(s) = pv.items.get_mut(&id) {
                    if s.version == version && s.synced_version < version {
                        s.synced_version = version;
                        changed = true;
                    }
                }
            }
            LocalFix::Replace { id, expect, row } => {
                if pv.items.get(&id).map(|s| s.version) == Some(expect) {
                    pv.items.insert(id, row);
                    changed = true;
                    content_changed = true;
                }
            }
            LocalFix::InsertIfAbsent { id, row } => {
                if let std::collections::btree_map::Entry::Vacant(slot) = pv.items.entry(id) {
                    slot.insert(row);
                    changed = true;
                    content_changed = true;
                }
            }
        }
    }
    (changed, content_changed)
}

/// THEIR rows for the 409 reconcile: one full `/items` snapshot, fetched lazily
/// on the first resolvable conflict of a push and shared by the rest.
enum TheirRows {
    Unfetched,
    Fetched(std::collections::HashMap<String, ItemRow>),
    Unavailable,
}

/// Outcome of reconciling one 409.
enum Resolved {
    /// Resolved on the cloud; apply these to the local store.
    Fixed(Vec<LocalFix>),
    /// Not resolvable now (unreadable row, network error, raced again): the row
    /// stays dirty and is reconciled on the next push.
    LeaveDirty,
    /// `/items` is not live (404): stop the push.
    EndpointMissing,
}

/// Replace our dirty row with THEIR row (clean), guarded on our version.
fn adopt_fix(ours: &DirtyRow, theirs: &ItemRow, ct: Vec<u8>, tombstone: bool) -> LocalFix {
    LocalFix::Replace {
        id: ours.id.clone(),
        expect: ours.version,
        row: clean_row(
            theirs.version,
            ct,
            tombstone,
            theirs.sig.clone(),
            theirs.signer.clone(),
        ),
    }
}

/// THEIR current row opened under `K`: `(row, raw ct, payload)`.
type TheirItem = (ItemRow, Vec<u8>, item_layer::ItemPayload);

/// Open OUR dirty row and read THEIR current row (`None` = gone) from the full
/// `/items` snapshot (fetched once per push, shared via [`TheirRows`]).
/// `current_version == Some(0)` (a 409 on a GC'd row) skips the fetch. `Err`
/// says how to leave the row (unreadable, snapshot unavailable, endpoint gone).
async fn load_conflict_pair(
    client: &DeviceClient,
    vault_id: &str,
    keys: item_layer::VaultKeys<'_>,
    their_rows: &mut TheirRows,
    ours_row: &DirtyRow,
    current_version: Option<u64>,
) -> Result<(item_layer::ItemPayload, Option<TheirItem>), Resolved> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    type S = sudp::primitives::StdPrimitives;

    let ours = item_layer::open_wire_item::<S>(
        keys,
        vault_id,
        &ours_row.id,
        ours_row.version,
        &ours_row.ct,
    )
    .map_err(|e| {
        tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item reconcile: can't open our row ({}); left dirty", e);
        Resolved::LeaveDirty
    })?;

    let theirs_row: Option<ItemRow> = if current_version == Some(0) {
        None
    } else {
        if matches!(their_rows, TheirRows::Unfetched) {
            *their_rows = match fetch_item_rows(client, vault_id, 0).await {
                Ok(Some((rows, _))) => {
                    TheirRows::Fetched(rows.into_iter().map(|r| (r.item_id.clone(), r)).collect())
                }
                Ok(None) => return Err(Resolved::EndpointMissing),
                Err(e) => {
                    tracing::warn!(vault = %vault_id, "per-item reconcile: snapshot fetch failed ({}); rows left dirty", e);
                    TheirRows::Unavailable
                }
            };
        }
        match &*their_rows {
            TheirRows::Fetched(map) => map.get(&ours_row.id).cloned(),
            _ => return Err(Resolved::LeaveDirty),
        }
    };
    let theirs = match theirs_row {
        None => None,
        Some(r) => {
            let opened = URL_SAFE_NO_PAD
                .decode(r.ct.as_bytes())
                .map_err(|e| e.to_string())
                .and_then(|ct| {
                    item_layer::open_wire_item::<S>(keys, vault_id, &r.item_id, r.version, &ct)
                        .map(|p| (ct, p))
                        .map_err(|e| e.to_string())
                });
            match opened {
                Ok((ct, p)) => Some((r, ct, p)),
                Err(e) => {
                    tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item reconcile: can't open their row ({}); left dirty", e);
                    return Err(Resolved::LeaveDirty);
                }
            }
        }
    };
    Ok((ours, theirs))
}

/// Local fixes for a TERMINAL rejection of OUR dirty row
/// ([`is_terminal_put_status`]). The server will never take these bytes, and
/// the pull cursor has already moved past THEIR row (a pull never adopts over a
/// dirty row), so just leaving ours dirty would pin the canonical id to a value
/// only this device holds and re-offer it forever. Instead THEIR row becomes
/// the canonical one locally and, for a differing live value in a keep-both
/// namespace, OURS moves to a LOCAL conflict-copy row (the id the console would
/// use) that stays DIRTY: it is re-offered on every push and lands once the
/// entitlement returns (e.g. the plan is unfrozen). A refused delete, an equal
/// value, or another namespace (owner-only config, where a copy row would be
/// invisible to the fold) just takes theirs. `None` = nothing to take (no row
/// of theirs: a refused create), so ours stays dirty where it is.
fn rejection_fixes(
    keys: item_layer::VaultKeys<'_>,
    vault_id: &str,
    ours_row: &DirtyRow,
    ours: &item_layer::ItemPayload,
    theirs: Option<TheirItem>,
) -> Option<Vec<LocalFix>> {
    type S = sudp::primitives::StdPrimitives;
    let (r, ct, p) = theirs?;
    let mut fixes = Vec::new();
    if decide_conflict(ours, Some(&p)) == ConflictAction::KeepBoth {
        match item_layer::seal_conflict_copy::<S>(keys, vault_id, ours, r.version) {
            Ok((copy_id, copy_ct)) => fixes.push(LocalFix::InsertIfAbsent {
                id: copy_id,
                // Dirty (`synced_version` 0): pushed as a create next time.
                row: pv_store::StoredItem {
                    version: item_layer::CONFLICT_COPY_VERSION,
                    ct: copy_ct,
                    synced_version: 0,
                    tombstone: false,
                    sig: None,
                    signer: None,
                },
            }),
            Err(e) => {
                tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item rejection: seal local conflict copy failed ({}); left dirty", e);
                return None;
            }
        }
    }
    fixes.push(adopt_fix(ours_row, &r, ct, p.is_tombstone()));
    Some(fixes)
}

/// Reconcile a TERMINAL rejection of OUR dirty row: see [`rejection_fixes`].
async fn resolve_rejection(
    client: &DeviceClient,
    vault_id: &str,
    keys: item_layer::VaultKeys<'_>,
    their_rows: &mut TheirRows,
    ours_row: &DirtyRow,
) -> Resolved {
    let (ours, theirs) =
        match load_conflict_pair(client, vault_id, keys, their_rows, ours_row, None).await {
            Ok(pair) => pair,
            Err(r) => return r,
        };
    match rejection_fixes(keys, vault_id, ours_row, &ours, theirs) {
        Some(f) => Resolved::Fixed(f),
        None => Resolved::LeaveDirty,
    }
}

/// Warn ONCE per (vault, item, version, status) about a terminal rejection: a
/// row the server keeps refusing (a refused create on a frozen plan) is
/// re-offered on every push and must not flood the log.
fn warn_rejected_once(vault_id: &str, item: &str, version: u64, status: u16, error: &str) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let key = format!("{}/{}@{}:{}", vault_id, item, version, status);
    let first = SEEN
        .get_or_init(Default::default)
        .lock()
        .map(|mut seen| seen.insert(key))
        .unwrap_or(true);
    if first {
        tracing::warn!(
            vault = %vault_id, item = %item, version, status, error = %error,
            "per-item push: rejected by the server (not retryable); theirs kept canonical, ours kept as a local conflict copy where possible"
        );
    } else {
        tracing::debug!(vault = %vault_id, item = %item, version, status, "per-item push: rejected again");
    }
}

/// Reconcile one 409 on OUR dirty row (§4) under `K` (`keys`): open ours, read
/// THEIR current row from the full snapshot, then per [`decide_conflict`]:
///   - `Adopt`    → take theirs locally;
///   - `KeepBoth` → write ours as the conflict copy (CREATE at version 1 under
///     `conflict_copy_id(id_seed, ns, name, their_version)`; a 409 on it means
///     an earlier attempt already wrote it), then take theirs locally;
///   - `Reapply`  → re-seal ours at `their_version + 1` and CAS on their version
///     (their row gone → re-create ours as-is).
///
/// A terminal rejection of the extra write falls back to [`rejection_fixes`].
/// At most ONE extra write per item per push: a second 409 leaves the row dirty
/// for the next push (bounded, no loop). Nothing local changes unless the cloud
/// write it depends on landed (or was refused for good), so a retry re-derives
/// the same decision and the same copy id (idempotent).
async fn resolve_conflict(
    client: &DeviceClient,
    vault_id: &str,
    keys: item_layer::VaultKeys<'_>,
    their_rows: &mut TheirRows,
    ours_row: &DirtyRow,
    current_version: u64,
) -> Resolved {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    type S = sudp::primitives::StdPrimitives;

    let (ours, theirs) = match load_conflict_pair(
        client,
        vault_id,
        keys,
        their_rows,
        ours_row,
        Some(current_version),
    )
    .await
    {
        Ok(pair) => pair,
        Err(r) => return r,
    };

    match decide_conflict(&ours, theirs.as_ref().map(|(_, _, p)| p)) {
        ConflictAction::Adopt => {
            let Some((r, ct, p)) = theirs else {
                return Resolved::LeaveDirty;
            };
            Resolved::Fixed(vec![adopt_fix(ours_row, &r, ct, p.is_tombstone())])
        }
        ConflictAction::KeepBoth => {
            let Some((r, ct, p)) = theirs else {
                return Resolved::LeaveDirty;
            };
            let (copy_id, copy_ct) = match item_layer::seal_conflict_copy::<S>(
                keys, vault_id, &ours, r.version,
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item 409: seal conflict copy failed ({}); left dirty", e);
                    return Resolved::LeaveDirty;
                }
            };
            let mut fixes = Vec::new();
            match push_item(
                client,
                vault_id,
                &copy_id,
                None,
                item_layer::CONFLICT_COPY_VERSION,
                &URL_SAFE_NO_PAD.encode(&copy_ct),
            )
            .await
            {
                Ok(PushOutcome::Ok { .. }) => fixes.push(LocalFix::InsertIfAbsent {
                    id: copy_id.clone(),
                    row: clean_row(
                        item_layer::CONFLICT_COPY_VERSION,
                        copy_ct,
                        false,
                        None,
                        None,
                    ),
                }),
                Ok(PushOutcome::Conflict { .. }) => {
                    // The copy already exists (an earlier attempt wrote it):
                    // idempotent. Mirror it locally if the snapshot has it.
                    if let TheirRows::Fetched(map) = &*their_rows {
                        if let Some(c) = map.get(&copy_id) {
                            if let Ok(cct) = URL_SAFE_NO_PAD.decode(c.ct.as_bytes()) {
                                fixes.push(LocalFix::InsertIfAbsent {
                                    id: copy_id.clone(),
                                    row: clean_row(
                                        c.version,
                                        cct,
                                        false,
                                        c.sig.clone(),
                                        c.signer.clone(),
                                    ),
                                });
                            }
                        }
                    }
                }
                Ok(PushOutcome::EndpointMissing) => return Resolved::EndpointMissing,
                Ok(PushOutcome::Rejected { status, error }) => {
                    // The copy itself is refused for good (a NEW item on a frozen
                    // plan): keep it as a LOCAL dirty copy and take theirs.
                    warn_rejected_once(
                        vault_id,
                        &copy_id,
                        item_layer::CONFLICT_COPY_VERSION,
                        status,
                        &error,
                    );
                    return match rejection_fixes(keys, vault_id, ours_row, &ours, Some((r, ct, p)))
                    {
                        Some(f) => Resolved::Fixed(f),
                        None => Resolved::LeaveDirty,
                    };
                }
                Err(e) => {
                    // Ours stays dirty; the retry re-targets the same copy id.
                    tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item 409: conflict copy write failed ({}); left dirty", e);
                    return Resolved::LeaveDirty;
                }
            }
            tracing::info!(
                vault = %vault_id, item = %ours_row.id, copy = %copy_id, their_version = r.version,
                "per-item 409: kept both (theirs canonical, ours as conflict copy)"
            );
            fixes.push(adopt_fix(ours_row, &r, ct, p.is_tombstone()));
            Resolved::Fixed(fixes)
        }
        ConflictAction::Reapply => {
            let (base, version, ct) = match &theirs {
                // Their row is gone (GC'd): re-create ours as-is, at OUR version
                // with its existing ct (sealed at that version, so the AAD
                // matches). The backend takes a create at any version
                // (`coalesce(p_version, 1)`); re-creating at 1 like the console
                // would be ignored by a device still holding the GC'd row at a
                // higher version (a pull adopts strictly-newer only).
                None => (None, ours_row.version, ours_row.ct.clone()),
                Some((r, _, _)) => {
                    let v = r.version + 1;
                    match item_layer::seal_wire_item::<S>(keys, vault_id, &ours_row.id, v, &ours) {
                        Ok(ct) => (Some(r.version), v, ct),
                        Err(e) => {
                            tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item 409: re-seal failed ({}); left dirty", e);
                            return Resolved::LeaveDirty;
                        }
                    }
                }
            };
            match push_item(
                client,
                vault_id,
                &ours_row.id,
                base,
                version,
                &URL_SAFE_NO_PAD.encode(&ct),
            )
            .await
            {
                Ok(PushOutcome::Ok { .. }) => {
                    let fix = if version == ours_row.version {
                        LocalFix::Synced {
                            id: ours_row.id.clone(),
                            version,
                        }
                    } else {
                        LocalFix::Replace {
                            id: ours_row.id.clone(),
                            expect: ours_row.version,
                            row: clean_row(version, ct, ours.is_tombstone(), None, None),
                        }
                    };
                    Resolved::Fixed(vec![fix])
                }
                // Raced again: one retry per item per push; the next push reconciles.
                Ok(PushOutcome::Conflict { .. }) => Resolved::LeaveDirty,
                Ok(PushOutcome::EndpointMissing) => Resolved::EndpointMissing,
                Ok(PushOutcome::Rejected { status, error }) => {
                    warn_rejected_once(vault_id, &ours_row.id, version, status, &error);
                    match rejection_fixes(keys, vault_id, ours_row, &ours, theirs) {
                        Some(f) => Resolved::Fixed(f),
                        None => Resolved::LeaveDirty,
                    }
                }
                Err(e) => {
                    tracing::warn!(vault = %vault_id, item = %ours_row.id, "per-item 409: re-apply failed ({}); left dirty", e);
                    Resolved::LeaveDirty
                }
            }
        }
    }
}

/// Push every LOCAL item whose version is ahead of what the cloud last confirmed
/// (`version > synced_version`), each with per-item CAS against the last version
/// known to be on the cloud ([`push_base_version`]). Writes go before deletes.
///
/// A 409 (someone else wrote the same item) is reconciled inline by
/// [`resolve_conflict`], never last-writer-wins:
///   - `secret` / `connection`: if theirs equals ours, adopt it; otherwise KEEP
///     BOTH: theirs stays at the canonical id, ours is written as a conflict
///     copy (`"<name> (conflict copy)"`, version 1, id
///     `conflict_copy_id(id_seed, ns, name, their_version)`, byte-identical to
///     the console's `putConflictCopy`), and the local store converges to
///     theirs + the copy;
///   - every other namespace: re-apply ours on their fresh version;
///   - our tombstone vs their edit: delete wins (our tombstone is re-applied).
///
/// A TERMINAL rejection (400/402/403/413/422) is reconciled by
/// [`resolve_rejection`]: theirs is taken at the canonical id and ours, where it
/// differs, is kept as a LOCAL dirty conflict copy (warned once).
///
/// Reconciling needs `K` (open ours/theirs, seal the copy), taken from the
/// unlocked session ([`AppState::cloned_state_key`]). A LOCKED vault leaves the
/// row dirty (nothing dropped, nothing copied); the pull side never adopts over
/// a dirty row, so it is reconciled on the first push after unlock. One
/// conflict never stops the loop for the other items.
pub async fn push_items_best_effort(state: &Arc<AppState>, vault_id: &str) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let Some(client) = state.cloud() else { return };
    let client = &client;
    let state_dir = &state.config.state_dir;

    let Some(pv) = read_per_item_store(state_dir, vault_id) else {
        return;
    };
    // Snapshot only the DIRTY rows (version > synced_version) so we don't hold
    // the store across awaits. Clean rows (already confirmed on the cloud) are
    // skipped outright — re-offering them cost one 409 round-trip PER ROW on
    // EVERY sync (the "sc sync is slow and nothing even changed" bug).
    let mut rows: Vec<DirtyRow> = pv
        .items
        .iter()
        .filter(|(_, s)| s.version > s.synced_version)
        .map(|(id, s)| DirtyRow {
            id: id.clone(),
            version: s.version,
            synced_version: s.synced_version,
            ct: s.ct.clone(),
            tombstone: s.tombstone,
        })
        .collect();
    drop(pv);
    if rows.is_empty() {
        return;
    }
    // Writes BEFORE deletes: push every live row first, tombstones last (stable
    // sort keeps the id order within each group). A completed connect writes
    // its `connection`/secret rows AND a tombstone for the old `connecting` row
    // in one batch; if the tombstone reached the cloud first, a syncing console
    // would briefly see the connect withdrawn with no connection yet ("not
    // configured"). Ordering the delete last means every intermediate snapshot
    // is either still-connecting or fully-connected, never a dangling gap. A
    // 409 is reconciled inline, so the ordering holds for re-applied rows too.
    rows.sort_by_key(|r| r.tombstone);

    // K for the 409 reconcile — present only while the vault is unlocked.
    let k = state.cloned_state_key(vault_id);
    let keys = k
        .as_ref()
        .map(|m| item_layer::VaultKeys::from_material(m.as_slice()));

    // A conflict/error on ONE item says nothing about the others (each item_id
    // is independent), so we NEVER stop the loop early — doing so would strand
    // every item ordered after the first conflict.
    let mut their_rows = TheirRows::Unfetched;
    let mut endpoint_missing = false;
    let mut left_dirty = 0usize;
    let mut fixes: Vec<LocalFix> = Vec::new();
    for row in &rows {
        let base_version = push_base_version(row.synced_version);
        let ct_b64 = URL_SAFE_NO_PAD.encode(&row.ct);
        match push_item(
            client,
            vault_id,
            &row.id,
            base_version,
            row.version,
            &ct_b64,
        )
        .await
        {
            Ok(PushOutcome::Ok { .. }) => fixes.push(LocalFix::Synced {
                id: row.id.clone(),
                version: row.version,
            }),
            Ok(PushOutcome::EndpointMissing) => {
                endpoint_missing = true;
                break; // the whole /items endpoint is down — nothing more to try
            }
            Ok(PushOutcome::Conflict { current_version }) => {
                let Some(keys) = keys else {
                    tracing::debug!(
                        vault = %vault_id, item = %row.id, current_version,
                        "per-item push: 409 on a locked vault; left dirty until unlock"
                    );
                    left_dirty += 1;
                    continue;
                };
                match resolve_conflict(
                    client,
                    vault_id,
                    keys,
                    &mut their_rows,
                    row,
                    current_version,
                )
                .await
                {
                    Resolved::Fixed(f) => fixes.extend(f),
                    Resolved::LeaveDirty => left_dirty += 1,
                    Resolved::EndpointMissing => {
                        endpoint_missing = true;
                        break;
                    }
                }
            }
            Ok(PushOutcome::Rejected { status, error }) => {
                // Terminal (400/402/403/413/422): these bytes never land. Take
                // theirs, keep ours as a local dirty conflict copy (see
                // `rejection_fixes`); locked (no K) → left dirty.
                warn_rejected_once(vault_id, &row.id, row.version, status, &error);
                let Some(keys) = keys else {
                    left_dirty += 1;
                    continue;
                };
                match resolve_rejection(client, vault_id, keys, &mut their_rows, row).await {
                    Resolved::Fixed(f) => fixes.extend(f),
                    Resolved::LeaveDirty => left_dirty += 1,
                    Resolved::EndpointMissing => {
                        endpoint_missing = true;
                        break;
                    }
                }
            }
            Err(e) => {
                // Transient — skip this item, keep trying the others.
                tracing::warn!(vault = %vault_id, item = %row.id, "per-item push failed: {}", e);
            }
        }
    }
    // Apply what landed — re-read the store (a writer may have raced us); every
    // change is guarded on the exact version we pushed, so a row bumped
    // meanwhile stays dirty and goes out on the next sync.
    let mut content_changed = false;
    if !fixes.is_empty() {
        let lock = state.vault_write_lock(vault_id);
        let _guard = lock.lock().await;
        if let Some(mut pv) = read_per_item_store(state_dir, vault_id) {
            let (changed, content) = apply_local_fixes(&mut pv, fixes);
            if changed {
                match write_per_item_store(state_dir, vault_id, &pv) {
                    Ok(()) => content_changed = content,
                    Err(e) => {
                        tracing::warn!(vault = %vault_id, "per-item push: local write-back failed: {}", e)
                    }
                }
            }
        }
    }
    // Adopted theirs / added a conflict copy → serve it without a re-unlock.
    if content_changed {
        refresh_after_item_pull(state, vault_id);
    }
    tracing::debug!(
        vault = %vault_id, left_dirty, endpoint_missing,
        "per-item push: dirty items pushed"
    );
}

#[cfg(test)]
mod peritem_tests {
    use super::*;
    use crate::storage::item::{ItemNs, VaultKeys};
    use crate::storage::sealed_vault::PerItemVault;
    use sudp::primitives::StdPrimitives;

    fn empty_pv() -> PerItemVault {
        PerItemVault::new()
    }

    /// Adopt replaces a strictly-newer version and advances the cursor; a stale
    /// (<= local) version is ignored (no clobber of a fresher local push).
    #[test]
    fn adopt_replaces_newer_and_advances_cursor() {
        let k = [0x42u8; 32];
        let vid = "v";
        let mut pv = empty_pv();
        // Local row at version 2.
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "A",
                2,
                &crate::storage::item::ItemPayload::secret_live("A", "local"),
            )
            .unwrap();
        // ...confirmed on the cloud (clean): only a clean row is adoptable.
        pv.items.get_mut(&id).unwrap().synced_version = 2;

        // A stale row (version 1) must NOT replace it.
        let stale = ItemRow {
            item_id: id.clone(),
            version: 1,
            seq: 5,
            ct: "AAAA".into(),
            sig: None,
            signer: None,
        };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&stale), 5).unwrap();
        assert_eq!(n, 0, "stale version ignored");
        assert_eq!(pv.get_item(&id).unwrap().version, 2);
        assert_eq!(pv.items_seq, 5, "cursor still advances to max seq");

        // A newer row (version 3) replaces it (raw ct adopted verbatim).
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let newer_ct = URL_SAFE_NO_PAD.encode([1u8, 2, 3, 4]);
        let newer = ItemRow {
            item_id: id.clone(),
            version: 3,
            seq: 9,
            ct: newer_ct,
            sig: None,
            signer: None,
        };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&newer), 9).unwrap();
        assert_eq!(n, 1);
        assert_eq!(pv.get_item(&id).unwrap().version, 3);
        assert_eq!(pv.get_item(&id).unwrap().ct, vec![1u8, 2, 3, 4]);
        assert_eq!(pv.items_seq, 9);
    }

    /// A pull NEVER adopts over a DIRTY local row (an unpushed local write):
    /// that silently dropped our edit. The push-side 409 reconcile owns it; the
    /// cursor still advances.
    #[test]
    fn adopt_never_clobbers_dirty_row() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let k = [0x42u8; 32];
        let mut pv = empty_pv();
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                "v",
                ItemNs::Secret,
                "A",
                2,
                &crate::storage::item::ItemPayload::secret_live("A", "ours"),
            )
            .unwrap();
        pv.items.get_mut(&id).unwrap().synced_version = 1; // v2 = local edit, not pushed
        let ours_ct = pv.get_item(&id).unwrap().ct.clone();
        let theirs = ItemRow {
            item_id: id.clone(),
            version: 3,
            seq: 9,
            ct: URL_SAFE_NO_PAD.encode([9u8; 4]),
            sig: None,
            signer: None,
        };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&theirs), 9).unwrap();
        assert_eq!(n, 0, "dirty row is left to the push reconcile");
        assert_eq!(pv.get_item(&id).unwrap().version, 2);
        assert_eq!(pv.get_item(&id).unwrap().ct, ours_ct);
        assert_eq!(pv.items_seq, 9, "cursor still advances");
    }

    /// base_version = the last version known on the cloud, so N local bumps
    /// between pushes CAS against the cloud's row (no self-inflicted 409 → no
    /// spurious conflict copy). Never confirmed (0) is a CREATE, never a
    /// `version - 1` guess that could CAS-clobber another device's row.
    #[test]
    fn push_base_version_uses_synced_version() {
        assert_eq!(push_base_version(4), Some(4), "last confirmed version");
        assert_eq!(push_base_version(0), None, "never confirmed → create");
    }

    /// Terminal status classification: only the server's refusals of the write
    /// itself are terminal; 5xx / 503 / 429 / 401 stay transient.
    #[test]
    fn terminal_put_statuses() {
        for s in [400u16, 402, 403, 413, 422] {
            assert!(is_terminal_put_status(s), "{s}");
        }
        for s in [401u16, 404, 409, 429, 500, 502, 503] {
            assert!(!is_terminal_put_status(s), "{s}");
        }
    }

    /// A terminal rejection takes THEIRS at the canonical id and keeps OURS as
    /// a LOCAL, DIRTY conflict copy (re-offered on every push); a refused
    /// create with no row of theirs stays dirty; a refused delete just adopts.
    #[test]
    fn rejection_keeps_ours_as_local_dirty_copy() {
        use crate::storage::item::{self as il, ItemPayload};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let k = [0x42u8; 32];
        let vid = "v";
        let keys = VaultKeys::single(&k);
        let mut pv = empty_pv();
        // Ours: local edit at v3 (cloud last confirmed v2).
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                keys,
                vid,
                ItemNs::Secret,
                "A",
                3,
                &ItemPayload::secret_live("A", "ours"),
            )
            .unwrap();
        pv.items.get_mut(&id).unwrap().synced_version = 2;
        let s = pv.get_item(&id).unwrap().clone();
        let dirty = DirtyRow {
            id: id.clone(),
            version: s.version,
            synced_version: s.synced_version,
            ct: s.ct.clone(),
            tombstone: false,
        };
        let ours = il::open_wire_item::<StdPrimitives>(keys, vid, &id, 3, &s.ct).unwrap();
        // Theirs: v5 on the cloud with a different value.
        let their_payload = ItemPayload::secret_live("A", "theirs");
        let their_ct =
            il::seal_wire_item::<StdPrimitives>(keys, vid, &id, 5, &their_payload).unwrap();
        let their_row = ItemRow {
            item_id: id.clone(),
            version: 5,
            seq: 9,
            ct: URL_SAFE_NO_PAD.encode(&their_ct),
            sig: None,
            signer: None,
        };

        // Refused create (no row of theirs): nothing to take, ours stays dirty.
        assert!(rejection_fixes(keys, vid, &dirty, &ours, None).is_none());

        let fixes = rejection_fixes(
            keys,
            vid,
            &dirty,
            &ours,
            Some((their_row.clone(), their_ct.clone(), their_payload.clone())),
        )
        .unwrap();
        let (changed, content) = apply_local_fixes(&mut pv, fixes);
        assert!(changed && content);
        // Canonical id = theirs, clean.
        let canon = pv.get_item(&id).unwrap();
        assert_eq!((canon.version, canon.synced_version), (5, 5));
        assert_eq!(canon.ct, their_ct);
        // Ours lives on as a DIRTY local conflict copy at the console's id.
        let (copy_id, _) = il::seal_conflict_copy::<StdPrimitives>(keys, vid, &ours, 5).unwrap();
        let copy = pv.get_item(&copy_id).expect("local conflict copy");
        assert_eq!(
            (copy.version, copy.synced_version),
            (il::CONFLICT_COPY_VERSION, 0)
        );
        let opened =
            il::open_wire_item::<StdPrimitives>(keys, vid, &copy_id, copy.version, &copy.ct)
                .unwrap();
        assert_eq!(opened.name, il::conflict_copy_name("A"));
        assert_eq!(opened.body, ours.body);
        // Next push offers it as a create.
        assert_eq!(push_base_version(copy.synced_version), None);

        // A refused DELETE just adopts theirs (no copy of a tombstone).
        let tomb = ItemPayload::tombstone(ItemNs::Secret, "A");
        let fixes = rejection_fixes(
            keys,
            vid,
            &dirty,
            &tomb,
            Some((their_row, their_ct, their_payload)),
        )
        .unwrap();
        assert_eq!(fixes.len(), 1, "adopt only");
    }

    /// The §4 decision table (console parity: KEEP_BOTH_NS = secret, connection).
    #[test]
    fn decide_conflict_table() {
        use crate::storage::item::ItemPayload;
        let live = |ns, name: &str, v: serde_json::Value| ItemPayload::live(ns, name, v);
        let tomb = |ns, name: &str| ItemPayload::tombstone(ns, name);
        let s_ours = live(ItemNs::Secret, "T", serde_json::json!("ours"));
        let s_theirs = live(ItemNs::Secret, "T", serde_json::json!("theirs"));
        let s_same = live(ItemNs::Secret, "T", serde_json::json!("ours"));

        // Equal live body → adopt, no copy.
        assert_eq!(
            decide_conflict(&s_ours, Some(&s_same)),
            ConflictAction::Adopt
        );
        // Genuine same-item conflict in a keep-both ns → keep both.
        assert_eq!(
            decide_conflict(&s_ours, Some(&s_theirs)),
            ConflictAction::KeepBoth
        );
        let c_ours = live(ItemNs::Connection, "gmail", serde_json::json!({"a": 1}));
        let c_theirs = live(ItemNs::Connection, "gmail", serde_json::json!({"a": 2}));
        assert_eq!(
            decide_conflict(&c_ours, Some(&c_theirs)),
            ConflictAction::KeepBoth
        );
        // Their delete vs our edit (keep-both ns) → copy keeps ours, delete stands.
        assert_eq!(
            decide_conflict(&s_ours, Some(&tomb(ItemNs::Secret, "T"))),
            ConflictAction::KeepBoth
        );
        // Other namespaces re-apply ours on the fresh version.
        for ns in [
            ItemNs::Policy,
            ItemNs::Stores,
            ItemNs::StoreOrder,
            ItemNs::Connecting,
        ] {
            let ours = live(ns, "", serde_json::json!({"x": 1}));
            let theirs = live(ns, "", serde_json::json!({"x": 2}));
            assert_eq!(
                decide_conflict(&ours, Some(&theirs)),
                ConflictAction::Reapply,
                "{ns:?}"
            );
            assert_eq!(
                decide_conflict(&ours, Some(&ours.clone())),
                ConflictAction::Adopt,
                "{ns:?}"
            );
        }
        // Our delete vs their edit → delete wins (re-apply the tombstone).
        assert_eq!(
            decide_conflict(&tomb(ItemNs::Secret, "T"), Some(&s_theirs)),
            ConflictAction::Reapply
        );
        // Both deleted → adopt.
        assert_eq!(
            decide_conflict(&tomb(ItemNs::Secret, "T"), Some(&tomb(ItemNs::Secret, "T"))),
            ConflictAction::Adopt
        );
        // Their row is gone → re-create ours.
        assert_eq!(decide_conflict(&s_ours, None), ConflictAction::Reapply);
    }

    /// Post-push local fixes are version-guarded: a row a writer bumped during
    /// the push is never clobbered (it stays dirty for the next push), and a
    /// conflict copy is inserted only if absent (idempotent on retry).
    #[test]
    fn apply_local_fixes_is_guarded_and_idempotent() {
        let k = [0x42u8; 32];
        let mut pv = empty_pv();
        let put = |pv: &mut PerItemVault, name: &str, v: u64| {
            pv.seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                "v",
                ItemNs::Secret,
                name,
                v,
                &crate::storage::item::ItemPayload::secret_live(name, "x"),
            )
            .unwrap()
        };
        let a = put(&mut pv, "A", 2);
        let b = put(&mut pv, "B", 5); // raced: pushed at 4, bumped to 5 meanwhile
        let c = put(&mut pv, "C", 3);

        let fixes = vec![
            // A: theirs adopted at v3 (we pushed/held v2).
            LocalFix::Replace {
                id: a.clone(),
                expect: 2,
                row: clean_row(3, vec![7u8; 4], false, None, None),
            },
            // B: adopt guarded on v4, but the row is now v5 → untouched.
            LocalFix::Replace {
                id: b.clone(),
                expect: 4,
                row: clean_row(6, vec![8u8; 4], false, None, None),
            },
            // C: our push landed.
            LocalFix::Synced {
                id: c.clone(),
                version: 3,
            },
            // A conflict copy, inserted once.
            LocalFix::InsertIfAbsent {
                id: "copy".into(),
                row: clean_row(1, vec![1u8; 4], false, None, None),
            },
        ];
        let (changed, content) = apply_local_fixes(&mut pv, fixes);
        assert!(changed && content);
        let ra = pv.get_item(&a).unwrap();
        assert_eq!(
            (ra.version, ra.synced_version, ra.ct.clone()),
            (3, 3, vec![7u8; 4])
        );
        let rb = pv.get_item(&b).unwrap();
        assert_eq!(rb.version, 5);
        assert!(rb.version > rb.synced_version, "raced row stays dirty");
        let rc = pv.get_item(&c).unwrap();
        assert_eq!(rc.synced_version, 3);
        assert_eq!(pv.get_item("copy").unwrap().version, 1);

        // Retry: the copy is already there → no-op; nothing else changes.
        let (changed2, content2) = apply_local_fixes(
            &mut pv,
            vec![LocalFix::InsertIfAbsent {
                id: "copy".into(),
                row: clean_row(1, vec![2u8; 4], false, None, None),
            }],
        );
        assert!(!changed2 && !content2);
        assert_eq!(pv.get_item("copy").unwrap().ct, vec![1u8; 4]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vault_list_parses_both_shapes_and_skips_junk() {
        let arr = serde_json::json!([
            { "vault_id": "v1", "label": "Personal", "kind": "personal", "role": "owner" },
            { "vault_id": "v2", "kind": "team", "role": "member" },
            { "role": "owner" },
        ]);
        let got = parse_vault_list(&arr);
        assert_eq!(
            got,
            vec![
                DiscoveredVault {
                    id: "v1".into(),
                    label: Some("Personal".into()),
                    kind: Some("personal".into())
                },
                DiscoveredVault {
                    id: "v2".into(),
                    label: None,
                    kind: Some("team".into())
                },
            ]
        );
        assert_eq!(
            parse_vault_list(&serde_json::json!({ "vaults": arr })).len(),
            2
        );
        assert!(parse_vault_list(&serde_json::json!("x")).is_empty());
    }

    #[test]
    fn state_parses_status_tombstone_and_seqs() {
        let s = parse_state(&serde_json::json!({
            "status": "deleted",
            "tombstone": { "sig": "c2ln", "signer": "us_x" },
            "member_seq": 7, "items_seq": 40,
        }));
        assert!(s.deleted);
        assert_eq!(s.tombstone, Some(("c2ln".into(), "us_x".into())));
        assert_eq!((s.member_seq, s.items_seq), (7, 40));
        let live = parse_state(&serde_json::json!({ "status": "live", "member_seq": 1 }));
        assert!(!live.deleted && live.tombstone.is_none() && live.items_seq == 0);
    }

    /// A deleted status destroys local state ONLY with an owner-signed tombstone
    /// that verifies against the stored record: unsigned, forged, or no local
    /// store at all → never.
    #[test]
    fn only_a_verified_tombstone_drops() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::sealed_vault::{MemberRecord, RecordMember};
        use base64::{engine::general_purpose::STANDARD, Engine};
        let dir = tempdir().unwrap();
        let vault = "vault-tomb";
        let owner = UikRoot::from_root([0x11; 32]);
        let oid = owner.user_id();
        let grant = owner
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &oid, "owner", 0));
        let mut members = std::collections::BTreeMap::new();
        members.insert(
            oid.clone(),
            RecordMember {
                user_id: oid.clone(),
                sig_pub: owner.signing().public_bytes().to_vec(),
                role: crate::storage::plaintext::MemberRole::Owner,
                role_sig: grant.to_vec(),
            },
        );
        let pv = PerItemVault {
            record: Some(MemberRecord {
                anchor: owner.signing().public_bytes().to_vec(),
                members,
                generation: 0,
                rekey_proof: None,
                delegation_log: vec![],
                root_succession: vec![],
                seq: 1,
                hash: vec![],
                reader: oid.clone(),
            }),
            ..PerItemVault::new()
        };
        let deleted = |tomb: Option<(String, String)>| VaultStateResp {
            deleted: true,
            tombstone: tomb,
            member_seq: 1,
            items_seq: 0,
        };
        let sig = STANDARD.encode(
            owner
                .signing()
                .sign(&crate::identity::vault_tombstone_input(vault)),
        );
        // No local store: nothing to drop.
        assert!(!tombstone_verified(
            dir.path(),
            vault,
            &deleted(Some((sig.clone(), oid.clone())))
        ));
        std::fs::create_dir_all(dir.path().join("vaults").join(vault)).unwrap();
        write_per_item_store(dir.path(), vault, &pv).unwrap();
        assert!(
            !tombstone_verified(dir.path(), vault, &deleted(None)),
            "unsigned"
        );
        let forged = STANDARD.encode(
            UikRoot::from_root([0x12; 32])
                .signing()
                .sign(&crate::identity::vault_tombstone_input(vault)),
        );
        assert!(
            !tombstone_verified(dir.path(), vault, &deleted(Some((forged, oid.clone())))),
            "forged"
        );
        assert!(
            tombstone_verified(dir.path(), vault, &deleted(Some((sig, oid)))),
            "owner-signed"
        );
    }

    /// Only `ag_` ids ship as agent attribution; a historic api-key prefix in a
    /// local audit row ships without one.
    #[test]
    fn audit_wire_attributes_agents_by_ag_id_only() {
        let row = |agent: Option<&str>| crate::audit::ApprovalRow {
            id: "op-1".into(),
            created_at: 1,
            decided_at: Some(2),
            expires_at: 3,
            status: "approved".into(),
            act_kind: "use".into(),
            service: None,
            method: Some("GET".into()),
            path: Some("/x".into()),
            target: None,
            reason: None,
            credential_id: None,
            upstream_status: None,
            agent_prefix: agent.map(str::to_string),
        };
        let ag = "ag_abcdefghijklmnopqrstuvwxyz234567";
        assert_eq!(event_from_row(&row(Some(ag))).agent_id.as_deref(), Some(ag));
        assert_eq!(event_from_row(&row(Some("sc_agent_abc"))).agent_id, None);
        assert_eq!(event_from_row(&row(None)).agent_id, None);
    }

    #[test]
    fn audit_ceremonies_switch() {
        let cfg = |v: Option<&str>| crate::cli::active::CliConfig {
            audit_ceremonies: v.map(str::to_string),
            ..Default::default()
        };
        assert!(audit_ceremonies_enabled(&cfg(None)));
        assert!(audit_ceremonies_enabled(&cfg(Some("auto"))));
        assert!(!audit_ceremonies_enabled(&cfg(Some("off"))));
    }

    /// `forget_vault` removes a known vault by vid alone and is idempotent.
    /// (Drives the delete path's CLI-config cleanup.) Runs against a temp HOME.
    #[test]
    fn forget_vault_by_vid_is_idempotent() {
        use crate::cli::active::{self, CliConfig, KnownVault};
        let home = tempdir().unwrap();
        // active.rs resolves config via dirs::home_dir() → $HOME.
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());

        let cfg = CliConfig {
            daemon: Some("http://localhost:1".into()),
            vault: Some("vid-A".into()),
            known_vaults: vec![
                KnownVault {
                    daemon: "http://localhost:1".into(),
                    vault: "vid-A".into(),
                    label: None,
                    kind: None,
                },
                KnownVault {
                    daemon: "http://localhost:1".into(),
                    vault: "vid-B".into(),
                    label: None,
                    kind: None,
                },
            ],
            ..Default::default()
        };
        active::save(&cfg).unwrap();

        // Remove the ACTIVE vault by vid: dropped from the catalog AND cleared
        // active. The write also migrates the legacy config-field entries into
        // the catalog file (`known_vaults.toml`) and clears the field.
        assert_eq!(active::forget_vault("vid-A"), Ok(true));
        let after = active::load().unwrap();
        assert!(after.vault.is_none());
        assert!(after.daemon.is_none());
        assert!(
            after.known_vaults.is_empty(),
            "legacy field migrated to the file"
        );
        // Dropping the ACTIVE vault leaves the deleted-upstream breadcrumb so
        // `sc status` / `resolve_active` can say "re-pair", not "no vaults yet".
        assert_eq!(after.vault_deleted_upstream.as_deref(), Some("vid-A"));
        let known = active::known_vaults();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].vault, "vid-B");

        // Idempotent: forgetting it again is a no-op (Ok(false)).
        assert_eq!(active::forget_vault("vid-A"), Ok(false));
        // A non-active known vault: removed, active untouched — and no
        // breadcrumb overwrite (vid-A is still the one worth reporting).
        assert_eq!(active::forget_vault("vid-B"), Ok(true));
        assert!(active::known_vaults().is_empty());
        assert_eq!(
            active::load().unwrap().vault_deleted_upstream.as_deref(),
            Some("vid-A")
        );

        // The next successful pairing/selection clears the breadcrumb.
        active::put_active("http://localhost:1", "vid-C").unwrap();
        assert!(active::load().unwrap().vault_deleted_upstream.is_none());

        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    /// The fallback long-poll never re-waits on a held seq the server already
    /// answered past when the pull did not adopt, and backs off between
    /// retries; a settled record resets both. A fast round is padded.
    #[test]
    fn fallback_pacer_never_storms_on_an_unadopted_record() {
        let mut p = FallbackPacer::new();
        assert_eq!(p.since(3), 3);
        // Served 5, held 3, not adopted (refused / no pin / transient).
        assert_eq!(p.after_pull(5, 3, false), Some(MIN_ROUND));
        assert_eq!(p.since(3), 5, "wait on the server's seq, not the held one");
        assert_eq!(p.after_pull(5, 3, false), Some(MIN_ROUND * 2));
        for _ in 0..10 {
            p.after_pull(5, 3, false);
        }
        assert_eq!(p.after_pull(5, 3, false), Some(UNSETTLED_MAX));
        // Adopted: back to waiting on the held seq, no extra sleep.
        assert_eq!(p.after_pull(5, 3, true), None);
        assert_eq!(p.since(5), 5);
        assert_eq!(p.after_pull(6, 6, false), None, "nothing to adopt");
        // A rolled-back server seq never lowers the wait below the held one.
        p.after_pull(2, 4, false);
        assert_eq!(p.since(4), 4);
        // Every round lasts at least MIN_ROUND.
        assert_eq!(pace_remaining(Duration::ZERO), MIN_ROUND);
        assert_eq!(
            pace_remaining(Duration::from_secs(2)),
            MIN_ROUND - Duration::from_secs(2)
        );
        assert_eq!(pace_remaining(Duration::from_secs(30)), Duration::ZERO);
    }

    /// A fake backend whose every device route answers `403 not_member`.
    async fn not_member_backend() -> String {
        use axum::{http::StatusCode, routing::any, Json, Router};
        let app = Router::new().fallback(any(|| async {
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "not_member", "message": "not a member"})),
            )
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{}", addr)
    }

    /// `403 not_member` is a claim, not a verified removal: the vault parks
    /// (its sync pauses) and its local state stays.
    #[tokio::test]
    async fn not_member_parks_the_vault_and_keeps_local_state() {
        assert!(is_not_member(
            403,
            &serde_json::json!({"error": "not_member"})
        ));
        assert!(!is_not_member(
            403,
            &serde_json::json!({"code": "SC_DEVICE_REVOKED"})
        ));
        assert!(!is_not_member(
            404,
            &serde_json::json!({"error": "not_member"})
        ));

        let dir = tempdir().unwrap();
        let state = Arc::new(AppState::new(crate::config::Config {
            state_dir: dir.path().to_path_buf(),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            body_cap: crate::config::DEFAULT_BODY_CAP,
        }));
        crate::ops::test_support::pair(&state, 0x71, 0x72);
        let base = not_member_backend().await;
        let client = DeviceClient::new(base, crate::device::tests_support::device(0x71));
        state.set_cloud(Some(client.clone()));

        let vault = format!("nm-state-{}", std::process::id());
        let store = pv_store::test_support::store_for(&vault, &[3u8; 64]);
        write_per_item_store(dir.path(), &vault, &store).unwrap();
        assert!(parked_for(&vault).is_none());

        let http = crate::cli::egress_proxy::client(FETCH_TIMEOUT).unwrap();
        assert!(matches!(
            fetch_state(&state, &client, &http, &vault, None).await,
            Err(StateError::NotMember)
        ));
        let left = parked_for(&vault).expect("parked");
        assert!(left > NOT_MEMBER_PARK - Duration::from_secs(60) && left <= NOT_MEMBER_PARK);
        let err = sync_vault_now(&state, &vault).await.err().unwrap();
        assert!(err.contains("not a member"), "{err}");
        assert!(
            read_per_item_store(dir.path(), &vault).is_some(),
            "local state kept"
        );

        // The item and record routes park too, and never drop anything.
        let other = format!("nm-items-{}", std::process::id());
        write_per_item_store(dir.path(), &other, &store).unwrap();
        assert!(fetch_item_rows(&client, &other, 0).await.is_err());
        assert!(parked_for(&other).is_some());
        let third = format!("nm-record-{}", std::process::id());
        write_per_item_store(dir.path(), &third, &store).unwrap();
        assert!(pull_member_record(&state, &client, &third).await.is_err());
        assert!(parked_for(&third).is_some());
        assert!(read_per_item_store(dir.path(), &other).is_some());
        assert!(read_per_item_store(dir.path(), &third).is_some());
    }
}
