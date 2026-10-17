//! §15 account principal ledger, enforced (DESIGN-principal-ledger-enforced.md).
//!
//! The cloud serves the account's append-only, owner-UIK-signed log of device and
//! agent ADMIT / REVOKE events plus an owner-signed head (grant-v3 C1, C4) at
//! `GET /api/vault/principals`, authenticated by this device's DIK proof of
//! possession alone (no bearer: a revoked device whose key the backend already
//! dropped still pulls its own revoke).
//!
//! The ledger is an ALLOWLIST (I1): this device serves only while the verified
//! ledger's latest event for its `dev_` is an admit over its own `sc_pk`, and an
//! agent is brokered only while the latest event for its `ag_` is an admit. Three
//! outcomes, used exactly:
//! - **hold**: a fetch failure or an invalid pull (one event that does not verify,
//!   events that do not hash to a validly signed head, a regressed `max_seq`)
//!   keeps the last persisted verified decision. Never wipes, never locks.
//! - **park**: this device not admitted, no anchor, or no DIK: K is evicted and
//!   unlock and broker are refused (`device_not_admitted`).
//! - **lock**: no verified pull for 7 days (the lease): K is evicted and unlock
//!   is refused until a fresh verified pull (`ledger_stale`). Data stays on disk.
//!
//! A VERIFIED revoke of this device (above the admit it was paired under) latches
//! in `principal_floor.json` and wipes local state (`self_wipe_and_logout`). There
//! are no flags: enforcement is the only branch.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::device_auth::DeviceRequestSigner;
use crate::identity::{self, IdKind};
use crate::state::AppState;

/// The lease (W6): a device that cannot pull a verified ledger for this long locks.
pub const LEASE_SECS: u64 = 7 * 24 * 3600;

/// Poll cadence: a revoke reaches an online device within one interval (I4).
const INTERVAL: Duration = Duration::from_secs(120);

// ── Wire shapes (GET /api/vault/principals) ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct AnchorJson {
    #[allow(dead_code)]
    uik_id: String,
    /// raw 32-byte Ed25519 owner-UIK signing pubkey (standard base64; base64url
    /// tolerated).
    uik_pub: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalEventJson {
    seq: u64,
    op: String,           // "admit" | "revoke"
    principal_id: String, // dev_… / ag_…
    #[serde(default)]
    #[allow(dead_code)]
    principal_kind: String,
    #[serde(default)]
    anchor_uik: String,
    owner_id: String,
    sig: String, // raw 64-byte Ed25519 (standard base64; base64url tolerated)
    /// Contract C1: the admitted device's raw 32-byte X25519 grant-seal key
    /// (base64url; standard base64 tolerated). Absent for an agent and a revoke.
    #[serde(default)]
    sc_pk: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    created_at: String,
}

/// The owner-signed ledger head (contract C4): the owner's commitment to the
/// whole event list, so a forged or truncated tail is detectable.
#[derive(Debug, Deserialize)]
struct HeadJson {
    anchor: String,
    max_seq: u64,
    /// SHA256(lp(sig_1) ‖ … ‖ lp(sig_n)), base64url (standard tolerated).
    events_hash: String,
    /// Owner-UIK signature over `principal_head_input`, base64url (standard tolerated).
    sig: String,
}

#[derive(Debug, Deserialize)]
struct LedgerJson {
    #[serde(default)]
    events: Vec<PrincipalEventJson>,
    #[serde(default)]
    anchor: Option<AnchorJson>,
    #[serde(default)]
    head: Option<HeadJson>,
}

// ── base64 → fixed arrays ────────────────────────────────────────────────────

fn decode_pub32(b64: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(decode_b64_any(b64)?.as_slice()).ok()
}

fn decode_sig64(b64: &str) -> Option<[u8; 64]> {
    <[u8; 64]>::try_from(decode_b64_any(b64)?.as_slice()).ok()
}

/// Decode base64url-no-pad (the grant-v3 wire convention) or standard base64
/// (the ledger's original encoding). The alphabets are unambiguous for a
/// fixed-length key or signature, so accepting both is not a parsing hazard.
fn decode_b64_any(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .ok()
}

// ── Pull ──────────────────────────────────────────────────────────────────

/// GET the account ledger, authenticated by this device's DIK proof of
/// possession ALONE (W4: no bearer, so a device whose key the backend dropped on
/// revoke still receives its own revoke). The one actionable unsigned response
/// is the backend's explicit `SC_DEVICE_UNKNOWN`: it parks this process without
/// changing the persisted signed decision. Every other failure is held.
#[derive(Debug)]
enum FetchError {
    DeviceUnknown,
    Other(String),
}

fn is_device_unknown_response(status: reqwest::StatusCode, body: &[u8]) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED
        && serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(str::to_string))
            .as_deref()
            == Some("SC_DEVICE_UNKNOWN")
}

async fn fetch_ledger(
    client: &reqwest::Client,
    cloud: &str,
    anchor_uik: &str,
    signer: &DeviceRequestSigner,
) -> Result<LedgerJson, FetchError> {
    // `uik` names the pinned account explicitly (the backend would otherwise
    // pick the account with the newest event naming this device).
    let url = format!(
        "{}/api/vault/principals?uik={}",
        cloud.trim_end_matches('/'),
        urlencoding::encode(anchor_uik)
    );
    let path = crate::device_auth::path_and_query(&url)
        .ok_or_else(|| FetchError::Other("unparseable cloud URL".into()))?;
    let mut rb = client.get(&url);
    for (k, v) in signer.headers("GET", &path, crate::util::now_unix(), &[]) {
        rb = rb.header(k, v);
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| FetchError::Other(format!("fetch: {}", e)))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.bytes().await.unwrap_or_default();
        if is_device_unknown_response(status, &body) {
            return Err(FetchError::DeviceUnknown);
        }
        return Err(FetchError::Other(format!("HTTP {}", status)));
    }
    resp.json()
        .await
        .map_err(|e| FetchError::Other(format!("parse: {}", e)))
}

// ── Strict verify + fold ─────────────────────────────────────────────────────

/// The latest event about one principal in a verified ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Latest {
    admit: bool,
    seq: u64,
    /// The admitted `sc_pk` (empty for an agent admit and every revoke).
    sc_pk: Vec<u8>,
}

/// A ledger that verified as a whole.
#[derive(Debug, Default)]
struct Folded {
    max_seq: u64,
    latest: HashMap<String, Latest>,
}

impl Folded {
    /// The agents whose latest event is an admit, sorted.
    fn admitted_agents(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .latest
            .iter()
            .filter(|(id, l)| id.starts_with("ag_") && l.admit)
            .map(|(id, _)| id.clone())
            .collect();
        v.sort();
        v
    }
}

/// Verify a pulled ledger STRICTLY (W2, the console's `verifyEvents` rule): the
/// anchor self-certifies against the pinned `anchor_uik`, the events carry seqs
/// `1..=n` in order, they hash to a validly owner-signed head (C4), and EVERY
/// event is an owner-signed admit / revoke by this account. Any failure refuses
/// the whole pull (`ledger_head_invalid` → hold); nothing is skipped.
fn verify_strict(ledger: &LedgerJson, anchor_uik: &str) -> Result<Folded, String> {
    let anchor = ledger.anchor.as_ref().ok_or("no account anchor")?;
    let anchor_pub = decode_pub32(&anchor.uik_pub).ok_or("anchor key undecodable")?;
    if identity::derive_id(IdKind::User, &anchor_pub) != anchor_uik {
        return Err("the anchor key does not belong to the paired account".into());
    }
    let mut events: Vec<&PrincipalEventJson> = ledger.events.iter().collect();
    events.sort_by_key(|e| e.seq);
    for (i, e) in events.iter().enumerate() {
        if e.seq != i as u64 + 1 {
            return Err(format!("event seqs are not contiguous at {}", e.seq));
        }
    }
    verify_head(ledger.head.as_ref(), &events, anchor_uik, &anchor_pub)?;
    let mut folded = Folded::default();
    for e in events {
        if e.owner_id != anchor_uik || (!e.anchor_uik.is_empty() && e.anchor_uik != anchor_uik) {
            return Err(format!("event {} is not by the account owner", e.seq));
        }
        let admit = match e.op.as_str() {
            "admit" => true,
            "revoke" => false,
            other => return Err(format!("event {} has an unknown op {}", e.seq, other)),
        };
        let sc_pk = match e.sc_pk.as_deref().filter(|s| !s.is_empty()) {
            None => Vec::new(),
            Some(b) => decode_b64_any(b)
                .filter(|v| v.len() == 32)
                .ok_or_else(|| format!("event {} has an undecodable sc_pk", e.seq))?,
        };
        let sig =
            decode_sig64(&e.sig).ok_or_else(|| format!("event {} signature undecodable", e.seq))?;
        let input = identity::principal_event_input(
            anchor_uik,
            &e.op,
            &e.principal_id,
            e.seq,
            &e.owner_id,
            &sc_pk,
        );
        if !identity::verify(&anchor_pub, &input, &sig) {
            return Err(format!("event {} signature does not verify", e.seq));
        }
        folded.max_seq = e.seq;
        folded.latest.insert(
            e.principal_id.clone(),
            Latest {
                admit,
                seq: e.seq,
                sc_pk,
            },
        );
    }
    Ok(folded)
}

/// Contract C4: `head` must be signed by the account owner over
/// `principal_head_input(anchor, max_seq, SHA256(lp(sig_1) ‖ … ‖ lp(sig_n)))`, and
/// the served `events` (in seq order) must hash to its `events_hash` and end at
/// its `max_seq`. Every event signature counts, valid or not: the head commits to
/// the list the owner wrote.
fn verify_head(
    head: Option<&HeadJson>,
    events: &[&PrincipalEventJson],
    anchor_uik: &str,
    anchor_pub: &[u8; 32],
) -> Result<(), String> {
    let head = head.ok_or("no signed ledger head")?;
    if head.anchor != anchor_uik {
        return Err("ledger head names another account".into());
    }
    let sig = decode_sig64(&head.sig).ok_or("ledger head signature undecodable")?;
    let claimed = decode_b64_any(&head.events_hash)
        .filter(|h| h.len() == 32)
        .ok_or("ledger head events_hash undecodable")?;
    let input = identity::principal_head_input(anchor_uik, head.max_seq, &claimed);
    if !identity::verify(anchor_pub, &input, &sig) {
        return Err("ledger head signature does not verify".into());
    }
    let mut sigs = Vec::with_capacity(events.len());
    for e in events {
        sigs.push(decode_b64_any(&e.sig).ok_or("an event signature is undecodable")?);
    }
    if identity::principal_events_hash(&sigs).as_slice() != claimed.as_slice() {
        return Err("the served events do not match the signed head".into());
    }
    let max = events.last().map(|e| e.seq).unwrap_or(0);
    if max != head.max_seq {
        return Err("the served events end at another seq than the signed head".into());
    }
    Ok(())
}

// ── The persisted decision (`principal_floor.json`) ──────────────────────────

/// What the last verified pull decided, persisted so a restart within the lease
/// serves without a successful pull (hold).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerFloor {
    /// This device's latest verified admit (over its own `sc_pk`), or the admit
    /// pairing just verified.
    #[serde(default)]
    pub admitted_seq: u64,
    /// The latest verified event for this device is that admit.
    #[serde(default)]
    pub admitted: bool,
    /// A verified revoke of this device. The latch is honored only while
    /// `self_revoke_seq > admitted_seq`, so a re-paired device never wipes on
    /// its old revoke.
    #[serde(default)]
    pub self_revoke_seq: u64,
    /// Wall time of the last verified pull (the lease starts here).
    #[serde(default)]
    pub fresh_at: u64,
    /// The highest `seq` of the last verified pull; a pull below it is a
    /// rollback (hold).
    #[serde(default)]
    pub max_seq: u64,
    /// The latest wall time seen since `fresh_at`: a clock moved backwards never
    /// extends the lease.
    #[serde(default)]
    pub max_wall: u64,
    /// The account's admitted agents (`ag_`), per the last verified pull.
    #[serde(default)]
    pub agents: Vec<String>,
}

pub(crate) fn floor_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("principal_floor.json")
}

pub(crate) fn load_floor(state_dir: &Path) -> LedgerFloor {
    std::fs::read_to_string(floor_path(state_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn store_floor(state_dir: &Path, floor: &LedgerFloor) {
    if let Ok(json) = serde_json::to_string(floor) {
        if let Err(e) = std::fs::write(floor_path(state_dir), json) {
            tracing::warn!("principal ledger: failed to persist the decision: {}", e);
        }
    }
}

/// Pairing success writes the decision fresh from the complete set the CLI just
/// verified (W2): the device is admitted at its seq, the signed head fixes the
/// rollback floor, and agents admitted by the same ceremony are recorded.
pub fn write_pairing_floor(
    state_dir: &Path,
    admit_seq: u64,
    head_max_seq: u64,
    mut agents: Vec<String>,
    now: u64,
) -> Result<(), String> {
    agents.sort();
    agents.dedup();
    let floor = LedgerFloor {
        admitted_seq: admit_seq,
        admitted: true,
        self_revoke_seq: 0,
        fresh_at: now,
        max_seq: head_max_seq,
        max_wall: now,
        agents,
    };
    std::fs::create_dir_all(state_dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string(&floor).map_err(|e| e.to_string())?;
    std::fs::write(floor_path(state_dir), json).map_err(|e| e.to_string())
}

/// Fold a VERIFIED pull into the decision (pure). `Err` = hold (a pull whose
/// `max_seq` regressed below the last verified one).
fn apply_pull(
    mut floor: LedgerFloor,
    folded: &Folded,
    my_dev: &str,
    my_sc_pk: &[u8],
    now: u64,
) -> Result<LedgerFloor, String> {
    if folded.max_seq < floor.max_seq {
        return Err(format!(
            "the ledger regressed to seq {} below the known {}",
            folded.max_seq, floor.max_seq
        ));
    }
    floor.max_seq = folded.max_seq;
    // A verified pull proves contact now: the lease restarts from this clock.
    floor.fresh_at = now;
    floor.max_wall = now;
    match folded.latest.get(my_dev) {
        Some(l) if !l.admit => {
            if l.seq > floor.admitted_seq {
                floor.self_revoke_seq = floor.self_revoke_seq.max(l.seq);
            }
            floor.admitted = false;
        }
        Some(l) if l.sc_pk == my_sc_pk => {
            floor.admitted = true;
            floor.admitted_seq = l.seq;
        }
        // An admit of this dev_ over another daemon key, or no event at all.
        _ => floor.admitted = false,
    }
    floor.agents = folded.admitted_agents();
    Ok(floor)
}

/// This device's standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceGate {
    /// Admitted, within the lease: serve.
    Open,
    /// Park: not admitted (or no anchor / no DIK). Refuse unlock and broker.
    NotAdmitted,
    /// The backend completed the lookup and no account names this device.
    /// Unsigned and process-local: park without deleting local data.
    AccountMissing,
    /// Lock: the lease ran out. Refuse unlock until a fresh verified pull.
    Stale,
    /// A verified revoke of this device: wipe.
    Revoked,
}

/// The standing of this device given its persisted decision (pure). `now` is the
/// wall clock; a clock earlier than `fresh_at`, or the latest wall time seen more
/// than the lease past it, is stale.
pub fn gate(floor: &LedgerFloor, now: u64, has_anchor: bool, has_dik: bool) -> DeviceGate {
    if !has_anchor || !has_dik {
        return DeviceGate::NotAdmitted;
    }
    if floor.self_revoke_seq > floor.admitted_seq {
        return DeviceGate::Revoked;
    }
    if !floor.admitted {
        return DeviceGate::NotAdmitted;
    }
    let seen = now.max(floor.max_wall);
    if now < floor.fresh_at || seen.saturating_sub(floor.fresh_at) > LEASE_SECS {
        return DeviceGate::Stale;
    }
    DeviceGate::Open
}

/// Whole days left on the lease (`sc status`), `None` when not admitted.
pub fn lease_days_left(floor: &LedgerFloor, now: u64) -> Option<u64> {
    if !floor.admitted {
        return None;
    }
    let seen = now.max(floor.max_wall);
    let used = seen.saturating_sub(floor.fresh_at);
    Some(LEASE_SECS.saturating_sub(used) / 86_400)
}

/// The daemon's in-memory ledger standing ([`AppState::ledger`]).
#[derive(Debug, Clone)]
pub struct LedgerGate {
    pub device: DeviceGate,
    /// The account's admitted agents; `None` = no verified decision.
    pub agents: Option<HashSet<String>>,
    /// Unix time of the signed ledger pull, or the explicit account-missing
    /// check, that produced this standing.
    pub checked_at: Option<u64>,
}

impl Default for LedgerGate {
    /// Fail closed: nothing is admitted until a decision is loaded.
    fn default() -> Self {
        Self {
            device: DeviceGate::NotAdmitted,
            agents: None,
            checked_at: None,
        }
    }
}

// ── Pairing: the owner-signed admit of THIS principal (C1) ─────────────────

/// Verify the owner-signed admit a pairing returned (contract C1) for THIS
/// principal and return the owner's `us_…` it proves. The owner key `uik_pub`
/// self-certifies the id; the admit must be an `admit` of exactly
/// `principal_id`, by that owner as account anchor, over exactly `sc_pk`
/// (empty for an agent), with a valid signature. The caller pins the returned
/// id and key, never a server label.
pub fn verify_pairing_admit(
    admit: &serde_json::Value,
    uik_pub: &[u8; 32],
    principal_id: &str,
    sc_pk: &[u8],
) -> Result<String, String> {
    let e: PrincipalEventJson = serde_json::from_value(admit.clone())
        .map_err(|e| format!("the pairing returned a malformed admit: {}", e))?;
    let owner = identity::derive_id(IdKind::User, uik_pub);
    if e.op != "admit" || e.principal_id != principal_id {
        return Err("the pairing's admit is not for the requested principal".into());
    }
    if e.owner_id != owner || (!e.anchor_uik.is_empty() && e.anchor_uik != owner) {
        return Err("the pairing's admit is not signed by the approving account".into());
    }
    let served_pk = match e.sc_pk.as_deref().filter(|s| !s.is_empty()) {
        None => Vec::new(),
        Some(b) => decode_b64_any(b).ok_or("the admit's sc_pk is undecodable")?,
    };
    if served_pk != sc_pk {
        return Err("the pairing's admit binds another daemon key".into());
    }
    let sig = decode_sig64(&e.sig).ok_or("the admit's signature is undecodable")?;
    let input =
        identity::principal_event_input(&owner, "admit", principal_id, e.seq, &owner, sc_pk);
    if !identity::verify(uik_pub, &input, &sig) {
        return Err("the pairing's admit signature does not verify".into());
    }
    Ok(owner)
}

/// Verify the owner-signed ledger head returned with a pairing approval and
/// return its authenticated `max_seq`. The approval carries only the new admits,
/// not the complete event list, so this verifies the head signature and owner
/// binding; normal ledger pulls additionally verify the full events hash.
pub fn verify_pairing_head(head: &serde_json::Value, uik_pub: &[u8; 32]) -> Result<u64, String> {
    let head: HeadJson = serde_json::from_value(head.clone())
        .map_err(|e| format!("the pairing returned a malformed ledger head: {}", e))?;
    let owner = identity::derive_id(IdKind::User, uik_pub);
    if head.anchor != owner {
        return Err("the pairing's ledger head names another account".into());
    }
    let hash = decode_b64_any(&head.events_hash)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or("the pairing's ledger head hash is undecodable")?;
    let sig =
        decode_sig64(&head.sig).ok_or("the pairing's ledger head signature is undecodable")?;
    let input = identity::principal_head_input(&owner, head.max_seq, &hash);
    if !identity::verify(uik_pub, &input, &sig) {
        return Err("the pairing's ledger head signature does not verify".into());
    }
    Ok(head.max_seq)
}

// ── Enforcement ──────────────────────────────────────────────────────────────

/// Self-revoke enforcement: the owner revoked THIS device (a VERIFIED revoke,
/// latched in `principal_floor.json` before this runs). Lock + wipe every local
/// vault (evict retained K + delete sealed blobs, in-process — no CLI), delete the
/// device-key, clear the pairing config, then EXIT. The DIK and `sc_sk.bin` stay,
/// so a re-pair re-admits the same `dev_` and `sc_pk`. Does not return.
async fn self_wipe_and_logout(state: &Arc<AppState>) -> ! {
    tracing::warn!(
        code = "ledger_device_revoked",
        "principal ledger: THIS DEVICE was revoked by the account owner (VERIFIED signature) — \
         locking + wiping all local vaults and logging out"
    );
    // 1. Lock + wipe every synced vault, in-process (zeroize retained K + remove the
    //    sealed blob), through the same locked drop the tombstone path uses.
    let mut vaults: std::collections::BTreeSet<String> = crate::cli::active::known_vaults()
        .into_iter()
        .map(|kv| kv.vault)
        .filter(|v| !v.is_empty())
        .collect();
    vaults.extend(state.runtime_ids());
    vaults.extend(state.vaults.list().unwrap_or_default());
    // F2: evict retained K from EVERY vault UP-FRONT (synchronous, in-memory) so the
    // serve window closes immediately — no in-flight request can be handed K for a
    // not-yet-dropped vault while the per-vault disk wipe below iterates.
    for vid in &vaults {
        state.mark_vault_closing(vid, crate::vault_runtime::TombstoneReason::DeviceRevoked);
    }
    for vid in &vaults {
        crate::sync::revoke_vault_access_verified(state, vid).await;
    }
    // 2. Delete the device-key (this host's cloud credential): once gone, the bearer
    //    can never be matched again.
    if let Some(home) = dirs::home_dir() {
        let _ = std::fs::remove_file(home.join(".safeclaw").join("device-key"));
    }
    // 3. Clear the pairing from config + known-vaults (mirrors `sc logout`).
    if let Err(e) = crate::cli::active::clear_pairing() {
        tracing::warn!(
            "principal ledger: failed to clear pairing config on self-revoke: {}",
            e
        );
    }
    // 4. Stop serving. With K evicted, blobs wiped, and the pairing gone, the daemon
    //    must not keep running; process exit is the in-process equivalent of the CLI
    //    `sc logout` stopping it.
    tracing::warn!("principal ledger: local state wiped; daemon exiting (re-pair with `sc login`)");
    std::process::exit(0);
}

// ── Runtime ──────────────────────────────────────────────────────────────────

/// What a pull needs: the cloud, the pinned anchor, this device's DIK and its
/// daemon key. `None` (no pairing / anchor / DIK) parks the device.
struct Ctx {
    cloud: String,
    anchor_uik: String,
    signer: DeviceRequestSigner,
    sc_pk: Vec<u8>,
}

fn context(state: &AppState) -> Option<Ctx> {
    let cfg = crate::cli::active::load().ok()?;
    let cloud = cfg.cloud_backend.filter(|s| !s.is_empty())?;
    let anchor_uik = cfg.account_uik.filter(|s| !s.is_empty())?;
    let signer = crate::device_auth::device_signer()?;
    Some(Ctx {
        cloud,
        anchor_uik,
        signer,
        sc_pk: state.sc.pk_bytes(),
    })
}

/// Publish a standing: not open evicts K from every vault (park / lock / wipe).
fn publish(state: &AppState, device: DeviceGate, floor: &LedgerFloor, checked_at: Option<u64>) {
    let agents = (device == DeviceGate::Open).then(|| floor.agents.iter().cloned().collect());
    state.set_ledger(LedgerGate {
        device,
        agents,
        checked_at,
    });
}

fn held_gate(current: DeviceGate, persisted: DeviceGate) -> DeviceGate {
    match current {
        DeviceGate::AccountMissing => current,
        _ => persisted,
    }
}

/// The standing at startup, from the persisted decision alone (no network): a
/// restart within the lease serves (hold); no anchor or no DIK parks.
pub fn init_gate(state: &AppState) {
    let floor = load_floor(&state.config.state_dir);
    let cfg = crate::cli::active::load().unwrap_or_default();
    let has_anchor = cfg.account_uik.as_deref().is_some_and(|s| !s.is_empty());
    let has_dik = crate::device_auth::device_signer().is_some();
    let g = gate(&floor, crate::util::now_unix(), has_anchor, has_dik);
    if g != DeviceGate::Open {
        tracing::warn!(standing = ?g, "principal ledger: this device is not serving until a verified pull admits it");
    }
    publish(
        state,
        g,
        &floor,
        (floor.fresh_at != 0).then_some(floor.fresh_at),
    );
}

/// One pull → verify → decide → persist → publish, serialized by
/// [`AppState::ledger_sync`] (the caller holds it). Returns the new standing.
async fn pull_now(state: &AppState, timeout: Duration) -> DeviceGate {
    let state_dir = state.config.state_dir.clone();
    let mut floor = load_floor(&state_dir);
    let now = crate::util::now_unix();
    let Some(ctx) = context(state) else {
        publish(state, DeviceGate::NotAdmitted, &floor, None);
        return DeviceGate::NotAdmitted;
    };
    let current = state.ledger.lock().unwrap().clone();
    let before = floor.clone();
    floor.max_wall = floor.max_wall.max(now);
    let pulled = match crate::cli::egress_proxy::client(timeout) {
        Ok(client) => fetch_ledger(&client, &ctx.cloud, &ctx.anchor_uik, &ctx.signer).await,
        Err(e) => Err(FetchError::Other(e.to_string())),
    };
    let mut accepted = false;
    match pulled {
        Err(FetchError::DeviceUnknown) => {
            publish(state, DeviceGate::AccountMissing, &floor, Some(now));
            return DeviceGate::AccountMissing;
        }
        Err(FetchError::Other(e)) => {
            tracing::debug!("principal ledger: fetch failed ({}); holding", e)
        }
        Ok(ledger) => match verify_strict(&ledger, &ctx.anchor_uik) {
            Err(why) => tracing::warn!(
                code = "ledger_head_invalid",
                "principal ledger: pull refused ({}); holding the last verified decision",
                why
            ),
            Ok(folded) => {
                match apply_pull(
                    floor.clone(),
                    &folded,
                    ctx.signer.device_id(),
                    &ctx.sc_pk,
                    now,
                ) {
                    Ok(f) => {
                        floor = f;
                        accepted = true;
                    }
                    Err(why) => tracing::warn!("principal ledger: {}; holding", why),
                }
            }
        },
    }
    if floor != before {
        store_floor(&state_dir, &floor);
    }
    let persisted = gate(&floor, now, true, true);
    let g = if accepted {
        persisted
    } else {
        held_gate(current.device, persisted)
    };
    if g == DeviceGate::AccountMissing {
        return g;
    }
    publish(
        state,
        g,
        &floor,
        (floor.fresh_at != 0).then_some(floor.fresh_at),
    );
    g
}

/// Periodic pull (every [`INTERVAL`], and on a backend principals / agent-key
/// stream event). A verified revoke of this device wipes (does not return).
pub async fn principal_ledger_loop(state: Arc<AppState>) {
    loop {
        let g = {
            let mut last = state.ledger_sync.lock().await;
            *last = Some(std::time::Instant::now());
            pull_now(&state, Duration::from_secs(15)).await
        };
        match g {
            DeviceGate::Revoked => self_wipe_and_logout(&state).await,
            DeviceGate::NotAdmitted => tracing::warn!(
                code = "device_not_admitted",
                "principal ledger: this device is not admitted to the account; run `sc login`"
            ),
            DeviceGate::AccountMissing => tracing::warn!(
                code = "device_not_admitted",
                "principal ledger: this device is no longer paired with a SafeClaw account; run `sc login`"
            ),
            DeviceGate::Stale => tracing::warn!(
                code = "ledger_stale",
                "principal ledger: no verified pull for 7 days; vaults locked until one succeeds"
            ),
            DeviceGate::Open => {}
        }
        tokio::select! {
            _ = tokio::time::sleep(INTERVAL) => {}
            _ = crate::sync_stream::agent_hashes_notified() => {}
            _ = crate::sync_stream::device_auth_rejected_notified() => {}
        }
    }
}

/// Is `agent_id` NOT admitted by the account ledger (W3)? On a miss, one
/// debounced re-pull first, so an agent approved seconds ago is not refused
/// for the poll interval. Fails closed: no verified decision = not admitted.
pub async fn agent_not_admitted(state: &Arc<AppState>, agent_id: &str) -> bool {
    if state.agent_admitted(agent_id) {
        return false;
    }
    const DEBOUNCE: Duration = Duration::from_secs(2);
    {
        let mut last = state.ledger_sync.lock().await;
        if !matches!(*last, Some(t) if t.elapsed() < DEBOUNCE) {
            *last = Some(std::time::Instant::now());
            if pull_now(state, Duration::from_secs(3)).await == DeviceGate::Revoked {
                // The loop wipes on its next turn; refuse meanwhile.
                return true;
            }
        }
    }
    !state.agent_admitted(agent_id)
}

/// Why an agent request is refused ([`authorize_agent`]).
#[derive(Debug)]
pub enum AgentRefusal {
    /// This device itself may not serve (park / lock / revoked).
    Device(crate::error::AppError),
    /// The vault runtime was closed with a durable in-process reason.
    Gone(crate::error::AppError),
    /// No verified agent identity (no or invalid AIK proof): an api key alone is
    /// no longer an agent credential (W3).
    NoIdentity,
    /// The ledger does not admit this `ag_`.
    NotAdmitted,
    /// Admitted to the account, but not turned on for this vault (or for any
    /// vault, on an account-scoped read).
    NotAuthorized,
    /// The target vault is locked, or no vault is unlocked for an
    /// account-scoped read.
    Locked,
}

/// The one agent admission rule (W3), shared by the proxy and the API face: this
/// device serves, the agent proved its AIK, the account ledger admits its `ag_`
/// (no later revoke), and the vault's authorized-agents table lists it (`vault`
/// `None` = an account-scoped read: any unlocked vault). Returns the `ag_`.
pub async fn authorize_agent(
    state: &Arc<AppState>,
    agent: Option<&str>,
    vault: Option<&str>,
) -> Result<String, AgentRefusal> {
    if let Some(e) = state.ledger_refusal() {
        return Err(AgentRefusal::Device(e));
    }
    if let Some(error) = vault.and_then(|v| state.vault_gone_error(v)) {
        return Err(AgentRefusal::Gone(error));
    }
    let ag = agent.ok_or(AgentRefusal::NoIdentity)?;
    if agent_not_admitted(state, ag).await {
        return Err(AgentRefusal::NotAdmitted);
    }
    let locked = match vault {
        Some(v) => state.is_vault_locked(v),
        None => !state.has_unlocked_vault(),
    };
    if locked {
        return Err(AgentRefusal::Locked);
    }
    let listed = match vault {
        Some(v) => state.agent_is_authorized(v, ag),
        None => state.agent_is_authorized_any(ag),
    };
    if !listed {
        return Err(AgentRefusal::NotAuthorized);
    }
    Ok(ag.to_string())
}

/// The refusal for a request with no verified agent identity.
pub const NO_AGENT_IDENTITY_MSG: &str = "this request carries no SafeClaw agent identity. Run the \
     agent through `sc run`, or set it up with `sc agent add`";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningIdentity;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const OWNER_SEED: [u8; 32] = [7u8; 32];
    const MY_PK: [u8; 32] = [5u8; 32];
    const MY_DEV: &str = "dev_me";
    const T0: u64 = 1_800_000_000;

    fn owner() -> SigningIdentity {
        SigningIdentity::from_seed(&OWNER_SEED)
    }

    #[tokio::test]
    async fn locked_named_vault_returns_locked_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            state_dir: dir.path().to_path_buf(),
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
        };
        let state = Arc::new(AppState::new(cfg));
        state.open_ledger_for_tests(&["ag_locked"]);

        let refusal = authorize_agent(&state, Some("ag_locked"), Some("vault_locked"))
            .await
            .unwrap_err();
        assert!(matches!(refusal, AgentRefusal::Locked));
    }

    #[tokio::test]
    async fn revoked_named_vault_precedes_locked_and_agent_checks() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            state_dir: dir.path().to_path_buf(),
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
        };
        let state = Arc::new(AppState::new(cfg));
        state.open_ledger_for_tests(&[]);
        state.mark_vault_closing("v", crate::vault_runtime::TombstoneReason::Removed);
        assert!(matches!(
            authorize_agent(&state, None, Some("v")).await,
            Err(AgentRefusal::Gone(
                crate::error::AppError::VaultAccessRevoked
            ))
        ));
    }

    fn ev(
        o: &SigningIdentity,
        op: &str,
        principal: &str,
        seq: u64,
        sc_pk: &[u8],
    ) -> PrincipalEventJson {
        let acct = o.user_id();
        let input = identity::principal_event_input(&acct, op, principal, seq, &acct, sc_pk);
        PrincipalEventJson {
            seq,
            op: op.to_string(),
            principal_id: principal.to_string(),
            principal_kind: if principal.starts_with("dev_") {
                "device"
            } else {
                "agent"
            }
            .to_string(),
            anchor_uik: acct.clone(),
            owner_id: acct,
            sig: STANDARD.encode(o.sign(&input)),
            sc_pk: (!sc_pk.is_empty()).then(|| URL_SAFE_NO_PAD.encode(sc_pk)),
            created_at: String::new(),
        }
    }

    /// The owner's signed head over `events` (C4), as the console writes it.
    fn sign_head(o: &SigningIdentity, events: &[PrincipalEventJson]) -> HeadJson {
        let mut sorted: Vec<&PrincipalEventJson> = events.iter().collect();
        sorted.sort_by_key(|e| e.seq);
        let sigs: Vec<Vec<u8>> = sorted
            .iter()
            .map(|e| decode_b64_any(&e.sig).unwrap())
            .collect();
        let hash = identity::principal_events_hash(&sigs);
        let max_seq = sorted.last().map(|e| e.seq).unwrap_or(0);
        let sig = o.sign(&identity::principal_head_input(
            &o.user_id(),
            max_seq,
            &hash,
        ));
        HeadJson {
            anchor: o.user_id(),
            max_seq,
            events_hash: URL_SAFE_NO_PAD.encode(hash),
            sig: URL_SAFE_NO_PAD.encode(sig),
        }
    }

    fn ledger(o: &SigningIdentity, events: Vec<PrincipalEventJson>) -> LedgerJson {
        let head = Some(sign_head(o, &events));
        LedgerJson {
            events,
            anchor: Some(AnchorJson {
                uik_id: o.user_id(),
                uik_pub: STANDARD.encode(o.public_bytes()),
            }),
            head,
        }
    }

    /// One verified pull folded into `floor`.
    fn pull(floor: LedgerFloor, l: &LedgerJson, now: u64) -> Result<LedgerFloor, String> {
        let folded = verify_strict(l, &owner().user_id())?;
        apply_pull(floor, &folded, MY_DEV, &MY_PK, now)
    }

    fn paired_at(seq: u64) -> LedgerFloor {
        LedgerFloor {
            admitted_seq: seq,
            admitted: true,
            fresh_at: T0,
            max_seq: seq,
            max_wall: T0,
            ..Default::default()
        }
    }

    #[test]
    fn pairing_floor_uses_signed_head_and_set_agents() {
        let dir = tempfile::tempdir().unwrap();
        write_pairing_floor(
            dir.path(),
            7,
            9,
            vec!["ag_b".into(), "ag_a".into(), "ag_a".into()],
            T0,
        )
        .unwrap();
        let floor = load_floor(dir.path());
        assert_eq!(floor.admitted_seq, 7);
        assert_eq!(floor.max_seq, 9);
        assert_eq!(floor.agents, vec!["ag_a", "ag_b"]);
    }

    /// Revoked self → wipe: a verified revoke above the paired admit latches.
    #[test]
    fn a_verified_revoke_of_this_device_wipes() {
        let o = owner();
        let l = ledger(
            &o,
            vec![
                ev(&o, "admit", MY_DEV, 1, &MY_PK),
                ev(&o, "revoke", MY_DEV, 2, &[]),
            ],
        );
        let f = pull(paired_at(1), &l, T0 + 60).unwrap();
        assert_eq!(f.self_revoke_seq, 2);
        assert_eq!(gate(&f, T0 + 60, true, true), DeviceGate::Revoked);
        // Latched: a later pull that drops the revoke regresses (hold), so the
        // persisted latch stands.
        let dropped = ledger(&o, vec![ev(&o, "admit", MY_DEV, 1, &MY_PK)]);
        assert!(pull(f.clone(), &dropped, T0 + 120).is_err());
        assert_eq!(gate(&f, T0 + 120, true, true), DeviceGate::Revoked);
    }

    /// Re-pair after a revoke: pairing writes the decision fresh at the new
    /// admit, so the old revoke never wipes again; the first pull serves.
    #[test]
    fn re_pairing_after_a_revoke_serves_without_a_wipe_loop() {
        let o = owner();
        let dir = tempfile::tempdir().unwrap();
        // The old decision carried a latched revoke at seq 2.
        store_floor(
            dir.path(),
            &LedgerFloor {
                admitted_seq: 1,
                self_revoke_seq: 2,
                ..paired_at(1)
            },
        );
        // Re-pair: C6 writes revoke(old) at 3 then admit(new) at 4.
        write_pairing_floor(dir.path(), 4, 4, Vec::new(), T0).unwrap();
        let f = load_floor(dir.path());
        assert_eq!(gate(&f, T0 + 1, true, true), DeviceGate::Open);
        let l = ledger(
            &o,
            vec![
                ev(&o, "admit", MY_DEV, 1, &MY_PK),
                ev(&o, "revoke", MY_DEV, 2, &[]),
                ev(&o, "revoke", MY_DEV, 3, &[]),
                ev(&o, "admit", MY_DEV, 4, &MY_PK),
            ],
        );
        let f = pull(f, &l, T0 + 60).unwrap();
        assert_eq!(gate(&f, T0 + 60, true, true), DeviceGate::Open);
        assert_eq!(f.admitted_seq, 4);
    }

    /// Restart within the lease with the backend down: the persisted decision
    /// serves (hold).
    #[test]
    fn a_restart_within_the_lease_serves_without_a_pull() {
        let dir = tempfile::tempdir().unwrap();
        store_floor(dir.path(), &paired_at(3));
        let f = load_floor(dir.path());
        assert_eq!(gate(&f, T0 + 6 * 86_400, true, true), DeviceGate::Open);
        assert_eq!(lease_days_left(&f, T0 + 6 * 86_400), Some(1));
    }

    /// Not admitted → park, never a wipe: no event for this device, or an
    /// admit of its dev_ over another daemon key.
    #[test]
    fn a_device_without_its_admit_parks() {
        let o = owner();
        let none = ledger(&o, vec![ev(&o, "admit", "dev_other", 1, &[9u8; 32])]);
        let f = pull(LedgerFloor::default(), &none, T0).unwrap();
        assert_eq!(gate(&f, T0, true, true), DeviceGate::NotAdmitted);
        let other_key = ledger(&o, vec![ev(&o, "admit", MY_DEV, 1, &[9u8; 32])]);
        let f = pull(LedgerFloor::default(), &other_key, T0).unwrap();
        assert_eq!(gate(&f, T0, true, true), DeviceGate::NotAdmitted);
        assert_eq!(f.self_revoke_seq, 0, "no wipe");
        // Never paired: nothing persisted.
        assert_eq!(
            gate(&LedgerFloor::default(), T0, true, true),
            DeviceGate::NotAdmitted
        );
    }

    /// No anchor (or no DIK) → park, whatever was persisted.
    #[test]
    fn no_anchor_or_no_dik_parks() {
        assert_eq!(
            gate(&paired_at(1), T0, false, true),
            DeviceGate::NotAdmitted
        );
        assert_eq!(
            gate(&paired_at(1), T0, true, false),
            DeviceGate::NotAdmitted
        );
    }

    /// One bad event, a head mismatch, a foreign anchor, a gap: the whole pull
    /// is refused (hold), nothing is folded, nothing wipes.
    #[test]
    fn one_bad_event_or_a_head_mismatch_holds() {
        let o = owner();
        let acct = o.user_id();
        let good = || {
            vec![
                ev(&o, "admit", MY_DEV, 1, &MY_PK),
                ev(&o, "revoke", MY_DEV, 2, &[]),
            ]
        };
        assert!(verify_strict(&ledger(&o, good()), &acct).is_ok());

        // A forged revoke the head even commits to: still refused whole.
        let mut events = good();
        events[1].sig = STANDARD.encode([0u8; 64]);
        assert!(
            verify_strict(&ledger(&o, events), &acct).is_err(),
            "bad event"
        );

        let mut l = ledger(&o, good());
        l.head = None;
        assert!(verify_strict(&l, &acct).is_err(), "no head");

        let mut l = ledger(&o, good());
        l.events.pop();
        assert!(verify_strict(&l, &acct).is_err(), "truncated tail");

        let mut l = ledger(&o, good());
        l.events.push(ev(&o, "admit", "ag_x", 3, &[]));
        assert!(verify_strict(&l, &acct).is_err(), "event outside the head");

        let imposter = SigningIdentity::from_seed(&[9u8; 32]);
        let mut l = ledger(&o, good());
        l.anchor = Some(AnchorJson {
            uik_id: imposter.user_id(),
            uik_pub: STANDARD.encode(imposter.public_bytes()),
        });
        assert!(verify_strict(&l, &acct).is_err(), "swapped anchor");

        let mut l = ledger(&o, good());
        let mut h = sign_head(&imposter, &l.events);
        h.anchor = acct.clone();
        l.head = Some(h);
        assert!(verify_strict(&l, &acct).is_err(), "head by another key");

        let gap = ledger(
            &o,
            vec![
                ev(&o, "admit", MY_DEV, 1, &MY_PK),
                ev(&o, "admit", "ag_x", 3, &[]),
            ],
        );
        assert!(verify_strict(&gap, &acct).is_err(), "seq gap");

        let mut foreign = good();
        foreign[0].owner_id = "us_someone_else".into();
        assert!(
            verify_strict(&ledger(&o, foreign), &acct).is_err(),
            "foreign owner"
        );

        // The persisted decision is untouched by a refused pull: still serving.
        assert_eq!(gate(&paired_at(1), T0 + 60, true, true), DeviceGate::Open);
    }

    /// The agent allowlist: the latest event per ag_ decides; a revoked agent
    /// is out at the next fold.
    #[test]
    fn agents_are_admitted_only_while_their_latest_event_is_an_admit() {
        let o = owner();
        let l = ledger(
            &o,
            vec![
                ev(&o, "admit", MY_DEV, 1, &MY_PK),
                ev(&o, "admit", "ag_a", 2, &[]),
                ev(&o, "admit", "ag_b", 3, &[]),
                ev(&o, "revoke", "ag_b", 4, &[]),
            ],
        );
        let f = pull(paired_at(1), &l, T0).unwrap();
        assert_eq!(f.agents, vec!["ag_a".to_string()]);
    }

    /// Lease expiry → lock (never a wipe); a fresh verified pull reopens.
    #[test]
    fn the_lease_locks_after_seven_days_and_a_pull_reopens() {
        let o = owner();
        let f = paired_at(1);
        assert_eq!(gate(&f, T0 + LEASE_SECS, true, true), DeviceGate::Open);
        assert_eq!(gate(&f, T0 + LEASE_SECS + 1, true, true), DeviceGate::Stale);
        let l = ledger(&o, vec![ev(&o, "admit", MY_DEV, 1, &MY_PK)]);
        let later = T0 + LEASE_SECS + 10;
        let f = pull(f, &l, later).unwrap();
        assert_eq!(gate(&f, later, true, true), DeviceGate::Open);
        assert_eq!(f.self_revoke_seq, 0);
    }

    /// A clock moved backwards never extends the lease: earlier than the last
    /// verified pull is stale, and the latest wall time seen keeps counting.
    #[test]
    fn a_clock_rollback_does_not_extend_the_lease() {
        let mut f = paired_at(1);
        assert_eq!(gate(&f, T0 - 1, true, true), DeviceGate::Stale);
        f.max_wall = T0 + LEASE_SECS + 5; // seen 7 days on, then the clock went back
        assert_eq!(gate(&f, T0 + 3600, true, true), DeviceGate::Stale);
    }

    #[test]
    fn floor_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let f = LedgerFloor {
            agents: vec!["ag_a".into()],
            ..paired_at(2)
        };
        store_floor(dir.path(), &f);
        assert_eq!(load_floor(dir.path()), f);
    }

    /// Lease expiry (or a park) locks: K is evicted from every vault at once,
    /// nothing on disk is touched, and unlock is refused until a verified pull.
    #[test]
    fn a_stale_standing_locks_without_wiping() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            state_dir: dir.path().to_path_buf(),
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
        };
        let state = AppState::new(cfg);
        let blob = dir.path().join("vaults").join("v1");
        std::fs::create_dir_all(&blob).unwrap();
        std::fs::write(blob.join("vault.per-item.json"), b"{}").unwrap();
        state.open_ledger_for_tests(&[]);
        state.unlock_vault(
            "v1".into(),
            crate::state::SecretsCache::default(),
            zeroize::Zeroizing::new(vec![0x42u8; 32]),
        );
        assert!(state.ledger_refusal().is_none());
        let f = paired_at(1);
        let g = gate(&f, T0 + LEASE_SECS + 1, true, true);
        assert_eq!(g, DeviceGate::Stale);
        publish(&state, g, &f, Some(f.fresh_at));
        assert!(state.is_vault_locked("v1"), "K evicted");
        assert!(
            blob.join("vault.per-item.json").exists(),
            "data stays on disk"
        );
        assert_eq!(
            state.ledger_refusal().unwrap().code().0.as_str(),
            "ledger_stale"
        );
    }

    #[test]
    fn only_the_named_401_is_the_account_missing_signal() {
        use reqwest::StatusCode;
        let named = br#"{"code":"SC_DEVICE_UNKNOWN","error":"SC_DEVICE_UNKNOWN"}"#;
        assert!(is_device_unknown_response(StatusCode::UNAUTHORIZED, named));
        for (status, body) in [
            (StatusCode::UNAUTHORIZED, br#"{"code":"OTHER"}"#.as_slice()),
            (StatusCode::UNAUTHORIZED, b"not-json".as_slice()),
            (StatusCode::FORBIDDEN, named.as_slice()),
            (StatusCode::INTERNAL_SERVER_ERROR, named.as_slice()),
        ] {
            assert!(!is_device_unknown_response(status, body));
        }
        assert_eq!(
            held_gate(DeviceGate::AccountMissing, DeviceGate::Open),
            DeviceGate::AccountMissing,
            "an ordinary failure holds the account-missing decision"
        );
        assert_eq!(
            held_gate(DeviceGate::Open, DeviceGate::Open),
            DeviceGate::Open
        );
    }

    #[test]
    fn an_account_missing_signal_parks_and_keeps_local_data() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            state_dir: dir.path().to_path_buf(),
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
        };
        let state = AppState::new(cfg);
        let blob = dir.path().join("vaults").join("v1").join("sentinel");
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"keep").unwrap();
        state.open_ledger_for_tests(&[]);
        state.unlock_vault(
            "v1".into(),
            crate::state::SecretsCache::default(),
            zeroize::Zeroizing::new(vec![0x42u8; 32]),
        );

        publish(&state, DeviceGate::AccountMissing, &paired_at(1), Some(T0));

        assert!(state.is_vault_locked("v1"), "the retained key is evicted");
        assert!(blob.exists(), "the unsigned signal deletes nothing");
        let refusal = state.ledger_refusal().unwrap();
        assert_eq!(refusal.code().0.as_str(), "device_not_admitted");
        assert_eq!(refusal.code().1, crate::error::DEVICE_ACCOUNT_MISSING_MSG);
        assert_eq!(state.ledger.lock().unwrap().checked_at, Some(T0));
    }

    /// The pull authenticates by DIK proof of possession alone, so a revoked
    /// device whose bearer the backend already dropped still receives its own
    /// revoke, and one pull decides the wipe.
    #[tokio::test]
    async fn a_revoked_device_without_a_bearer_still_pulls_its_revoke() {
        use axum::{http::HeaderMap, routing::get, Json, Router};
        let o = owner();
        let dik = SigningIdentity::from_seed(&[3u8; 32]);
        let dev = identity::derive_id(IdKind::Device, &dik.public_bytes());
        let dik_pub = dik.public_bytes();
        let events = vec![
            ev(&o, "admit", &dev, 1, &MY_PK),
            ev(&o, "revoke", &dev, 2, &[]),
        ];
        let head = sign_head(&o, &events);
        let body = serde_json::json!({
            "anchor": { "uik_id": o.user_id(), "uik_pub": STANDARD.encode(o.public_bytes()) },
            "events": events.iter().map(|e| serde_json::json!({
                "seq": e.seq, "op": e.op, "principal_id": e.principal_id,
                "anchor_uik": e.anchor_uik, "owner_id": e.owner_id, "sig": e.sig,
                "sc_pk": e.sc_pk,
            })).collect::<Vec<_>>(),
            "head": { "anchor": head.anchor, "max_seq": head.max_seq,
                      "events_hash": head.events_hash, "sig": head.sig },
        });
        let dev2 = dev.clone();
        let uik_q = format!("/api/vault/principals?uik={}", o.user_id());
        let app = Router::new().route(
            "/api/vault/principals",
            get(move |h: HeaderMap, uri: axum::http::Uri| {
                let body = body.clone();
                let dev = dev2.clone();
                let uik_q = uik_q.clone();
                async move {
                    // The pinned account rides the query, and the PoP covers it.
                    let pq = uri
                        .path_and_query()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default();
                    if pq != uik_q {
                        return Err(axum::http::StatusCode::BAD_REQUEST);
                    }
                    // The backend dropped this device's key: any bearer is refused.
                    if h.contains_key("authorization") {
                        return Err(axum::http::StatusCode::UNAUTHORIZED);
                    }
                    let hv = |k: &str| {
                        h.get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string()
                    };
                    let ts: u64 = hv(crate::device_auth::HDR_DEVICE_TS).parse().unwrap_or(0);
                    let sig = STANDARD
                        .decode(hv(crate::device_auth::HDR_DEVICE_SIG))
                        .unwrap_or_default();
                    let input = identity::device_request_signature_input("GET", &pq, ts, &[], &dev);
                    let ok = hv(crate::device_auth::HDR_DEVICE_ID) == dev
                        && <[u8; 64]>::try_from(sig.as_slice())
                            .is_ok_and(|s| identity::verify(&dik_pub, &input, &s));
                    if !ok {
                        return Err(axum::http::StatusCode::UNAUTHORIZED);
                    }
                    Ok(Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let signer = DeviceRequestSigner::new(dik, dev.clone());
        let client = reqwest::Client::new();
        let l = fetch_ledger(&client, &format!("http://{}", addr), &o.user_id(), &signer)
            .await
            .unwrap();
        let folded = verify_strict(&l, &o.user_id()).unwrap();
        let f = apply_pull(paired_at(1), &folded, &dev, &MY_PK, T0 + 60).unwrap();
        assert_eq!(gate(&f, T0 + 60, true, true), DeviceGate::Revoked);
    }

    /// The pairing admit proves the owner only over THIS machine's own keys.
    #[test]
    fn pairing_admit_binds_principal_key_and_owner() {
        let o = owner();
        let acct = o.user_id();
        let pk = [5u8; 32];
        let admit = |principal: &str, sc_pk: &[u8], seq: u64| {
            let input =
                identity::principal_event_input(&acct, "admit", principal, seq, &acct, sc_pk);
            let mut v = serde_json::json!({
                "seq": seq, "op": "admit", "principal_id": principal, "principal_kind": "device",
                "anchor_uik": acct, "owner_id": acct, "sig": STANDARD.encode(o.sign(&input)),
            });
            if !sc_pk.is_empty() {
                v["sc_pk"] = serde_json::json!(URL_SAFE_NO_PAD.encode(sc_pk));
            }
            v
        };
        let me = o.public_bytes();
        assert_eq!(
            verify_pairing_admit(&admit("dev_me", &pk, 3), &me, "dev_me", &pk).unwrap(),
            acct
        );
        assert_eq!(
            verify_pairing_admit(&admit("ag_me", &[], 4), &me, "ag_me", &[]).unwrap(),
            acct
        );
        assert!(verify_pairing_admit(&admit("dev_other", &pk, 3), &me, "dev_me", &pk).is_err());
        assert!(verify_pairing_admit(&admit("dev_me", &[6u8; 32], 3), &me, "dev_me", &pk).is_err());
        let imposter = SigningIdentity::from_seed(&[9u8; 32]).public_bytes();
        assert!(verify_pairing_admit(&admit("dev_me", &pk, 3), &imposter, "dev_me", &pk).is_err());
        let mut forged = admit("dev_me", &pk, 3);
        forged["seq"] = serde_json::json!(4);
        assert!(verify_pairing_admit(&forged, &me, "dev_me", &pk).is_err());
    }
}
