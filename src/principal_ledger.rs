//! §15 account principal ledger — daemon-side sync + verify + enforce.
//!
//! The cloud serves an append-only, owner-UIK-signed log of device/agent ADMIT +
//! REVOKE events at `GET /api/vault/principals`. This module pulls it, verifies
//! every event against the ACCOUNT ANCHOR (the owner UIK, self-certifying:
//! `derive_id(User, uik_pub) == anchor_uik`), folds by monotone `seq`, and — behind
//! a flag, DEFAULT OFF until the P6 cutover — ENFORCES a verified revoke of THIS
//! device by locking + wiping every local vault + logging out.
//!
//! Invariants (design §15):
//! - Destructive action fires ONLY on a daemon-VERIFIED owner signature, NEVER on a
//!   bare 401 (that class caused the transient-403 mass-outage incident; a fetch
//!   failure just parks and keeps the prior decision).
//! - The `anchor_uik`, trusted-on-pairing (TOFU), IS the anchor: a swapped anchor
//!   pubkey fails the self-cert check and the whole pull is rejected. No separate
//!   pin file is needed (the per-vault genesis-anchor trick, lifted to account scope).
//! - Rollback-resistant: a verified self-revoke LATCHES to disk (`principal_floor.json`),
//!   and a later pull whose max `seq` regresses below the recorded floor is ignored, so
//!   a malicious server dropping the revoke event cannot un-revoke a device.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::device_auth::DikRequestExt;
use crate::identity::{self, IdKind};
use crate::state::AppState;

// ── Wire shapes (GET /api/vault/principals) ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct AnchorJson {
    #[allow(dead_code)]
    uik_id: String,
    /// base64 raw 32-byte Ed25519 owner-UIK signing pubkey (public — `derive_id`
    /// is one-way, so serving it leaks nothing).
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
    sig: String, // base64 raw 64-byte Ed25519
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
    #[serde(default)]
    #[allow(dead_code)]
    cursor: u64,
}

/// The folded outcome of a verified ledger.
#[derive(Debug, Default)]
struct Folded {
    /// principal id → (final live-state, seq of its latest applied event). A principal
    /// ABSENT from the map has NO verified event in this pull (e.g. the server omitted
    /// it) — distinct from a present-but-revoked `(false, seq)`.
    state: HashMap<String, (bool, u64)>,
    /// highest `seq` among applied (verified) events.
    max_seq: u64,
}

impl Folded {
    /// The latest verified `(live, seq)` for a principal, or `None` if this pull carries
    /// no verified event about it. `None` must NEVER clear a latched decision — omission
    /// is not an owner action.
    fn status(&self, id: &str) -> Option<(bool, u64)> {
        self.state.get(id).copied()
    }
}

/// Persisted, rollback-resistant decision floor (`<state_dir>/principal_floor.json`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct LedgerFloor {
    /// Monotone high-water of applied `seq` (never regresses).
    #[serde(default)]
    seq: u64,
    /// MONOTONE self-revoke latch: set once THIS device's own revoke is VERIFIED, and
    /// cleared ONLY by a verified LATER admit (`seq > self_revoke_seq`) — NEVER because a
    /// pull merely omits the revoke event. So a compromised server that drops the revoke
    /// cannot un-revoke the device (the wave's headline invariant).
    #[serde(default)]
    self_revoked: bool,
    /// The `seq` at which `self_revoked` was latched (0 when not latched). A re-admit only
    /// clears the latch if it is strictly newer than this.
    #[serde(default)]
    self_revoke_seq: u64,
}

// ── Flag ────────────────────────────────────────────────────────────────────

/// Enforcement flag — DEFAULT OFF until the P6 cutover. A NEW destructive behavior
/// opts IN (the inverse of the `sync_stream` kill switch, which opts out).
/// `SAFECLAW_PRINCIPAL_ENFORCE` wins over the `principal_enforce` config key (the env
/// var survives an old binary's config save, so it is the robust lever either way).
pub fn principal_enforce_enabled() -> bool {
    let v = std::env::var("SAFECLAW_PRINCIPAL_ENFORCE")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            crate::cli::active::load()
                .ok()
                .and_then(|c| c.principal_enforce)
                .map(|s| s.trim().to_ascii_lowercase())
        });
    matches!(v.as_deref(), Some("on" | "1" | "true" | "yes" | "enabled"))
}

/// §15 leg-A require-signed-tombstone flag — DEFAULT OFF (an unsigned `status:"deleted"`
/// still drops local state, the legacy behavior). `SAFECLAW_REQUIRE_SIGNED_TOMBSTONE`
/// wins over `CliConfig.require_signed_tombstone`. Flipped on at the P6 cutover so a
/// server can no longer force a local wipe by flipping `status` without a valid
/// owner-signed tombstone (verified against the vault's fold-owner set).
pub fn require_signed_tombstone() -> bool {
    let v = std::env::var("SAFECLAW_REQUIRE_SIGNED_TOMBSTONE")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            crate::cli::active::load()
                .ok()
                .and_then(|c| c.require_signed_tombstone)
                .map(|s| s.trim().to_ascii_lowercase())
        });
    matches!(v.as_deref(), Some("on" | "1" | "true" | "yes" | "enabled"))
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

/// GET the account principal ledger with device-key bearer + DIK PoP (same auth
/// shape as vault discovery). Best-effort: any failure returns `None` and the
/// caller PARKS (keeps the prior decision) — a fetch failure is never a revoke.
async fn fetch_ledger(cloud: &str, dk: &str) -> Option<LedgerJson> {
    let cloud = cloud.trim_end_matches('/');
    let url = format!("{}/api/vault/principals", cloud);
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15)).ok()?;
    let resp = client
        .get(&url)
        .bearer_auth(dk)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        // 404 = a backend that predates the ledger; anything else transient. Park.
        tracing::debug!(status = %resp.status(), "principal ledger: non-success (old backend / transient)");
        return None;
    }
    resp.json().await.ok()
}

// ── Verify + fold ────────────────────────────────────────────────────────────

/// Verify every event against the account anchor and fold admit/revoke by monotone
/// `seq`. Returns `None` (fail closed → park) iff the anchor is missing or does NOT
/// self-certify against `anchor_uik` (a swapped anchor = untrusted source). An
/// individually invalid event (bad sig, foreign owner, unknown op) is SKIPPED, not
/// fatal — mirrors the per-vault `fold_roles`.
fn fold_verified(ledger: &LedgerJson, anchor_uik: &str) -> Option<Folded> {
    let anchor = ledger.anchor.as_ref()?;
    let anchor_pub = decode_pub32(&anchor.uik_pub)?;
    // Self-cert: the anchor pubkey MUST derive to the anchor_uik we pinned at pairing.
    if identity::derive_id(IdKind::User, &anchor_pub) != anchor_uik {
        tracing::warn!("principal ledger: anchor pubkey does not self-certify against anchor_uik; rejecting pull");
        return None;
    }

    // Deterministic total order; strictly-increasing seq (consumed-seq dup guard).
    let mut events: Vec<&PrincipalEventJson> = ledger.events.iter().collect();
    events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));

    // C4: the served events must be exactly what the owner committed to in a
    // validly signed head; otherwise the whole pull is refused (park, keep the
    // prior decision). Closes a forged or truncated tail.
    if let Err(why) = verify_head(ledger.head.as_ref(), &events, anchor_uik, &anchor_pub) {
        tracing::warn!(code = "ledger_head_invalid", "principal ledger: {}; rejecting pull", why);
        return None;
    }

    let mut state: HashMap<String, (bool, u64)> = HashMap::new();
    let mut last_seq: Option<u64> = None;
    let mut max_seq: u64 = 0;
    for e in events {
        if matches!(last_seq, Some(ls) if e.seq <= ls) {
            continue; // duplicate/backwards seq at the same position — keep the first
        }
        // The signer must be the account owner (owner_id == the anchor id), and the
        // event's own anchor_uik (when carried) must match too.
        if e.owner_id != anchor_uik {
            tracing::warn!(seq = e.seq, "principal ledger: event owner_id != account anchor; skipping");
            continue;
        }
        if !e.anchor_uik.is_empty() && e.anchor_uik != anchor_uik {
            tracing::warn!(seq = e.seq, "principal ledger: event anchor_uik mismatch; skipping");
            continue;
        }
        let Some(sig) = decode_sig64(&e.sig) else {
            tracing::warn!(seq = e.seq, "principal ledger: undecodable signature; skipping");
            continue;
        };
        // anchor_uik is the first signed field (== anchor for a personal account).
        let sc_pk = match e.sc_pk.as_deref().filter(|s| !s.is_empty()) {
            None => Vec::new(),
            Some(b) => match decode_b64_any(b) {
                Some(v) if v.len() == 32 => v,
                _ => {
                    tracing::warn!(seq = e.seq, "principal ledger: undecodable sc_pk; skipping");
                    continue;
                }
            },
        };
        let input =
            identity::principal_event_input(anchor_uik, &e.op, &e.principal_id, e.seq, &e.owner_id, &sc_pk);
        if !identity::verify(&anchor_pub, &input, &sig) {
            tracing::warn!(seq = e.seq, "principal ledger: signature does not verify; skipping");
            continue;
        }
        last_seq = Some(e.seq);
        max_seq = max_seq.max(e.seq);
        match e.op.as_str() {
            "admit" => {
                state.insert(e.principal_id.clone(), (true, e.seq));
            }
            "revoke" => {
                state.insert(e.principal_id.clone(), (false, e.seq));
            }
            other => tracing::warn!(op = %other, "principal ledger: unknown op; skipping"),
        }
    }
    Some(Folded { state, max_seq })
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
        return Err("the pairing's admit is not an admit of this machine".into());
    }
    if e.owner_id != owner || (!e.anchor_uik.is_empty() && e.anchor_uik != owner) {
        return Err("the pairing's admit is not signed by the approving account".into());
    }
    let served_pk = match e.sc_pk.as_deref().filter(|s| !s.is_empty()) {
        None => Vec::new(),
        Some(b) => decode_b64_any(b).ok_or("the admit's sc_pk is undecodable")?,
    };
    if served_pk != sc_pk {
        return Err("the pairing's admit binds another daemon key than this machine's".into());
    }
    let sig = decode_sig64(&e.sig).ok_or("the admit's signature is undecodable")?;
    let input = identity::principal_event_input(&owner, "admit", principal_id, e.seq, &owner, sc_pk);
    if !identity::verify(uik_pub, &input, &sig) {
        return Err("the pairing's admit signature does not verify".into());
    }
    Ok(owner)
}

// ── Floor persistence (rollback resistance) ─────────────────────────────────

pub(crate) fn floor_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("principal_floor.json")
}

fn load_floor(state_dir: &Path) -> LedgerFloor {
    std::fs::read_to_string(floor_path(state_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn store_floor(state_dir: &Path, floor: &LedgerFloor) {
    if let Ok(json) = serde_json::to_string(floor) {
        if let Err(e) = std::fs::write(floor_path(state_dir), json) {
            tracing::warn!("principal ledger: failed to persist floor: {}", e);
        }
    }
}

/// Fold a NON-REGRESSED pull into the decision floor — the F1 MONOTONE self-revoke latch,
/// as a pure function so it is directly testable. `my_dev` is THIS device's id. Rules:
/// - a verified self-`revoke` LATCHES `self_revoked` (raising `self_revoke_seq`);
/// - a verified self-`admit` clears it ONLY if strictly newer (`seq > self_revoke_seq`);
/// - the server OMITTING the revoke → `status(my_dev)` is `None` (or an OLDER admit) →
///   the latch is left UNTOUCHED, so a compromised server can never un-revoke by dropping
///   the event. `seq` only moves forward.
fn apply_fold_to_floor(mut floor: LedgerFloor, folded: &Folded, my_dev: Option<&str>) -> LedgerFloor {
    floor.seq = folded.max_seq.max(floor.seq);
    if let Some(dev) = my_dev {
        match folded.status(dev) {
            Some((false, rseq)) => {
                if !floor.self_revoked || rseq > floor.self_revoke_seq {
                    floor.self_revoked = true;
                    floor.self_revoke_seq = rseq;
                }
            }
            Some((true, aseq)) => {
                if floor.self_revoked && aseq > floor.self_revoke_seq {
                    floor.self_revoked = false;
                }
            }
            None => { /* omission is not an owner action — keep the latch */ }
        }
    }
    floor
}

// ── Enforcement ──────────────────────────────────────────────────────────────

/// Self-revoke enforcement: the owner revoked THIS device. Lock + wipe every local
/// vault (evict retained K + delete sealed blobs, in-process — no CLI), delete the
/// device-key, clear the pairing config, then EXIT. "A revoked device can't use
/// secrets" (design §15). Does not return.
async fn self_wipe_and_logout(state: &Arc<AppState>) -> ! {
    tracing::warn!(
        code = "ledger_device_revoked",
        "principal ledger: THIS DEVICE was revoked by the account owner (VERIFIED signature) — \
         locking + wiping all local vaults and logging out"
    );
    // 1. Lock + wipe every synced vault, in-process (zeroize retained K + remove the
    //    sealed blob), through the same locked drop the tombstone path uses.
    let vaults: Vec<String> = crate::cli::active::known_vaults()
        .into_iter()
        .map(|kv| kv.vault)
        .filter(|v| !v.is_empty())
        .collect();
    // F2: evict retained K from EVERY vault UP-FRONT (synchronous, in-memory) so the
    // serve window closes immediately — no in-flight request can be handed K for a
    // not-yet-dropped vault while the per-vault disk wipe below iterates.
    for vid in &vaults {
        state.lock_vault(vid);
    }
    for vid in &vaults {
        crate::sync::drop_local_vault_locked(state, vid).await;
    }
    // 2. Delete the device-key (this host's cloud credential): once gone, the bearer
    //    can never be matched again.
    if let Some(home) = dirs::home_dir() {
        let _ = std::fs::remove_file(home.join(".safeclaw").join("device-key"));
    }
    // 3. Clear the pairing from config + known-vaults (mirrors `sc logout`).
    if let Err(e) = crate::cli::active::clear_pairing() {
        tracing::warn!("principal ledger: failed to clear pairing config on self-revoke: {}", e);
    }
    // 4. Stop serving. With K evicted, blobs wiped, and the pairing gone, the daemon
    //    must not keep running; process exit is the in-process equivalent of the CLI
    //    `sc logout` stopping it.
    tracing::warn!("principal ledger: local state wiped; daemon exiting (re-pair with `sc login`)");
    std::process::exit(0);
}

// ── Loop ──────────────────────────────────────────────────────────────────

/// Periodic principal-ledger poll: pull → verify + fold → (flag-gated) enforce a
/// verified self-revoke. Spawned once per paired daemon (like the vault-discovery
/// reconcile loop). `anchor_uik` is the account's owner-UIK id (`us_…`) pinned at
/// pairing — the self-certifying ledger anchor (NOT the Supabase account UUID).
pub async fn principal_ledger_loop(state: Arc<AppState>, cloud: String, dk: String, anchor_uik: String) {
    /// Poll cadence. A revoke propagates within one interval of the owner tapping
    /// (or instantly on the next daemon start via the latched floor).
    const INTERVAL: Duration = Duration::from_secs(120);
    let state_dir = state.config.state_dir.clone();

    // The self-revoke decision is a MONOTONE, on-disk LATCH (F1): once a verified revoke
    // of THIS device is seen it stays latched — a later pull that merely OMITS the revoke
    // can NEVER clear it (only a verified LATER admit does). Enforcement reads the LATCH,
    // not the current pull, so a compromised server cannot un-revoke by dropping the event.
    let mut floor = load_floor(&state_dir);
    let my_dev = crate::device_auth::device_signer().map(|s| s.device_id().to_string());

    loop {
        // Enforce the LATCHED decision every iteration, independent of the current pull.
        // Covers a latch that survived a restart AND the enforce flag being flipped ON
        // mid-run (it is read live, so no restart is needed to start biting).
        if floor.self_revoked && principal_enforce_enabled() {
            self_wipe_and_logout(&state).await; // does not return
        }

        // Work first (immediate on start), then wait — a fresh revoke enforces within one
        // poll rather than after a full INTERVAL.
        if let Some(ledger) = fetch_ledger(&cloud, &dk).await {
            if let Some(folded) = fold_verified(&ledger, &anchor_uik) {
                if folded.max_seq < floor.seq {
                    // Wholesale regression (max seq below our high-water). Ignore the pull;
                    // the monotone latch above already protects an already-observed revoke.
                    tracing::warn!(
                        max = folded.max_seq,
                        floor = floor.seq,
                        "principal ledger: pull regressed below the known seq (rollback?); ignoring"
                    );
                } else {
                    let before = (floor.seq, floor.self_revoked, floor.self_revoke_seq);
                    floor = apply_fold_to_floor(floor, &folded, my_dev.as_deref());
                    if (floor.seq, floor.self_revoked, floor.self_revoke_seq) != before {
                        store_floor(&state_dir, &floor);
                    }
                    // Enforce immediately after a fresh latch so a just-seen revoke wipes
                    // this round rather than next.
                    if floor.self_revoked {
                        if principal_enforce_enabled() {
                            self_wipe_and_logout(&state).await;
                        } else {
                            tracing::warn!(
                                code = "ledger_device_revoked",
                                device = ?my_dev,
                                "principal ledger: THIS device is revoked (VERIFIED, latched) but enforcement \
                                 is OFF (SAFECLAW_PRINCIPAL_ENFORCE); NOT wiping — the P6 cutover flips the default"
                            );
                        }
                    }
                    // Agent revokes ride the existing /agents/hashes sync (backend drops
                    // the key); the ledger is the account-level record + daemon-verifiable
                    // authority the P6 cutover enforces directly.
                    // Tail omission is closed by the owner-signed head (C4, verified in
                    // `fold_verified`). RESIDUAL: the server can still serve an OLDER but
                    // consistent head + list (hiding a later revoke), bounded by re-key
                    // on offboard (design approval-key-delivery §3).
                }
            }
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningIdentity;

    // Deterministic owner UIK for the vectors below.
    const OWNER_SEED: [u8; 32] = [7u8; 32];

    fn owner() -> SigningIdentity {
        SigningIdentity::from_seed(&OWNER_SEED)
    }

    fn signed_event(owner: &SigningIdentity, anchor_uik: &str, op: &str, principal: &str, seq: u64) -> PrincipalEventJson {
        let input = identity::principal_event_input(anchor_uik, op, principal, seq, anchor_uik, &[]);
        let sig = owner.sign(&input);
        PrincipalEventJson {
            seq,
            op: op.to_string(),
            principal_id: principal.to_string(),
            principal_kind: if principal.starts_with("dev_") { "device" } else { "agent" }.to_string(),
            anchor_uik: anchor_uik.to_string(),
            owner_id: anchor_uik.to_string(),
            sig: STANDARD.encode(sig),
            sc_pk: None,
            created_at: String::new(),
        }
    }

    fn ledger(owner: &SigningIdentity, events: Vec<PrincipalEventJson>) -> LedgerJson {
        let head = Some(sign_head(owner, &events));
        LedgerJson {
            events,
            anchor: Some(AnchorJson {
                uik_id: owner.user_id(),
                uik_pub: STANDARD.encode(owner.public_bytes()),
            }),
            head,
            cursor: 0,
        }
    }

    /// The owner's signed head over `events` (C4), as the console writes it.
    fn sign_head(owner: &SigningIdentity, events: &[PrincipalEventJson]) -> HeadJson {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut sorted: Vec<&PrincipalEventJson> = events.iter().collect();
        sorted.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
        let sigs: Vec<Vec<u8>> = sorted.iter().map(|e| STANDARD.decode(&e.sig).unwrap()).collect();
        let hash = identity::principal_events_hash(&sigs);
        let max_seq = sorted.last().map(|e| e.seq).unwrap_or(0);
        let sig = owner.sign(&identity::principal_head_input(&owner.user_id(), max_seq, &hash));
        HeadJson {
            anchor: owner.user_id(),
            max_seq,
            events_hash: URL_SAFE_NO_PAD.encode(hash),
            sig: URL_SAFE_NO_PAD.encode(sig),
        }
    }

    #[test]
    fn admit_then_revoke_folds_to_revoked() {
        let o = owner();
        let acct = o.user_id();
        let l = ledger(&o, vec![
            signed_event(&o, &acct, "admit", "dev_box", 1),
            signed_event(&o, &acct, "revoke", "dev_box", 2),
        ]);
        let folded = fold_verified(&l, &acct).expect("trusted anchor folds");
        assert_eq!(folded.status("dev_box"), Some((false, 2)), "final state is revoked @ seq 2");
        assert_eq!(folded.max_seq, 2);
    }

    #[test]
    fn revoke_then_readmit_clears() {
        let o = owner();
        let acct = o.user_id();
        let l = ledger(&o, vec![
            signed_event(&o, &acct, "admit", "dev_box", 1),
            signed_event(&o, &acct, "revoke", "dev_box", 2),
            signed_event(&o, &acct, "admit", "dev_box", 3),
        ]);
        let folded = fold_verified(&l, &acct).unwrap();
        assert_eq!(folded.status("dev_box"), Some((true, 3)), "a higher-seq re-admit un-revokes");
        assert_eq!(folded.max_seq, 3);
    }

    #[test]
    fn wrong_anchor_rejects_whole_pull() {
        let o = owner();
        let acct = o.user_id();
        let mut l = ledger(&o, vec![signed_event(&o, &acct, "revoke", "dev_box", 1)]);
        // Swap the anchor pubkey to a different key: self-cert (derive_id == anchor_uik) fails.
        let imposter = SigningIdentity::from_seed(&[9u8; 32]);
        l.anchor = Some(AnchorJson { uik_id: imposter.user_id(), uik_pub: STANDARD.encode(imposter.public_bytes()) });
        assert!(fold_verified(&l, &acct).is_none(), "a swapped anchor is untrusted → park");
    }

    #[test]
    fn forged_signature_event_is_skipped_not_fatal() {
        let o = owner();
        let acct = o.user_id();
        let mut forged = signed_event(&o, &acct, "revoke", "dev_box", 2);
        // Corrupt the signature: this event must be skipped, the valid admit still applies.
        forged.sig = STANDARD.encode([0u8; 64]);
        let l = ledger(&o, vec![signed_event(&o, &acct, "admit", "ag_bot", 1), forged]);
        let folded = fold_verified(&l, &acct).expect("valid anchor");
        assert_eq!(folded.status("dev_box"), None, "forged revoke is skipped (no verified event about dev_box)");
        assert_eq!(folded.status("ag_bot"), Some((true, 1)), "ag_bot was admitted, not revoked");
        assert_eq!(folded.max_seq, 1, "only the verified admit counts");
    }

    #[test]
    fn foreign_owner_event_is_skipped() {
        let o = owner();
        let acct = o.user_id();
        // An event whose owner_id is someone else, but signed by our owner (a confused
        // or malicious re-attribution): owner_id != account anchor → skipped.
        let mut ev = signed_event(&o, &acct, "revoke", "dev_box", 1);
        ev.owner_id = "us_someone_else".to_string();
        let l = ledger(&o, vec![ev]);
        let folded = fold_verified(&l, &acct).unwrap();
        assert!(folded.state.is_empty(), "foreign-owner event does not fold");
    }

    /// C4: a ledger without a head, with a dropped or added event, or whose
    /// head another key signed is refused whole (park), never folded.
    #[test]
    fn a_ledger_not_matching_its_signed_head_is_refused() {
        let o = owner();
        let acct = o.user_id();
        let events = || {
            vec![
                signed_event(&o, &acct, "admit", "dev_box", 1),
                signed_event(&o, &acct, "revoke", "dev_box", 2),
            ]
        };
        assert!(fold_verified(&ledger(&o, events()), &acct).is_some(), "honest ledger folds");

        let mut l = ledger(&o, events());
        l.head = None;
        assert!(fold_verified(&l, &acct).is_none(), "no head");

        // Truncated tail: the revoke dropped, the full head kept.
        let mut l = ledger(&o, events());
        l.events.pop();
        assert!(fold_verified(&l, &acct).is_none(), "truncated tail");

        // An extra (validly signed) event the head does not commit to.
        let mut l = ledger(&o, events());
        l.events.push(signed_event(&o, &acct, "admit", "dev_other", 3));
        assert!(fold_verified(&l, &acct).is_none(), "extra event");

        // A head signed by someone else over the same list.
        let imposter = SigningIdentity::from_seed(&[9u8; 32]);
        let mut l = ledger(&o, events());
        let mut forged = sign_head(&imposter, &l.events);
        forged.anchor = acct.clone();
        l.head = Some(forged);
        assert!(fold_verified(&l, &acct).is_none(), "foreign head signer");

        // A head whose max_seq lies about the tail.
        let mut l = ledger(&o, events());
        let mut h = sign_head(&o, &l.events);
        h.max_seq = 5;
        l.head = Some(h);
        assert!(fold_verified(&l, &acct).is_none(), "max_seq mismatch");
    }

    /// The pairing admit proves the owner only over THIS machine's own keys.
    #[test]
    fn pairing_admit_binds_principal_key_and_owner() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let o = owner();
        let acct = o.user_id();
        let pk = [5u8; 32];
        let admit = |principal: &str, sc_pk: &[u8], seq: u64| {
            let input = identity::principal_event_input(&acct, "admit", principal, seq, &acct, sc_pk);
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
        assert_eq!(verify_pairing_admit(&admit("dev_me", &pk, 3), &me, "dev_me", &pk).unwrap(), acct);
        assert_eq!(verify_pairing_admit(&admit("ag_me", &[], 4), &me, "ag_me", &[]).unwrap(), acct);
        assert!(verify_pairing_admit(&admit("dev_other", &pk, 3), &me, "dev_me", &pk).is_err());
        assert!(verify_pairing_admit(&admit("dev_me", &[6u8; 32], 3), &me, "dev_me", &pk).is_err());
        let imposter = SigningIdentity::from_seed(&[9u8; 32]).public_bytes();
        assert!(verify_pairing_admit(&admit("dev_me", &pk, 3), &imposter, "dev_me", &pk).is_err());
        let mut forged = admit("dev_me", &pk, 3);
        forged["seq"] = serde_json::json!(4);
        assert!(verify_pairing_admit(&forged, &me, "dev_me", &pk).is_err());
    }

    // F1 regression: the MONOTONE self-revoke latch (`apply_fold_to_floor`). Once a revoke
    // of self is verified, a later pull that OMITS it — even while serving an OLDER admit
    // and a NEWER unrelated event — must NOT un-revoke. Only a verified LATER admit clears it.
    #[test]
    fn monotone_latch_survives_omitted_revoke() {
        let o = owner();
        let acct = o.user_id();
        let dev = "dev_me";

        // Pull 1: dev_me revoked at seq 2 → latch {revoked, revoke_seq: 2, seq: 2}.
        let p1 = ledger(&o, vec![
            signed_event(&o, &acct, "admit", dev, 1),
            signed_event(&o, &acct, "revoke", dev, 2),
        ]);
        let f1 = apply_fold_to_floor(LedgerFloor::default(), &fold_verified(&p1, &acct).unwrap(), Some(dev));
        assert!(f1.self_revoked && f1.self_revoke_seq == 2 && f1.seq == 2);

        // Pull 2 (malicious): revoke(2) OMITTED, admit(1) kept (dev_me looks "admitted" @1),
        // plus a genuine NEWER unrelated event (admit dev_other @3) so max_seq advances. The
        // OLDER admit (seq 1 <= revoke seq 2) must NOT clear the latch.
        let p2 = ledger(&o, vec![
            signed_event(&o, &acct, "admit", dev, 1),
            signed_event(&o, &acct, "admit", "dev_other", 3),
        ]);
        let f2 = apply_fold_to_floor(f1, &fold_verified(&p2, &acct).unwrap(), Some(dev));
        assert!(f2.self_revoked, "an omitted revoke (only an OLDER admit served) must NOT un-revoke");
        assert_eq!(f2.seq, 3, "high-water still advances on the unrelated event");

        // Pull 3: a genuine re-admit at seq > the revoke seq is the ONLY thing that clears it.
        let p3 = ledger(&o, vec![signed_event(&o, &acct, "admit", dev, 4)]);
        let f3 = apply_fold_to_floor(f2, &fold_verified(&p3, &acct).unwrap(), Some(dev));
        assert!(!f3.self_revoked, "a verified LATER admit clears the latch");
    }
}
