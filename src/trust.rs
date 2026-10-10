//! The daemon's trust chain (trust-reset design D4-D6, A3).
//!
//! Everything the daemon accepts rests on ONE anchor: the person (`us_` + UIK
//! sign pub) it pinned at `sc login`, after the admission mac verified under the
//! code the human typed. From there:
//!
//!  - **own ledger**: folded under the pinned UIK sign pub. It yields this
//!    person's vault pins, live passkeys and devices, and the self-read latch:
//!    a verified `revoke{device}` of THIS device wipes the DIK and enc key;
//!  - **member records**: verified against the reader's OWN pin for the vault
//!    ([`MemberRecord::from_served`]); a record whose anchor differs is refused;
//!  - **other members' ledgers**: folded under the sign pub the verified member
//!    record carries for them; used ONLY for the passkey pubs an approval
//!    assertion is checked against (an approver's passkey must be admitted in
//!    that approver's own ledger).
//!
//! Latching (A3): every ledger the daemon has seen is cached; a served ledger
//! must EXTEND the cached one (same hash at every seq it already holds). A known
//! seq served with a different hash, or a shorter ledger, is a hard failure: the
//! cached state stays and nothing new is trusted from that ledger. Member
//! records latch `(seq, hash)` the same way (see [`adopt_record`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cloud::{DeviceClient, Refusal};
use crate::crypto::ledger::{
    fold_ledger_inputs, LedgerError, LedgerEventFields, LedgerState, SignedInput,
};
use crate::passkey::PasskeyEntry;
use crate::storage::sealed_vault::{MemberRecord, PerItemVault, RecordError};

const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// The person this device is paired to, pinned at `sc login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonAnchor {
    pub us: String,
    pub sign_pub: [u8; 32],
}

/// The pinned anchor from config. `None` when this machine was never paired
/// under the trust reset (an old `account_uik` alone is not an anchor: it was
/// served, never checked).
pub fn own_anchor() -> Option<PersonAnchor> {
    let cfg = crate::cli::active::load().ok()?;
    let us = cfg.person.filter(|s| !s.is_empty())?;
    let sign_pub: [u8; 32] = BASE64URL_NOPAD
        .decode(cfg.person_sign_pub.as_deref()?.as_bytes())
        .ok()?
        .try_into()
        .ok()?;
    (crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub) == us)
        .then_some(PersonAnchor { us, sign_pub })
}

/// Why a ledger could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// Could not fetch (network, a 5xx, …): the cached state stands.
    Fetch(String),
    /// A device-wide refusal ([`Refusal`]).
    Refused(Refusal),
    /// The ledger does not fold (bad signature, seq gap, …): hard failure.
    Invalid(LedgerError),
    /// A seq this daemon already latched was served with a different event.
    Equivocation { seq: u64 },
    /// The served ledger is shorter than the one this daemon latched.
    Rollback { held: u64, served: u64 },
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::Fetch(m) => write!(f, "ledger fetch failed: {}", m),
            TrustError::Refused(r) => f.write_str(&r.message()),
            TrustError::Invalid(e) => write!(f, "{}", e),
            TrustError::Equivocation { seq } => write!(
                f,
                "the server served a different ledger event at seq {} than it did before",
                seq
            ),
            TrustError::Rollback { held, served } => write!(
                f,
                "the server served {} ledger events but this device already holds {}",
                served, held
            ),
        }
    }
}

impl TrustError {
    /// A hard failure (equivocation, rollback, invalid) as opposed to a
    /// transient one: hard failures are logged at error level and refuse.
    pub fn is_hard(&self) -> bool {
        matches!(
            self,
            TrustError::Invalid(_) | TrustError::Equivocation { .. } | TrustError::Rollback { .. }
        )
    }
}

/// One cached event, as served (`{input, sig}`, b64url).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WireEvent {
    input: String,
    sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerCache {
    us: String,
    sign_pub: String,
    events: Vec<WireEvent>,
}

fn ledger_path(state_dir: &Path, us: &str) -> Option<PathBuf> {
    // `us` comes from a verified source, but it names a file: refuse anything
    // that is not a well-formed id.
    (crate::identity::parse_id(us) == Some(crate::identity::IdKind::User))
        .then(|| state_dir.join("ledgers").join(format!("{}.json", us)))
}

fn decode_events(events: &[WireEvent]) -> Option<Vec<SignedInput>> {
    events
        .iter()
        .map(|e| {
            Some(SignedInput {
                input: BASE64URL_NOPAD.decode(e.input.as_bytes()).ok()?,
                sig: BASE64URL_NOPAD.decode(e.sig.as_bytes()).ok()?,
            })
        })
        .collect()
}

fn encode_events(events: &[SignedInput]) -> Vec<WireEvent> {
    events
        .iter()
        .map(|e| WireEvent {
            input: BASE64URL_NOPAD.encode(&e.input),
            sig: BASE64URL_NOPAD.encode(&e.sig),
        })
        .collect()
}

fn load_cache(state_dir: &Path, us: &str, sign_pub: &[u8; 32]) -> Vec<SignedInput> {
    let Some(path) = ledger_path(state_dir, us) else {
        return Vec::new();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    let Ok(cache) = serde_json::from_slice::<LedgerCache>(&bytes) else {
        return Vec::new();
    };
    // A cache for another key is not this person's ledger.
    if cache.us != us || cache.sign_pub != BASE64URL_NOPAD.encode(sign_pub) {
        return Vec::new();
    }
    decode_events(&cache.events).unwrap_or_default()
}

fn store_cache(state_dir: &Path, us: &str, sign_pub: &[u8; 32], events: &[SignedInput]) {
    let Some(path) = ledger_path(state_dir, us) else {
        return;
    };
    let cache = LedgerCache {
        us: us.to_string(),
        sign_pub: BASE64URL_NOPAD.encode(sign_pub),
        events: encode_events(events),
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("json.tmp");
    match serde_json::to_vec_pretty(&cache) {
        Ok(bytes) => {
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
        Err(e) => tracing::warn!(us = %us, "ledger cache encode failed: {}", e),
    }
}

/// The latch (design A3): the served events must EXTEND the held ones — every
/// seq already held carries the identical signing input and signature.
pub fn latch(held: &[SignedInput], served: &[SignedInput]) -> Result<(), TrustError> {
    if served.len() < held.len() {
        return Err(TrustError::Rollback {
            held: held.len() as u64,
            served: served.len() as u64,
        });
    }
    for (i, (h, s)) in held.iter().zip(served.iter()).enumerate() {
        if h != s {
            return Err(TrustError::Equivocation { seq: i as u64 });
        }
    }
    Ok(())
}

/// Parse a `{events: [{input, sig}], head_seq}` body. A body that doesn't parse
/// is a fetch failure (nothing to fold); an event whose fields aren't base64url
/// is folded as `bad_fields` at its index (the strict parse sees the garbage).
fn parse_served(body: &Value) -> Result<Vec<SignedInput>, TrustError> {
    let events = body
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| TrustError::Fetch("ledger response has no events".into()))?;
    Ok(events
        .iter()
        .map(|e| SignedInput {
            input: e
                .get("input")
                .and_then(|v| v.as_str())
                .and_then(|s| BASE64URL_NOPAD.decode(s.as_bytes()).ok())
                .unwrap_or_default(),
            sig: e
                .get("sig")
                .and_then(|v| v.as_str())
                .and_then(|s| BASE64URL_NOPAD.decode(s.as_bytes()).ok())
                .unwrap_or_default(),
        })
        .collect())
}

/// Fold a ledger already served (the testable core of [`refresh_ledger`]):
/// latch against `held`, then fold the whole served ledger.
pub fn verify_served(
    us: &str,
    sign_pub: &[u8; 32],
    held: &[SignedInput],
    served: &[SignedInput],
) -> Result<LedgerState, TrustError> {
    latch(held, served)?;
    fold_ledger_inputs(us, sign_pub, served).map_err(TrustError::Invalid)
}

/// Fetch, latch, fold and cache a person's ledger (`GET /device/ledger/{us}`).
/// The whole ledger is fetched every time (they are small) so the latch covers
/// every event, with no dependence on how `since` counts.
pub async fn refresh_ledger(
    client: &DeviceClient,
    state_dir: &Path,
    us: &str,
    sign_pub: &[u8; 32],
) -> Result<LedgerState, TrustError> {
    let held = load_cache(state_dir, us, sign_pub);
    let served = fetch_ledger(client, us).await?;
    let state = verify_served(us, sign_pub, &held, &served)?;
    if served.len() != held.len() {
        store_cache(state_dir, us, sign_pub, &served);
    }
    Ok(state)
}

/// The most pages one ledger read follows before giving up as incomplete.
const MAX_LEDGER_PAGES: usize = 256;

/// What to do after one ledger page (contract 8.8: reads are paged and
/// complete; `head_seq` is `max(seq)`, null for an empty ledger).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageStep {
    Done,
    /// Read on from `since` (the seq of the page's last event).
    More(u64),
    /// The page stops short of `head_seq` and gives nowhere to read on from.
    Incomplete,
}

fn next_page(head_seq: Option<u64>, page: &[SignedInput]) -> PageStep {
    let Some(head) = head_seq else {
        return PageStep::Done;
    };
    let Some(last) = page.last() else {
        return PageStep::Incomplete;
    };
    match LedgerEventFields::parse_signing_input(&last.input) {
        Some(ev) if ev.seq >= head => PageStep::Done,
        Some(ev) => PageStep::More(ev.seq),
        // An unparseable event: stop here and let the fold report it.
        None => PageStep::Done,
    }
}

/// Read a person's whole ledger, page by page.
async fn fetch_ledger(client: &DeviceClient, us: &str) -> Result<Vec<SignedInput>, TrustError> {
    let mut events = Vec::new();
    let mut since: Option<u64> = None;
    for _ in 0..MAX_LEDGER_PAGES {
        let path = match since {
            None => format!("/device/ledger/{}", us),
            Some(s) => format!("/device/ledger/{}?since={}", us, s),
        };
        let resp = client
            .get(&path, FETCH_TIMEOUT)
            .await
            .map_err(TrustError::Fetch)?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status != 200 {
            if let Some(r) = crate::cloud::refusal(status, &body) {
                return Err(TrustError::Refused(r));
            }
            return Err(TrustError::Fetch(format!("ledger GET HTTP {}", status)));
        }
        let page = parse_served(&body)?;
        let step = next_page(body.get("head_seq").and_then(|v| v.as_u64()), &page);
        events.extend(page);
        match step {
            PageStep::Done => return Ok(events),
            PageStep::More(s) => since = Some(s),
            PageStep::Incomplete => {
                return Err(TrustError::Fetch(
                    "the ledger read stopped short of its head_seq".into(),
                ))
            }
        }
    }
    Err(TrustError::Fetch(format!(
        "the ledger did not complete within {} pages",
        MAX_LEDGER_PAGES
    )))
}

/// Fold the cached ledger with no network (startup, offline).
pub fn cached_ledger(state_dir: &Path, us: &str, sign_pub: &[u8; 32]) -> Option<LedgerState> {
    let held = load_cache(state_dir, us, sign_pub);
    if held.is_empty() {
        return None;
    }
    fold_ledger_inputs(us, sign_pub, &held).ok()
}

/// What this device's own ledger says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfStatus {
    Live,
    /// A verified `revoke{device}` of this `dv_`: wipe the device identity.
    Revoked,
    /// Not in the ledger (yet).
    Unknown,
}

pub fn self_status(ledger: &LedgerState, dv: &str) -> SelfStatus {
    if ledger.device_revoked_at(dv).is_some() {
        SelfStatus::Revoked
    } else if ledger.device(dv).is_some() {
        SelfStatus::Live
    } else {
        SelfStatus::Unknown
    }
}

/// The daemon's in-memory trust state.
#[derive(Default)]
pub struct TrustCache {
    /// The own person's folded ledger (pins, passkeys, devices).
    own: Mutex<Option<LedgerState>>,
    /// Other members' folded ledgers, keyed by `us_`.
    others: Mutex<HashMap<String, LedgerState>>,
    /// Vaults refused by a hard trust failure (equivocation, rollback, pin
    /// mismatch), with the reason. Approvals and serving refuse while set.
    refused: Mutex<HashMap<String, String>>,
    /// A digest of the whole member record last adopted (or confirmed) per
    /// vault in this process ([`record_digest`]): a held record must still be
    /// exactly that one, field for field.
    records: Mutex<HashMap<String, [u8; 32]>>,
}

impl TrustCache {
    pub fn own_ledger(&self) -> Option<LedgerState> {
        self.own.lock().unwrap().clone()
    }
    pub fn set_own_ledger(&self, l: LedgerState) {
        *self.own.lock().unwrap() = Some(l);
    }
    pub fn ledger_of(&self, us: &str) -> Option<LedgerState> {
        if let Some(own) = self.own.lock().unwrap().as_ref().filter(|l| l.us() == us) {
            return Some(own.clone());
        }
        self.others.lock().unwrap().get(us).cloned()
    }
    pub fn set_ledger_of(&self, l: LedgerState) {
        self.others.lock().unwrap().insert(l.us().to_string(), l);
    }
    pub fn refuse_vault(&self, vault: &str, why: String) {
        self.refused.lock().unwrap().insert(vault.to_string(), why);
    }
    pub fn clear_refusal(&self, vault: &str) {
        self.refused.lock().unwrap().remove(vault);
    }
    pub fn refusal(&self, vault: &str) -> Option<String> {
        self.refused.lock().unwrap().get(vault).cloned()
    }
    /// Latch the record just adopted or confirmed for `vault`. Called under
    /// the vault write lock, with the store write, so readers never see the
    /// store and the latch disagree.
    pub fn latch_record(&self, vault: &str, record: &MemberRecord) {
        self.records
            .lock()
            .unwrap()
            .insert(vault.to_string(), record_digest(record));
    }
    /// Forget a vault's latch (its local state was dropped).
    pub fn forget_record(&self, vault: &str) {
        self.records.lock().unwrap().remove(vault);
    }
    fn record_latch(&self, vault: &str) -> Option<[u8; 32]> {
        self.records.lock().unwrap().get(vault).copied()
    }
}

/// SHA-256 of a held record's full serialized form: every field, so a store
/// edit that keeps `seq` and `hash` but changes anything else is caught.
fn record_digest(record: &MemberRecord) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(serde_json::to_vec(record).unwrap_or_default()).into()
}

/// Re-verify a record loaded from the store before it decides anything (design
/// D7: the store is not a trust root). It must fold under the anchor the own
/// ledger pins for this vault, for this person, with this person a current
/// member, and be the record this process last latched (when it latched one;
/// a fresh process relies on the pin and the fold until the first pull).
pub fn check_held_record(
    trust: &TrustCache,
    vault_id: &str,
    record: &MemberRecord,
) -> Result<(), RecordError> {
    let own = trust.own_ledger().ok_or(RecordError::Unpinned)?;
    let pin = own.pin(vault_id).ok_or(RecordError::Unpinned)?;
    record.verify_held(vault_id, pin.anchor(), own.us())?;
    if let Some(latched) = trust.record_latch(vault_id) {
        if latched != record_digest(record) {
            return Err(RecordError::NotLatched);
        }
    }
    Ok(())
}

/// The outcome of adopting a served member record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordAdopt {
    /// Verified and newer: stored.
    Adopted,
    /// Same seq and hash as held: nothing to do.
    Unchanged,
}

/// Why a served member record was not adopted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptError {
    /// The record itself failed to verify.
    Record(RecordError),
    /// The person has no pin for this vault yet.
    NoPin,
    /// A seq this daemon holds was served with different content.
    Equivocation { seq: u64 },
    /// An older seq or generation than the one this daemon holds.
    Rollback,
}

impl std::fmt::Display for AdoptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptError::Record(e) => write!(f, "{}", e),
            AdoptError::NoPin => f.write_str(
                "your account has no pin for this vault yet — open it in the console \
                 (upgrade this vault, or join it from its link)",
            ),
            AdoptError::Equivocation { seq } => write!(
                f,
                "the server served a different member record at seq {} than before",
                seq
            ),
            AdoptError::Rollback => {
                f.write_str("the server served an older member record than this device holds")
            }
        }
    }
}

/// Verify a served record against the reader's pin and latch it against the
/// one `pv` holds: a different hash at the held seq is equivocation; a lower
/// seq (or a lower K generation) is a rollback. On success `pv.record` holds
/// the verified record.
pub fn adopt_record(
    pv: &mut PerItemVault,
    vault_id: &str,
    body: &Value,
    own_ledger: &LedgerState,
) -> Result<RecordAdopt, AdoptError> {
    let pin = own_ledger.pin(vault_id).ok_or(AdoptError::NoPin)?;
    let record = MemberRecord::from_served(vault_id, body, pin.anchor(), own_ledger.us())
        .map_err(AdoptError::Record)?;
    if let Some(held) = pv.record.as_ref() {
        if record.seq < held.seq || record.generation < held.generation {
            return Err(AdoptError::Rollback);
        }
        if record.seq == held.seq {
            if record.hash != held.hash {
                return Err(AdoptError::Equivocation { seq: record.seq });
            }
            // Same seq, same served content: unchanged, unless the held copy
            // differs from what verified now (a store edited outside sync).
            // Then the verified one replaces it.
            if *held == record {
                return Ok(RecordAdopt::Unchanged);
            }
        }
    }
    pv.record = Some(record);
    Ok(RecordAdopt::Adopted)
}

/// The passkey a grant's assertion must verify against: a live passkey with
/// credential id `cid` in the ledger of a CURRENT member of the verified
/// record (design D5.3: assertion pubs come only from the approver member's
/// ledger passkey admits). Ledgers are taken from the cache first, refreshed
/// (latched) from the backend when `cid` isn't found. `None` when no member
/// admitted such a passkey.
pub async fn approver_passkey(
    trust: &TrustCache,
    client: Option<&DeviceClient>,
    state_dir: &Path,
    record: &MemberRecord,
    vault_id: &str,
    cid: &str,
) -> Option<PasskeyEntry> {
    let cid = canonical_cid(cid)?;
    let members = member_keys(record, vault_id);
    for (us, _) in &members {
        if let Some(e) = trust.ledger_of(us).and_then(|l| passkey_entry(&l, &cid)) {
            return Some(e);
        }
    }
    let client = client?;
    // Own person first: most approvals are the requester's own.
    let own = trust.own_ledger().map(|l| l.us().to_string());
    let mut ordered = members;
    ordered.sort_by_key(|(us, _)| Some(us) != own.as_ref());
    for (us, sign_pub) in ordered {
        match refresh_ledger(client, state_dir, &us, &sign_pub).await {
            Ok(l) => {
                let hit = passkey_entry(&l, &cid);
                if Some(&us) == own.as_ref() {
                    trust.set_own_ledger(l);
                } else {
                    trust.set_ledger_of(l);
                }
                if hit.is_some() {
                    return hit;
                }
            }
            Err(e) => tracing::warn!(us = %us, "approver ledger refresh failed: {}", e),
        }
    }
    None
}

/// The current members of a verified record with the sign pub each one's
/// ledger folds under (a member row, or the resolved root for a root without one).
fn member_keys(record: &MemberRecord, vault_id: &str) -> Vec<(String, [u8; 32])> {
    record
        .current_members(vault_id)
        .into_keys()
        .filter_map(|us| {
            let pk = record.member_sig_pub(&us).or_else(|| {
                <[u8; 32]>::try_from(record.anchor.as_slice())
                    .ok()
                    .filter(|a| crate::identity::derive_id(crate::identity::IdKind::User, a) == us)
            })?;
            Some((us, pk))
        })
        .collect()
}

/// A credential id in the ledger's spelling (canonical unpadded base64url).
fn canonical_cid(cid: &str) -> Option<String> {
    let raw = crate::protocol::operation::decode_credential_id(cid).ok()?;
    Some(BASE64URL_NOPAD.encode(&raw))
}

fn passkey_entry(ledger: &LedgerState, cid: &str) -> Option<PasskeyEntry> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let p = ledger.passkey(cid)?;
    Some(PasskeyEntry {
        x: STANDARD.encode(&p.xy()[..32]),
        y: STANDARD.encode(&p.xy()[32..]),
        device_name: p.label().to_string(),
        created_at: 0,
    })
}

/// A person whose ledger tests can grow and fold (no files, no network).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::crypto::ledger::LedgerEventFields;
    use crate::identity::SigningIdentity;

    pub(crate) struct Person {
        pub uik: SigningIdentity,
        pub events: Vec<SignedInput>,
    }

    impl Person {
        pub fn new(seed: u8) -> Self {
            Self::from_identity(SigningIdentity::from_seed(&[seed; 32]))
        }
        pub fn from_identity(uik: SigningIdentity) -> Self {
            Self {
                uik,
                events: Vec::new(),
            }
        }
        pub fn us(&self) -> String {
            self.uik.user_id()
        }
        pub fn push(
            &mut self,
            op: &str,
            kind: &str,
            principal: String,
            sig_pub: Vec<u8>,
            enc_pub: Vec<u8>,
        ) {
            let f = LedgerEventFields {
                us: self.us(),
                op: op.into(),
                kind: kind.into(),
                principal,
                sig_pub,
                enc_pub,
                label: "x".into(),
                seq: self.events.len() as u64,
            };
            let input = f.signing_input();
            self.events.push(SignedInput {
                sig: self.uik.sign(&input).to_vec(),
                input,
            });
        }
        pub fn fold(&self) -> LedgerState {
            fold_ledger_inputs(&self.us(), &self.uik.public_bytes(), &self.events).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::Person;
    use super::*;
    use crate::crypto::ledger::{KIND_DEVICE, KIND_PASSKEY, KIND_PIN, OP_ADMIT, OP_REVOKE};
    use crate::identity::SigningIdentity;

    /// Ledger reads are paged (8.8): read on from the last event's seq until
    /// it reaches `head_seq`; an empty ledger is done; a short empty page is
    /// incomplete.
    #[test]
    fn ledger_paging_reads_to_head_seq() {
        let mut p = Person::new(5);
        for i in 0..3u8 {
            p.push(
                OP_ADMIT,
                KIND_PIN,
                format!("vault-{i}"),
                vec![9; 32],
                vec![],
            );
        }
        assert_eq!(next_page(None, &[]), PageStep::Done);
        assert_eq!(next_page(Some(2), &p.events), PageStep::Done);
        assert_eq!(next_page(Some(2), &p.events[..2]), PageStep::More(1));
        assert_eq!(next_page(Some(2), &[]), PageStep::Incomplete);
        let junk = SignedInput {
            input: b"junk".to_vec(),
            sig: vec![],
        };
        assert_eq!(next_page(Some(9), &[junk]), PageStep::Done);
    }

    /// A held record is honored only under the own ledger's pin for its vault,
    /// and only while it is the record this process latched.
    #[test]
    fn held_records_reverify_against_the_pin_and_the_latch() {
        use crate::storage::sealed_vault::test_support::{owner, record_for};
        let vault = "vault-held";
        let record = record_for(vault, &[4u8; 64]);
        let trust = TrustCache::default();
        assert_eq!(
            check_held_record(&trust, vault, &record),
            Err(RecordError::Unpinned),
            "no own ledger yet"
        );
        let anchor = owner().signing().public_bytes().to_vec();
        let mut me = Person::from_identity(owner().signing());
        me.push(
            OP_ADMIT,
            KIND_PIN,
            "another-vault".into(),
            anchor.clone(),
            vec![],
        );
        trust.set_own_ledger(me.fold());
        assert_eq!(
            check_held_record(&trust, vault, &record),
            Err(RecordError::Unpinned)
        );
        me.push(OP_ADMIT, KIND_PIN, vault.into(), anchor, vec![]);
        trust.set_own_ledger(me.fold());
        assert_eq!(check_held_record(&trust, vault, &record), Ok(()));

        // Latched: the same record passes; any other field content doesn't.
        trust.latch_record(vault, &record);
        assert_eq!(check_held_record(&trust, vault, &record), Ok(()));
        let mut edited = record.clone();
        edited.hash = vec![0; 32];
        assert_eq!(
            check_held_record(&trust, vault, &edited),
            Err(RecordError::NotLatched)
        );
        trust.forget_record(vault);
        assert_eq!(check_held_record(&trust, vault, &edited), Ok(()));
    }

    #[test]
    fn latch_accepts_extension_refuses_equivocation_and_rollback() {
        let mut p = Person::new(3);
        let dik = SigningIdentity::from_seed(&[4; 32]);
        p.push(
            OP_ADMIT,
            KIND_DEVICE,
            dik.id(crate::identity::IdKind::Device),
            dik.public_bytes().to_vec(),
            vec![1; 32],
        );
        p.push(OP_ADMIT, KIND_PIN, "vault-1".into(), vec![9; 32], vec![]);
        let held = p.events[..1].to_vec();
        let st = verify_served(&p.us(), &p.uik.public_bytes(), &held, &p.events).unwrap();
        assert_eq!(st.next_seq(), 2);
        assert_eq!(
            verify_served(&p.us(), &p.uik.public_bytes(), &p.events, &held).unwrap_err(),
            TrustError::Rollback { held: 2, served: 1 }
        );
        // A different (validly signed) event at a held seq: equivocation.
        let mut q = Person::new(3);
        q.push(OP_ADMIT, KIND_PIN, "vault-2".into(), vec![8; 32], vec![]);
        assert_eq!(
            verify_served(&p.us(), &p.uik.public_bytes(), &held, &q.events).unwrap_err(),
            TrustError::Equivocation { seq: 0 }
        );
        // A ledger signed by another key does not fold under this person.
        let other = Person::new(5);
        assert!(matches!(
            verify_served(&p.us(), &other.uik.public_bytes(), &[], &p.events),
            Err(TrustError::Invalid(_))
        ));
        assert!(TrustError::Rollback { held: 1, served: 0 }.is_hard());
        assert!(!TrustError::Fetch("x".into()).is_hard());
    }

    #[test]
    fn self_status_reads_the_revoke() {
        let mut p = Person::new(6);
        let dik = SigningIdentity::from_seed(&[7; 32]);
        let dv = dik.id(crate::identity::IdKind::Device);
        assert_eq!(self_status(&p.fold(), &dv), SelfStatus::Unknown);
        p.push(
            OP_ADMIT,
            KIND_DEVICE,
            dv.clone(),
            dik.public_bytes().to_vec(),
            vec![2; 32],
        );
        assert_eq!(self_status(&p.fold(), &dv), SelfStatus::Live);
        p.push(
            OP_REVOKE,
            KIND_DEVICE,
            dv.clone(),
            dik.public_bytes().to_vec(),
            vec![2; 32],
        );
        assert_eq!(self_status(&p.fold(), &dv), SelfStatus::Revoked);
    }

    #[test]
    fn ledger_cache_roundtrip_and_key_binding() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = Person::new(8);
        p.push(OP_ADMIT, KIND_PASSKEY, "Y3JlZA".into(), vec![5; 64], vec![]);
        store_cache(dir.path(), &p.us(), &p.uik.public_bytes(), &p.events);
        assert_eq!(
            load_cache(dir.path(), &p.us(), &p.uik.public_bytes()),
            p.events
        );
        assert!(cached_ledger(dir.path(), &p.us(), &p.uik.public_bytes()).is_some());
        // A cache under another key is not this person's.
        assert!(load_cache(dir.path(), &p.us(), &[1; 32]).is_empty());
        // A non-id can't name a cache file.
        assert!(ledger_path(dir.path(), "../x").is_none());
    }

    #[test]
    fn served_events_with_garbage_fields_fold_to_bad_fields() {
        let body = serde_json::json!({ "events": [{ "input": "!!", "sig": "??" }], "head_seq": 0 });
        let served = parse_served(&body).unwrap();
        let p = Person::new(9);
        match verify_served(&p.us(), &p.uik.public_bytes(), &[], &served) {
            Err(TrustError::Invalid(e)) => {
                assert_eq!(e.code, crate::crypto::ledger::LedgerErrorCode::BadFields)
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_served(&serde_json::json!({})).is_err());
    }

    #[test]
    fn approver_passkey_comes_only_from_a_members_ledger() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let vault = "vault-ap";
        let owner = crate::crypto::vault_key::UikRoot::from_root([0x11; 32]);
        let mut p = Person {
            uik: owner.signing(),
            events: Vec::new(),
        };
        p.push(
            OP_ADMIT,
            KIND_PASSKEY,
            "Y3JlZA".into(),
            [vec![1; 32], vec![2; 32]].concat(),
            vec![],
        );
        let mut stranger = Person::new(0x44);
        stranger.push(
            OP_ADMIT,
            KIND_PASSKEY,
            "b3RoZXI".into(),
            vec![3; 64],
            vec![],
        );
        let trust = TrustCache::default();
        trust.set_own_ledger(p.fold());
        trust.set_ledger_of(stranger.fold());
        let record = {
            let id = owner.user_id();
            let grant = owner
                .signing()
                .sign(&crate::identity::role_grant_input(vault, &id, "owner", 0));
            let mut members = std::collections::BTreeMap::new();
            members.insert(
                id.clone(),
                crate::storage::sealed_vault::RecordMember {
                    user_id: id,
                    sig_pub: owner.signing().public_bytes().to_vec(),
                    role: crate::storage::plaintext::MemberRole::Owner,
                    role_sig: grant.to_vec(),
                },
            );
            MemberRecord {
                anchor: owner.signing().public_bytes().to_vec(),
                members,
                generation: 0,
                rekey_proof: None,
                delegation_log: vec![],
                root_succession: vec![],
                seq: 1,
                hash: vec![],
                reader: owner.user_id(),
            }
        };
        let dir = tempfile::tempdir().unwrap();
        let hit = rt
            .block_on(approver_passkey(
                &trust,
                None,
                dir.path(),
                &record,
                vault,
                "Y3JlZA",
            ))
            .expect("the member's admitted passkey");
        use base64::{engine::general_purpose::STANDARD, Engine};
        assert_eq!(hit.x, STANDARD.encode([1u8; 32]));
        // A padded spelling of the same credential id resolves the same passkey.
        assert!(rt
            .block_on(approver_passkey(
                &trust,
                None,
                dir.path(),
                &record,
                vault,
                "Y3JlZA"
            ))
            .is_some());
        // A passkey admitted only by a NON-member never verifies an approval.
        assert!(rt
            .block_on(approver_passkey(
                &trust,
                None,
                dir.path(),
                &record,
                vault,
                "b3RoZXI"
            ))
            .is_none());
    }
}
