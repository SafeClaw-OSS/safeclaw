//! The daemon's per-vault local store (`vaults/{vid}/vault.per-item.json`):
//! the vault's VERIFIED member record (trust-reset design D5) plus N sealed item
//! records under the vault key K.
//!
//! The member record is today's fold — set-once anchor, any-owner delegation
//! log, root succession, owner-signed K proof — verified against the READER's
//! own pin (the anchor their person signed into their ledger) before it lands
//! here ([`MemberRecord::from_served`]). It authorizes owner config, agent
//! records and tombstones, and is what a delivered K is checked against
//! ([`MemberRecord::k_matches`], contract 1.5/1.7). The daemon never holds a
//! passkey wrap or a member's K seal: K arrives only in a grant sealed to this
//! device, and a vault without a verified record is refused ([`NO_RECORD`]).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sudp::primitives::PrimitiveSuite;

use crate::error::{AppError, Result};
use crate::storage::item::{
    aad_id_from_wire, item_id, item_id_bytes, parse_secret_body, seal_item, secret_body,
    unseal_item, wire_id_for, ItemCtx, ItemNs, ItemPayload, VaultKeys,
};

/// Per-vault count of items the LAST fold had to skip (unreadable at a format
/// this build supports: corrupt, malformed, or sealed under a key we lack).
/// Process-wide because the fold has no `AppState`; `/health` reports the total
/// so `sc doctor` can warn. Diagnostic only, never a security decision.
static UNREADABLE_ITEMS: std::sync::Mutex<BTreeMap<String, usize>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Total items skipped by the most recent fold of each vault (see
/// [`UNREADABLE_ITEMS`]).
pub fn unreadable_item_total() -> usize {
    UNREADABLE_ITEMS
        .lock()
        .map(|m| m.values().sum())
        .unwrap_or(0)
}

/// serde (de)serialization of `Vec<u8>` as **base64url-nopad** — the ONE
/// binary-in-JSON encoding across the entire per-item stack (contract §1).
/// NEVER std-base64 (the recurring bug); Rust and TS both use exactly this.
mod b64url_bytes {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Serde helper: encode bytes as STANDARD base64 (matching the frontend `toBase64`)
/// and decode LENIENTLY (accept standard OR url-safe, padded or not) — the same
/// mixed-encoding tolerance as [`decode_b64_lenient`]. Used for the member
/// record's signature + pubkey byte fields so the record's wire shape (what the
/// browser writes) round-trips byte-for-byte through the daemon's local store.
mod b64_std {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let norm: String = s
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();
        let norm = norm.trim_end_matches('=');
        let pad = norm.len() % 4;
        let padded = if pad == 0 {
            norm.to_string()
        } else {
            let mut t = norm.to_string();
            t.push_str(&"=".repeat(4 - pad));
            t
        };
        STANDARD
            .decode(padded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// LENIENT base64 decode: accept standard OR url-safe, padded or not. Member
/// record and owner-config fields were written by the browser with mixed
/// encodings (standard `toBase64` for most, base64url for some), and its reader
/// accepts both, so the daemon must too. Normalize url→std (`-`→`+`, `_`→`/`),
/// re-pad to a multiple of 4, then STANDARD-decode. Item ids and `ct` stay strict
/// base64url-nopad (the per-item stack, `b64url_bytes`).
pub fn decode_b64_lenient(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let std: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let std = std.trim_end_matches('=');
    let pad = std.len() % 4;
    let padded = if pad == 0 {
        std.to_string()
    } else {
        let mut t = std.to_string();
        t.push_str(&"=".repeat(4 - pad));
        t
    };
    STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("field not base64: {}", e)))
}

/// One sealed content item at rest: the writer-assigned CAS `version` (plaintext,
/// also AAD-bound inside `ct` so it can't lie) + the sudp sealed-record bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredItem {
    /// Monotonic per-id CAS version (contract §6). Mirrors the cloud row's
    /// `vault_items.version` for the same `item_id`.
    pub version: u64,
    /// `sudp::seal_record` output (`suite ‖ nonce ‖ ct ‖ tag`), base64url-nopad
    /// in JSON.
    #[serde(with = "b64url_bytes")]
    pub ct: Vec<u8>,
    /// The highest `version` of this id KNOWN to be on the cloud —
    /// `version > synced_version` means the row is DIRTY (needs a push);
    /// equal means clean, and the push loop skips it. Without this every sync
    /// re-offered every already-synced row and burned one 409 round-trip per
    /// row. Local bookkeeping only (not AAD-bound, never sent): set by the
    /// pull/adopt path and by a successful push; `0` (the serde default, and
    /// what an existing on-disk store loads as) = "never confirmed on cloud",
    /// which safely re-offers the row once.
    #[serde(default)]
    pub synced_version: u64,
    /// True when this row's sealed body is a tombstone (`status:"deleted"`).
    /// Local metadata only (not AAD-bound, never sent) — it lets the push loop
    /// order writes BEFORE deletes so a syncing observer never sees a dangling
    /// reference. Concretely: a completed connect writes 3 rows at once (the
    /// refresh-token secret, the `connection` record, and a tombstone for the
    /// old `connecting` row); if the tombstone lands on the cloud first, the
    /// console briefly sees the connect withdrawn with no connection yet and
    /// renders "not configured". Serde-defaulted to false (an adopted or
    /// pre-upgrade row reads as live — harmless, it only affects push order).
    #[serde(default)]
    pub tombstone: bool,
    /// The per-record Ed25519 signature (A1.2, `record_signature_input` over the
    /// CIPHERTEXT), base64url-nopad — `None` for an unsigned record (an unsigned
    /// owner-config or agent row is never honored). Carried on the wire
    /// (`vault_items.sig`) so a blind server can gate + every reader can verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// The signing principal's self-id (`us_`/`dv_`) — a UIK for human writes, the
    /// DIK for automatic (daemon/OAuth) writes (A2). `None` iff unsigned. Wire:
    /// `vault_items.signer`. The reader maps it to a pubkey (a member of the
    /// verified record) to verify + to a role for the role×type gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// One member of a vault's member record: the person's `us_`, their UIK signing
/// pub (self-certifying: `derive_id(User, sig_pub) == user_id`, checked when the
/// record is verified) and the checkpoint role grant signed by the current root.
/// The daemon never stores a member's K seal: K reaches it only in a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMember {
    /// The member's `us_…`.
    pub user_id: String,
    /// The member's UIK Ed25519 signing pub (raw 32 bytes).
    #[serde(with = "b64_std")]
    pub sig_pub: Vec<u8>,
    /// The checkpoint role (`#[serde(default)]` = Member: least privilege).
    #[serde(default)]
    pub role: crate::storage::plaintext::MemberRole,
    /// The current root's signature over
    /// [`crate::identity::role_grant_input`]`(vault, user, role, role_epoch)`;
    /// empty = no checkpoint grant (the member is then seated only by the
    /// delegation log, if at all).
    #[serde(default, with = "b64_std")]
    pub role_sig: Vec<u8>,
}

/// An owner-signed proof for the record's current K `generation` (contract 1.5).
/// Generation 0 needs one too. It binds the generation to the full 64-byte K
/// bundle ([`crate::identity::k_commitment`]), so a backend can neither storm
/// fake generations nor pair a signed generation with a K it chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyProof {
    /// The generation this proof authorizes (must equal the record's).
    pub generation: u64,
    /// [`crate::identity::k_commitment`]`(vault, generation, bundle64)`.
    #[serde(with = "b64_std")]
    pub k_commitment: Vec<u8>,
    /// The owner's Ed25519 signature over [`crate::identity::rekey_sig_input`].
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
    /// The signing owner's `us_…` (must be an owner in the verified fold).
    pub signer_id: String,
    /// Membership anti-rollback: the number of delegation events at the current
    /// role-epoch captured when the proof was signed. `0` = empty prefix.
    #[serde(default)]
    pub membership_len: u64,
    /// [`crate::identity::membership_commitment`] over that prefix's event
    /// signatures, in `(seq, sig)` order. A served log whose prefix does not hash
    /// to this was rolled back or altered.
    #[serde(default, with = "b64_std")]
    pub membership_hash: Vec<u8>,
}

/// An owner-signed delegation event — the any-owner, issuance-time-authority half
/// of the owner-set fold (design/identity-uik-aik.md §4.3,
/// delegation-log-impl-spec.md §1.2). Appended between root-signed checkpoints so
/// ANY current owner (not just the root) can add / promote / demote / remove
/// without a re-key. The fold honors an event iff its `granter_id` is an Owner in
/// the owner-set folded up to this event's `seq` — so a member can't grant, and
/// the fact "granter WAS an owner when they signed" survives the granter's own
/// later removal (NON-CASCADE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationEvent {
    /// `"set"` (insert `subject_id → role`: add / promote / demote) or `"remove"`
    /// (drop `subject_id`; touches ONLY the subject — non-cascade).
    pub op: String,
    /// The `us_…` whose role this event changes.
    pub subject_id: String,
    /// The role for a `"set"` (ignored for `"remove"`). `#[serde(default)]` = Member.
    #[serde(default)]
    pub role: crate::storage::plaintext::MemberRole,
    /// The signing owner's `us_…`. Must be an Owner in the fold up to `seq`.
    pub granter_id: String,
    /// The granter's Ed25519 signing pubkey (raw 32 bytes), carried INLINE and
    /// SELF-CERTIFYING: the fold requires `derive_id(granter_sig_pub) ==
    /// granter_id`, then verifies `sig` under it. Inline (not resolved from the
    /// member list) so the event stays verifiable after the granter is removed.
    #[serde(default, with = "b64_std")]
    pub granter_sig_pub: Vec<u8>,
    /// Monotone ordering within `role_epoch` (rollback / reorder guard).
    pub seq: u64,
    /// The checkpoint epoch this event rides on. An event whose `role_epoch`
    /// differs from the record's current (succession-derived) epoch is a
    /// pre-compaction replay → ignored by the fold.
    pub role_epoch: u64,
    /// `granter`'s Ed25519 over [`crate::identity::delegation_event_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

/// A root-succession certificate — the CURRENT root signs the NEXT root's id +
/// signing pubkey, letting a reader follow a short chain from the pinned anchor to
/// the current root (creator transfer / offboard; design/identity-uik-aik.md §4.3).
/// A pure compaction is a self-succession that only advances `role_epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSuccession {
    /// The retiring root's `us_…` (must equal `derive_id(current root)` when applied).
    pub old_root_id: String,
    /// The incoming root's `us_…` (must equal `derive_id(new_root_sig_pub)`).
    pub new_root_id: String,
    /// The incoming root's UIK Ed25519 signing pubkey (raw 32 bytes), bound in
    /// the signature so a colluding server can't swap in a root of its choosing.
    #[serde(with = "b64_std")]
    pub new_root_sig_pub: Vec<u8>,
    /// The checkpoint epoch at which the transfer / compaction takes effect
    /// (strictly increasing along the chain; the SOLE source of the current
    /// `role_epoch`).
    pub role_epoch: u64,
    /// `old_root`'s Ed25519 over [`crate::identity::root_succession_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

/// The lowercase serde token for a role (`"owner"` / `"member"`) — the EXACT
/// bytes signed in [`crate::identity::role_grant_input`]. Kept in one place so
/// the signing input and the enum's serde spelling can never drift.
pub(crate) fn role_str(role: crate::storage::plaintext::MemberRole) -> &'static str {
    match role {
        crate::storage::plaintext::MemberRole::Owner => "owner",
        crate::storage::plaintext::MemberRole::Member => "member",
    }
}

/// A vault's member record as this daemon holds it (design D5): today's fold —
/// the set-once anchor, the checkpoint grants, the any-owner delegation log, the
/// root succession and the owner-signed K proof — after it verified against the
/// READER's own pin. Built from the wire only by [`MemberRecord::from_served`]
/// (plus test fixtures).
///
/// It is also `Deserialize` with pub fields because the daemon persists the
/// latched record in its 0600 per-item store and reloads it across restarts; a
/// verified-only newtype would ripple through every store consumer. So a held
/// record is never trusted for being on disk: every use re-verifies it through
/// [`MemberRecord::verify_held`] (pin, reader, fold, current membership) and the
/// in-memory latch ([`crate::trust::check_held_record`]) — the approve path and
/// every view fold — and every owner-config, agent-record, tombstone and K
/// check folds it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// The anchor's UIK signing pub (32 bytes) — equal to the reader's pin.
    #[serde(with = "b64_std")]
    pub anchor: Vec<u8>,
    /// `us_ → member`, only members whose `sig_pub` self-certifies.
    #[serde(default)]
    pub members: BTreeMap<String, RecordMember>,
    /// The current K generation.
    #[serde(default)]
    pub generation: u64,
    /// The owner-signed proof for `generation` (required, generation 0 too).
    #[serde(default)]
    pub rekey_proof: Option<RekeyProof>,
    /// Owner-signed delegation events since the last checkpoint.
    #[serde(default)]
    pub delegation_log: Vec<DelegationEvent>,
    /// The succession / compaction chain from the anchor.
    #[serde(default)]
    pub root_succession: Vec<RootSuccession>,
    /// The record's CAS seq, latched with [`Self::hash`].
    #[serde(default)]
    pub seq: u64,
    /// The latch hash of this record as served ([`record_wire_hash`]).
    #[serde(default, with = "b64_std")]
    pub hash: Vec<u8>,
    /// The `us_` of the person this record was verified FOR (the reader): agent
    /// records signed by this person are honored besides owners' (design D5.3).
    #[serde(default)]
    pub reader: String,
}

/// Why a served member record was refused. Every variant keeps the vault closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The body is not a member record (missing / malformed fields).
    Malformed(String),
    /// The record's anchor is not the reader's pin: "this vault points to a
    /// different owner".
    PinMismatch,
    /// The fold does not verify (no resolvable root, a rolled-back delegation
    /// log, or a missing / invalid owner-signed K proof).
    Unverifiable(String),
    /// The reader is not a member of the record's current epoch.
    NotAMember,
    /// The reader's own ledger pins no anchor for this vault (yet).
    Unpinned,
    /// The held record is not the one this daemon last latched for the vault
    /// (the store changed outside sync, or rolled back).
    NotLatched,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Malformed(m) => write!(f, "member record malformed: {}", m),
            RecordError::PinMismatch => f.write_str(
                "this vault's member record points to a different owner than the one your \
                 account pinned",
            ),
            RecordError::Unverifiable(m) => write!(f, "member record does not verify: {}", m),
            RecordError::NotAMember => f.write_str("you are not a member of this vault"),
            RecordError::Unpinned => f.write_str(
                "this vault isn't pinned in your account ledger yet — upgrade this vault in the \
                 console, then `sc sync`",
            ),
            RecordError::NotLatched => f.write_str(
                "this vault's member record on disk is not the one SafeClaw verified — run \
                 `sc sync`",
            ),
        }
    }
}

fn decode_field(
    v: Option<&serde_json::Value>,
    what: &str,
) -> std::result::Result<Vec<u8>, RecordError> {
    let s = v
        .and_then(|x| x.as_str())
        .ok_or_else(|| RecordError::Malformed(format!("{} missing", what)))?;
    decode_b64_lenient(s).map_err(|_| RecordError::Malformed(format!("{} not base64", what)))
}

/// The latch hash of a served member record: SHA-256 of the canonical JSON of
/// the record's OWN wire content, `{anchor, members, proof, seq}` exactly as
/// served. The `persons` join (sig pubs, enc keys, emails) is left out: those
/// rows belong to the persons, not to the record, so a deleted or re-keyed
/// person row never makes the same seq look like equivocation. A served record
/// at a seq this daemon already holds must hash the same, or the server
/// equivocated.
pub fn record_wire_hash(body: &serde_json::Value) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let field = |k: &str| body.get(k).cloned().unwrap_or(serde_json::Value::Null);
    let v = serde_json::json!({
        "anchor": field("anchor"),
        "members": field("members"),
        "proof": field("proof"),
        "seq": field("seq"),
    });
    Sha256::digest(crate::crypto::canonical::canonicalize(&v)).into()
}

impl MemberRecord {
    /// Verify a served record (contract 8.3/8.4 `GET …/member-record`:
    /// `{anchor, members, proof, seq, persons}`) against the reader's pin and
    /// fold. Checks, in order:
    ///  1. `anchor` equals `pin_anchor` (the reader's own ledger pin);
    ///  2. each member's `persons[us].sig_pub` folds to its `us_` (others are
    ///     dropped: their grants can't be verified);
    ///  3. a root resolves from the anchor and the delegation log is not rolled
    ///     back against the K proof's membership commitment;
    ///  4. an owner-signed K proof exists for the record's generation (0 too);
    ///  5. the reader is a member of the current epoch.
    pub fn from_served(
        vault_id: &str,
        body: &serde_json::Value,
        pin_anchor: &[u8; 32],
        reader_us: &str,
    ) -> std::result::Result<MemberRecord, RecordError> {
        let anchor = decode_field(body.get("anchor"), "anchor")?;
        if anchor.as_slice() != pin_anchor.as_slice() {
            return Err(RecordError::PinMismatch);
        }
        let seq = body
            .get("seq")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| RecordError::Malformed("seq missing".into()))?;
        let members_wire = body
            .get("members")
            .and_then(|v| v.as_object())
            .ok_or_else(|| RecordError::Malformed("members missing".into()))?;
        let persons = body.get("persons").and_then(|v| v.as_object());
        let mut members = BTreeMap::new();
        for (us, m) in members_wire {
            let Some(sig_pub) = persons
                .and_then(|p| p.get(us))
                .and_then(|p| p.get("sig_pub"))
                .and_then(|v| v.as_str())
                .and_then(|s| decode_b64_lenient(s).ok())
            else {
                continue;
            };
            let Ok(pub32) = <[u8; 32]>::try_from(sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &pub32) != *us {
                continue; // not self-certifying → can't seat this member
            }
            // A bad role token degrades to Member (least privilege).
            let role: crate::storage::plaintext::MemberRole = m
                .get("role")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            let role_sig = m
                .get("role_sig")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(decode_b64_lenient)
                .transpose()
                .map_err(|_| RecordError::Malformed(format!("role_sig of {} not base64", us)))?
                .unwrap_or_default();
            members.insert(
                us.clone(),
                RecordMember {
                    user_id: us.clone(),
                    sig_pub,
                    role,
                    role_sig,
                },
            );
        }
        let proof = body
            .get("proof")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let generation = proof
            .get("generation")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let parse_list =
            |key: &str| -> std::result::Result<Option<serde_json::Value>, RecordError> {
                Ok(proof.get(key).filter(|v| !v.is_null()).cloned())
            };
        let delegation_log: Vec<DelegationEvent> = match parse_list("delegation_log")? {
            Some(v) => serde_json::from_value(v)
                .map_err(|e| RecordError::Malformed(format!("delegation_log: {}", e)))?,
            None => Vec::new(),
        };
        let succession = match parse_list("succession")? {
            Some(v) => Some(v),
            None => parse_list("root_succession")?,
        };
        let root_succession: Vec<RootSuccession> = match succession {
            Some(v) => serde_json::from_value(v)
                .map_err(|e| RecordError::Malformed(format!("succession: {}", e)))?,
            None => Vec::new(),
        };
        let rekey_proof = match proof.get("rekey_proof").filter(|v| !v.is_null()) {
            None => None,
            Some(p) => Some(RekeyProof {
                generation: p
                    .get("generation")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| RecordError::Malformed("rekey_proof.generation".into()))?,
                k_commitment: decode_field(p.get("k_commitment"), "rekey_proof.k_commitment")?,
                sig: decode_field(p.get("sig"), "rekey_proof.sig")?,
                signer_id: p
                    .get("signer_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RecordError::Malformed("rekey_proof.signer_id".into()))?
                    .to_string(),
                membership_len: p
                    .get("membership_len")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                membership_hash: match p.get("membership_hash").and_then(|v| v.as_str()) {
                    Some(s) => decode_b64_lenient(s).map_err(|_| {
                        RecordError::Malformed("rekey_proof.membership_hash".into())
                    })?,
                    None => Vec::new(),
                },
            }),
        };
        let mut record = MemberRecord {
            anchor,
            members,
            generation,
            rekey_proof,
            delegation_log,
            root_succession,
            seq,
            hash: Vec::new(),
            reader: reader_us.to_string(),
        };
        record.verify_fold(vault_id)?;
        if !record.fold_owner_set(vault_id).contains_key(reader_us) {
            return Err(RecordError::NotAMember);
        }
        record.hash = record_wire_hash(body).to_vec();
        Ok(record)
    }

    /// Re-verify a HELD record (one loaded from the store) for the reader whose
    /// own ledger pins `pin_anchor` for this vault: the anchor is that pin, the
    /// record was verified for this reader, the fold verifies, and the reader
    /// is a current member. A record edited on disk can't pass without owner
    /// signatures under the pinned anchor.
    pub fn verify_held(
        &self,
        vault_id: &str,
        pin_anchor: &[u8; 32],
        reader_us: &str,
    ) -> std::result::Result<(), RecordError> {
        if self.anchor.as_slice() != pin_anchor.as_slice() {
            return Err(RecordError::PinMismatch);
        }
        if self.reader != reader_us {
            return Err(RecordError::Malformed(
                "held for another account — run `sc sync`".into(),
            ));
        }
        self.verify_fold(vault_id)?;
        if !self.fold_owner_set(vault_id).contains_key(reader_us) {
            return Err(RecordError::NotAMember);
        }
        Ok(())
    }

    /// Steps 3-4 of [`Self::from_served`], also re-run whenever a stored record
    /// is folded: a resolvable root, an un-rolled-back delegation log and an
    /// owner-signed K proof for the current generation.
    pub fn verify_fold(&self, vault_id: &str) -> std::result::Result<(), RecordError> {
        if resolve_current_root(self, vault_id).is_none() {
            return Err(RecordError::Unverifiable("no resolvable root".into()));
        }
        if !membership_prefix_ok(self, vault_id) {
            return Err(RecordError::Unverifiable(
                "the delegation log does not match the owner-signed membership commitment".into(),
            ));
        }
        if !self.k_proof_signed(vault_id) {
            return Err(RecordError::Unverifiable(format!(
                "no valid owner-signed K proof for generation {}",
                self.generation
            )));
        }
        Ok(())
    }

    /// Is the K proof for the current generation present and signed by an owner
    /// of the verified fold? (The commitment's match to an actual K bundle is
    /// [`Self::k_matches`].)
    fn k_proof_signed(&self, vault_id: &str) -> bool {
        let Some(proof) = self.rekey_proof.as_ref() else {
            return false;
        };
        if proof.generation != self.generation || proof.k_commitment.len() != 32 {
            return false;
        }
        let Ok(sig) = <[u8; 64]>::try_from(proof.sig.as_slice()) else {
            return false;
        };
        let owners = self.fold_owner_set(vault_id);
        if owners.get(&proof.signer_id) != Some(&crate::storage::plaintext::MemberRole::Owner) {
            return false;
        }
        let Some(signer_pub) = self.member_sig_pub(&proof.signer_id) else {
            return false;
        };
        let input = crate::identity::rekey_sig_input(
            vault_id,
            proof.generation,
            &proof.k_commitment,
            &proof.signer_id,
            proof.membership_len,
            &proof.membership_hash,
        );
        crate::identity::verify(&signer_pub, &input, &sig)
    }

    /// Does `bundle` (the 64-byte K) match the record's owner-signed
    /// commitment for its current generation (contract 1.5/1.7)? The daemon
    /// checks this before it uses or retains a delivered K.
    pub fn k_matches(&self, vault_id: &str, bundle: &[u8]) -> bool {
        let Ok(bundle) = <[u8; 64]>::try_from(bundle) else {
            return false;
        };
        let Some(proof) = self.rekey_proof.as_ref() else {
            return false;
        };
        proof.generation == self.generation
            && crate::crypto::constant_time_eq(
                &crate::identity::k_commitment(vault_id, self.generation, &bundle),
                &proof.k_commitment,
            )
    }

    /// A member's self-certified signing pub.
    pub fn member_sig_pub(&self, us: &str) -> Option<[u8; 32]> {
        let m = self.members.get(us)?;
        let k = <[u8; 32]>::try_from(m.sig_pub.as_slice()).ok()?;
        (crate::identity::derive_id(crate::identity::IdKind::User, &k) == us).then_some(k)
    }

    /// The current members (`us_ → role`) of the verified fold.
    pub fn current_members(
        &self,
        vault_id: &str,
    ) -> BTreeMap<String, crate::storage::plaintext::MemberRole> {
        self.fold_owner_set(vault_id)
    }

    /// The derived owner-set (`user_id → role`) = the root-signed checkpoint at
    /// the current `role_epoch` folded with the delegation log
    /// (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md §0). The
    /// checkpoint verifies under the SUCCESSION-RESOLVED current root; each log
    /// event is honored iff its granter is an Owner in the fold so far with a
    /// valid self-certifying signature, and a `remove` drops ONLY its subject
    /// (NON-CASCADE). A last-owner removal/demote is ignored. Empty when no root
    /// resolves (callers fail closed).
    pub(crate) fn fold_owner_set(
        &self,
        vault_id: &str,
    ) -> BTreeMap<String, crate::storage::plaintext::MemberRole> {
        use crate::storage::plaintext::MemberRole;
        let mut map: BTreeMap<String, MemberRole> = BTreeMap::new();
        let Some((root_pub, role_epoch)) = resolve_current_root(self, vault_id) else {
            return map;
        };
        let root_id = crate::identity::derive_id(crate::identity::IdKind::User, &root_pub);
        // Genesis: the current root is an owner (pinned anchor + succession).
        map.insert(root_id.clone(), MemberRole::Owner);
        // Checkpoint: root-signed grants @ the current role_epoch.
        for m in self.members.values() {
            if m.user_id == root_id {
                continue; // a checkpoint grant never demotes the root
            }
            let Ok(m_pub) = <[u8; 32]>::try_from(m.sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &m_pub) != m.user_id {
                continue;
            }
            let Ok(sig) = <[u8; 64]>::try_from(m.role_sig.as_slice()) else {
                continue;
            };
            let input = crate::identity::role_grant_input(
                vault_id,
                &m.user_id,
                role_str(m.role),
                role_epoch,
            );
            if crate::identity::verify(&root_pub, &input, &sig) {
                map.insert(m.user_id.clone(), m.role);
            }
        }
        // Delegation log at the current epoch, in a server-independent order.
        let mut events: Vec<&DelegationEvent> = self
            .delegation_log
            .iter()
            .filter(|e| e.role_epoch == role_epoch)
            .collect();
        events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
        let mut last_seq: Option<u64> = None;
        for e in events {
            if matches!(last_seq, Some(ls) if e.seq <= ls) {
                continue; // a seq already consumed by a validated event
            }
            if map.get(&e.granter_id) != Some(&MemberRole::Owner) {
                continue; // a junk / non-owner event must not consume the seq slot
            }
            let Ok(granter_pub) = <[u8; 32]>::try_from(e.granter_sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &granter_pub)
                != e.granter_id
            {
                continue;
            }
            let role_tok = if e.op == "remove" {
                ""
            } else {
                role_str(e.role)
            };
            let input = crate::identity::delegation_event_input(
                vault_id,
                &e.op,
                &e.subject_id,
                role_tok,
                &e.granter_id,
                e.seq,
                e.role_epoch,
            );
            let Ok(sig) = <[u8; 64]>::try_from(e.sig.as_slice()) else {
                continue;
            };
            if !crate::identity::verify(&granter_pub, &input, &sig) {
                continue;
            }
            last_seq = Some(e.seq);
            let owner_count = |m: &BTreeMap<String, MemberRole>| {
                m.values().filter(|r| **r == MemberRole::Owner).count()
            };
            match e.op.as_str() {
                "remove" => {
                    if map.get(&e.subject_id) == Some(&MemberRole::Owner) && owner_count(&map) <= 1
                    {
                        continue; // last-owner guard
                    }
                    map.remove(&e.subject_id);
                }
                "set" => {
                    if e.role != MemberRole::Owner
                        && map.get(&e.subject_id) == Some(&MemberRole::Owner)
                        && owner_count(&map) <= 1
                    {
                        continue;
                    }
                    map.insert(e.subject_id.clone(), e.role);
                }
                _ => {}
            }
        }
        map
    }
}

/// C.3 — integrity-verify a signed **owner-config** item body (team-shared-vault-
/// security-model.md §9: owner-authored config carries a UIK signature, and the
/// daemon verifying it is "the real wall" against a server rewriting policy).
///
/// A signed body is `{ data, uik_sig, uik_sign_pub }`; the signature covers
/// [`crate::identity::config_sig_input`]`(vault, config_name, version,
/// JCS(data), derive_id(sign_pub))`. Returns:
///   - `None` — DROP it: a body with no signature, a malformed or failing
///     signature, or a signer whose pubkey is not a member of the verified record
///     (a server-minted key can't be a member).
///   - `Some((data, signer_id))` — a valid signature by a record member; the
///     caller decides whether that member may author this config (owners only).
///
/// `config_name` is the addressing-independent logical name (`policy`, `stores`,
/// …) so the same signature verifies whether the item rode legacy `aux:<name>`
/// or the unified ns.
fn verify_config_sig(
    body: serde_json::Value,
    record: &MemberRecord,
    vault_id: &str,
    config_name: &str,
    version: u64,
) -> Option<(serde_json::Value, String)> {
    let obj = match &body {
        serde_json::Value::Object(o) if o.contains_key("uik_sig") => o,
        _ => return None, // unsigned: no member authored it
    };
    let sig_b64 = obj.get("uik_sig").and_then(|v| v.as_str())?;
    let sign_pub_b64 = obj.get("uik_sign_pub").and_then(|v| v.as_str())?;
    let data = obj.get("data")?.clone();
    let sig_vec = decode_b64_lenient(sig_b64).ok()?;
    let sign_pub_vec = decode_b64_lenient(sign_pub_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let sign_pub: [u8; 32] = sign_pub_vec.as_slice().try_into().ok()?;
    let signer_id = crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub);
    // Anti-server-forgery: the signer must be a member of the verified record.
    if record.member_sig_pub(&signer_id) != Some(sign_pub) {
        return None;
    }
    let canonical = crate::crypto::canonical::canonicalize(&data);
    let input = crate::identity::config_sig_input(
        vault_id,
        config_name,
        version,
        Some(&canonical),
        &signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some((data, signer_id))
    } else {
        None
    }
}

/// A1.2/A1.5 — verify a per-record **sidecar** signature (`StoredItem.sig`/
/// `signer`) over the record's CIPHERTEXT by a member of the verified record.
/// Returns the signer's `us_…` iff the signature verifies AND the signer is a
/// member whose pubkey self-certifies (the anti-server-forgery anchor); else
/// `None` (drop). `item_id_raw` = the 32-byte blinded id; `status_live` = live
/// vs tombstone.
#[allow(clippy::too_many_arguments)]
fn verify_record_sidecar_sig(
    ct: &[u8],
    record: &MemberRecord,
    vault_id: &str,
    item_id_raw: &[u8],
    record_type: &str,
    version: u64,
    status_live: bool,
    sig_b64: &str,
    signer_id: &str,
) -> Option<String> {
    let sig_vec = decode_b64_lenient(sig_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let sign_pub = record.member_sig_pub(signer_id)?;
    let input = crate::identity::record_signature_input(
        record_type,
        item_id_raw,
        version,
        vault_id,
        ct,
        status_live,
        signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some(signer_id.to_string())
    } else {
        None
    }
}

/// Fold one NATIVE authorized-agents row (`ItemNs::Agent`, wire id == ag_id; the
/// caller enforces the id). Honored ONLY with a valid sidecar item-sig (A1.2:
/// type `"agent"`, over the ciphertext, by a member of the verified record) whose
/// signer is a vault OWNER or the daemon's OWN person (`record.reader`): design
/// D5.3 — an agent record counts only if signed by the daemon's own person or an
/// owner. Another member's record authorizes that member's agents on THEIR
/// devices, never on this one. Unsigned rows, legacy in-body wrappers and an
/// untrusted record drop.
#[allow(clippy::too_many_arguments)]
fn fold_agent_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    record: &MemberRecord,
    vault_id: &str,
    item_id_raw: &[u8],
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    let MembershipTrust::Verified(membership) = trust else {
        return None;
    };
    let sig = stored_sig?;
    let signer = stored_signer?;
    let sid = verify_record_sidecar_sig(
        ct,
        record,
        vault_id,
        item_id_raw,
        "agent",
        version,
        true,
        sig,
        signer,
    )?;
    let is_owner = membership.get(&sid) == Some(&crate::storage::plaintext::MemberRole::Owner);
    let is_reader = !record.reader.is_empty() && sid == record.reader;
    (is_owner || is_reader).then_some(body)
}

/// Fold one owner-config singleton, PREFERRING the sidecar item-sig (A1.2) and
/// falling back to the in-body config-sig during migration. `config_name` doubles
/// as the plaintext record type for the sidecar (owner-config ns == its name).
/// Owner-only: the signer must be an owner of the verified record; an unsigned
/// body is dropped (any K-holding member could have written it). Returns the raw
/// `data` to honor or `None` to drop (the field then falls to its safe default).
#[allow(clippy::too_many_arguments)]
fn fold_owner_config_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    record: &MemberRecord,
    vault_id: &str,
    item_id_raw: &[u8],
    config_name: &str,
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    let MembershipTrust::Verified(membership) = trust else {
        return None;
    };
    let is_owner =
        |sid: &str| membership.get(sid) == Some(&crate::storage::plaintext::MemberRole::Owner);
    match stored_sig {
        Some(sig) => {
            let signer = stored_signer?;
            let sid = verify_record_sidecar_sig(
                ct,
                record,
                vault_id,
                item_id_raw,
                config_name,
                version,
                true,
                sig,
                signer,
            )?;
            is_owner(&sid).then_some(body)
        }
        None => {
            let (data, sid) = verify_config_sig(body, record, vault_id, config_name, version)?;
            is_owner(&sid).then_some(data)
        }
    }
}

/// The trust a reader derives from the vault's member record (design D5). There
/// is no "legacy, integrity-only" state: a vault without a verified record is
/// refused before any fold.
enum MembershipTrust {
    /// The record verifies (anchor = the reader's pin, a resolvable root, an
    /// un-rolled-back log). Owner config and agent records are gated by this
    /// derived owner-set (`user_id → role`).
    Verified(BTreeMap<String, crate::storage::plaintext::MemberRole>),
    /// The record does not verify. FAIL CLOSED: every owner-config and agent row
    /// is dropped and folds refuse.
    Untrusted,
}

/// Resolve the CURRENT root's signing pubkey AND the current `role_epoch` by
/// walking the record's succession chain from its pinned anchor
/// (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md §1.2). The
/// epoch is DERIVED here: a compaction is a self-succession that only advances
/// it, so it can never be forged upward without a root signature.
///
/// A hop from the current `(root, epoch)` is VALID iff: `old_root_id ==
/// derive_id(current root)`, `role_epoch` strictly increases, `new_root_id ==
/// derive_id(new_root_sig_pub)`, and the `sig` verifies under the CURRENT root
/// over [`crate::identity::root_succession_input`]. The walk is ORDER-ROBUST (it
/// searches the whole chain at each step) and deterministic under equivocation
/// (lowest epoch, then lowest `new_root_id`). `None` iff the anchor is not 32
/// bytes.
fn resolve_current_root(record: &MemberRecord, vault_id: &str) -> Option<([u8; 32], u64)> {
    let mut cur = <[u8; 32]>::try_from(record.anchor.as_slice()).ok()?;
    let mut cur_epoch: u64 = 0;
    loop {
        let cur_id = crate::identity::derive_id(crate::identity::IdKind::User, &cur);
        let mut best: Option<(&RootSuccession, [u8; 32])> = None;
        for s in &record.root_succession {
            if s.old_root_id != cur_id || s.role_epoch <= cur_epoch {
                continue;
            }
            let Ok(new_pub) = <[u8; 32]>::try_from(s.new_root_sig_pub.as_slice()) else {
                continue;
            };
            if s.new_root_id != crate::identity::derive_id(crate::identity::IdKind::User, &new_pub)
            {
                continue;
            }
            let Ok(sig) = <[u8; 64]>::try_from(s.sig.as_slice()) else {
                continue;
            };
            let input = crate::identity::root_succession_input(
                vault_id,
                &s.old_root_id,
                &s.new_root_id,
                &new_pub,
                s.role_epoch,
            );
            if !crate::identity::verify(&cur, &input, &sig) {
                continue;
            }
            let better = match &best {
                None => true,
                Some((b, _)) => {
                    s.role_epoch < b.role_epoch
                        || (s.role_epoch == b.role_epoch && s.new_root_id < b.new_root_id)
                }
            };
            if better {
                best = Some((s, new_pub));
            }
        }
        match best {
            Some((s, new_pub)) => {
                cur = new_pub;
                cur_epoch = s.role_epoch;
            }
            None => return Some((cur, cur_epoch)),
        }
    }
}

/// Membership anti-rollback (delegation-log-review-findings.md C2): the K proof
/// committed a delegation-log PREFIX (`membership_len` events at the current
/// role-epoch, `(seq, sig)` order, hashed to `membership_hash`). Recompute it
/// over the SERVED log and compare — a mismatch means the server rolled the log
/// back (e.g. omitted a `remove`). No proof → nothing committed (the separate
/// proof requirement refuses such a record anyway).
fn membership_prefix_ok(record: &MemberRecord, vault_id: &str) -> bool {
    let Some(proof) = record.rekey_proof.as_ref() else {
        return true;
    };
    let role_epoch = resolve_current_root(record, vault_id)
        .map(|(_, e)| e)
        .unwrap_or(0);
    let mut events: Vec<&DelegationEvent> = record
        .delegation_log
        .iter()
        .filter(|e| e.role_epoch == role_epoch)
        .collect();
    events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
    let n = proof.membership_len as usize;
    if events.len() < n {
        return false; // the server dropped committed events
    }
    let prefix_sigs: Vec<&[u8]> = events.iter().take(n).map(|e| e.sig.as_slice()).collect();
    crate::identity::membership_commitment(&prefix_sigs).as_slice()
        == proof.membership_hash.as_slice()
}

/// What [`PerItemVault::reconcile_from_view`] treats as the CALLER's change.
/// Only a difference from the view's base is one: a row a concurrent pull
/// changed or adopted after the base was taken (pull does not take the vault
/// write lock, and a connect awaits a token exchange in between) is neither
/// reverted nor dropped.
#[derive(Clone, Copy)]
pub enum ReconcileBase<'a> {
    /// The view was derived from `base` (captured before mutating it): upsert
    /// only items whose body differs from the base, tombstone only items the
    /// base had and the view dropped.
    Since(&'a ViewBase),
    /// The view IS this store's own fold, taken inside the same `&mut self`
    /// call (nothing can interleave): every difference is the caller's.
    OwnFold,
}

/// A view's items as `(ns, name) → SHA-256(body)`, captured as a
/// [`ReconcileBase::Since`] base. Digests only: no secret values are copied.
#[derive(Debug, Clone, Default)]
pub struct ViewBase {
    items: BTreeMap<(ItemNs, String), [u8; 32]>,
}

impl ViewBase {
    pub fn of(view: &crate::storage::plaintext::VaultPlaintextView) -> Result<Self> {
        let items = PerItemVault::view_items(view, true)?
            .into_iter()
            .map(|(k, body)| (k, body_digest(&body)))
            .collect();
        Ok(Self { items })
    }

    fn has(&self, ns: ItemNs, name: &str) -> bool {
        self.items.contains_key(&(ns, name.to_string()))
    }

    fn digest(&self, ns: ItemNs, name: &str) -> Option<&[u8; 32]> {
        self.items.get(&(ns, name.to_string()))
    }

    fn unchanged(&self, ns: ItemNs, name: &str, body: &serde_json::Value) -> bool {
        self.digest(ns, name) == Some(&body_digest(body))
    }
}

/// SHA-256 of the body's JCS canonical form (sorted keys), so the digest never
/// depends on map ordering (e.g. a `preserve_order` serde_json feature).
fn body_digest(body: &serde_json::Value) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(crate::crypto::canonical::canonicalize(body)).into()
}

/// The message a daemon gives for a vault that has no verified member record:
/// a v1 / personal-keyset vault that the console's "Upgrade vault" door has not
/// converted yet (design D9), or one whose record does not verify.
pub const NO_RECORD: &str =
    "this vault isn't on a verified member record yet — upgrade this vault in the console";

/// The daemon's per-item on-disk vault: the verified member record + N sealed
/// item records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerItemVault {
    /// The vault's member record, verified against this person's pin. `None`
    /// until one verified ([`NO_RECORD`]); a pre-trust-reset store (which had a
    /// `keyset` here) loads with `None` and stays closed until the record lands.
    #[serde(default)]
    pub record: Option<MemberRecord>,
    /// `item_id (base64url) → StoredItem`. Disjoint items live in disjoint
    /// entries → two writers touching different items never collide.
    #[serde(default)]
    pub items: BTreeMap<String, StoredItem>,
    /// Last cloud `vault_items.seq` this local store has pulled (the incremental
    /// pull cursor). `0` = full resync.
    #[serde(default)]
    pub items_seq: u64,
}

impl PerItemVault {
    /// An empty store (no record, no items).
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow a stored item by its base64url id.
    pub fn get_item(&self, item_id_b64: &str) -> Option<&StoredItem> {
        self.items.get(item_id_b64)
    }

    /// Insert or replace a raw sealed item (used by the pull/adopt path — the ct
    /// is already sealed by whoever wrote the cloud row, so by construction the
    /// cloud has this exact version: the row lands clean). `tombstone` stays
    /// false: an adopted row is clean and never re-pushed, so its push-order
    /// flag is never consulted (and we hold no K here to open the ct anyway).
    pub fn put_raw(&mut self, item_id_b64: String, version: u64, ct: Vec<u8>) {
        self.put_raw_signed(item_id_b64, version, ct, None, None)
    }

    /// Like [`Self::put_raw`] but carrying the per-record signature fields pulled
    /// from the cloud row (`vault_items.sig`/`signer`, A1.2). Unsigned rows pass
    /// `None`/`None` (content rows; an unsigned config/agent row never folds).
    pub fn put_raw_signed(
        &mut self,
        item_id_b64: String,
        version: u64,
        ct: Vec<u8>,
        sig: Option<String>,
        signer: Option<String>,
    ) {
        self.items.insert(
            item_id_b64,
            StoredItem {
                version,
                ct,
                synced_version: version,
                tombstone: false,
                sig,
                signer,
            },
        );
    }

    /// Drop a stored item outright (local GC of a fully-propagated tombstone).
    pub fn remove_item(&mut self, item_id_b64: &str) -> Option<StoredItem> {
        self.items.remove(item_id_b64)
    }

    /// The current CAS version of item `(ns, name)`, or `0` if absent — i.e.
    /// the `base_version` a new write should CAS against (contract §6).
    pub fn item_version<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        ns: ItemNs,
        name: &str,
    ) -> Result<u64> {
        let id = item_id::<S>(keys.id_seed, ns.as_str(), name)?;
        Ok(self.items.get(&id).map(|s| s.version).unwrap_or(0))
    }

    /// Seal `payload` for `(ns, name)` at the NEXT version (current + 1) under
    /// `K` and upsert it — the monotonic-bump write the connect / write paths
    /// use so an offline peer's CAS sees a strictly higher version (contract
    /// §6). Returns `(item_id_b64, new_version)`.
    pub fn seal_and_bump<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        payload: &ItemPayload,
    ) -> Result<(String, u64)> {
        let next = self.item_version::<S>(keys, ns, name)? + 1;
        let id = self.seal_and_upsert::<S>(keys, vault_id, ns, name, next, payload)?;
        Ok((id, next))
    }

    /// Seal `payload` for `(ns, name)` at `version` under `K` and upsert it,
    /// returning the base64url item id. Bridges the item.rs primitives
    /// (contract §1/§2) into the local store.
    pub fn seal_and_upsert<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        payload: &ItemPayload,
    ) -> Result<String> {
        // The daemon NEVER writes an authorized-agents row, in ANY spelling (native
        // `agent:<ag_id>` or legacy `aux:agent/<ag_id>`), live or tombstone: it holds
        // no UIK so it can't sign one (a v2 fold drops unsigned rows). Agent
        // authorization is written only by the console, UIK-signed (§11.1).
        if ns == ItemNs::Agent || (ns == ItemNs::Aux && name.starts_with("agent/")) {
            return Err(AppError::Internal(format!(
                "refusing to write agent row '{}': agent rows are console-written and UIK-signed only",
                name
            )));
        }
        let ctx = ItemCtx::for_item::<S>(keys.id_seed, vault_id, ns, name, version)?;
        let ct = seal_item::<S>(keys.content, &ctx, payload)?;
        let id = ctx.item_id_b64();
        // A local write leaves `synced_version` where it was (the new version
        // is by definition not on the cloud yet) — the row is dirty until pushed.
        let synced_version = self.items.get(&id).map(|s| s.synced_version).unwrap_or(0);
        let tombstone = payload.is_tombstone();
        // Seal-level writers land UNSIGNED (sig/signer None): the daemon writes
        // content rows only. An unsigned owner-config / agent row never folds.
        self.items.insert(
            id.clone(),
            StoredItem {
                version,
                ct,
                synced_version,
                tombstone,
                sig: None,
                signer: None,
            },
        );
        Ok(id)
    }

    /// Unseal one stored item addressed by `(ns, name)` under `K`. `Ok(None)` if
    /// no such item is stored. The stored `version` is fed into the `SealCtx`,
    /// so a tampered version would fail the AEAD (contract §6).
    pub fn open_item<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
    ) -> Result<Option<ItemPayload>> {
        // DP-S1: address by the STABLE id-seed, unseal with the CURRENT content
        // key (they're the same at gen 0; distinct after a re-key).
        let id = wire_id_for::<S>(keys.id_seed, ns, name)?;
        let Some(stored) = self.items.get(&id) else {
            return Ok(None);
        };
        let raw = item_id_bytes::<S>(keys.id_seed, ns.as_str(), name)?;
        let ctx = ItemCtx::new(vault_id, raw, stored.version);
        Ok(Some(unseal_item::<S>(keys.content, &ctx, &stored.ct)?))
    }

    /// Seed / re-seed this vault's item rows from a decrypted
    /// [`VaultPlaintextView`] (contract §2 `ns` split). Used by the per-item
    /// cut-over of the whole-blob paths (enroll, write): the browser still
    /// hands the daemon ONE sealed `ProtectedState` ciphertext, which the
    /// daemon opens into a view and then re-shards into N sealed item records
    /// under the SAME `K`.
    ///
    /// Each item's CAS `version` starts at `bump_from + 1` for a freshly-sealed
    /// row, so re-seeding after a write monotonically advances the version an
    /// offline peer will CAS against (the enroll case passes `0`). Aux subtrees
    /// with their default/empty value are NOT sealed (they'd only add tombstone-
    /// like noise); only `stores`, `store_order`, `policy`,
    /// `audit_retention_days`, plus every connection/connecting entry and every
    /// native secret, become their own item.
    pub fn seed_items_from_view<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
    ) -> Result<()> {
        // native secrets → one `secret` item each.
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            let notes = view.native_secret_notes.get(name).map(String::as_str);
            let payload =
                ItemPayload::live(ItemNs::Secret, name.clone(), secret_body(&value, notes));
            self.seal_and_upsert::<S>(keys, vault_id, ItemNs::Secret, name, 1, &payload)?;
        }
        // established connections → one `connection` item each.
        for (conn_id, conn) in &view.aux.connections {
            let body = serde_json::to_value(conn).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connection, conn_id.clone(), body);
            self.seal_and_upsert::<S>(keys, vault_id, ItemNs::Connection, conn_id, 1, &payload)?;
        }
        // in-flight connects → one `connecting` item each.
        for (conn_id, c) in &view.aux.connecting {
            let body = serde_json::to_value(c).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connecting, conn_id.clone(), body);
            self.seal_and_upsert::<S>(keys, vault_id, ItemNs::Connecting, conn_id, 1, &payload)?;
        }
        // aux config subtrees → one `aux:<name>` item each. Agents are NEVER
        // written by the daemon (console-written, UIK-signed only; §11.1).
        for (name, body) in Self::aux_blob_bodies(&view.aux)? {
            self.seal_and_upsert::<S>(
                keys,
                vault_id,
                ItemNs::Aux,
                &name,
                1,
                &ItemPayload::live(ItemNs::Aux, name.clone(), body),
            )?;
        }
        Ok(())
    }

    /// The aux items a view wants materialised, as `(aux_name, body)` pairs
    /// under `aux:<name>` addressing. Shared by seed + reconcile so the two
    /// write paths can never disagree. Config singletons only: the authorized-
    /// agents table is NEVER emitted (the daemon can't sign an agent row; agent
    /// authorization is console-written, UIK-signed). Default/empty subtrees are
    /// skipped (no tombstone-like noise).
    fn aux_blob_bodies(
        aux: &crate::storage::plaintext::VaultAux,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let mut out: Vec<(String, serde_json::Value)> = Vec::new();
        out.push((
            "stores".into(),
            serde_json::to_value(&aux.stores).map_err(AppError::from)?,
        ));
        out.push((
            "store_order".into(),
            serde_json::to_value(&aux.store_order).map_err(AppError::from)?,
        ));
        if let Some(policy) = &aux.policy {
            out.push((
                "policy".into(),
                serde_json::to_value(policy).map_err(AppError::from)?,
            ));
        }
        if let Some(days) = aux.audit_retention_days {
            out.push(("audit_retention_days".into(), serde_json::json!(days)));
        }
        if !aux.services.is_empty() {
            out.push((
                "services".into(),
                serde_json::to_value(&aux.services).map_err(AppError::from)?,
            ));
        }
        Ok(out)
    }

    /// Keep-both (§4), locally: store `ours` as the conflict copy beside THEIR row
    /// at `their_version` (the console's `putConflictCopy` id/name, version 1),
    /// DIRTY (`synced_version` 0) so the next push sends it as a create. Inserted
    /// only if absent (idempotent). Returns the copy id when it was inserted.
    fn put_local_conflict_copy<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ours: &ItemPayload,
        their_version: u64,
    ) -> Result<Option<String>> {
        let (copy_id, ct) =
            crate::storage::item::seal_conflict_copy::<S>(keys, vault_id, ours, their_version)?;
        if self.items.contains_key(&copy_id) {
            return Ok(None);
        }
        self.items.insert(
            copy_id.clone(),
            StoredItem {
                version: crate::storage::item::CONFLICT_COPY_VERSION,
                ct,
                synced_version: 0,
                tombstone: false,
                sig: None,
                signer: None,
            },
        );
        Ok(Some(copy_id))
    }

    /// A view's reconcilable items as `(ns, name) → body`: every native secret,
    /// connection and in-flight connect, plus (`with_aux`) the aux config
    /// subtrees at legacy `aux:<name>`. Shared by [`Self::reconcile_from_view`]
    /// and [`ViewBase::of`] so a base and a view are always compared on the
    /// same representation.
    fn view_items(
        view: &crate::storage::plaintext::VaultPlaintextView,
        with_aux: bool,
    ) -> Result<BTreeMap<(ItemNs, String), serde_json::Value>> {
        let mut out: BTreeMap<(ItemNs, String), serde_json::Value> = BTreeMap::new();
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            // Re-attach the secret's notes: a value rewrite must not drop them.
            let notes = view.native_secret_notes.get(name).map(String::as_str);
            out.insert((ItemNs::Secret, name.clone()), secret_body(&value, notes));
        }
        for (id, conn) in &view.aux.connections {
            out.insert(
                (ItemNs::Connection, id.clone()),
                serde_json::to_value(conn).map_err(AppError::from)?,
            );
        }
        for (id, c) in &view.aux.connecting {
            out.insert(
                (ItemNs::Connecting, id.clone()),
                serde_json::to_value(c).map_err(AppError::from)?,
            );
        }
        if with_aux {
            for (name, body) in Self::aux_blob_bodies(&view.aux)? {
                out.insert((ItemNs::Aux, name.to_string()), body);
            }
        }
        Ok(out)
    }

    /// Reconcile the item rows toward a freshly-decrypted [`VaultPlaintextView`]
    /// (the post-connect / post-write state), applying ONLY the changes with a
    /// monotonic version bump so the sync layer's per-item CAS sees a strictly
    /// higher version (contract §4/§6). Unlike [`seed_items_from_view`] (which
    /// resets every version to 1), this:
    ///   - upserts a `secret`/`connection`/`connecting`/`aux` item whose sealed
    ///     value changed, at `current + 1`;
    ///   - writes a `tombstone` (also bumped) for a `secret`/`connection`/
    ///     `connecting` item that the view no longer has (e.g. a completed
    ///     connect MOVEs its `connecting` entry away → tombstone the old row).
    ///
    /// This is the daemon-side, single-writer equivalent of "PUT the changed
    /// items" (contract §5 `writeVault` diff). What counts as changed is
    /// relative to the caller's [`ReconcileBase`]: only a view with a known base
    /// can tell "the caller changed/deleted it" from "someone else changed it
    /// since". Returns the ids that changed.
    pub fn reconcile_from_view<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
        base: ReconcileBase<'_>,
    ) -> Result<Vec<String>> {
        let mut changed: Vec<String> = Vec::new();
        // Owner config is honored only when owner-signed and the daemon holds no
        // UIK: an unsigned copy would be dropped by every fold, and re-writing it
        // could clobber an owner-signed row (or replace a dropped one with the
        // safe default). So aux config is never emitted, nor are agent rows.
        let desired = Self::view_items(view, false)?;

        // Upsert every desired item the caller changed (vs its base) whose sealed
        // body differs from what we hold.
        for ((ns, name), body) in &desired {
            if let ReconcileBase::Since(b) = base {
                if b.unchanged(*ns, name, body) {
                    continue;
                }
            }
            // `open_item` is unconverted (single-key); id_seed == content here so
            // the read is byte-identical either way.
            let existing = self.open_item::<S>(keys, vault_id, *ns, name)?;
            let same = existing
                .as_ref()
                .map(|p| !p.is_tombstone() && &p.body == body)
                .unwrap_or(false);
            if same {
                continue;
            }
            let payload = ItemPayload::live(*ns, name.clone(), body.clone());
            // §4 same-item conflict: the caller changed it AND the stored row no
            // longer matches the base (a pull changed or deleted it meanwhile,
            // e.g. during a connect's token exchange). Keep-both namespaces keep
            // THEIRS at the canonical id and OURS as a local dirty conflict copy;
            // the rest take the caller's write (console parity).
            if let ReconcileBase::Since(b) = base {
                let wire = wire_id_for::<S>(keys.id_seed, *ns, name)?;
                if let Some(their_version) = self.items.get(&wire).map(|s| s.version) {
                    let theirs = existing
                        .as_ref()
                        .filter(|p| !p.is_tombstone())
                        .map(|p| body_digest(&p.body));
                    if ns.keeps_both_on_conflict() && theirs.as_ref() != b.digest(*ns, name) {
                        if let Some(copy) = self.put_local_conflict_copy::<S>(
                            keys,
                            vault_id,
                            &payload,
                            their_version,
                        )? {
                            changed.push(copy);
                        }
                        continue;
                    }
                }
            }
            let (id, _v) = self.seal_and_bump::<S>(keys, vault_id, *ns, name, &payload)?;
            changed.push(id);
        }

        // Tombstone secret/connection/connecting rows the caller dropped. Our own
        // folded view gives the currently-live (ns, name) set; tombstone any not
        // in `desired` that the base had (a completed connect MOVEs its
        // `connecting` entry, so the old connecting row must become a tombstone).
        let removed = |ns: ItemNs, name: &String| -> bool {
            !desired.contains_key(&(ns, name.clone()))
                && match base {
                    ReconcileBase::Since(b) => b.has(ns, name),
                    ReconcileBase::OwnFold => true,
                }
        };
        let mine = self.fold_view::<S>(keys, vault_id)?;
        for name in mine.native_secrets.keys() {
            if removed(ItemNs::Secret, name) {
                let (id, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Secret,
                    name,
                    &ItemPayload::tombstone(ItemNs::Secret, name.clone()),
                )?;
                changed.push(id);
            }
        }
        for id in mine.aux.connections.keys() {
            if removed(ItemNs::Connection, id) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Connection,
                    id,
                    &ItemPayload::tombstone(ItemNs::Connection, id.clone()),
                )?;
                changed.push(iid);
            }
        }
        for id in mine.aux.connecting.keys() {
            if removed(ItemNs::Connecting, id) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Connecting,
                    id,
                    &ItemPayload::tombstone(ItemNs::Connecting, id.clone()),
                )?;
                changed.push(iid);
            }
        }
        // Agent rows are never written here (no live upsert, no tombstone): a
        // revoke is the console deleting the UIK-signed row.
        Ok(changed)
    }

    /// The [`MembershipTrust`] of this store's record: `Verified(owner-set)` iff a
    /// record is present and its fold verifies (resolvable root from the pinned
    /// anchor, an un-rolled-back log); else `Untrusted` (fail closed).
    fn resolve_membership_trust(&self, vault_id: &str) -> MembershipTrust {
        match self.record.as_ref() {
            Some(r)
                if resolve_current_root(r, vault_id).is_some()
                    && membership_prefix_ok(r, vault_id) =>
            {
                MembershipTrust::Verified(r.fold_owner_set(vault_id))
            }
            _ => MembershipTrust::Untrusted,
        }
    }

    /// Is `us_id` a member of this vault per the verified record?
    /// - `Some(true)`  = the verified fold seats this id (owner or member).
    /// - `Some(false)` = the fold is verified and non-empty and does NOT seat it:
    ///   an owner-signed removal (or never granted). The caller may drop the vault.
    /// - `None`        = can't decide safely (no record, or it doesn't verify): park.
    #[cfg(test)]
    pub(crate) fn verified_membership(&self, vault_id: &str, us_id: &str) -> Option<bool> {
        match self.resolve_membership_trust(vault_id) {
            MembershipTrust::Verified(map) if !map.is_empty() => Some(map.contains_key(us_id)),
            _ => None,
        }
    }

    /// Verify an owner-signed vault-DELETE tombstone (`{sig, signer}`): true iff
    /// `signer` is an OWNER of the verified record and `sig_b64` verifies over
    /// [`crate::identity::vault_tombstone_input`] under the signer's
    /// self-certifying pubkey. Without a verified record nothing verifies, so a
    /// server can never force a local wipe by flipping a status field.
    pub(crate) fn tombstone_verified(&self, vault_id: &str, signer: &str, sig_b64: &str) -> bool {
        use crate::storage::plaintext::MemberRole;
        let Some(record) = self.record.as_ref() else {
            return false;
        };
        let MembershipTrust::Verified(owners) = self.resolve_membership_trust(vault_id) else {
            return false;
        };
        if owners.get(signer) != Some(&MemberRole::Owner) {
            return false;
        }
        let Some(pub32) = record.member_sig_pub(signer).or_else(|| {
            // The current root may be an owner without a member row of its own.
            resolve_current_root(record, vault_id).and_then(|(root, _)| {
                (crate::identity::derive_id(crate::identity::IdKind::User, &root) == signer)
                    .then_some(root)
            })
        }) else {
            return false;
        };
        let Some(sig) = decode_b64_lenient(sig_b64)
            .ok()
            .and_then(|v| <[u8; 64]>::try_from(v.as_slice()).ok())
        else {
            return false;
        };
        crate::identity::verify(
            &pub32,
            &crate::identity::vault_tombstone_input(vault_id),
            &sig,
        )
    }

    /// Fold all **live** items into a [`VaultPlaintextView`]. Refuses a store
    /// without a verified member record ([`NO_RECORD`]) and a K that does not
    /// match the record's owner-signed commitment. Unseals every stored record
    /// under `K`, drops tombstones, and rebuilds the in-memory view by grouping
    /// on `ns` (contract §2). The item id is an HMAC so `(ns, name)` is unknown
    /// from the key alone — the sealed payload carries them; we rebuild the
    /// `SealCtx` from the id bytes (decoded from the base64url row key) + the
    /// stored `version`, so a tampered `version` fails the AEAD. The ONE read
    /// path: every grant, unlock and cache refresh folds through here.
    pub fn fold_view<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
    ) -> Result<crate::storage::plaintext::VaultPlaintextView> {
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};

        // Start from the fresh-vault defaults; config items OVERRIDE their
        // subtree, secret/connection/connecting/agent items fill their maps.
        //
        // Unified addressing (team §8.2): config singletons live at their own
        // ns with the empty name. Legacy `aux:<name>` items are still parsed
        // (read-compat for not-yet-migrated vaults) but NEW addresses win when
        // both spellings exist mid-migration — precedence is tracked with
        // `seen_new`, not item order (the id map iterates in hash order).
        let mut aux = VaultAux::initial();
        let mut native_secrets: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut native_secret_notes: BTreeMap<String, String> = BTreeMap::new();
        #[derive(Default)]
        struct SeenNew {
            stores: bool,
            store_order: bool,
            policy: bool,
            retention: bool,
            services: bool,
        }
        let mut seen_new = SeenNew::default();
        // Legacy values parked until the loop ends (applied only where no new-
        // address item set the field).
        let mut legacy_stores: Option<serde_json::Value> = None;
        let mut legacy_store_order: Option<serde_json::Value> = None;
        let mut legacy_policy: Option<serde_json::Value> = None;
        let mut legacy_retention: Option<serde_json::Value> = None;
        let mut legacy_services: Option<serde_json::Value> = None;
        let mut legacy_addressing = false;

        // The verified member record's OWNER-SET authorizes owner-config
        // (owner-only) and, with the reader's own person, agent records.
        let Some(record) = self.record.as_ref() else {
            return Err(AppError::Conflict(NO_RECORD.into()));
        };
        let trust = self.resolve_membership_trust(vault_id);
        if matches!(trust, MembershipTrust::Untrusted) {
            return Err(AppError::Unauthorized(
                "this vault's member record does not verify; it stays closed".into(),
            ));
        }
        // K must be the bundle the record's owner-signed proof commits to for
        // its CURRENT generation (contract 1.5): a backend can't pair a signed
        // generation with a K it chose, and a K retained across a re-key stops
        // folding (lock + unlock fetches the new one).
        let mut bundle = Vec::with_capacity(keys.id_seed.len() + keys.content.len());
        bundle.extend_from_slice(keys.id_seed);
        bundle.extend_from_slice(keys.content);
        if !record.k_proof_signed(vault_id) || !record.k_matches(vault_id, &bundle) {
            return Err(AppError::Unauthorized(
                "the vault key does not match the member record's owner-signed commitment \
                 (re-keyed?) — lock and unlock again"
                    .into(),
            ));
        }

        let mut unreadable = 0usize;
        for (id_b64, stored) in &self.items {
            // Fold each item independently: a single unreadable/unparseable item
            // (seal-parity mismatch, a body shape from a newer client, a rotated
            // K) must NOT hide EVERY other secret. Skip + log it; keep the rest.
            let one: crate::error::Result<()> = (|| {
                // Seal AAD id: blinded ids decode; a cleartext agent wire id
                // recomputes its HMAC (design/agent-authz-cleartext-cutover.md).
                let raw = aad_id_from_wire::<S>(keys.id_seed, id_b64)?;
                let ctx = ItemCtx::new(vault_id, raw, stored.version);
                let payload = unseal_item::<S>(keys.content, &ctx, &stored.ct)?;
                if payload.is_tombstone() {
                    return Ok(());
                }
                let name = payload.name;
                match payload.ns {
                    ItemNs::Secret => {
                        let (value, notes) = parse_secret_body(&payload.body).map_err(|e| {
                            AppError::Internal(format!("secret item '{}': {}", name, e))
                        })?;
                        if let Some(n) = notes {
                            native_secret_notes.insert(name.clone(), n);
                        }
                        native_secrets.insert(name, value.into_bytes());
                    }
                    ItemNs::Connection => {
                        let conn = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("connection '{}' parse: {}", name, e))
                        })?;
                        aux.connections.insert(name, conn);
                    }
                    ItemNs::Connecting => {
                        let c = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("connecting '{}' parse: {}", name, e))
                        })?;
                        aux.connecting.insert(name, c);
                    }
                    ItemNs::Agent => {
                        // T2 (design/agent-authz-cleartext-cutover.md): a native agent
                        // item MUST live at its own cleartext id (wire id == ag_id ==
                        // name). Drop a body smuggled at any other id, so the backend
                        // ownership gate on the ag_id cannot be dodged.
                        if id_b64.as_str() != name.as_str() {
                            tracing::warn!(vault = %vault_id, agent = %name, wire = %id_b64, "fold: dropping agent grant — wire id != ag_id");
                            return Ok(());
                        }
                        let Some(data) = fold_agent_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            record,
                            vault_id,
                            &raw,
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, agent = %name, "fold: dropping agent grant — unsigned/unauthorized/invalid signature");
                            return Ok(());
                        };
                        let entry: crate::storage::plaintext::AgentEntry =
                            serde_json::from_value(data).map_err(|e| {
                                AppError::Internal(format!("agent '{}' parse: {}", name, e))
                            })?;
                        aux.agents.insert(name, entry);
                    }
                    ItemNs::Policy => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            record,
                            vault_id,
                            &raw,
                            "policy",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping policy — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.policy = Some(
                            serde_json::from_value(data)
                                .map_err(|e| AppError::Internal(format!("policy parse: {}", e)))?,
                        );
                        seen_new.policy = true;
                    }
                    ItemNs::Stores => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            record,
                            vault_id,
                            &raw,
                            "stores",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping stores — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.stores = serde_json::from_value(data)
                            .map_err(|e| AppError::Internal(format!("stores parse: {}", e)))?;
                        seen_new.stores = true;
                    }
                    ItemNs::StoreOrder => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            record,
                            vault_id,
                            &raw,
                            "store_order",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping store_order — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.store_order = serde_json::from_value(data)
                            .map_err(|e| AppError::Internal(format!("store_order parse: {}", e)))?;
                        seen_new.store_order = true;
                    }
                    ItemNs::AuditRetentionDays => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            record,
                            vault_id,
                            &raw,
                            "audit_retention_days",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping audit_retention_days — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.audit_retention_days = serde_json::from_value(data).map_err(|e| {
                            AppError::Internal(format!("audit_retention_days parse: {}", e))
                        })?;
                        seen_new.retention = true;
                    }
                    ItemNs::Services => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            record,
                            vault_id,
                            &raw,
                            "services",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping services — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.services = serde_json::from_value(data)
                            .map_err(|e| AppError::Internal(format!("services parse: {}", e)))?;
                        seen_new.services = true;
                    }
                    ItemNs::Members => {
                        // The in-vault membership is RETIRED (finding #1): roles
                        // come from the member record only. Any legacy `members:`
                        // item is ignored.
                    }
                    ItemNs::Aux => {
                        // Config singletons ride `aux:<name>` blobs (parked +
                        // applied after the loop if no unified-ns item set the
                        // field — the cosmetic `aux:` drop is deferred). Legacy
                        // `aux:agent/<id>` rows are ignored (native ns only).
                        legacy_addressing = true;
                        // C.3: owner-config carries an owner's UIK signature;
                        // a bad / missing signature parks `None` (→ safe default).
                        // `config_name` is addressing-independent.
                        // A legacy `aux:members` blob is ignored (membership retired).
                        match name.as_str() {
                            "stores" => {
                                legacy_stores = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    record,
                                    vault_id,
                                    &raw,
                                    "stores",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "store_order" => {
                                legacy_store_order = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    record,
                                    vault_id,
                                    &raw,
                                    "store_order",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "policy" => {
                                legacy_policy = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    record,
                                    vault_id,
                                    &raw,
                                    "policy",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "audit_retention_days" => {
                                legacy_retention = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    record,
                                    vault_id,
                                    &raw,
                                    "audit_retention_days",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "services" => {
                                legacy_services = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    record,
                                    vault_id,
                                    &raw,
                                    "services",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            n => {
                                if let Some(agent_id) = n.strip_prefix("agent/") {
                                    // Legacy `aux:agent/<ag_id>` rows are NEVER folded
                                    // (any trust state): the id is blinded, so the
                                    // backend's ownership gate on the ag_id can't see
                                    // the write. Only native `agent:<ag_id>` rows count.
                                    tracing::debug!(vault = %vault_id, agent = %agent_id, "fold: ignoring legacy aux:agent row (only native, UIK-signed agent rows authorize)");
                                }
                                // other unknown aux names: ignored (forward-compat).
                            }
                        }
                    }
                }
                Ok(())
            })();
            if let Err(e) = one {
                // Not a version problem (a too-new vault format is refused before
                // this, via the signed envelope): this record is unreadable as is.
                unreadable += 1;
                tracing::warn!(vault = %vault_id, item = %id_b64, "fold: skipping unreadable item: {}", e);
            }
        }
        if let Ok(mut m) = UNREADABLE_ITEMS.lock() {
            if unreadable > 0 {
                m.insert(vault_id.to_string(), unreadable);
            } else {
                m.remove(vault_id);
            }
        }

        // Apply parked legacy values where no new-address item set the field.
        if !seen_new.stores {
            if let Some(v) = legacy_stores {
                aux.stores = serde_json::from_value(v)
                    .map_err(|e| AppError::Internal(format!("aux.stores parse: {}", e)))?;
            }
        }
        if !seen_new.store_order {
            if let Some(v) = legacy_store_order {
                aux.store_order = serde_json::from_value(v)
                    .map_err(|e| AppError::Internal(format!("aux.store_order parse: {}", e)))?;
            }
        }
        if !seen_new.policy {
            if let Some(v) = legacy_policy {
                aux.policy = Some(
                    serde_json::from_value(v)
                        .map_err(|e| AppError::Internal(format!("aux.policy parse: {}", e)))?,
                );
            }
        }
        if !seen_new.retention {
            if let Some(v) = legacy_retention {
                aux.audit_retention_days = serde_json::from_value(v).map_err(|e| {
                    AppError::Internal(format!("aux.audit_retention_days parse: {}", e))
                })?;
            }
        }
        if !seen_new.services {
            if let Some(v) = legacy_services {
                aux.services = serde_json::from_value(v)
                    .map_err(|e| AppError::Internal(format!("aux.services parse: {}", e)))?;
            }
        }
        // No `members` legacy blob to merge: roles come from the member record.

        Ok(VaultPlaintextView {
            aux,
            native_secrets,
            native_secret_notes,
            legacy_addressing,
        })
    }

    /// Names of live (non-tombstone) items in one namespace (tests only).
    #[cfg(test)]
    fn live_names_in_ns<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        want: ItemNs,
    ) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for (id_b64, stored) in &self.items {
            let raw = aad_id_from_wire::<S>(keys.id_seed, id_b64)?;
            let ctx = ItemCtx::new(vault_id, raw, stored.version);
            let payload = unseal_item::<S>(keys.content, &ctx, &stored.ct)?;
            if payload.ns == want && !payload.is_tombstone() {
                out.push(payload.name);
            }
        }
        Ok(out)
    }
}

/// Read the per-item vault file. `None` if it doesn't exist.
pub fn read_per_item(path: &Path) -> Result<Option<PerItemVault>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let v: PerItemVault = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("per-item vault parse: {}", e)))?;
    Ok(Some(v))
}

/// Atomically write the per-item vault file (same F-18 random-suffix temp +
/// rename discipline as [`write_atomic`]).
pub fn write_per_item_atomic(path: &Path, vault: &PerItemVault) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(vault)?;
    let tmp = path.with_extension(format!("dat.tmp.{:08x}", rand::random::<u32>()));
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Fixtures other modules' tests share: a store on a verified record whose
/// owner-signed generation-0 proof commits to a given K bundle.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    /// The owner (anchor, root, reader) of [`store_for`]'s record.
    pub fn owner() -> crate::crypto::vault_key::UikRoot {
        crate::crypto::vault_key::UikRoot::from_root([0x11u8; 32])
    }

    /// The [`owner`]'s own ledger pinning each of `vaults` to its anchor, as
    /// the console writes at create/upgrade: what a held record of
    /// [`store_for`] re-verifies against.
    pub fn owner_ledger_pinning(vaults: &[&str]) -> crate::crypto::ledger::LedgerState {
        use crate::crypto::ledger::{KIND_PIN, OP_ADMIT};
        let o = owner();
        let mut p = crate::trust::test_support::Person::from_identity(o.signing());
        for v in vaults {
            p.push(
                OP_ADMIT,
                KIND_PIN,
                v.to_string(),
                o.signing().public_bytes().to_vec(),
                Vec::new(),
            );
        }
        p.fold()
    }

    /// A store whose record (anchored at [`owner`], read by the owner) carries a
    /// generation-0 proof over `bundle`.
    pub fn store_for(vault: &str, bundle: &[u8; 64]) -> PerItemVault {
        PerItemVault {
            record: Some(record_for(vault, bundle)),
            ..PerItemVault::new()
        }
    }

    /// The record [`store_for`] uses.
    pub fn record_for(vault: &str, bundle: &[u8; 64]) -> MemberRecord {
        let o = owner();
        let id = o.user_id();
        let grant = o
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &id, "owner", 0));
        let mut members = BTreeMap::new();
        members.insert(
            id.clone(),
            RecordMember {
                user_id: id.clone(),
                sig_pub: o.signing().public_bytes().to_vec(),
                role: crate::storage::plaintext::MemberRole::Owner,
                role_sig: grant.to_vec(),
            },
        );
        let commit = crate::identity::k_commitment(vault, 0, bundle);
        let membership = crate::identity::membership_commitment(&[]);
        let sig = o.signing().sign(&crate::identity::rekey_sig_input(
            vault,
            0,
            &commit,
            &id,
            0,
            &membership,
        ));
        let mut r = MemberRecord {
            anchor: o.signing().public_bytes().to_vec(),
            members,
            generation: 0,
            rekey_proof: Some(RekeyProof {
                generation: 0,
                k_commitment: commit.to_vec(),
                sig: sig.to_vec(),
                signer_id: id.clone(),
                membership_len: 0,
                membership_hash: membership.to_vec(),
            }),
            delegation_log: Vec::new(),
            root_succession: Vec::new(),
            seq: 1,
            hash: Vec::new(),
            reader: id,
        };
        r.hash = record_wire_hash(&wire(&r)).to_vec();
        r
    }

    /// The served wire form of a record (contract 8.3/8.4).
    pub fn wire(record: &MemberRecord) -> serde_json::Value {
        let members: serde_json::Map<String, serde_json::Value> = record
            .members
            .iter()
            .map(|(us, m)| {
                (
                    us.clone(),
                    serde_json::json!({
                        "role": role_str(m.role),
                        "role_sig": STANDARD.encode(&m.role_sig),
                        "k_encapped": "AAAA", "k_ct": "AAAA",
                    }),
                )
            })
            .collect();
        let persons: serde_json::Map<String, serde_json::Value> = record
            .members
            .iter()
            .map(|(us, m)| {
                (
                    us.clone(),
                    serde_json::json!({ "sig_pub": STANDARD.encode(&m.sig_pub), "enc_pub": "AAAA", "enc_sig": "AAAA" }),
                )
            })
            .collect();
        serde_json::json!({
            "anchor": STANDARD.encode(&record.anchor),
            "members": members,
            "persons": persons,
            "seq": record.seq,
            "proof": {
                "generation": record.generation,
                "rekey_proof": record.rekey_proof.as_ref().map(|p| serde_json::json!({
                    "generation": p.generation,
                    "k_commitment": STANDARD.encode(&p.k_commitment),
                    "sig": STANDARD.encode(&p.sig),
                    "signer_id": p.signer_id,
                    "membership_len": p.membership_len,
                    "membership_hash": STANDARD.encode(&p.membership_hash),
                })),
                "delegation_log": record.delegation_log,
                "succession": record.root_succession,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::wire;
    use super::*;
    use crate::crypto::vault_key::UikRoot;
    use crate::storage::plaintext::MemberRole;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use sudp::primitives::StdPrimitives;
    use tempfile::tempdir;

    // ── fixtures ────────────────────────────────────────────────────────────

    /// The 64-byte K bundle (`id_seed ‖ content`) a `VaultKeys` view stands for.
    fn bundle(keys: VaultKeys) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(keys.id_seed);
        b[32..].copy_from_slice(keys.content);
        b
    }

    /// A record anchored at `creator`, who is its root and a self-granted owner
    /// at role_epoch 0, verified for `reader`. No K proof yet.
    fn record_anchored(vault: &str, creator: &UikRoot, reader: &str) -> MemberRecord {
        let id = creator.user_id();
        let grant = creator
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &id, "owner", 0));
        let mut members = BTreeMap::new();
        members.insert(
            id.clone(),
            RecordMember {
                user_id: id,
                sig_pub: creator.signing().public_bytes().to_vec(),
                role: MemberRole::Owner,
                role_sig: grant.to_vec(),
            },
        );
        MemberRecord {
            anchor: creator.signing().public_bytes().to_vec(),
            members,
            generation: 0,
            rekey_proof: None,
            delegation_log: Vec::new(),
            root_succession: Vec::new(),
            seq: 1,
            hash: Vec::new(),
            reader: reader.to_string(),
        }
    }

    /// Sign the K proof for the record's current generation over `bundle`,
    /// committing the current-epoch delegation-log prefix.
    fn sign_k_proof(record: &mut MemberRecord, vault: &str, signer: &UikRoot, bundle: &[u8; 64]) {
        let role_epoch = resolve_current_root(record, vault)
            .map(|(_, e)| e)
            .unwrap_or(0);
        let mut events: Vec<&DelegationEvent> = record
            .delegation_log
            .iter()
            .filter(|e| e.role_epoch == role_epoch)
            .collect();
        events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
        let sigs: Vec<&[u8]> = events.iter().map(|e| e.sig.as_slice()).collect();
        let membership = crate::identity::membership_commitment(&sigs);
        let commit = crate::identity::k_commitment(vault, record.generation, bundle);
        let signer_id = signer.user_id();
        let sig = signer.signing().sign(&crate::identity::rekey_sig_input(
            vault,
            record.generation,
            &commit,
            &signer_id,
            sigs.len() as u64,
            &membership,
        ));
        record.rekey_proof = Some(RekeyProof {
            generation: record.generation,
            k_commitment: commit.to_vec(),
            sig: sig.to_vec(),
            signer_id,
            membership_len: sigs.len() as u64,
            membership_hash: membership.to_vec(),
        });
    }

    fn creator() -> UikRoot {
        UikRoot::from_root([0x11u8; 32])
    }

    /// A store whose record is anchored at [`creator`], read BY the creator, with
    /// a generation-0 proof over `keys` — what a fold needs to open items.
    fn store_for(vault: &str, keys: VaultKeys) -> PerItemVault {
        let c = creator();
        let mut r = record_anchored(vault, &c, &c.user_id());
        sign_k_proof(&mut r, vault, &c, &bundle(keys));
        PerItemVault {
            record: Some(r),
            ..PerItemVault::new()
        }
    }

    fn record_mut(pv: &mut PerItemVault) -> &mut MemberRecord {
        pv.record.as_mut().expect("fixture record")
    }

    /// Seat `who` as a member with `role` and the given checkpoint `role_sig`.
    fn set_member(pv: &mut PerItemVault, who: &UikRoot, role: MemberRole, role_sig: Vec<u8>) {
        let id = who.user_id();
        record_mut(pv).members.insert(
            id.clone(),
            RecordMember {
                user_id: id,
                sig_pub: who.signing().public_bytes().to_vec(),
                role,
                role_sig,
            },
        );
    }

    /// The creator-anchored role fixture: creator (root, owner) + a member key
    /// not yet seated.
    fn role_fixture() -> (&'static str, UikRoot, UikRoot, String, String, PerItemVault) {
        let vault = "vault-role";
        let c = creator();
        let member = UikRoot::from_root([0x22u8; 32]);
        let (cid, mid) = (c.user_id(), member.user_id());
        let pv = PerItemVault {
            record: Some(record_anchored(vault, &c, &cid)),
            ..PerItemVault::new()
        };
        (vault, c, member, cid, mid, pv)
    }

    fn owner_set(pv: &PerItemVault, vault: &str) -> BTreeMap<String, MemberRole> {
        match pv.resolve_membership_trust(vault) {
            MembershipTrust::Verified(m) => m,
            MembershipTrust::Untrusted => panic!("expected Verified"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_event(
        pv: &mut PerItemVault,
        vault: &str,
        signer: &UikRoot,
        op: &str,
        subject_id: &str,
        role: MemberRole,
        seq: u64,
        role_epoch: u64,
    ) {
        let granter_id = signer.user_id();
        let role_tok = if op == "remove" { "" } else { role_str(role) };
        let sig = signer
            .signing()
            .sign(&crate::identity::delegation_event_input(
                vault,
                op,
                subject_id,
                role_tok,
                &granter_id,
                seq,
                role_epoch,
            ));
        record_mut(pv).delegation_log.push(DelegationEvent {
            op: op.into(),
            subject_id: subject_id.into(),
            role,
            granter_id,
            granter_sig_pub: signer.signing().public_bytes().to_vec(),
            seq,
            role_epoch,
            sig: sig.to_vec(),
        });
    }

    /// A root-signed self-succession (a compaction) to `epoch`.
    fn push_compaction(pv: &mut PerItemVault, vault: &str, root: &UikRoot, epoch: u64) {
        let root_id = root.user_id();
        let root_pub = root.signing().public_bytes();
        let sig = root.signing().sign(&crate::identity::root_succession_input(
            vault, &root_id, &root_id, &root_pub, epoch,
        ));
        record_mut(pv).root_succession.push(RootSuccession {
            old_root_id: root_id.clone(),
            new_root_id: root_id,
            new_root_sig_pub: root_pub.to_vec(),
            role_epoch: epoch,
            sig: sig.to_vec(),
        });
    }

    /// An in-body owner-config wrapper signed by `signer`.
    fn signed_config(
        signer: &UikRoot,
        vault: &str,
        name: &str,
        version: u64,
        data: &serde_json::Value,
    ) -> serde_json::Value {
        let canonical = crate::crypto::canonical::canonicalize(data);
        let input = crate::identity::config_sig_input(
            vault,
            name,
            version,
            Some(&canonical),
            &signer.user_id(),
        );
        serde_json::json!({
            "data": data,
            "uik_sig": STANDARD.encode(signer.signing().sign(&input)),
            "uik_sign_pub": STANDARD.encode(signer.signing().public_bytes()),
        })
    }

    // ── base64 + item store ─────────────────────────────────────────────────

    #[test]
    fn decode_b64_lenient_accepts_std_and_url() {
        let raw: Vec<u8> = vec![
            0xFB, 0xFF, 0xBF, 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B,
        ];
        let std_pad = STANDARD.encode(&raw);
        assert!(std_pad.contains('+') || std_pad.contains('/'));
        let std_nopad = std_pad.trim_end_matches('=').to_string();
        let url_pad = std_pad.replace('+', "-").replace('/', "_");
        let url_nopad = url_pad.trim_end_matches('=').to_string();
        for s in [&std_pad, &std_nopad, &url_pad, &url_nopad] {
            assert_eq!(decode_b64_lenient(s).unwrap(), raw, "decode {}", s);
        }
    }

    #[test]
    fn per_item_vault_seal_write_read_open_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.per-item.json");
        let k = [0x42u8; 32];
        let vid = "vault-xyz";
        let mut pv = store_for(vid, VaultKeys::single(&k));
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN",
                1,
                &ItemPayload::secret_live("GMAIL_REFRESH_TOKEN", "ya29.value"),
            )
            .unwrap();
        assert_eq!(
            id,
            item_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap()
        );
        assert_eq!(pv.get_item(&id).unwrap().version, 1);

        // Persist and reload: the sealed ct AND the verified record survive.
        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert_eq!(loaded.items.len(), 1);
        assert_eq!(loaded.record, pv.record, "member record survives the store");

        let payload = loaded
            .open_item::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN",
            )
            .unwrap()
            .unwrap();
        assert_eq!(payload.body, serde_json::Value::String("ya29.value".into()));
        assert!(loaded
            .open_item::<StdPrimitives>(
                VaultKeys::single(&k),
                "other-vault",
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN"
            )
            .is_err());
        assert!(loaded
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Secret, "NOPE")
            .unwrap()
            .is_none());
    }

    /// A pre-trust-reset store (a `keyset` + `keyset_seq`, no record) still
    /// loads — its items are kept — but it has no record, so every fold refuses
    /// with the "upgrade this vault in the console" message.
    #[test]
    fn pre_reset_store_loads_without_a_record_and_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.per-item.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "keyset": { "version": 3, "registry": {}, "credentials": [] },
                "keyset_seq": 9,
                "items": {},
                "items_seq": 4,
            }))
            .unwrap(),
        )
        .unwrap();
        let pv = read_per_item(&path).unwrap().unwrap();
        assert!(pv.record.is_none());
        assert_eq!(pv.items_seq, 4);
        let k = [1u8; 64];
        let err = pv
            .fold_view::<StdPrimitives>(VaultKeys::from_material(&k), "v")
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("upgrade this vault in the console"),
            "{err}"
        );
    }

    #[test]
    fn synced_version_tracks_dirty_vs_clean() {
        let k = [0x21u8; 32];
        let vid = "vault-dirty";
        let mut pv = PerItemVault::new();
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "T",
                1,
                &ItemPayload::secret_live("T", "v1"),
            )
            .unwrap();
        assert_eq!(
            pv.get_item(&id).unwrap().synced_version,
            0,
            "local write starts dirty"
        );
        let ct = pv.get_item(&id).unwrap().ct.clone();
        pv.put_raw(id.clone(), 1, ct);
        assert_eq!(
            pv.get_item(&id).unwrap().synced_version,
            1,
            "adopted row is clean"
        );
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "T",
            2,
            &ItemPayload::secret_live("T", "v2"),
        )
        .unwrap();
        let s = pv.get_item(&id).unwrap();
        assert_eq!((s.version, s.synced_version), (2, 1));
    }

    #[test]
    fn tombstone_flag_tracks_payload_status() {
        let k = [0x33u8; 32];
        let vid = "vault-tomb";
        let mut pv = PerItemVault::new();
        let live = pv
            .seal_and_bump::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Connection,
                "gcp",
                &ItemPayload::live(
                    ItemNs::Connection,
                    "gcp",
                    serde_json::json!({"service": "gcp"}),
                ),
            )
            .unwrap()
            .0;
        assert!(!pv.get_item(&live).unwrap().tombstone);
        let dead = pv
            .seal_and_bump::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Connecting,
                "gcp",
                &ItemPayload::tombstone(ItemNs::Connecting, "gcp"),
            )
            .unwrap()
            .0;
        assert!(pv.get_item(&dead).unwrap().tombstone);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.per-item.json");
        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert!(!loaded.get_item(&live).unwrap().tombstone);
        assert!(loaded.get_item(&dead).unwrap().tombstone);
    }

    #[test]
    fn agent_mask_serde_all_and_blocked() {
        use crate::storage::plaintext::{AgentEntry, AgentMask};
        let all: AgentEntry = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(all.connections.allows("anything"));
        assert!(matches!(all.connections, AgentMask::All(_)));
        assert_eq!(
            serde_json::to_value(&AgentEntry::default()).unwrap(),
            serde_json::json!({ "connections": "all" })
        );
        let blk: AgentEntry = serde_json::from_value(
            serde_json::json!({ "connections": { "deny": ["stripe-live"] } }),
        )
        .unwrap();
        assert!(matches!(blk.connections, AgentMask::Blocked { .. }));
        assert!(!blk.connections.allows("stripe-live"));
        assert!(blk.connections.allows("github-work"));
        assert!(blk.connections.allows("added-later-conn"));
        assert_eq!(
            serde_json::to_value(&blk).unwrap(),
            serde_json::json!({ "connections": { "deny": ["stripe-live"] } })
        );
        assert!(AgentMask::default().allows("x"));
        assert!(AgentMask::Blocked {
            deny: vec!["a".into()]
        }
        .allows("b"));
        assert!(!AgentMask::Blocked {
            deny: vec!["a".into()]
        }
        .allows("a"));
        assert!(AgentMask::Blocked { deny: vec![] }.allows("anything"));
    }

    // `ReconcileBase`: only a difference from the view's base is the caller's.
    #[test]
    fn reconcile_is_relative_to_the_base() {
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};
        let k = [0x56u8; 32];
        let vid = "vault-del";
        let keys = VaultKeys::single(&k);
        let view_of = |pairs: &[(&str, &str)]| VaultPlaintextView {
            aux: VaultAux::initial(),
            native_secrets: pairs
                .iter()
                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                .collect(),
            native_secret_notes: Default::default(),
            legacy_addressing: false,
        };
        let store = || {
            let mut pv = store_for(vid, keys);
            pv.seed_items_from_view::<StdPrimitives>(
                keys,
                vid,
                &view_of(&[("A", "a"), ("B", "b"), ("C", "new"), ("D", "d")]),
            )
            .unwrap();
            pv
        };
        let live = |pv: &PerItemVault| -> Vec<(String, String)> {
            pv.fold_view::<StdPrimitives>(keys, vid)
                .unwrap()
                .native_secrets
                .into_iter()
                .map(|(n, v)| (n, String::from_utf8(v).unwrap()))
                .collect()
        };
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        let base = ViewBase::of(&view_of(&[("A", "a"), ("C", "old"), ("D", "d")])).unwrap();
        let view = view_of(&[("C", "old"), ("D", "d2")]);
        let mut pv = store();
        pv.reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(live(&pv), pairs(&[("B", "b"), ("C", "new"), ("D", "d2")]));
        let mut pv = store();
        pv.reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::OwnFold)
            .unwrap();
        assert_eq!(live(&pv), pairs(&[("C", "old"), ("D", "d2")]));
    }

    #[test]
    fn reconcile_keeps_both_on_a_concurrent_same_item_change() {
        use crate::storage::item::{self as il};
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};
        let k = [0x57u8; 32];
        let vid = "vault-kb";
        let keys = VaultKeys::single(&k);
        let view_of = |k_val: &str| VaultPlaintextView {
            aux: VaultAux::initial(),
            native_secrets: [("K".to_string(), k_val.as_bytes().to_vec())].into(),
            native_secret_notes: Default::default(),
            legacy_addressing: false,
        };
        let mut pv = store_for(vid, keys);
        pv.seed_items_from_view::<StdPrimitives>(keys, vid, &view_of("theirs"))
            .unwrap();
        for s in pv.items.values_mut() {
            s.synced_version = s.version;
        }
        let k_id = il::wire_id_for::<StdPrimitives>(&k, ItemNs::Secret, "K").unwrap();
        let their_k = pv.get_item(&k_id).unwrap().clone();
        let base = ViewBase::of(&view_of("base")).unwrap();
        let view = view_of("ours");
        pv.reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();
        let k_now = pv.get_item(&k_id).unwrap();
        assert_eq!(
            (k_now.version, k_now.synced_version, k_now.ct.clone()),
            (their_k.version, their_k.version, their_k.ct.clone())
        );
        let (copy_id, _) = il::seal_conflict_copy::<StdPrimitives>(
            keys,
            vid,
            &ItemPayload::secret_live("K", "ours"),
            their_k.version,
        )
        .unwrap();
        let copy = pv.get_item(&copy_id).expect("local conflict copy").clone();
        assert_eq!(
            (copy.version, copy.synced_version),
            (il::CONFLICT_COPY_VERSION, 0)
        );
        let folded = pv.fold_view::<StdPrimitives>(keys, vid).unwrap();
        assert_eq!(folded.native_secrets["K"], b"theirs");
        assert_eq!(folded.native_secrets[&il::conflict_copy_name("K")], b"ours");
        let n = pv.items.len();
        pv.reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(pv.items.len(), n);
    }

    /// The daemon NEVER writes authorized-agents rows or owner config: it holds no
    /// UIK. Reconcile from a view carrying agents and policy writes neither, and
    /// the seal primitive refuses agent rows in both spellings.
    #[test]
    fn daemon_never_writes_agent_rows_or_owner_config() {
        use crate::storage::plaintext::{AgentEntry, AgentMask, VaultAux};
        let k = [0x55u8; 32];
        let vid = "vault-t1";
        let mut pv = store_for(vid, VaultKeys::single(&k));
        let mut aux = VaultAux::initial();
        aux.policy = Some(serde_json::from_value(serde_json::json!({ "timeout": 222 })).unwrap());
        aux.agents.insert(
            "ag_alice".into(),
            AgentEntry {
                connections: AgentMask::Blocked {
                    deny: vec!["stripe".into()],
                },
                ..Default::default()
            },
        );
        let view = crate::storage::plaintext::VaultPlaintextView {
            aux,
            native_secrets: BTreeMap::new(),
            native_secret_notes: BTreeMap::new(),
            legacy_addressing: false,
        };
        let changed = pv
            .reconcile_from_view::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                &view,
                ReconcileBase::OwnFold,
            )
            .unwrap();
        assert!(
            changed.is_empty(),
            "no agent or config rows written: {:?}",
            changed
        );
        let folded = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert!(folded.aux.policy.is_none() && folded.aux.agents.is_empty());

        let ag = "ag_abcdefghijklmnopqrstuvwxyz234567";
        let body = serde_json::to_value(AgentEntry::default()).unwrap();
        assert!(pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Agent,
                ag,
                1,
                &ItemPayload::live(ItemNs::Agent, ag.to_string(), body.clone()),
            )
            .is_err());
        assert!(pv
            .seal_and_bump::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Agent,
                ag,
                &ItemPayload::tombstone(ItemNs::Agent, ag.to_string()),
            )
            .is_err());
        let legacy = format!("agent/{}", ag);
        assert!(pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Aux,
                &legacy,
                1,
                &ItemPayload::live(ItemNs::Aux, legacy.clone(), body),
            )
            .is_err());
        assert!(pv.items.is_empty(), "refused writes stored nothing");
    }

    /// Native `ns=Agent` items address by the CLEARTEXT ag_id (row PK == ag_id)
    /// while the seal AAD stays the HMAC.
    #[test]
    fn native_agent_cleartext_seal_open_roundtrip() {
        use crate::storage::plaintext::AgentEntry;
        let k = [0x66u8; 32];
        let vid = "vault-agent-ct";
        let mut pv = PerItemVault::new();
        let ag = "ag_abcdefghijklmnopqrstuvwxyz234567";
        let body = serde_json::to_value(AgentEntry::default()).unwrap();
        let id = wire_id_for::<StdPrimitives>(&k, ItemNs::Agent, ag).unwrap();
        assert_eq!(id.as_str(), ag);
        let ctx = ItemCtx::for_item::<StdPrimitives>(&k, vid, ItemNs::Agent, ag, 1).unwrap();
        let ct = seal_item::<StdPrimitives>(
            &k,
            &ctx,
            &ItemPayload::live(ItemNs::Agent, ag.to_string(), body),
        )
        .unwrap();
        pv.put_raw_signed(id, 1, ct, None, None);
        let opened = pv
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Agent, ag)
            .unwrap()
            .expect("native cleartext agent item opens");
        assert_eq!(opened.ns, ItemNs::Agent);
        let names = pv
            .live_names_in_ns::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Agent)
            .unwrap();
        assert!(names.contains(&ag.to_string()));
    }

    #[test]
    fn secret_notes_survive_a_daemon_value_rewrite() {
        let k = [0x43u8; 32];
        let vid = "vault-notes";
        let mut pv = store_for(vid, VaultKeys::single(&k));
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "TOKEN",
            1,
            &ItemPayload::live(
                ItemNs::Secret,
                "TOKEN",
                secret_body("old", Some("prod key")),
            ),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "PLAIN",
            1,
            &ItemPayload::secret_live("PLAIN", "p"),
        )
        .unwrap();
        let mut view = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert_eq!(
            view.native_secret_notes.get("TOKEN").map(String::as_str),
            Some("prod key")
        );
        view.native_secrets.insert("TOKEN".into(), b"new".to_vec());
        pv.reconcile_from_view::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            &view,
            ReconcileBase::OwnFold,
        )
        .unwrap();
        let token = pv
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Secret, "TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(
            token.body,
            serde_json::json!({ "value": "new", "notes": "prod key" })
        );
        let plain = pv
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Secret, "PLAIN")
            .unwrap()
            .unwrap();
        assert_eq!(plain.body, serde_json::Value::String("p".into()));
    }

    #[test]
    fn fold_view_rebuilds_secrets_connections_and_owner_signed_config() {
        let k = [0x42u8; 32];
        let vid = "vault-fold";
        let keys = VaultKeys::single(&k);
        let mut pv = store_for(vid, keys);
        let seal = |pv: &mut PerItemVault, ns: ItemNs, name: &str, v: u64, p: ItemPayload| {
            pv.seal_and_upsert::<StdPrimitives>(keys, vid, ns, name, v, &p)
                .unwrap();
        };
        seal(
            &mut pv,
            ItemNs::Secret,
            "OPENAI_KEY",
            1,
            ItemPayload::secret_live("OPENAI_KEY", "sk-live"),
        );
        seal(
            &mut pv,
            ItemNs::Secret,
            "GONE",
            2,
            ItemPayload::tombstone(ItemNs::Secret, "GONE"),
        );
        seal(
            &mut pv,
            ItemNs::Connection,
            "gmail",
            1,
            ItemPayload::live(
                ItemNs::Connection,
                "gmail",
                serde_json::json!({ "service": "gmail" }),
            ),
        );
        // Owner-signed store_order (honored) and an unsigned policy (dropped).
        let order = serde_json::json!(["native-secrets", "gcp-1"]);
        seal(
            &mut pv,
            ItemNs::StoreOrder,
            "",
            1,
            ItemPayload::live(
                ItemNs::StoreOrder,
                "",
                signed_config(&creator(), vid, "store_order", 1, &order),
            ),
        );
        seal(
            &mut pv,
            ItemNs::Policy,
            "",
            1,
            ItemPayload::live(ItemNs::Policy, "", serde_json::json!({ "timeout": 5 })),
        );
        let view = pv.fold_view::<StdPrimitives>(keys, vid).unwrap();
        assert_eq!(
            view.resolve_value_native("OPENAI_KEY"),
            Some(&b"sk-live"[..])
        );
        assert_eq!(view.native_secrets.get("GONE"), None);
        assert_eq!(
            view.aux
                .connections
                .get("gmail")
                .and_then(|c| c.service.as_deref()),
            Some("gmail")
        );
        assert_eq!(view.aux.store_order, vec!["native-secrets", "gcp-1"]);
        assert!(
            view.aux.policy.is_none(),
            "unsigned owner config never folds"
        );
    }

    // ── K commitment (contract 1.5/1.7) ─────────────────────────────────────

    /// A fold refuses a K that doesn't match the owner-signed commitment for the
    /// record's CURRENT generation, a record without a proof (generation 0
    /// included), and a proof signed by a non-owner.
    #[test]
    fn fold_requires_the_committed_k_and_a_generation_proof() {
        let vid = "vault-kc";
        let k = [0x10u8; 64];
        let keys = VaultKeys::from_material(&k);
        let mut pv = store_for(vid, keys);
        pv.seal_and_upsert::<StdPrimitives>(
            keys,
            vid,
            ItemNs::Secret,
            "A",
            1,
            &ItemPayload::secret_live("A", "a"),
        )
        .unwrap();
        assert!(pv.fold_view::<StdPrimitives>(keys, vid).is_ok());
        let record = pv.record.clone().unwrap();
        assert!(record.k_matches(vid, &k));
        assert!(!record.k_matches(vid, &[0x11u8; 64]), "another bundle");
        assert!(!record.k_matches(vid, &k[..32]), "not a 64-byte bundle");
        assert!(
            !record.k_matches("other-vault", &k),
            "commitment binds the vault"
        );

        // A wrong K (sharing the id-seed) is refused before any item is opened.
        let mut wrong = k;
        wrong[63] ^= 1;
        assert!(pv
            .fold_view::<StdPrimitives>(VaultKeys::from_material(&wrong), vid)
            .is_err());

        // No proof at all (generation 0 too): refused.
        record_mut(&mut pv).rekey_proof = None;
        assert!(pv.fold_view::<StdPrimitives>(keys, vid).is_err());

        // A proof signed by a mere member: refused.
        let member = UikRoot::from_root([0x22u8; 32]);
        let grant = creator().signing().sign(&crate::identity::role_grant_input(
            vid,
            &member.user_id(),
            "member",
            0,
        ));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        sign_k_proof(record_mut(&mut pv), vid, &member, &k);
        assert!(!pv.record.as_ref().unwrap().k_proof_signed(vid));
        assert!(pv.fold_view::<StdPrimitives>(keys, vid).is_err());

        // A re-key: generation 1 proof over the NEW bundle; the old K stops folding.
        let k2 = [0x20u8; 64];
        {
            let r = record_mut(&mut pv);
            r.generation = 1;
        }
        sign_k_proof(record_mut(&mut pv), vid, &creator(), &k2);
        assert!(pv.record.as_ref().unwrap().k_matches(vid, &k2));
        assert!(
            pv.fold_view::<StdPrimitives>(keys, vid).is_err(),
            "K retained across a re-key"
        );
        // A proof for a different generation than the record's is refused.
        record_mut(&mut pv).generation = 2;
        assert!(!pv.record.as_ref().unwrap().k_proof_signed(vid));
    }

    #[test]
    fn dps1_content_rotation_preserves_ids_and_forward_secrecy() {
        use crate::storage::item::vault_key_bundle;
        let vid = "vault-rekey";
        let seed = [0x11u8; 32];
        let c_old = [0x22u8; 32];
        let c_new = [0x33u8; 32];
        let mut pv = PerItemVault::new();
        let vk_new = VaultKeys {
            id_seed: &seed,
            content: &c_new,
        };
        pv.seal_and_upsert::<StdPrimitives>(
            vk_new,
            vid,
            ItemNs::Secret,
            "TOKEN",
            1,
            &ItemPayload::secret_live("TOKEN", "sk-new"),
        )
        .unwrap();
        let id_from_seed =
            item_id::<StdPrimitives>(&seed, ItemNs::Secret.as_str(), "TOKEN").unwrap();
        assert!(pv.items.contains_key(&id_from_seed));
        let vk_old = VaultKeys {
            id_seed: &seed,
            content: &c_old,
        };
        assert!(pv
            .open_item::<StdPrimitives>(vk_old, vid, ItemNs::Secret, "TOKEN")
            .is_err());
        let bundle = vault_key_bundle(&seed, &c_new);
        let vk = VaultKeys::from_material(&bundle);
        let got = pv
            .open_item::<StdPrimitives>(vk, vid, ItemNs::Secret, "TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(got.body, serde_json::Value::String("sk-new".into()));
    }

    // ── served record verification (design D5, A3) ──────────────────────────

    #[test]
    fn served_record_verifies_against_the_readers_pin() {
        let vid = "vault-served";
        let c = creator();
        let member = UikRoot::from_root([0x22u8; 32]);
        let k = [7u8; 64];
        let mut pv = PerItemVault {
            record: Some(record_anchored(vid, &c, &c.user_id())),
            ..PerItemVault::new()
        };
        let grant = c.signing().sign(&crate::identity::role_grant_input(
            vid,
            &member.user_id(),
            "member",
            0,
        ));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        sign_k_proof(record_mut(&mut pv), vid, &c, &k);
        let served = wire(pv.record.as_ref().unwrap());
        let pin = c.signing().public_bytes();

        // The member verifies it against the pin it holds.
        let got = MemberRecord::from_served(vid, &served, &pin, &member.user_id()).unwrap();
        assert_eq!(got.reader, member.user_id());
        assert_eq!(got.seq, 1);
        assert!(got.k_matches(vid, &k));
        assert_eq!(got.hash, record_wire_hash(&served).to_vec());
        assert_eq!(got.current_members(vid).len(), 2);

        // Another pin: refused (the link pointed to a different owner).
        let other = UikRoot::from_root([0x99u8; 32]).signing().public_bytes();
        assert_eq!(
            MemberRecord::from_served(vid, &served, &other, &member.user_id()).unwrap_err(),
            RecordError::PinMismatch
        );
        // A reader who is not a member: refused.
        assert_eq!(
            MemberRecord::from_served(vid, &served, &pin, "us_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap_err(),
            RecordError::NotAMember
        );
        // No K proof (generation 0): refused.
        let mut no_proof = served.clone();
        no_proof["proof"]["rekey_proof"] = serde_json::Value::Null;
        assert!(matches!(
            MemberRecord::from_served(vid, &no_proof, &pin, &member.user_id()),
            Err(RecordError::Unverifiable(_))
        ));
        // A member whose served sig_pub doesn't fold to its id is dropped: here the
        // server swaps the member's person key, so the member falls out and the
        // reader is no longer a member.
        let mut swapped = served.clone();
        swapped["persons"][member.user_id()]["sig_pub"] = serde_json::json!(
            STANDARD.encode(UikRoot::from_root([0x98u8; 32]).signing().public_bytes())
        );
        assert_eq!(
            MemberRecord::from_served(vid, &swapped, &pin, &member.user_id()).unwrap_err(),
            RecordError::NotAMember
        );
        // Missing pieces are malformed, never a panic.
        assert!(matches!(
            MemberRecord::from_served(vid, &serde_json::json!({}), &pin, &member.user_id()),
            Err(RecordError::Malformed(_))
        ));
        let mut no_seq = served.clone();
        no_seq.as_object_mut().unwrap().remove("seq");
        assert!(matches!(
            MemberRecord::from_served(vid, &no_seq, &pin, &member.user_id()),
            Err(RecordError::Malformed(_))
        ));
    }

    /// The latch hash covers the record's own wire content (anchor, members,
    /// proof, seq) and nothing joined from `persons`.
    #[test]
    fn latch_hash_is_the_records_own_wire_content() {
        let vid = "vault-hash";
        let c = creator();
        let mut r = record_anchored(vid, &c, &c.user_id());
        sign_k_proof(&mut r, vid, &c, &[1u8; 64]);
        let served = wire(&r);
        let h = record_wire_hash(&served);
        let mut no_persons = served.clone();
        no_persons.as_object_mut().unwrap().remove("persons");
        assert_eq!(
            record_wire_hash(&no_persons),
            h,
            "persons are not record content"
        );
        let mut rekeyed = served.clone();
        rekeyed["persons"][c.user_id()]["enc_pub"] = serde_json::json!("BBBB");
        assert_eq!(record_wire_hash(&rekeyed), h);
        for (k, v) in [
            ("seq", serde_json::json!(2)),
            ("anchor", serde_json::json!("AAAA")),
            ("proof", serde_json::json!({})),
            ("members", serde_json::json!({})),
        ] {
            let mut x = served.clone();
            x[k] = v;
            assert_ne!(record_wire_hash(&x), h, "{k} binds");
        }
    }

    /// Backend migration (B1) strips pre-reset `rekey_proof`s: such a record
    /// has no owner-signed K commitment, so the daemon refuses it (the vault
    /// stays closed and no grant can match a commitment) until the console
    /// re-commits at a generation >= 1, which is then accepted.
    #[test]
    fn stripped_k_proof_closes_the_vault_until_a_generation_ge1_recommit() {
        use crate::crypto::ledger::{KIND_PIN, OP_ADMIT};
        use crate::trust::{adopt_record, AdoptError, RecordAdopt};
        let vid = "vault-migrated";
        let c = creator();
        let old_k = [0x31u8; 64];
        let new_k = [0x32u8; 64];
        let mut r = record_anchored(vid, &c, &c.user_id());
        sign_k_proof(&mut r, vid, &c, &old_k);
        let pin = c.signing().public_bytes();
        let mut reader = crate::trust::test_support::Person::from_identity(c.signing());
        reader.push(OP_ADMIT, KIND_PIN, vid.into(), pin.to_vec(), Vec::new());
        let own = reader.fold();

        // Migrated: proof stripped, at generation 0 or a later pre-reset one.
        for generation in [0u64, 3] {
            let mut stripped = wire(&r);
            stripped["proof"]["generation"] = serde_json::json!(generation);
            stripped["proof"]["rekey_proof"] = serde_json::Value::Null;
            assert!(matches!(
                MemberRecord::from_served(vid, &stripped, &pin, &c.user_id()),
                Err(RecordError::Unverifiable(_))
            ));
            let mut store = PerItemVault::new();
            assert!(matches!(
                adopt_record(&mut store, vid, &stripped, &own),
                Err(AdoptError::Record(RecordError::Unverifiable(_)))
            ));
            assert!(
                store.record.is_none(),
                "nothing adopted: the vault stays closed"
            );
        }

        // The console re-commits K at generation 1 (owner-signed proof over the
        // full 64-byte bundle): accepted, and only the new K matches.
        let mut recommit = r.clone();
        recommit.generation = 1;
        recommit.seq += 1;
        sign_k_proof(&mut recommit, vid, &c, &new_k);
        let served = wire(&recommit);
        let got = MemberRecord::from_served(vid, &served, &pin, &c.user_id()).unwrap();
        assert_eq!(got.generation, 1);
        assert!(got.k_matches(vid, &new_k));
        assert!(!got.k_matches(vid, &old_k));
        let mut store = PerItemVault::new();
        assert_eq!(
            adopt_record(&mut store, vid, &served, &own).unwrap(),
            RecordAdopt::Adopted
        );
        assert_eq!(
            store
                .record
                .as_ref()
                .unwrap()
                .verify_held(vid, &pin, &c.user_id()),
            Ok(())
        );
    }

    /// A held record re-verifies against the reader's pin and person: a
    /// foreign anchor, another reader or a broken fold is refused.
    #[test]
    fn held_record_reverifies_against_pin_and_reader() {
        let vid = "vault-held";
        let c = creator();
        let mut r = record_anchored(vid, &c, &c.user_id());
        sign_k_proof(&mut r, vid, &c, &[2u8; 64]);
        let pin = c.signing().public_bytes();
        assert_eq!(r.verify_held(vid, &pin, &c.user_id()), Ok(()));
        let other = UikRoot::from_root([0x77u8; 32]).signing().public_bytes();
        assert_eq!(
            r.verify_held(vid, &other, &c.user_id()),
            Err(RecordError::PinMismatch)
        );
        assert!(matches!(
            r.verify_held(vid, &pin, "us_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Err(RecordError::Malformed(_))
        ));
        let mut no_proof = r.clone();
        no_proof.rekey_proof = None;
        assert!(matches!(
            no_proof.verify_held(vid, &pin, &c.user_id()),
            Err(RecordError::Unverifiable(_))
        ));
    }

    /// A deleted person row at the same seq is not equivocation; a changed
    /// record at the same seq is.
    #[test]
    fn deleted_person_row_is_not_equivocation() {
        use crate::crypto::ledger::{KIND_PIN, OP_ADMIT};
        use crate::trust::{adopt_record, AdoptError, RecordAdopt};
        let vid = "vault-latch";
        let c = creator();
        let member = UikRoot::from_root([0x22u8; 32]);
        let k = [7u8; 64];
        let mut pv = PerItemVault {
            record: Some(record_anchored(vid, &c, &c.user_id())),
            ..PerItemVault::new()
        };
        let grant = c.signing().sign(&crate::identity::role_grant_input(
            vid,
            &member.user_id(),
            "member",
            0,
        ));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        sign_k_proof(record_mut(&mut pv), vid, &c, &k);
        let served = wire(pv.record.as_ref().unwrap());
        let mut reader = crate::trust::test_support::Person::from_identity(c.signing());
        reader.push(
            OP_ADMIT,
            KIND_PIN,
            vid.into(),
            c.signing().public_bytes().to_vec(),
            Vec::new(),
        );
        let own = reader.fold();

        let mut store = PerItemVault::new();
        assert_eq!(
            adopt_record(&mut store, vid, &served, &own).unwrap(),
            RecordAdopt::Adopted
        );
        assert_eq!(
            adopt_record(&mut store, vid, &served, &own).unwrap(),
            RecordAdopt::Unchanged
        );
        // The member whose person row is gone can't be seated (no sig pub to
        // verify its grant), so the verified view drops it: same seq, same
        // latch hash, adopted — never equivocation.
        let mut gone = served.clone();
        gone["persons"]
            .as_object_mut()
            .unwrap()
            .remove(&member.user_id());
        assert_eq!(
            adopt_record(&mut store, vid, &gone, &own).unwrap(),
            RecordAdopt::Adopted
        );
        assert!(!store
            .record
            .as_ref()
            .unwrap()
            .members
            .contains_key(&member.user_id()));
        assert_eq!(
            adopt_record(&mut store, vid, &served, &own).unwrap(),
            RecordAdopt::Adopted
        );
        // A held copy edited on disk (same seq and hash field, other content)
        // is replaced by the verified one.
        let verified = store.record.clone().unwrap();
        store
            .record
            .as_mut()
            .unwrap()
            .members
            .get_mut(&member.user_id())
            .unwrap()
            .role_sig = vec![0; 64];
        assert_eq!(
            adopt_record(&mut store, vid, &served, &own).unwrap(),
            RecordAdopt::Adopted
        );
        assert_eq!(store.record.as_ref(), Some(&verified));
        let mut forked = served.clone();
        forked["members"][member.user_id()]["k_ct"] = serde_json::json!("BBBB");
        assert!(matches!(
            adopt_record(&mut store, vid, &forked, &own),
            Err(AdoptError::Equivocation { seq: 1 })
        ));
    }

    // ── owner config and agent records ──────────────────────────────────────

    #[test]
    fn config_signature_verify_accept_reject() {
        let (vault, c, member, cid, mid, mut pv) = role_fixture();
        let grant = c
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "member", 0));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        let record = pv.record.clone().unwrap();
        let trust = || pv.resolve_membership_trust(vault);
        let data = serde_json::json!({ "timeout": 30, "default": { "read": "ask" } });
        let version = 7u64;
        let by_owner = signed_config(&c, vault, "policy", version, &data);
        let fold = |body: serde_json::Value, name: &str, v: u64, t: &MembershipTrust| {
            fold_owner_config_record(
                None, None, b"", &record, vault, &[0u8; 32], name, v, body, t,
            )
        };
        assert_eq!(
            fold(by_owner.clone(), "policy", version, &trust()),
            Some(data.clone())
        );
        assert_eq!(
            fold(by_owner.clone(), "policy", version + 1, &trust()),
            None,
            "version binds"
        );
        assert_eq!(
            fold(by_owner.clone(), "stores", version, &trust()),
            None,
            "name binds"
        );
        assert_eq!(
            fold(data.clone(), "policy", version, &trust()),
            None,
            "unsigned dropped"
        );
        let bad = serde_json::json!({ "data": data, "uik_sig": "!!!", "uik_sign_pub": "!!!" });
        assert_eq!(fold(bad, "policy", version, &trust()), None);
        let stranger = UikRoot::from_root([0x44u8; 32]);
        assert_eq!(
            fold(
                signed_config(&stranger, vault, "policy", version, &data),
                "policy",
                version,
                &trust()
            ),
            None,
            "a non-member signer is dropped"
        );
        assert_eq!(
            fold(
                signed_config(&member, vault, "policy", version, &data),
                "policy",
                version,
                &trust()
            ),
            None,
            "a member (not an owner) can't author owner config"
        );
        assert_eq!(
            fold(by_owner, "policy", version, &MembershipTrust::Untrusted),
            None,
            "an untrusted record drops even a valid owner signature"
        );
        let _ = cid;
    }

    /// Land an agent row the way the PULL path does (console-sealed ct + the wire
    /// sidecar sig/signer).
    #[allow(clippy::too_many_arguments)]
    fn put_agent_row(
        pv: &mut PerItemVault,
        k: &[u8; 32],
        vault: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        body: serde_json::Value,
        signer: Option<&UikRoot>,
    ) {
        let ctx = ItemCtx::for_item::<StdPrimitives>(k, vault, ns, name, version).unwrap();
        let ct =
            seal_item::<StdPrimitives>(k, &ctx, &ItemPayload::live(ns, name.to_string(), body))
                .unwrap();
        let (sig, sid) = match signer {
            Some(sg) => {
                let input = crate::identity::record_signature_input(
                    "agent",
                    ctx.id_bytes(),
                    version,
                    vault,
                    &ct,
                    true,
                    &sg.user_id(),
                );
                (
                    Some(STANDARD.encode(sg.signing().sign(&input))),
                    Some(sg.user_id()),
                )
            }
            None => (None, None),
        };
        let wire = wire_id_for::<StdPrimitives>(k, ns, name).unwrap();
        pv.put_raw_signed(wire, version, ct, sig, sid);
    }

    /// Design D5.3: an agent record counts only if signed by the daemon's OWN
    /// person (the record's reader) or an owner. A member's record for their
    /// own agent authorizes it on that member's devices, never on another
    /// member's; outsiders, unsigned rows, in-body wrappers and legacy
    /// `aux:agent/*` rows never count.
    #[test]
    fn agent_records_count_only_from_the_reader_or_an_owner() {
        let (vault, c, member, cid, mid, mut pv) = role_fixture();
        let grant = c
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "member", 0));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        let k = [0x5au8; 32];
        sign_k_proof(
            record_mut(&mut pv),
            vault,
            &c,
            &bundle(VaultKeys::single(&k)),
        );
        let outsider = UikRoot::from_root([0x99u8; 32]);
        let v = 3u64;
        let ag = |ch: char| format!("ag_{}", ch.to_string().repeat(32));
        let body = |owner: &str| serde_json::json!({ "owner": owner, "connections": "all" });
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('a'),
            v,
            body(&mid),
            Some(&member),
        );
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('b'),
            v,
            body(&mid),
            Some(&c),
        );
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('d'),
            v,
            body(&outsider.user_id()),
            Some(&outsider),
        );
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('e'),
            v,
            body(&mid),
            None,
        );
        let wrapper = signed_config(&c, vault, &format!("agent/{}", ag('f')), v, &body(&mid));
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('f'),
            v,
            wrapper,
            None,
        );
        let legacy = format!("agent/{}", ag('h'));
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Aux,
            &legacy,
            v,
            body(&mid),
            Some(&c),
        );

        let keys = VaultKeys::single(&k);
        // Read by the CREATOR (an owner): owner-signed rows count, the member's
        // own-agent row does not (it is not the creator's and not owner-signed).
        let got: Vec<String> = pv
            .fold_view::<StdPrimitives>(keys, vault)
            .unwrap()
            .aux
            .agents
            .keys()
            .cloned()
            .collect();
        assert_eq!(got, vec![ag('b')]);

        // Read by the MEMBER: their own row and owner-signed rows count.
        record_mut(&mut pv).reader = mid.clone();
        let got: Vec<String> = pv
            .fold_view::<StdPrimitives>(keys, vault)
            .unwrap()
            .aux
            .agents
            .keys()
            .cloned()
            .collect();
        assert_eq!(got, vec![ag('a'), ag('b')]);

        // A record that no longer verifies (anchor tampered) folds nothing.
        record_mut(&mut pv).anchor = vec![1u8; 31];
        assert!(pv.fold_view::<StdPrimitives>(keys, vault).is_err());
        let _ = cid;
    }

    #[test]
    fn verify_record_sidecar_sig_accept_and_reject() {
        let (vault, c, _member, cid, _mid, pv) = role_fixture();
        let record = pv.record.as_ref().unwrap();
        let outsider = UikRoot::from_root([0x77u8; 32]);
        let ct = b"pretend-sealed-ciphertext-bytes";
        let id_raw = [0x09u8; 32];
        let sign = |signer: &UikRoot, ty: &str, body: &[u8]| -> String {
            let input = crate::identity::record_signature_input(
                ty,
                &id_raw,
                4,
                vault,
                body,
                true,
                &signer.user_id(),
            );
            STANDARD.encode(signer.signing().sign(&input))
        };
        let good = sign(&c, "policy", ct);
        assert_eq!(
            verify_record_sidecar_sig(ct, record, vault, &id_raw, "policy", 4, true, &good, &cid),
            Some(cid.clone())
        );
        assert_eq!(
            verify_record_sidecar_sig(ct, record, vault, &id_raw, "secret", 4, true, &good, &cid),
            None
        );
        assert_eq!(
            verify_record_sidecar_sig(
                b"other", record, vault, &id_raw, "policy", 4, true, &good, &cid
            ),
            None
        );
        let bad = sign(&outsider, "policy", ct);
        assert_eq!(
            verify_record_sidecar_sig(
                ct,
                record,
                vault,
                &id_raw,
                "policy",
                4,
                true,
                &bad,
                &outsider.user_id()
            ),
            None
        );
    }

    #[test]
    fn tombstone_verifies_only_for_an_owner_of_the_verified_record() {
        let (vault, c, member, cid, mid, mut pv) = role_fixture();
        let grant = c
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "member", 0));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        let input = crate::identity::vault_tombstone_input(vault);
        let by_owner = STANDARD.encode(c.signing().sign(&input));
        let by_member = STANDARD.encode(member.signing().sign(&input));
        assert!(pv.tombstone_verified(vault, &cid, &by_owner));
        assert!(
            !pv.tombstone_verified(vault, &mid, &by_member),
            "members can't delete"
        );
        assert!(
            !pv.tombstone_verified(vault, &cid, &by_member),
            "signature binds the signer"
        );
        assert!(
            !pv.tombstone_verified("other", &cid, &by_owner),
            "binds the vault"
        );
        assert!(
            !PerItemVault::new().tombstone_verified(vault, &cid, &by_owner),
            "no record"
        );
    }

    // ── the owner-set fold (finding #1, delegation, succession) ─────────────

    #[test]
    fn role_self_promote_blocked() {
        let (vault, _c, member, cid, mid, mut pv) = role_fixture();
        let self_grant = member
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "owner", 0));
        set_member(&mut pv, &member, MemberRole::Owner, self_grant.to_vec());
        let os = owner_set(&pv, vault);
        assert_eq!(os.get(&cid), Some(&MemberRole::Owner));
        assert!(!os.contains_key(&mid), "self-signed owner grant rejected");
    }

    #[test]
    fn role_grant_role_epoch_bound() {
        let (vault, c, member, cid, mid, mut pv) = role_fixture();
        let grant0 = c
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "owner", 0));
        set_member(&mut pv, &member, MemberRole::Owner, grant0.to_vec());
        assert_eq!(owner_set(&pv, vault).get(&mid), Some(&MemberRole::Owner));
        record_mut(&mut pv).generation = 5;
        assert_eq!(
            owner_set(&pv, vault).get(&mid),
            Some(&MemberRole::Owner),
            "a K-generation bump alone leaves the owner-set intact"
        );
        push_compaction(&mut pv, vault, &c, 1);
        let os = owner_set(&pv, vault);
        assert!(
            !os.contains_key(&mid),
            "stale grant dropped at role_epoch 1"
        );
        assert_eq!(os.get(&cid), Some(&MemberRole::Owner));
        let grant1 = c
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "owner", 1));
        record_mut(&mut pv).members.get_mut(&mid).unwrap().role_sig = grant1.to_vec();
        assert_eq!(owner_set(&pv, vault).get(&mid), Some(&MemberRole::Owner));
    }

    #[test]
    fn delegation_event_grant_and_non_cascade() {
        let (vault, c, _m, _cid, _mid, mut pv) = role_fixture();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        set_member(&mut pv, &a, MemberRole::Member, Vec::new());
        set_member(&mut pv, &b, MemberRole::Member, Vec::new());
        assert!(!owner_set(&pv, vault).contains_key(&a_id));
        push_event(&mut pv, vault, &c, "set", &a_id, MemberRole::Owner, 1, 0);
        assert_eq!(owner_set(&pv, vault).get(&a_id), Some(&MemberRole::Owner));
        push_event(&mut pv, vault, &a, "set", &b_id, MemberRole::Owner, 2, 0);
        assert_eq!(owner_set(&pv, vault).get(&b_id), Some(&MemberRole::Owner));
        push_event(
            &mut pv,
            vault,
            &c,
            "remove",
            &a_id,
            MemberRole::Member,
            3,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(!os.contains_key(&a_id));
        assert_eq!(os.get(&b_id), Some(&MemberRole::Owner), "non-cascade");
    }

    #[test]
    fn delegation_event_by_non_owner_rejected() {
        let (vault, _c, member, _cid, mid, mut pv) = role_fixture();
        set_member(&mut pv, &member, MemberRole::Member, Vec::new());
        push_event(
            &mut pv,
            vault,
            &member,
            "set",
            &mid,
            MemberRole::Owner,
            1,
            0,
        );
        assert!(!owner_set(&pv, vault).contains_key(&mid));
    }

    #[test]
    fn delegation_log_dup_seq_replay_rejected() {
        let (vault, c, _m, _cid, _mid, mut pv) = role_fixture();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        push_event(&mut pv, vault, &c, "set", &a_id, MemberRole::Owner, 1, 0);
        push_event(&mut pv, vault, &c, "set", &b_id, MemberRole::Owner, 1, 0);
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.contains_key(&a_id) as u8 + os.contains_key(&b_id) as u8,
            1,
            "exactly one seq-1 event applies"
        );
    }

    #[test]
    fn junk_same_seq_event_does_not_suppress_legit() {
        let (vault, c, _m, _cid, _mid, mut pv) = role_fixture();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        push_event(&mut pv, vault, &c, "set", &a_id, MemberRole::Owner, 1, 0);
        record_mut(&mut pv).delegation_log.push(DelegationEvent {
            op: "set".into(),
            subject_id: "us_ghost".into(),
            role: MemberRole::Owner,
            granter_id: c.user_id(),
            granter_sig_pub: c.signing().public_bytes().to_vec(),
            seq: 2,
            role_epoch: 0,
            sig: vec![0u8; 64],
        });
        push_event(
            &mut pv,
            vault,
            &c,
            "remove",
            &a_id,
            MemberRole::Member,
            2,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(!os.contains_key(&a_id));
        assert!(!os.contains_key("us_ghost"));
    }

    #[test]
    fn root_succession_transfers_root_and_offboards_creator() {
        let (vault, c, _m, cid, _mid, mut pv) = role_fixture();
        let newroot = UikRoot::from_root([0x55u8; 32]);
        let nid = newroot.user_id();
        let npub = newroot.signing().public_bytes();
        let sig = c.signing().sign(&crate::identity::root_succession_input(
            vault, &cid, &nid, &npub, 1,
        ));
        record_mut(&mut pv).root_succession.push(RootSuccession {
            old_root_id: cid.clone(),
            new_root_id: nid.clone(),
            new_root_sig_pub: npub.to_vec(),
            role_epoch: 1,
            sig: sig.to_vec(),
        });
        let grant = newroot
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &nid, "owner", 1));
        set_member(&mut pv, &newroot, MemberRole::Owner, grant.to_vec());
        let os = owner_set(&pv, vault);
        assert_eq!(os.get(&nid), Some(&MemberRole::Owner));
        assert!(!os.contains_key(&cid));
    }

    #[test]
    fn forged_succession_does_not_advance_root() {
        let (vault, _c, member, cid, _mid, mut pv) = role_fixture();
        let evil = UikRoot::from_root([0x66u8; 32]);
        let eid = evil.user_id();
        let epub = evil.signing().public_bytes();
        let bad = member
            .signing()
            .sign(&crate::identity::root_succession_input(
                vault, &cid, &eid, &epub, 1,
            ));
        record_mut(&mut pv).root_succession.push(RootSuccession {
            old_root_id: cid.clone(),
            new_root_id: eid.clone(),
            new_root_sig_pub: epub.to_vec(),
            role_epoch: 1,
            sig: bad.to_vec(),
        });
        let os = owner_set(&pv, vault);
        assert_eq!(os.get(&cid), Some(&MemberRole::Owner));
        assert!(!os.contains_key(&eid));
    }

    #[test]
    fn last_owner_cannot_be_removed() {
        let (vault, c, _m, cid, _mid, mut pv) = role_fixture();
        push_event(&mut pv, vault, &c, "remove", &cid, MemberRole::Member, 1, 0);
        push_event(&mut pv, vault, &c, "set", &cid, MemberRole::Member, 2, 0);
        assert_eq!(owner_set(&pv, vault).get(&cid), Some(&MemberRole::Owner));
    }

    #[test]
    fn creator_removable_when_another_owner_exists() {
        let (vault, c, _m, cid, _mid, mut pv) = role_fixture();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        push_event(&mut pv, vault, &c, "set", &a_id, MemberRole::Owner, 1, 0);
        push_event(&mut pv, vault, &c, "remove", &cid, MemberRole::Member, 2, 0);
        let os = owner_set(&pv, vault);
        assert!(!os.contains_key(&cid));
        assert_eq!(os.get(&a_id), Some(&MemberRole::Owner));
    }

    /// Anti-rollback: the owner-signed K proof commits the delegation-log prefix;
    /// a served log with a committed event omitted makes the record Untrusted.
    #[test]
    fn membership_rollback_is_rejected() {
        let (vault, c, _m, _cid, _mid, mut pv) = role_fixture();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        push_event(&mut pv, vault, &c, "set", &a_id, MemberRole::Owner, 1, 0);
        sign_k_proof(record_mut(&mut pv), vault, &c, &[3u8; 64]);
        assert!(matches!(
            pv.resolve_membership_trust(vault),
            MembershipTrust::Verified(_)
        ));
        assert_eq!(owner_set(&pv, vault).get(&a_id), Some(&MemberRole::Owner));
        assert!(pv.record.as_ref().unwrap().verify_fold(vault).is_ok());
        record_mut(&mut pv).delegation_log.clear();
        assert!(matches!(
            pv.resolve_membership_trust(vault),
            MembershipTrust::Untrusted
        ));
        assert!(pv.record.as_ref().unwrap().verify_fold(vault).is_err());
    }

    #[test]
    fn verified_membership_answers_offboarding_safely() {
        let (vault, c, member, cid, mid, mut pv) = role_fixture();
        assert_eq!(pv.verified_membership(vault, &cid), Some(true));
        assert_eq!(pv.verified_membership(vault, &mid), Some(false));
        let grant = c
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &mid, "member", 0));
        set_member(&mut pv, &member, MemberRole::Member, grant.to_vec());
        assert_eq!(pv.verified_membership(vault, &mid), Some(true));
        assert_eq!(PerItemVault::new().verified_membership(vault, &mid), None);
    }
}
