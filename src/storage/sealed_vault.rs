//! Sealed-vault on-disk format = [`sudp::state::SealedState`].
//!
//! As of Phase 3b.M (2026-05-21), safeclaw uses sudp's canonical state shape
//! for vault.dat: `{ version, registry, credentials, ciphertext }` where
//! - `registry` keys credential_id → opaque public-key JSON (WebAuthn x/y/
//!   device_name)
//! - `credentials[i]` carries `cid, prf_salt, wrapped_key` (= `K̂_c` =
//!   AEAD-wrap of K under W_c with AAD `DS_WRAP ‖ cid ‖ ver_be`)
//! - `ciphertext` = AEAD-seal of canonical(ProtectedState) under K with AAD
//!   `DS_SEAL ‖ ver_be`
//!
//! The client does the sealing — safeclaw daemon never sees `K` (the state
//! key) or `M` (ProtectedState) in plaintext at setup time. The client sends
//! the already-sealed bytes; the daemon just rehouses them into a SealedState
//! file. At grant redemption (export / use / write) the client transmits `W_c`
//! over the confidential TLS leg; the daemon momentarily unwraps and acts on
//! `M`, then drops `K` and any decrypted target bytes.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sudp::passkey::WebAuthn;
use sudp::primitives::PrimitiveSuite;
use sudp::state::{Registry, SealedCredential, SealedState, Version, CURRENT_VERSION};

use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::decode_credential_id;
use crate::storage::item::{
    aad_id_from_wire, body_digest as item_body_digest, item_id, item_id_bytes, normalized_body,
    open_wire_item, parse_secret_body, seal_item, secret_body, unseal_item_keys,
    wire_id_for, Conflict, ItemCtx, ItemNs, ItemPayload, Read, VaultKeys,
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

/// On-disk vault is exactly the sudp sealed-state JSON.
pub type SealedVault = SealedState;

// (F-18) TMP_EXT removed — temp path is now generated with a random suffix per call.

/// Read the vault file. Returns `None` if it doesn't exist.
pub fn read(path: &Path) -> Result<Option<SealedVault>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let v: SealedVault = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("vault.dat parse: {}", e)))?;
    if v.version != CURRENT_VERSION {
        return Err(AppError::Internal(format!(
            "vault.dat version mismatch: {} (expected {})",
            v.version, CURRENT_VERSION
        )));
    }
    Ok(Some(v))
}

/// Atomically write vault.dat.
///
/// F-18: The temp file gets a random 32-bit hex suffix so that two
/// concurrent calls (which the per-vault async mutex in approve.rs should
/// prevent, but we defend in-depth) cannot collide on the same tmp path.
/// On success the tmp file is renamed over the final path. On any error
/// the tmp file is unlinked so stale temps don't accumulate.
pub fn write_atomic(path: &Path, vault: &SealedVault) -> Result<()> {
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

/// Look up a credential's WebAuthn public key from the registry.
///
/// Returns a safeclaw-side [`PasskeyEntry`] so existing call sites that fetch
/// `(x, y, device_name)` for binding verification don't need to know the
/// sudp Registry shape.
pub fn find_pubkey(vault: &SealedVault, credential_id_b64: &str) -> Option<PasskeyEntry> {
    find_pubkey_in_registry(&vault.registry, credential_id_b64)
}

/// Same as [`find_pubkey`] but against a bare [`Registry`] — used by callers
/// that hold a per-item [`Keyset`] (which carries its own `registry`) rather
/// than a whole [`SealedVault`].
pub fn find_pubkey_in_registry(
    registry: &Registry,
    credential_id_b64: &str,
) -> Option<PasskeyEntry> {
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    let pk = registry.get::<WebAuthn>(&cid_bytes).ok().flatten()?;
    Some(PasskeyEntry {
        x: pk.x,
        y: pk.y,
        device_name: pk.device_name,
        created_at: 0, // sudp Registry doesn't track this; lossy.
    })
}

/// Find a credential entry by base64 id. Returns None if absent.
pub fn find_credential<'a>(
    vault: &'a SealedVault,
    credential_id_b64: &str,
) -> Option<&'a SealedCredential> {
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    vault.find_credential(&cid_bytes)
}

/// Build a fresh single-credential vault for first-time setup.
///
/// All sealing is performed by the client; the daemon receives the already-
/// sealed bytes (`wrapped_key`, `ciphertext`) and just assembles the file.
pub fn build_initial(
    credential_id: Vec<u8>,
    public_key_x_b64: String,
    public_key_y_b64: String,
    device_name: String,
    prf_salt: Vec<u8>,
    wrapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<SealedVault> {
    let mut registry = Registry::new();
    let pk = sudp::passkey::WebAuthnPublicKey {
        x: public_key_x_b64,
        y: public_key_y_b64,
        device_name,
    };
    registry
        .insert::<WebAuthn>(&credential_id, &pk)
        .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
    let sealed_cred = SealedCredential {
        credential_id,
        prf_salt,
        wrapped_key,
        // The client seals everything; the KCV (if any) arrives via /keys sync
        // or the unlock backfill, not this assembly helper.
        wc_check: None,
    };
    Ok(SealedState {
        version: CURRENT_VERSION,
        registry,
        credentials: vec![sealed_cred],
        ciphertext,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM LOCAL STORE  (PER_ITEM_SYNC.md §11.B step 1 / build contract §4)
//
// The whole-blob `SealedVault` = `SealedState` path ABOVE is still the live
// on-disk format wired into sync/connect/approve/metadata. The types below are
// the ADDITIVE landing target for the per-item rework: the daemon's on-disk
// vault becomes `{ keyset, items }` —
//   - `keyset` = the passkey-wrap layer (registry + credentials + format
//     version) — the SAME small CAS blob as today (§7), NOT sealed under K;
//   - `items`  = `item_id (base64url) → { version, ct }`, each `ct` a
//     `sudp::seal_record` of one `ItemPayload` under K (contract §2).
//
// Single-writer (the daemon), so one JSON file is fine. NOTHING here is wired
// into the live handlers yet — cutting sync/connect/approve/metadata over to it
// is priorities 3–5; until then the whole-blob path above stays authoritative.
// ─────────────────────────────────────────────────────────────────────────

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
/// mixed-encoding tolerance as [`decode_keys_data_field`]. Used for the delegation
/// log / root-succession signature + pubkey byte fields so a keyset's `/keys` wire
/// shape (what the browser writes) round-trips byte-for-byte through the daemon AND
/// equals the on-disk `vault.dat` representation — ONE SSOT encoding for both, so
/// `serde_json::to_value(&uik.delegation_log)` yields exactly the wire the frontend
/// and backend agree on (no separate hand-rolled converter).
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

/// LENIENT base64 decode for a `/keys` row `data` field, mirroring the
/// frontend's `fromBase64` (lib/safeclaw-crypto.ts): the frontend writes these
/// fields with MIXED encodings — `x`/`y`/`prf_salt`/`wrapped_key` are STANDARD
/// base64 (`toBase64`, has `+`/`/`/`=`) while `x25519_pub` is base64url — and its
/// reader accepts BOTH. So the daemon must NOT use a strict base64url decoder
/// (it would reject `+`/`/`/`=` and fail to unwrap `K`). Normalize url→std
/// (`-`→`+`, `_`→`/`), re-pad to a multiple of 4, then STANDARD-decode.
/// This is EXCLUSIVELY for `/keys` data fields; the `cid` row PK stays strict
/// base64url-nopad (`decode_credential_id`), and content item `ct`/id bytes stay
/// strict base64url-nopad (the per-item stack, `b64url_bytes`).
pub fn decode_keys_data_field(s: &str) -> Result<Vec<u8>> {
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
        .map_err(|e| AppError::BadRequest(format!("keys data field not base64: {}", e)))
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
    /// CIPHERTEXT), base64url-nopad — `None` for an unsigned record (owner-config /
    /// agent rows are honored unsigned ONLY on a fmt1 NoUik vault). Carried on the wire
    /// (`vault_items.sig`) so a blind server can gate + every reader can verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// The signing principal's self-id (`us_`/`dev_`) — a UIK for human writes, the
    /// DIK for automatic (daemon/OAuth) writes (A2). `None` iff unsigned. Wire:
    /// `vault_items.signer`. The reader maps it to a pubkey (keyset UIK / authorized
    /// devices) to verify + to a role for the role×type gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// For a DIRTY row in a keep-both namespace: the hex
    /// [`crate::storage::item::body_digest`] of the body our change was made
    /// from (the base), when known. A same-item conflict whose body equals it
    /// is no conflict: ours applies. Local bookkeeping only (never sent);
    /// `None` = unknown (the keep-both rule applies as is).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Written by SafeClaw's automatic upgrade of this vault (the legacy-row
    /// migration), not by a person: a conflict on it pauses the upgrade,
    /// which retries. Local bookkeeping only (never sent).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub upgrade: bool,
    /// The keyset generation this device sealed the row under (its own
    /// change), sent with its push: a vault with a keyset takes a row only
    /// at its current generation. `None` for a row adopted from the cloud, or
    /// sealed before this was recorded. Local bookkeeping only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// Confirmed, after a keyset refresh with keys of the keyset's current
    /// generation, to open under no key this member holds (the current one,
    /// or a retired one that lists it): no current member reads it, so a
    /// writer that may write the record may write over it, at its next
    /// version ([`PerItemVault::confirm_unreadable`]). Never set before such
    /// a refresh; gone whenever the row is replaced. Local bookkeeping only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unreadable_confirmed: bool,
}

/// A pulled replacement this device did not adopt (see `crate::sync`): kept
/// with why, offered again on every pull and at unlock, and shown to the user
/// until it is adopted or superseded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldRow {
    pub version: u64,
    pub seq: u64,
    #[serde(with = "b64url_bytes")]
    pub ct: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Why it is not applied.
    pub reason: String,
}

/// What an item id addresses, as read with the vault key ([`PerItemVault::classify_rows`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RowKind {
    /// A data record (a secret, a connection, an in-flight connect, a
    /// service, `secret_order`), copies included: a pulled replacement needs
    /// no key to adopt.
    Data,
    /// Owner-config, an agent grant, or a row not at its own address: a
    /// pulled replacement on a vault with a keyset waits for the key.
    Guarded,
}

/// The v2 (UIK) material carried alongside one credential (device) row — the
/// per-row half of `custody → UIK → K`. `K` is HPKE-sealed to the member's UIK
/// X25519 **encryption public key** (team-shared-vault-security-model.md §1/§2:
/// "K 用该成员的 UIK 公钥封装成一份"). Logically the seal is per-MEMBER (one
/// `enc_pub` per person), but it is stored per-credential-ROW so the keyset sync
/// carries it losslessly: `/keys` rows are cid-keyed, and a daemon re-pushes an
/// adopted row verbatim without needing to map the credential back to its member
/// (it cannot — that needs the member's root). The copies across one member's
/// devices are identical and tiny; the "no duplication" rule (§2) targets ITEM
/// storage explosion, not these keyset seals. Cloud-visible by design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UikCred {
    /// The account primary key `us_…` of the member this credential belongs to.
    /// Carried so offboarding can drop every credential of a departed member.
    pub user_id: String,
    /// The member's UIK Ed25519 **signing** public key (raw 32 bytes). Published
    /// so any reader can verify this member's config / role signatures (§9):
    /// `user_id = derive_id(sig_pub)` is one-way, so the pubkey itself must be
    /// carried. The creator's `sig_pub` is the vault's config-integrity trust
    /// anchor (only owner-signed config is honored; a malicious server can't
    /// forge it). Same across a member's devices (per-person, like `enc_pub`).
    #[serde(default)]
    pub sig_pub: Vec<u8>,
    /// The member's UIK X25519 encryption public key (raw 32 bytes). The owner
    /// seals `K` here on join / re-key (needs only this PUBLIC key); the member
    /// derives the same key from its unwrapped root and opens the seal.
    pub enc_pub: Vec<u8>,
    /// HPKE encapsulated key for the K-seal.
    pub k_encapped: Vec<u8>,
    /// HPKE ciphertext = `Seal(K)` to `enc_pub`, `info = uik-kseal ‖ vault_id`
    /// ([`crate::crypto::vault_key::seal_k_to_uik`]).
    pub k_ct: Vec<u8>,
    /// This member's role in the vault — an owner-signed attribute riding on the
    /// SAME record as membership (SSOT: the keyset cred is SM §1's single home
    /// for "who is a member"; role rides it, so there is one representation, no
    /// in-vault membership to drift). Verified via `role_sig`. `#[serde(default)]` =
    /// `Member` (least privilege) for legacy rows that predate this field, so a
    /// missing role never confers owner powers.
    #[serde(default)]
    pub role: crate::storage::plaintext::MemberRole,
    /// The vault CREATOR's Ed25519 signature over
    /// [`crate::identity::role_grant_input`]`(vault_id, user_id, role, generation)`
    /// (raw 64 bytes), signed at the keyset's `generation`. The daemon derives the
    /// owner-set by verifying this against the TOFU-pinned `creator_sig_pub`
    /// ([`KeysetUik::creator_sig_pub`]) at the CURRENT `generation`: a cred is
    /// honored at its `role` iff its `role_sig` verifies under the pinned creator AT
    /// that generation. This roots role in genesis (closing finding #1 — a member
    /// can no longer self-sign `{me: owner}`) and binds the grant to the role epoch
    /// (F3-b — a re-key generation bump invalidates a stale grant, so a
    /// demoted/offboarded person's replayed grant fails verification). May be empty
    /// for a legacy cred (then the cred is NOT an owner: an empty/invalid `role_sig`
    /// fails verification).
    #[serde(default)]
    pub role_sig: Vec<u8>,
    /// The vault's previous content keys, sealed under the current one (the
    /// row's `uik_prev_content_ct`; an owner sets it on every member's row at
    /// a re-key and on an invite): open rows a re-key has not moved yet
    /// ([`crate::storage::item::material_with_prev`]). Empty when there is
    /// none. Carried as sealed: every write of this entry keeps it, and this
    /// process never makes a new one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prev_content_ct: Vec<u8>,
}

/// The v2 (UIK) layer of a keyset — the `custody → UIK → K` layering
/// (team-shared-vault-security-model.md §5, sudp-identity-signing-revision.md
/// §B3). Present (`Some`) iff the keyset is v2. In v2, each
/// `SealedCredential.wrapped_key` holds `Wrap_{W_c}(UIK root)` (the classic
/// custody slot, re-purposed from wrapping `K` to wrapping the identity root),
/// and `K` is recovered from that credential's per-row seal in `creds`. A v1
/// keyset has `uik = None` and its `wrapped_key` is the classic `Wrap_{W_c}(K)`.
/// An owner-signed DP-S1 re-key event (team-shared-vault-security-model.md §3.2 /
/// sudp-identity-signing-revision.md A1.7). Proves a `generation` bump + content-
/// key rotation was authorized by an owner — so a malicious backend can neither
/// storm fake generations (unlock DoS) nor swap in a content key it chose (the
/// commitment binds the signature to the actual new content key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyProof {
    /// The generation this event authorizes (must equal `KeysetUik::generation`).
    pub generation: u64,
    /// A one-way commitment to the new content key ([`rekey_commitment`]), so the
    /// signature is bound to the specific rotated key (anti content-swap).
    pub k_commitment: Vec<u8>,
    /// The owner's Ed25519 signature over [`crate::identity::rekey_sig_input`].
    pub sig: Vec<u8>,
    /// The signing owner's `us_…` (must be an owner in the verified membership).
    pub signer_id: String,
    /// Membership anti-rollback (owner-signed): the number of delegation events at the
    /// current role-epoch captured at re-key time. `0` = empty prefix.
    #[serde(default)]
    pub membership_len: u64,
    /// [`crate::identity::membership_commitment`] over that prefix's event signatures, in
    /// `(seq, sig)` order. The fold refuses a keyset whose delegation-log prefix does
    /// not hash to this (a server serving the current generation with a rolled-back
    /// log — e.g. an omitted `remove` — fails the check).
    #[serde(default, with = "b64_std")]
    pub membership_hash: Vec<u8>,
}

/// An owner-signed delegation event — the any-owner, issuance-time-authority half
/// of the owner-set fold (design/identity-uik-aik.md §4.3,
/// delegation-log-impl-spec.md §1.2). Appended to [`KeysetUik::delegation_log`]
/// between root-signed checkpoints so ANY current owner (not just the root/creator)
/// can add / promote / demote / remove without a re-key. The fold honors an event
/// iff its `granter_id` is an Owner in the owner-set folded up to this event's `seq`
/// — so a member can't grant, and the fact "granter WAS an owner when they signed"
/// survives the granter's own later removal (NON-CASCADE).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// SELF-CERTIFYING: the fold requires `derive_id(granter_sig_pub) == granter_id`,
    /// then verifies `sig` under it. Carrying it in the event (rather than resolving it
    /// from the granter's cred row) is load-bearing: it makes verification immune to a
    /// spoofed cred row that lies about `(user_id, sig_pub)`, AND keeps the event
    /// verifiable AFTER the granter's own cred row is deleted at offboard — so removing
    /// a granter never drops whom they added (NON-CASCADE survives eviction).
    #[serde(default, with = "b64_std")]
    pub granter_sig_pub: Vec<u8>,
    /// Monotone ordering within `role_epoch` (rollback / reorder guard).
    pub seq: u64,
    /// The checkpoint epoch this event rides on. An event whose `role_epoch` differs
    /// from the keyset's current (succession-derived) `role_epoch` is a pre-compaction
    /// replay → ignored by the fold.
    pub role_epoch: u64,
    /// `granter`'s Ed25519 over [`crate::identity::delegation_event_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

/// A root-succession certificate — the CURRENT root signs the NEXT root's id +
/// signing pubkey, letting the daemon follow a short chain from the TOFU-pinned
/// GENESIS root to the current root (creator transfer / offboard;
/// design/identity-uik-aik.md §4.3). A succession is always paired with a
/// checkpoint re-cut at `role_epoch` by the NEW root (the new root re-signs every
/// surviving grant, so the fold verifies checkpoint grants under the new root).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootSuccession {
    /// The retiring root's `us_…` (must equal `derive_id(current root)` when applied).
    pub old_root_id: String,
    /// The incoming root's `us_…` (must equal `derive_id(new_root_sig_pub)`).
    pub new_root_id: String,
    /// The incoming root's UIK Ed25519 signing pubkey (raw 32 bytes), bound in the
    /// signature so a colluding server can't swap in a root key of its choosing. For a
    /// pure COMPACTION (no ownership change) this equals the current root's pubkey and
    /// `old_root_id == new_root_id` — a self-succession that only advances `role_epoch`.
    #[serde(with = "b64_std")]
    pub new_root_sig_pub: Vec<u8>,
    /// The checkpoint epoch at which the transfer / compaction takes effect (strictly
    /// increasing along the chain — rollback guard, and the SOLE source of the current
    /// `role_epoch`, which is DERIVED from this chain rather than stored as a
    /// separately-forgeable scalar).
    pub role_epoch: u64,
    /// `old_root`'s Ed25519 over [`crate::identity::root_succession_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeysetUik {
    /// `cid_b64 → per-credential UIK material` (same cid key as the credential /
    /// `/keys` row). Membership = holding one of these seals (SM §1).
    #[serde(default)]
    pub creds: BTreeMap<String, UikCred>,
    /// DP-S1 re-key epoch (team-shared-vault-security-model.md §3.2). `0` = never
    /// re-keyed (the K-seals carry a bundle whose content half is the original
    /// content key). An offboard/compromise re-key rotates the content key and
    /// bumps this, gated by an owner-signed re-key event
    /// ([`crate::identity::rekey_sig_input`]). A daemon that sees a higher, signed
    /// generation drops its old content key and re-unlocks under the new one.
    #[serde(default)]
    pub generation: u64,
    /// The owner-signed proof for the CURRENT `generation` (present iff
    /// `generation > 0`). A daemon refuses to fold a re-keyed vault whose proof is
    /// missing/invalid — so a backend can't forge a re-key.
    #[serde(default)]
    pub rekey_proof: Option<RekeyProof>,
    /// The vault's ROOT owner — the CREATOR's UIK Ed25519 signing pubkey (raw
    /// 32 bytes). This is the genesis anchor for role authority (design/
    /// identity-uik-aik.md §4.3 RESOLVED): the owner-set is derived by verifying
    /// each cred's `role_sig` against THIS key ([`Self`]'s creds →
    /// `resolve_membership_trust`). TOFU-pinned SET-ONCE by the daemon (first-seen
    /// wins; a non-empty pin is NEVER overwritten), so a colluding backend can't
    /// swap the anchor to forge an owner-set. On a v2 keyset that carries creds,
    /// empty here (serde default) means the anchor was never pinned — a colluding
    /// backend can STRIP it, so that state FAILS CLOSED ([`MembershipTrust::Untrusted`]:
    /// ALL owner-config is dropped, NOT downgraded to integrity-only). Only a
    /// legacy v1 keyset (`uik == None`) reads config integrity-only.
    #[serde(default)]
    pub creator_sig_pub: Vec<u8>,
    /// Append-only owner-signed delegation events since the last checkpoint — the
    /// any-owner half of the owner-set fold ([`DelegationEvent`]). Empty right after
    /// a compaction. A fresh daemon folds `checkpoint(role_epoch) ∘ delegation_log`.
    #[serde(default)]
    pub delegation_log: Vec<DelegationEvent>,
    /// Root-succession + compaction chain from the GENESIS `creator_sig_pub` to the
    /// current root ([`RootSuccession`]). Empty = creator is still root at genesis
    /// epoch 0. The daemon walks it to resolve BOTH the current root AND the current
    /// `role_epoch` (the role-checkpoint epoch, ORTHOGONAL to the K-rotation
    /// `generation` — memory "generation ⊥ chain 正交"). `role_epoch` is DERIVED from
    /// this root-signed chain, not stored as a separate scalar: a pure compaction is a
    /// SELF-succession (`old_root == new_root`) that only advances the epoch, so the
    /// epoch can never be forged upward without a valid root signature (closing the
    /// generation-brick class of DoS by construction — [`resolve_current_root`]).
    #[serde(default)]
    pub root_succession: Vec<RootSuccession>,
}

/// A one-way commitment to a content key for a re-key event: `SHA-256(domain ‖
/// content_key)`. Byte-identical to the browser's `rekeyCommitment`
/// (lib/uik-crypto.ts). Binds a signed `generation` to the specific content key.
pub fn rekey_commitment(content_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"safeclaw/v1/rekey-kc");
    h.update(content_key);
    h.finalize().into()
}

/// The lowercase serde token for a role (`"owner"` / `"member"`) — the EXACT
/// bytes the creator signs in [`crate::identity::role_grant_input`]. Kept in one
/// place so the signing input and the enum's serde spelling can never drift.
pub(crate) fn role_str(role: crate::storage::plaintext::MemberRole) -> &'static str {
    match role {
        crate::storage::plaintext::MemberRole::Owner => "owner",
        crate::storage::plaintext::MemberRole::Member => "member",
    }
}

/// The passkey-wrap layer — §7's small CAS blob, unchanged in substance from
/// today's `SealedState` minus its `ciphertext`. This is what *gives* you `K`,
/// so it can never be a K-sealed item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyset {
    /// Format version of the keyset blob (= `SealedState::version` today).
    pub version: Version,
    pub registry: Registry,
    pub credentials: Vec<SealedCredential>,
    /// Whole-blob CAS cursor for the keyset (mirrors `vault_blobs.version`).
    /// Bumped on add/remove-passkey / K-rewrap. `0` before the first cloud push.
    #[serde(default)]
    pub keyset_version: u64,
    /// The v2 (UIK) layer — `Some` iff this keyset uses `custody → UIK → K`
    /// (team edition). `None` = a classic v1 keyset (`wrapped_key` = `Wrap(K)`).
    /// Serde-default `None` so existing on-disk v1 keysets load untouched.
    #[serde(default)]
    pub uik: Option<KeysetUik>,
}

/// C.3 — verify + unwrap a signed **owner-config** item body (team-shared-vault-
/// security-model.md §9: owner-authored config is integrity-protected by a UIK
/// signature; the reader/daemon verifying it is "the real wall" against a
/// malicious/compromised server rewriting policy).
///
/// A signed body is `{ data, uik_sig, uik_sign_pub }`; the signature covers
/// [`crate::identity::config_sig_input`]`(vault, config_name, version,
/// JCS(data), derive_id(sign_pub))`. Returns:
///   - `Some(data)` — a valid signed wrapper, OR a legacy/v1 raw body (no
///     `uik_sig`). Whether a raw body is HONORED is the caller's trust decision:
///     only a [`MembershipTrust::NoUik`] (legacy v1) keyset honors it.
///   - `None` — DROP it: a signed wrapper that FAILED (bad sig, malformed, or a
///     signer whose pubkey is NOT a published member key — the anti-forgery
///     anchor from C.1). Dropping falls the field to its safe default (A1.6:
///     isolate the bad record, never crash, safe-default security-relevant config).
///
/// `config_name` is the addressing-independent logical name (`policy`, `stores`,
/// …) so the same signature verifies whether the item rode legacy `aux:<name>`
/// or the unified ns. The browser signer is `lib/uik-crypto.ts` (JCS parity via
/// `crate::crypto::canonical`, byte-identical to the browser `canonicalize`).
/// Integrity-verify an owner-config body (the C.3 half — no role authorization).
/// Returns:
///   - `None` — a signed wrapper that FAILED (bad/malformed sig, or a signer
///     whose pubkey is NOT a published member key = the C.1 anti-forgery anchor).
///   - `Some((data, None))` — a legacy/v1 raw body (no `uik_sig`), no signer.
///     Integrity says nothing about authorization: callers honor it ONLY on a
///     [`MembershipTrust::NoUik`] keyset (a v2 keyset drops it).
///   - `Some((data, Some(signer_id)))` — a valid signature; `signer_id` = the
///     signing member's `us_…` (for D's role authorization by the caller).
fn verify_config_sig(
    body: serde_json::Value,
    keyset: &Keyset,
    vault_id: &str,
    config_name: &str,
    version: u64,
) -> Option<(serde_json::Value, Option<String>)> {
    // Not a signed wrapper → legacy raw body, no signer (the caller decides; only
    // a NoUik keyset honors it).
    let obj = match &body {
        serde_json::Value::Object(o) if o.contains_key("uik_sig") => o,
        _ => return Some((body, None)),
    };
    // A malformed signed wrapper is a DROP (fail-closed), not a legacy pass —
    // a present-but-broken `uik_sig` must never silently fall through unsigned.
    let sig_b64 = obj.get("uik_sig").and_then(|v| v.as_str())?;
    let sign_pub_b64 = obj.get("uik_sign_pub").and_then(|v| v.as_str())?;
    let data = obj.get("data")?.clone();
    let sig_vec = decode_keys_data_field(sig_b64).ok()?;
    let sign_pub_vec = decode_keys_data_field(sign_pub_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let sign_pub: [u8; 32] = sign_pub_vec.as_slice().try_into().ok()?;
    // Anti-server-forgery: the signer's pubkey MUST be a published member key
    // (the C.1 keyset anchor). A wrapper self-signed with a server-minted key is
    // rejected — the server can't add its key to the keyset with a valid K-seal.
    let known = keyset
        .uik
        .as_ref()
        .is_some_and(|u| u.creds.values().any(|c| c.sig_pub == sign_pub_vec));
    if !known {
        return None;
    }
    let signer_id = crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub);
    let canonical = crate::crypto::canonical::canonicalize(&data);
    let input = crate::identity::config_sig_input(
        vault_id,
        config_name,
        version,
        Some(&canonical),
        &signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some((data, Some(signer_id)))
    } else {
        None
    }
}

/// A1.2/A1.5 — verify a per-record **sidecar** signature (`StoredItem.sig`/`signer`)
/// over the record's CIPHERTEXT, by a keyset MEMBER (a UIK — `us_…`). This is the
/// daemon-side (trust wall) verification of the new signed-record scheme: unlike
/// [`verify_config_sig`] (the sig lives INSIDE the sealed body and covers the
/// plaintext), here the sig is a plaintext sidecar covering `record_signature_input`
/// over the ciphertext — so the same signature a blind server verified at write is
/// re-verified here. Returns the signer's `us_…` iff the signature verifies AND the
/// signer's pubkey is a published keyset cred (the anti-server-forgery anchor); else
/// `None` (drop). `item_id_raw` = the 32-byte blinded id; `status_live` = live vs
/// tombstone. DIK (`dev_…`) signers are NOT resolved here (device pubkeys aren't in
/// the keyset) — that path is served separately; this covers the UIK-signed
/// owner-config + authorized-agents records.
fn verify_record_sidecar_sig(
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    record_type: &str,
    version: u64,
    status_live: bool,
    sig_b64: &str,
    signer_id: &str,
) -> Option<String> {
    let sig_vec = decode_keys_data_field(sig_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    // Resolve the signer's pubkey from the published keyset creds and bind it to the
    // claimed `signer_id` (self-certifying: id = fold of pubkey). A server-minted
    // key isn't in the keyset (it can't add one with a valid K-seal) → rejected.
    let uik = keyset.uik.as_ref()?;
    let sign_pub_vec = uik.creds.values().map(|c| &c.sig_pub).find(|pk| {
        <[u8; 32]>::try_from(pk.as_slice())
            .map(|k| crate::identity::derive_id(crate::identity::IdKind::User, &k) == signer_id)
            .unwrap_or(false)
    })?;
    let sign_pub: [u8; 32] = sign_pub_vec.as_slice().try_into().ok()?;
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
/// caller enforces the id) — design/agent-device-identity-mtls.md §11.1, design/
/// agent-authz-cleartext-cutover.md. Returns the row body to honor, or `None` to
/// drop it (that `ag_id` is then simply not authorized). Per trust state:
///   - [`MembershipTrust::Verified`] (v2): honored ONLY with a valid sidecar item-sig
///     (A1.2: `record_signature_input`, type `"agent"`, over the ciphertext, by a
///     published keyset member) whose signer is a vault OWNER or the row's own
///     `owner` (a member authorizing their OWN agent). An unsigned row, or one that
///     carries only a legacy in-body `{data,uik_sig}` wrapper, is DROPPED: without
///     the sidecar any K-holding member could write an authorization row.
///   - [`MembershipTrust::NoUik`] (legacy v1): integrity-only. There are no member
///     keys (single-person vault), so nothing can be signed and the K-seal (AEAD) is
///     the only gate: a plain unsigned row is honored; anything claiming a signature
///     is dropped (it can't verify against an empty keyset).
///   - [`MembershipTrust::Untrusted`]: everything is dropped (fail closed).
#[allow(clippy::too_many_arguments)]
fn fold_agent_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    match trust {
        MembershipTrust::Untrusted => None,
        MembershipTrust::NoUik => {
            if stored_sig.is_some() || body.get("uik_sig").is_some() {
                return None;
            }
            Some(body)
        }
        MembershipTrust::Verified(membership) => {
            let sig = stored_sig?;
            let signer = stored_signer?;
            let sid = verify_record_sidecar_sig(
                ct,
                keyset,
                vault_id,
                item_id_raw,
                "agent",
                version,
                true,
                sig,
                signer,
            )?;
            let owner = body
                .get("owner")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let is_owner =
                membership.get(&sid) == Some(&crate::storage::plaintext::MemberRole::Owner);
            if is_owner || sid == owner {
                Some(body)
            } else {
                None
            }
        }
    }
}

/// Fold one owner-config record (`ns`: a native kind, or a legacy `aux` row).
/// `config_name` is the sidecar record type ([`crate::storage::item::ItemRule::signature_type`]).
/// With a keyset only an owner's sidecar signature counts (A1.2). A native
/// record is sidecar-only: the old in-body wrapper (`{data, uik_sig, ..}`),
/// whose signature is not bound to the record's name, counts only on a legacy
/// `aux:<field>` row ([`unwrap_verified_config`]). Without a keyset an
/// unsigned body is honored; a native body claiming a signature is not.
/// Returns the raw `data` to honor (the daemon then parses it) or `None` to
/// drop.
#[allow(clippy::too_many_arguments)]
fn fold_owner_config_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    ns: ItemNs,
    config_name: &str,
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    let Some(sig) = stored_sig else {
        if ns != ItemNs::Aux {
            return match trust {
                MembershipTrust::NoUik if body.get("uik_sig").is_none() => Some(body),
                _ => None,
            };
        }
        return unwrap_verified_config(body, keyset, vault_id, config_name, version, trust);
    };
    let signer = stored_signer?;
    let sid = verify_record_sidecar_sig(
        ct, keyset, vault_id, item_id_raw, config_name, version, true, sig, signer,
    )?;
    match trust {
        MembershipTrust::Untrusted => None,
        MembershipTrust::NoUik => Some(body),
        MembershipTrust::Verified(membership) => {
            if membership.get(&sid) == Some(&crate::storage::plaintext::MemberRole::Owner) {
                Some(body)
            } else {
                None
            }
        }
    }
}

/// The three-state trust an owner-config reader derives from the KEYSET's UIK
/// anchor (design/identity-uik-aik.md §4.3, team-shared-vault-security-model.md
/// §9). This REPLACES the old `Option<BTreeMap<..>>` membership signal, which
/// conflated two very different "no owner-set" cases into `None` and so
/// FAIL-OPENED: a v2 keyset whose `creator_sig_pub` a colluding server had
/// STRIPPED looked identical to a legacy v1 vault and silently downgraded to
/// integrity-only, letting a colluding member's signed owner-config be honored.
/// The three states keep those cases distinct:
enum MembershipTrust {
    /// Legacy v1 keyset (`keyset.uik == None`) — no UIK layer, never re-keyable.
    /// Owner-config is honored on integrity alone (additive; pre-signing vaults).
    NoUik,
    /// A v2 keyset with a valid 32-byte pinned creator anchor. Owner-config is
    /// gated by this derived owner-set (`user_id → role`); an empty map is fine
    /// (it just means every SIGNED owner-config item drops).
    Verified(BTreeMap<String, crate::storage::plaintext::MemberRole>),
    /// A v2 keyset that carries credentials but has NO valid creator anchor
    /// (`creator_sig_pub` empty / not 32 bytes). This is the server-strippable
    /// state (`adopt_creator_pin` only pins a non-empty value), so it FAILS
    /// CLOSED: ALL owner-config (signed OR legacy-raw) and ALL agent rows are
    /// dropped → the fields fall to their safe defaults. Never downgrade this to
    /// integrity-only.
    Untrusted,
}

/// C.3 + D — verify AND authorize an owner-config item body (team-shared-vault-
/// security-model.md §9 + §附 role×type: owner-authored config is honored only
/// when signed by an **owner**; the reader/daemon verifying it is "the real
/// wall"). Composes [`verify_config_sig`] (integrity) with role authorization,
/// keyed on the [`MembershipTrust`] state:
///   - [`MembershipTrust::NoUik`] (legacy v1) ⇒ integrity-only: a valid or unsigned
///     body is honored (additive — pre-signing vaults);
///   - [`MembershipTrust::Verified`] (v2, anchor pinned) ⇒ owner-gated: a valid
///     signature is honored only if the signer is an **owner** in the derived
///     owner-set; everything else is DROPPED (an unsigned legacy-raw body, which
///     any K-holding member could have written; a non-owner member; an unknown
///     signer; a bad/forged signature);
///   - [`MembershipTrust::Untrusted`] (v2, anchor stripped) ⇒ FAIL CLOSED: EVERYTHING
///     the owner-config path would otherwise honor is dropped, signed or not, so
///     a colluding member's config is never honored via integrity-only.
/// Dropping falls the field to its safe default (A1.6).
fn unwrap_verified_config(
    body: serde_json::Value,
    keyset: &Keyset,
    vault_id: &str,
    config_name: &str,
    version: u64,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    match verify_config_sig(body, keyset, vault_id, config_name, version) {
        None => None,
        Some((data, signer)) => match trust {
            // Anchor stripped: drop everything the owner-config path would honor.
            MembershipTrust::Untrusted => None,
            // Legacy v1: integrity-only (additive) — signed or unsigned honored.
            MembershipTrust::NoUik => Some(data),
            // Verified v2: honored ONLY when signed by an OWNER in the derived
            // owner-set. An unsigned legacy-raw body is dropped (a K-holding
            // member could have written it).
            MembershipTrust::Verified(membership) => match signer {
                Some(signer_id)
                    if membership.get(&signer_id)
                        == Some(&crate::storage::plaintext::MemberRole::Owner) =>
                {
                    Some(data)
                }
                _ => None,
            },
        },
    }
}

/// Resolve the CURRENT root's Ed25519 signing pubkey AND the current `role_epoch` by
/// walking the [`KeysetUik::root_succession`] chain from the TOFU-pinned GENESIS root
/// (`creator_sig_pub`) (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md
/// §1.2). The `role_epoch` is DERIVED here (not stored): a pure COMPACTION is a
/// SELF-succession (`old_root == new_root`, same pubkey) that only advances the
/// epoch, so the epoch can never be forged upward without a valid root signature.
///
/// A hop from the current `(root, epoch)` is VALID iff: `old_root_id ==
/// derive_id(current root)` (chains from the current root, so the server can't fork
/// it onto a key it controls), `role_epoch` STRICTLY increases (rollback guard),
/// `new_root_id == derive_id(new_root_sig_pub)` (id/pubkey bound), and the `sig`
/// verifies under the CURRENT root over [`crate::identity::root_succession_input`].
///
/// The walk is ORDER-ROBUST: at each step it SEARCHES the whole chain for a valid
/// extending hop (rather than reading in slice order), so a colluding server cannot
/// block a legitimate successor by reordering / prepending a bogus cert. Among
/// multiple valid extensions of the same root (a root that equivocated), the
/// lowest-`role_epoch` (ties broken by `new_root_id`) is taken for determinism; the
/// loop terminates because each step strictly increases the epoch. An unverifiable
/// succession never advances the root (fail-closed forward), so a forged succession
/// can't install a server-chosen root. Returns `None` iff the genesis anchor itself
/// is absent / not 32 bytes (the server-strippable state → callers fail closed).
fn resolve_current_root(uik: &KeysetUik, vault_id: &str) -> Option<([u8; 32], u64)> {
    let mut cur = <[u8; 32]>::try_from(uik.creator_sig_pub.as_slice()).ok()?;
    let mut cur_epoch: u64 = 0;
    loop {
        let cur_id = crate::identity::derive_id(crate::identity::IdKind::User, &cur);
        // Find the lowest-epoch valid hop extending the current root (order-robust +
        // deterministic under equivocation).
        let mut best: Option<(&RootSuccession, [u8; 32])> = None;
        for s in &uik.root_succession {
            if s.old_root_id != cur_id || s.role_epoch <= cur_epoch {
                continue;
            }
            let Ok(new_pub) = <[u8; 32]>::try_from(s.new_root_sig_pub.as_slice()) else {
                continue;
            };
            if s.new_root_id != crate::identity::derive_id(crate::identity::IdKind::User, &new_pub)
            {
                continue; // id/pubkey mismatch
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
                continue; // signature by anyone but the current root
            }
            // Prefer the lowest epoch; break ties on new_root_id for determinism.
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

/// Verify a keyset's DP-S1 re-key state (team-shared-vault-security-model.md
/// §3.2). A gen-0 keyset (or a v1 vault) is trivially valid. A re-keyed keyset
/// (`generation > 0`) is trusted only if it carries an owner-signed
/// [`RekeyProof`] that: matches the generation; commits to the ACTUAL content
/// key in use (anti content-swap by a backend); is signed by a key that is a
/// published keyset member (C.1 anchor) AND an OWNER in the verified owner-set
/// (D); with a valid signature over [`crate::identity::rekey_sig_input`]. A
/// missing or invalid proof on a re-keyed vault ⇒ `false` (the daemon refuses to
/// fold it), which is what stops a backend forging a generation bump (unlock
/// DoS). An [`MembershipTrust::Untrusted`] keyset (v2 anchor stripped) has no
/// confirmable owner, so a re-keyed (`generation > 0`) keyset is likewise refused
/// — a DoS a colluding server can already cause by stripping the anchor, NOT a
/// privilege escalation.
fn verify_rekey_proof(
    keyset: &Keyset,
    trust: &MembershipTrust,
    vault_id: &str,
    content_key: &[u8],
) -> bool {
    let Some(uik) = keyset.uik.as_ref() else {
        return true; // v1 / no UIK layer — not re-keyable
    };
    if uik.generation == 0 {
        return true; // never re-keyed
    }
    // A re-key must be authorized by an OWNER, so a confirmed owner-set is
    // required. `uik` is present here, so `trust` is Verified or Untrusted;
    // Untrusted (anchor stripped) ⇒ no confirmable owner ⇒ refuse the bump.
    let MembershipTrust::Verified(membership) = trust else {
        return false;
    };
    let Some(proof) = uik.rekey_proof.as_ref() else {
        return false; // gen > 0 with no proof = a forged bump
    };
    if proof.generation != uik.generation {
        return false;
    }
    // The signature must commit to the content key actually delivered (a backend
    // can't pair a valid signed generation with a content key it chose).
    if proof.k_commitment.as_slice() != rekey_commitment(content_key).as_slice() {
        return false;
    }
    let Ok(sig) = <[u8; 64]>::try_from(proof.sig.as_slice()) else {
        return false;
    };
    // The signer must be a PUBLISHED member key whose id matches the claimed
    // signer (C.1 anchor) — a backend-minted key isn't in the keyset.
    let signer_pub: Option<[u8; 32]> = uik.creds.values().find_map(|c| {
        let a = <[u8; 32]>::try_from(c.sig_pub.as_slice()).ok()?;
        (crate::identity::derive_id(crate::identity::IdKind::User, &a) == proof.signer_id)
            .then_some(a)
    });
    let Some(signer_pub) = signer_pub else {
        return false;
    };
    // The signer must be an OWNER in the verified owner-set (D).
    let owner = matches!(
        membership.get(&proof.signer_id),
        Some(crate::storage::plaintext::MemberRole::Owner)
    );
    if !owner {
        return false;
    }
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

/// Membership anti-rollback check (delegation-log-review-findings.md C2): the current
/// re-key proof committed a delegation-log PREFIX (`membership_len` events at the current
/// role-epoch, in `(seq, sig)` order, hashed to `membership_hash`). Recompute that
/// commitment over the SERVED log's prefix and compare — a mismatch means the server
/// rolled the log back (e.g. omitted a `remove`) or altered it, so the owner-set
/// can't be trusted. A proof with `membership_len == 0` (empty prefix) commits nothing
/// beyond "the log was empty at re-key". Returns `true` (no rollback detected) when
/// there is no proof. Because the daemon ratchets `generation` (won't adopt a lower
/// one) and this binds the log to that generation, a server can't serve the CURRENT
/// generation with a rolled-back log.
fn membership_prefix_ok(uik: &KeysetUik, vault_id: &str) -> bool {
    let Some(proof) = uik.rekey_proof.as_ref() else {
        return true; // no re-key → nothing committed to roll back
    };
    if proof.generation == 0 {
        return true;
    }
    let role_epoch = resolve_current_root(uik, vault_id)
        .map(|(_, e)| e)
        .unwrap_or(0);
    let mut events: Vec<&DelegationEvent> = uik
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
    crate::identity::membership_commitment(&prefix_sigs).as_slice() == proof.membership_hash.as_slice()
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

/// A view's items as `(ns, name) → digest(normalized body)`
/// ([`crate::storage::item::body_digest`]), captured as a
/// [`ReconcileBase::Since`] base. Digests only: no secret values are copied.
#[derive(Debug, Clone, Default)]
pub struct ViewBase {
    items: BTreeMap<(ItemNs, String), [u8; 32]>,
}

impl ViewBase {
    pub fn of(view: &crate::storage::plaintext::VaultPlaintextView) -> Result<Self> {
        let items = PerItemVault::view_items(view)?
            .into_iter()
            .map(|((ns, name), body)| {
                let d = item_body_digest(ns, &name, &body);
                ((ns, name), d)
            })
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
        self.digest(ns, name) == Some(&item_body_digest(ns, name, body))
    }
}

/// Hex form of a body digest (as [`StoredItem::base`] holds it).
fn digest_hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// What [`PerItemVault::reconcile_from_view`] did: the item ids it wrote; the
/// owner-config changes it set aside instead (the stored row changed since
/// the caller's base), each `(canonical item id, record)` for the caller to
/// report ("changed elsewhere meanwhile; re-run"); and the changes it refused
/// because a row they would write over cannot be read with this vault's key
/// (or no conflict copy may be written), each `(item id, why)`.
#[derive(Debug, Default)]
pub struct Reconciled {
    pub changed: Vec<String>,
    pub set_aside: Vec<(String, String)>,
    pub refused: Vec<(String, String)>,
}

/// Why a change to `record` was not applied over a row this device cannot
/// read (sealed under a key it does not have, or under a retired key that
/// row did not exist under): the row is never written over. The one sentence
/// for every such case, local write or sync.
pub fn unreadable_refusal(record: &str) -> String {
    format!(
        "{}: this item was changed with a vault key this device does not have; your change to it was not applied: run `sc sync` after the vault owner's console finishes, then re-run it",
        record
    )
}

// ── Owner-config records ─────────────────────────────────────────────────────
// Storage unit = edit unit: `policy:` = `{timeout, default}`,
// `policy:category:<tag>` = that tag's Levels, `policy:connection:<id>` =
// that connection's ConnectionPolicy, `store:<id>` = one Store,
// `store_order:` and `audit_retention_days:` one record each. The fold
// reassembles the `VaultAux` fields, so policy evaluation is unchanged.

/// The `policy:` record: the policy's own fields.
#[derive(Serialize, Deserialize)]
struct PolicyRoot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<crate::core::policy::Levels>,
}

/// The owner-config kinds, each reassembled into its `VaultAux` field.
const OWNER_CONFIG_KINDS: [ItemNs; 4] = [
    ItemNs::Policy,
    ItemNs::Store,
    ItemNs::StoreOrder,
    ItemNs::AuditRetentionDays,
];

/// One record of a view: `(ns, name) → body`.
type Record = ((ItemNs, String), serde_json::Value);

fn to_json<T: Serialize>(x: &T) -> Result<serde_json::Value> {
    serde_json::to_value(x).map_err(AppError::from)
}

/// A policy as its records. A present policy always has its `policy:` record
/// (so "set, but empty" stays distinct from "not set"); a category or
/// connection under an empty key has no address and is left out.
fn policy_items(p: &crate::core::policy::Policy) -> Result<Vec<Record>> {
    use crate::storage::item::{POLICY_CATEGORY, POLICY_CONNECTION};
    let root = PolicyRoot {
        timeout: p.timeout,
        default: p.default.clone(),
    };
    let mut out = vec![((ItemNs::Policy, String::new()), to_json(&root)?)];
    for (tag, levels) in p.categories.iter().filter(|(k, _)| !k.is_empty()) {
        out.push((
            (ItemNs::Policy, format!("{}{}", POLICY_CATEGORY, tag)),
            to_json(levels)?,
        ));
    }
    for (id, cp) in p.connections.iter().filter(|(k, _)| !k.is_empty()) {
        out.push((
            (ItemNs::Policy, format!("{}{}", POLICY_CONNECTION, id)),
            to_json(cp)?,
        ));
    }
    Ok(out)
}

/// The stores as their records, one per store (an empty id has no address).
fn store_items(stores: &BTreeMap<String, crate::storage::plaintext::Store>) -> Result<Vec<Record>> {
    stores
        .iter()
        .filter(|(id, _)| !id.is_empty())
        .map(|(id, store)| Ok(((ItemNs::Store, id.clone()), to_json(store)?)))
        .collect()
}

/// A view's owner-config as its native records. An unset policy or
/// retention has none.
fn owner_config_items(aux: &crate::storage::plaintext::VaultAux) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    if let Some(p) = &aux.policy {
        out.extend(policy_items(p)?);
    }
    out.extend(store_items(&aux.stores)?);
    out.push((
        (ItemNs::StoreOrder, String::new()),
        to_json(&aux.store_order)?,
    ));
    if let Some(days) = aux.audit_retention_days {
        out.push((
            (ItemNs::AuditRetentionDays, String::new()),
            serde_json::json!(days),
        ));
    }
    Ok(out)
}

/// LEGACY(aux addressing): the native records an honored legacy
/// `aux:<field>` value becomes, split exactly as a view's are (a null value:
/// none). `Err` when the value does not parse as its field.
fn legacy_field_items(field: &str, v: serde_json::Value) -> Result<Vec<Record>> {
    match field {
        "policy" => match parse_config::<Option<crate::core::policy::Policy>>("aux.policy", v)? {
            Some(p) => policy_items(&p),
            None => Ok(Vec::new()),
        },
        "stores" => {
            match parse_config::<Option<BTreeMap<String, crate::storage::plaintext::Store>>>(
                "aux.stores",
                v,
            )? {
                Some(s) => store_items(&s),
                None => Ok(Vec::new()),
            }
        }
        "store_order" => Ok(parse_config::<Option<Vec<String>>>("aux.store_order", v)?
            .map(|o| ((ItemNs::StoreOrder, String::new()), serde_json::json!(o)))
            .into_iter()
            .collect()),
        "audit_retention_days" => Ok(parse_config::<Option<u32>>("aux.audit_retention_days", v)?
            .map(|d| {
                (
                    (ItemNs::AuditRetentionDays, String::new()),
                    serde_json::json!(d),
                )
            })
            .into_iter()
            .collect()),
        _ => Ok(Vec::new()),
    }
}

/// An owner-config record body as its typed value re-serialized (a null or
/// unknown field drops out), so the same content compares equal whoever
/// wrote it ([`crate::storage::item::normalized_body`]). `None` when it does
/// not parse as the record `(ns, name)`.
pub(crate) fn owner_config_typed(
    ns: ItemNs,
    name: &str,
    body: &serde_json::Value,
) -> Option<serde_json::Value> {
    use crate::storage::item::{POLICY_CATEGORY, POLICY_CONNECTION};
    fn re<T: serde::de::DeserializeOwned + Serialize>(
        body: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        serde_json::from_value::<T>(body.clone())
            .ok()
            .and_then(|t| serde_json::to_value(t).ok())
    }
    match ns {
        ItemNs::Policy if name.is_empty() => re::<PolicyRoot>(body),
        ItemNs::Policy if name.starts_with(POLICY_CATEGORY) => {
            re::<crate::core::policy::Levels>(body)
        }
        ItemNs::Policy if name.starts_with(POLICY_CONNECTION) => {
            re::<crate::core::policy::ConnectionPolicy>(body)
        }
        ItemNs::Store => re::<crate::storage::plaintext::Store>(body),
        ItemNs::StoreOrder => re::<Vec<String>>(body),
        ItemNs::AuditRetentionDays => re::<Option<u32>>(body),
        _ => None,
    }
}

/// The native owner-config namespaces this process reads.
fn is_owner_config_ns(ns: ItemNs) -> bool {
    OWNER_CONFIG_KINDS.contains(&ns)
}

/// Parse an owner-config value, naming it in the error.
fn parse_config<T: serde::de::DeserializeOwned>(what: &str, v: serde_json::Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| AppError::Internal(format!("{} parse: {}", what, e)))
}

/// The owner-config the fold collects: the honored native records per key
/// (`Some(value)` live, `None` a tombstone), and (LEGACY) the honored live
/// legacy `aux:<field>` values. [`Self::apply`] resolves every kind the same
/// way, per key: the legacy row's entries, overlaid by the honored native
/// records (live sets its key, a tombstone removes it). A kind with no entry
/// left reads its default ([`crate::storage::plaintext::VaultAux::initial`]):
/// a tombstone alone never cancels a default. Keys: the policy's own fields
/// (`policy:`), each category tag, each connection id; each store id; the
/// whole store order; the whole retention. (The services union in the fold
/// is the same rule per id.)
#[derive(Default)]
struct OwnerConfigFold {
    native: BTreeMap<(ItemNs, String), Option<serde_json::Value>>,
    legacy: BTreeMap<String, serde_json::Value>,
}

impl OwnerConfigFold {
    /// An honored native record: `Some(body)` live, `None` a tombstone.
    fn native(&mut self, ns: ItemNs, name: String, data: Option<serde_json::Value>) {
        self.native.insert((ns, name), data);
    }

    /// LEGACY(aux addressing): an honored, live `aux:<field>` value.
    fn legacy(&mut self, field: &str, data: serde_json::Value) {
        self.legacy.insert(field.to_string(), data);
    }

    /// Set the owner-config fields of `aux` (which holds the defaults).
    /// Returns the kinds left at their default.
    fn apply(
        self,
        aux: &mut crate::storage::plaintext::VaultAux,
    ) -> Result<std::collections::BTreeSet<ItemNs>> {
        use crate::storage::item::{POLICY_CATEGORY, POLICY_CONNECTION};
        let mut merged: BTreeMap<ItemNs, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        for (field, v) in self.legacy {
            for ((ns, name), body) in legacy_field_items(&field, v)? {
                merged.entry(ns).or_default().insert(name, body);
            }
        }
        for ((ns, name), v) in self.native {
            let entries = merged.entry(ns).or_default();
            match v {
                Some(body) => {
                    entries.insert(name, body);
                }
                None => {
                    entries.remove(&name);
                }
            }
        }
        let mut defaults = std::collections::BTreeSet::new();
        for kind in OWNER_CONFIG_KINDS {
            let mut entries = merged.remove(&kind).unwrap_or_default();
            if entries.is_empty() {
                defaults.insert(kind);
                continue;
            }
            match kind {
                ItemNs::Policy => {
                    let mut p = crate::core::policy::Policy {
                        timeout: None,
                        default: None,
                        categories: Default::default(),
                        connections: Default::default(),
                    };
                    for (name, v) in entries {
                        if name.is_empty() {
                            let root: PolicyRoot = parse_config("policy", v)?;
                            p.timeout = root.timeout;
                            p.default = root.default;
                        } else if let Some(tag) = name.strip_prefix(POLICY_CATEGORY) {
                            p.categories
                                .insert(tag.to_string(), parse_config("policy category", v)?);
                        } else if let Some(id) = name.strip_prefix(POLICY_CONNECTION) {
                            p.connections
                                .insert(id.to_string(), parse_config("policy connection", v)?);
                        }
                    }
                    aux.policy = Some(p);
                }
                ItemNs::Store => {
                    aux.stores = entries
                        .into_iter()
                        .map(|(id, v)| Ok((id, parse_config("store", v)?)))
                        .collect::<Result<_>>()?;
                }
                ItemNs::StoreOrder => {
                    if let Some(v) = entries.remove("") {
                        aux.store_order = parse_config("store_order", v)?;
                    }
                }
                _ => {
                    if let Some(v) = entries.remove("") {
                        aux.audit_retention_days = parse_config("audit_retention_days", v)?;
                    }
                }
            }
        }
        Ok(defaults)
    }
}

/// Whether an owner-config TOMBSTONE counts as honored, by the same trust
/// rules as a live record ([`fold_owner_config_record`]): without a keyset an
/// unsigned one; with one, only an owner's sidecar signature over the
/// tombstone (`status_live = false`).
#[allow(clippy::too_many_arguments)]
fn owner_config_tombstone_honored(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    record_type: &str,
    version: u64,
    trust: &MembershipTrust,
) -> bool {
    match trust {
        MembershipTrust::Untrusted => false,
        MembershipTrust::NoUik => stored_sig.is_none(),
        MembershipTrust::Verified(membership) => {
            let (Some(sig), Some(signer)) = (stored_sig, stored_signer) else {
                return false;
            };
            verify_record_sidecar_sig(
                ct,
                keyset,
                vault_id,
                item_id_raw,
                record_type,
                version,
                false,
                sig,
                signer,
            )
            .is_some_and(|sid| {
                membership.get(&sid) == Some(&crate::storage::plaintext::MemberRole::Owner)
            })
        }
    }
}

/// LEGACY: how the native record at one key reads, for the migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeKey {
    /// No row at the key's address.
    Absent,
    /// A row the fold drops (not honored): a copy replaces it.
    NotHonored,
    /// A row that cannot be opened: nothing is written over it, and the
    /// legacy row it would replace stays.
    Unreadable,
    /// An honored record (live or tombstone) decides the key; `on_cloud`:
    /// the cloud holds this version (the row is clean).
    Decided { on_cloud: bool },
}

/// The daemon's per-item on-disk vault: keyset blob + N sealed item records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerItemVault {
    pub keyset: Keyset,
    /// `item_id (base64url) → StoredItem`. Disjoint items live in disjoint
    /// entries → two writers touching different items never collide.
    #[serde(default)]
    pub items: BTreeMap<String, StoredItem>,
    /// Last cloud `vault_items.seq` this local store has pulled (the incremental
    /// pull cursor — replaces the whole-blob `.blob_version`). `0` = full-resync.
    #[serde(default)]
    pub items_seq: u64,
    /// Last cloud `vault_keys.seq` this local store has pulled (the incremental
    /// keyset pull cursor — the `/keys` analogue of `items_seq`). The keyset now
    /// syncs via `/keys` (one `vault_keys` row per credential), NOT the whole-blob
    /// `/blob` path. `0` = full keyset resync. Pre-launch: serde-default'd so an
    /// existing on-disk `vault.per-item.json` loads without migration.
    #[serde(default)]
    pub keyset_seq: u64,
    /// Pulled replacements not adopted, by item id (the newest each).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub held: BTreeMap<String, HeldRow>,
    /// What each item id addresses, once read with the vault key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub row_kinds: BTreeMap<String, RowKind>,
}

impl PerItemVault {
    /// Fresh per-item vault for first-time setup: a keyset with one credential
    /// and no items.
    pub fn build_initial(
        credential_id: Vec<u8>,
        public_key_x_b64: String,
        public_key_y_b64: String,
        device_name: String,
        prf_salt: Vec<u8>,
        wrapped_key: Vec<u8>,
    ) -> Result<Self> {
        let mut registry = Registry::new();
        let pk = sudp::passkey::WebAuthnPublicKey {
            x: public_key_x_b64,
            y: public_key_y_b64,
            device_name,
        };
        registry
            .insert::<WebAuthn>(&credential_id, &pk)
            .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
        Ok(Self {
            keyset: Keyset {
                version: CURRENT_VERSION,
                registry,
                credentials: vec![SealedCredential {
                    credential_id,
                    prf_salt,
                    wrapped_key,
                    // KCV arrives via /keys sync or the unlock backfill.
                    wc_check: None,
                }],
                keyset_version: 0,
                uik: None,
            },
            items: BTreeMap::new(),
            items_seq: 0,
            keyset_seq: 0,
            held: BTreeMap::new(),
            row_kinds: BTreeMap::new(),
        })
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
    /// from the cloud row (`vault_items.sig`/`signer`, A1.2). Legacy rows pass
    /// `None`/`None` (unsigned; honored additively on NoUik).
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
                base: None,
                upgrade: false,
                generation: None,
                unreadable_confirmed: false,
            },
        );
    }

    /// Drop a stored item outright (local GC of a fully-propagated tombstone).
    pub fn remove_item(&mut self, item_id_b64: &str) -> Option<StoredItem> {
        self.items.remove(item_id_b64)
    }

    /// Adopt one pulled `/keys` row into the keyset: upsert the credential's
    /// WebAuthn registry entry (`x`/`y`/`device_name` — sudp's `WebAuthnPublicKey`
    /// stores `x`/`y` as verbatim strings, exactly what the frontend sent) and the
    /// `SealedCredential` (`credential_id` = decoded `cid`, `prf_salt`/`wrapped_key`
    /// = lenient-decoded data fields, contract §7). `cid_b64` is the row PK
    /// (base64url-nopad WebAuthn credential id). Returns `true` iff the keyset
    /// changed. `x25519_pub` is intentionally NOT stored — sudp's
    /// `WebAuthnPublicKey` has no field for it, and the daemon needs only
    /// `x`/`y` (assertion verify) + `prf_salt`/`wrapped_key` (unwrap `K`).
    ///
    /// Byte-compatibility: `x`/`y` are kept as the exact strings the frontend
    /// wrote (std-base64), and `prf_salt`/`wrapped_key` decode leniently
    /// ([`decode_keys_data_field`]) so a std-base64 field round-trips through
    /// sudp's own STANDARD `wire::b64bytes` codec on write.
    pub fn upsert_key_row(
        &mut self,
        cid_b64: &str,
        x_b64: &str,
        y_b64: &str,
        device_name: &str,
        prf_salt_b64: &str,
        wrapped_key_b64: &str,
        wc_check_b64: Option<&str>,
    ) -> Result<bool> {
        let cid_bytes = decode_credential_id(cid_b64)?;
        let prf_salt = decode_keys_data_field(prf_salt_b64)?;
        let wrapped_key = decode_keys_data_field(wrapped_key_b64)?;
        // Optional KCV (`wc_check`) — carried verbatim from the cloud row so a
        // pull preserves a value another device (or an earlier backfill) wrote.
        let wc_check = wc_check_b64
            .filter(|s| !s.is_empty())
            .map(decode_keys_data_field)
            .transpose()?;

        // Registry pubkey (x/y verbatim strings — sudp keeps them as-is).
        let pk = sudp::passkey::WebAuthnPublicKey {
            x: x_b64.to_string(),
            y: y_b64.to_string(),
            device_name: device_name.to_string(),
        };
        // `insert` overwrites an existing entry — idempotent.
        self.keyset
            .registry
            .insert::<WebAuthn>(&cid_bytes, &pk)
            .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;

        // SealedCredential (upsert by credential_id).
        if let Some(cred) = self
            .keyset
            .credentials
            .iter_mut()
            .find(|c| c.credential_id == cid_bytes)
        {
            cred.prf_salt = prf_salt;
            cred.wrapped_key = wrapped_key;
            // Only adopt a cloud-provided KCV; never clear a locally-backfilled
            // one just because an older row omitted it.
            if wc_check.is_some() {
                cred.wc_check = wc_check;
            }
        } else {
            self.keyset.credentials.push(SealedCredential {
                credential_id: cid_bytes,
                prf_salt,
                wrapped_key,
                wc_check,
            });
        }
        Ok(true)
    }

    /// Whether this vault's keyset is v2 (`custody → UIK → K`). In a v2 keyset,
    /// `SealedCredential.wrapped_key` wraps the UIK root (not `K`), and `K` is
    /// recovered from a per-credential seal ([`Self::uik_cred`]).
    pub fn is_uik(&self) -> bool {
        self.keyset.uik.is_some()
    }

    /// Borrow the v2 UIK material for credential `cid_b64` (v2 keysets). `None`
    /// if this is a v1 keyset or the credential carries no seal.
    pub fn uik_cred(&self, cid_b64: &str) -> Option<&UikCred> {
        self.keyset.uik.as_ref()?.creds.get(cid_b64)
    }

    /// Upsert a credential's v2 UIK material, promoting the keyset to v2 if it
    /// was v1 (owner-driven join / re-key sealed `K` to `enc_pub` via
    /// [`crate::crypto::vault_key::seal_k_to_uik`]). Idempotent by `cid_b64`.
    /// The entry's previous content keys ([`UikCred::prev_content_ct`]) are
    /// kept; [`Self::set_uik_prev_content_ct`] replaces them.
    #[allow(clippy::too_many_arguments)]
    pub fn set_uik_cred(
        &mut self,
        cid_b64: String,
        user_id: String,
        sig_pub: Vec<u8>,
        enc_pub: Vec<u8>,
        k_encapped: Vec<u8>,
        k_ct: Vec<u8>,
        role: crate::storage::plaintext::MemberRole,
        role_sig: Vec<u8>,
    ) {
        let creds = &mut self.keyset.uik.get_or_insert_with(KeysetUik::default).creds;
        let prev_content_ct = creds
            .get(&cid_b64)
            .map(|c| c.prev_content_ct.clone())
            .unwrap_or_default();
        creds.insert(
            cid_b64,
            UikCred {
                user_id,
                sig_pub,
                enc_pub,
                k_encapped,
                k_ct,
                role,
                role_sig,
                prev_content_ct,
            },
        );
    }

    /// Set the previous content keys an entry carries, as sealed (an adopted
    /// row's `uik_prev_content_ct`). A no-op for an entry that is not stored.
    pub fn set_uik_prev_content_ct(&mut self, cid_b64: &str, sealed: Vec<u8>) {
        if let Some(c) = self
            .keyset
            .uik
            .as_mut()
            .and_then(|u| u.creds.get_mut(cid_b64))
        {
            c.prev_content_ct = sealed;
        }
    }

    /// Adopt a pulled `/keys` row's v2 UIK fields (base64, lenient-decoded like
    /// the other keyset data fields). Mirrors [`Self::upsert_key_row`]'s b64-in
    /// contract so the sync layer never handles raw key bytes. Promotes the
    /// keyset to v2. `prev_content_ct_b64`: the row's sealed previous content
    /// keys; a row without them keeps what the entry holds (a re-key replaces
    /// it; the seal binds the generation, so a stale one never opens).
    #[allow(clippy::too_many_arguments)]
    pub fn set_uik_cred_b64(
        &mut self,
        cid_b64: &str,
        user_id: &str,
        sig_pub_b64: &str,
        enc_pub_b64: &str,
        k_encapped_b64: &str,
        k_ct_b64: &str,
        role: crate::storage::plaintext::MemberRole,
        role_sig_b64: &str,
        prev_content_ct_b64: Option<&str>,
    ) -> Result<()> {
        let prev_content_ct = prev_content_ct_b64
            .filter(|s| !s.is_empty())
            .map(decode_keys_data_field)
            .transpose()?;
        let sig_pub = decode_keys_data_field(sig_pub_b64)?;
        let enc_pub = decode_keys_data_field(enc_pub_b64)?;
        let k_encapped = decode_keys_data_field(k_encapped_b64)?;
        let k_ct = decode_keys_data_field(k_ct_b64)?;
        // Role signature is base64 (raw 64-byte Ed25519); an empty string = a
        // legacy row with no grant (decodes to an empty vec → not an owner).
        let role_sig = if role_sig_b64.is_empty() {
            Vec::new()
        } else {
            decode_keys_data_field(role_sig_b64)?
        };
        self.set_uik_cred(
            cid_b64.to_string(),
            user_id.to_string(),
            sig_pub,
            enc_pub,
            k_encapped,
            k_ct,
            role,
            role_sig,
        );
        if let Some(sealed) = prev_content_ct {
            self.set_uik_prev_content_ct(cid_b64, sealed);
        }
        Ok(())
    }

    /// Adopt a credential's WebAuthn pubkey (`x`/`y` verbatim strings + device_name)
    /// into the registry WITHOUT creating a v1 `SealedCredential` row. The v2
    /// (membership) keyset keeps K delivery in `uik.creds`, but the daemon still needs
    /// each credential's ES256 pubkey to VERIFY its approve/unlock assertion
    /// (`credential_lookup` + the `/passkeys` handler read the registry). `uik.creds`
    /// carries only the UIK/K-seal — not the WebAuthn pubkey — so a migrated/born-v2
    /// keyset had no way to verify a tap ("unknown credential"). Mirrors the registry
    /// half of [`Self::upsert_key_row`]; idempotent (insert overwrites).
    pub fn set_registry_pubkey(
        &mut self,
        cid_b64: &str,
        x_b64: &str,
        y_b64: &str,
        device_name: &str,
    ) -> Result<()> {
        let cid_bytes = decode_credential_id(cid_b64)?;
        let pk = sudp::passkey::WebAuthnPublicKey {
            x: x_b64.to_string(),
            y: y_b64.to_string(),
            device_name: device_name.to_string(),
        };
        self.keyset
            .registry
            .insert::<WebAuthn>(&cid_bytes, &pk)
            .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
        Ok(())
    }

    /// Drop every credential seal belonging to member `user_id` (offboarding /
    /// re-key removes the departed member's access; SM §3.2). No-op on a v1
    /// keyset. Returns the number of credential seals removed.
    pub fn remove_uik_member(&mut self, user_id: &str) -> usize {
        let Some(uik) = self.keyset.uik.as_mut() else {
            return 0;
        };
        let before = uik.creds.len();
        uik.creds.retain(|_, c| c.user_id != user_id);
        before - uik.creds.len()
    }

    /// The current keyset row version for `cid_b64` — the analogue of
    /// [`item_version`] for the keyset (there is no per-row version stored today,
    /// so this is a placeholder used only by tests / future CAS). The keyset row
    /// version lives cloud-side (`vault_keys.version`); the daemon adopts a row
    /// whenever its pulled version exceeds what it last saw for that cid, tracked
    /// by the caller (see `sync::pull_keys`), not on-disk.
    pub fn has_credential(&self, cid_b64: &str) -> bool {
        let Ok(cid_bytes) = decode_credential_id(cid_b64) else {
            return false;
        };
        self.keyset
            .credentials
            .iter()
            .any(|c| c.credential_id == cid_bytes)
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
        // This process writes as the device: only what the rule table lets
        // the device write. Never an authorized-agents row in any spelling
        // (native `agent:<ag_id>` or legacy `aux:agent/<ag_id>`, live or
        // tombstone: it holds no UIK, agent authorization is console-written
        // and UIK-signed, §11.1), never a legacy `aux` row except the
        // migration's tombstone, owner-config only on a vault without a keyset.
        let has_keyset = self.keyset.uik.is_some();
        if !crate::storage::item::device_may_write(ns, name, has_keyset, payload.is_tombstone()) {
            return Err(AppError::Internal(format!(
                "refusing to write {} '{}': this process may not write that record",
                ns.as_str(),
                name
            )));
        }
        self.seal_and_insert::<S>(keys, vault_id, ns, name, version, payload)
    }

    /// Plant a row as another writer would (an owner's console, an earlier
    /// version): sealed like [`Self::seal_and_upsert`], without its rule-table
    /// check. Test fixtures only.
    #[cfg(test)]
    pub(crate) fn plant<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        payload: &ItemPayload,
    ) -> Result<String> {
        self.seal_and_insert::<S>(keys, vault_id, ns, name, version, payload)
    }

    fn seal_and_insert<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        payload: &ItemPayload,
    ) -> Result<String> {
        let ctx = ItemCtx::for_item::<S>(keys.id_seed, vault_id, ns, name, version)?;
        let ct = seal_item::<S>(keys.content, &ctx, payload)?;
        let id = ctx.item_id_b64();
        // A local write leaves `synced_version` where it was (the new version
        // is by definition not on the cloud yet) — the row is dirty until pushed.
        // A row that was already dirty keeps the base its first change was made
        // from (the cloud still holds that one or a later one).
        let (synced_version, base) = match self.items.get(&id) {
            Some(s) if s.version > s.synced_version => (s.synced_version, s.base.clone()),
            Some(s) => (s.synced_version, None),
            None => (0, None),
        };
        let tombstone = payload.is_tombstone();
        let generation = self.seal_generation(keys);
        // B2a: seal-level writers land UNSIGNED (sig/signer None) — signing is done
        // by the write ORCHESTRATION (B2b), which knows the principal (the DIK for
        // the daemon's automatic writes). An unsigned owner-config / agent row is
        // honored ONLY on a NoUik (fmt1 personal) vault; a v2 fold drops it.
        self.items.insert(
            id.clone(),
            StoredItem {
                version,
                ct,
                synced_version,
                tombstone,
                sig: None,
                signer: None,
                base,
                upgrade: false,
                generation,
                unreadable_confirmed: false,
            },
        );
        Ok(id)
    }

    /// The keyset generation `keys` seal under: this keyset's current one
    /// when `keys.content` is the key its owner-signed re-key proof commits
    /// to (generation 0, the original key, has no proof; a vault without a
    /// keyset is generation 0). `None`: `keys` are not the current
    /// generation's (an earlier key this session still holds).
    pub fn seal_generation(&self, keys: VaultKeys) -> Option<u64> {
        match self.keyset.uik.as_ref() {
            None => Some(0),
            Some(u) if u.generation == 0 => Some(0),
            Some(u) => u
                .rekey_proof
                .as_ref()
                .filter(|p| {
                    p.generation == u.generation
                        && p.k_commitment.as_slice() == rekey_commitment(keys.content).as_slice()
                })
                .map(|_| u.generation),
        }
    }

    /// The keyset generation a row sealed now must carry (`None` without a
    /// keyset: unchecked).
    pub fn keyset_generation(&self) -> Option<u64> {
        self.keyset.uik.as_ref().map(|u| u.generation)
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
        Ok(Some(unseal_item_keys::<S>(keys, &id, &ctx, &stored.ct)?.0))
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
    /// offline peer will CAS against (the enroll case passes `0`). Every
    /// native secret, connection, in-flight connect and service becomes its own
    /// item, and (a vault without a keyset) the owner-config its native records
    /// ([`owner_config_items`]); an unset policy or retention writes nothing.
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
        // Owner-config → its native records (`policy:*`, `store:<id>`,
        // `store_order:`, `audit_retention_days:`), where the device may write
        // them (a vault without a keyset). Agents are NEVER written by the
        // daemon (console-written, UIK-signed only; §11.1).
        let has_keyset = self.keyset.uik.is_some();
        for ((ns, name), body) in owner_config_items(&view.aux)? {
            if !crate::storage::item::device_may_write(ns, &name, has_keyset, false) {
                continue;
            }
            self.seal_and_upsert::<S>(
                keys,
                vault_id,
                ns,
                &name,
                1,
                &ItemPayload::live(ns, name.clone(), body),
            )?;
        }
        for (id, body) in Self::service_bodies(&view.aux)? {
            self.seal_and_upsert::<S>(
                keys,
                vault_id,
                ItemNs::Service,
                &id,
                1,
                &ItemPayload::live(ItemNs::Service, id.clone(), body),
            )?;
        }
        Ok(())
    }

    /// The native `service` items a view wants, `id → body`: every entry of
    /// `aux.services` (legacy entries included), each its own item, always in
    /// the object form `{service, policy?, source?}`
    /// ([`crate::storage::item::normalized_body`]: a plain-string entry is
    /// `{service: <text>}`). A conflict copy is a record of its own name.
    fn service_bodies(
        aux: &crate::storage::plaintext::VaultAux,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        aux.services
            .iter()
            .map(|(id, e)| {
                let body = serde_json::to_value(e).map_err(AppError::from)?;
                Ok((id.clone(), normalized_body(ItemNs::Service, id, &body)))
            })
            .collect()
    }

    /// Keep `ours` as its keep-both conflict copy, an ordinary record
    /// ([`crate::storage::item::conflict_copy_slot`] against this store):
    /// written dirty (the next push sends it), or already here. Returns the
    /// id written, if any; `Err` when no copy may be written (a row that
    /// cannot be read, or the last copy level taken).
    pub(crate) fn keep_conflict_copy<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ours: &ItemPayload,
    ) -> Result<Option<String>> {
        use crate::storage::item::{conflict_copy_slot, row_at, CopySlot};
        let slot = conflict_copy_slot::<S>(keys.id_seed, ours, |wire| {
            row_at::<S>(
                keys,
                vault_id,
                wire,
                self.items.get(wire).map(|s| (s.version, s.ct.as_slice())),
            )
        })?;
        match slot {
            CopySlot::Same { .. } => Ok(None),
            CopySlot::Write { payload, .. } => {
                let (id, _) =
                    self.seal_and_bump::<S>(keys, vault_id, payload.ns, &payload.name, &payload)?;
                Ok(Some(id))
            }
        }
    }

    /// Whether the row at `(ns, name)` may be written over: absent, or one
    /// this key opens. A row that cannot be read is never written over.
    fn writable<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
    ) -> Result<bool> {
        let wire = wire_id_for::<S>(keys.id_seed, ns, name)?;
        Ok(match self.items.get(&wire) {
            None => true,
            Some(s) => {
                s.unreadable_confirmed
                    || open_wire_item::<S>(keys, vault_id, &wire, s.version, &s.ct).is_ok()
            }
        })
    }

    /// After a keyset refresh, with `keys` of the keyset's current
    /// generation: mark each clean row that opens under none of them
    /// ([`StoredItem::unreadable_confirmed`]) and unmark one that opens.
    /// Keys of another generation (a session from before the key changed)
    /// mark nothing. Returns whether a mark changed.
    pub fn confirm_unreadable<S: PrimitiveSuite>(&mut self, keys: VaultKeys, vault_id: &str) -> bool {
        let current = self.keyset_generation().unwrap_or(0);
        if self.seal_generation(keys) != Some(current) {
            return false;
        }
        let marks: Vec<(String, bool)> = self
            .items
            .iter()
            .filter(|(_, s)| s.version <= s.synced_version)
            .map(|(id, s)| {
                let unreadable = open_wire_item::<S>(keys, vault_id, id, s.version, &s.ct).is_err();
                (id.clone(), unreadable)
            })
            .collect();
        let mut changed = false;
        for (id, unreadable) in marks {
            if let Some(s) = self.items.get_mut(&id) {
                if s.unreadable_confirmed != unreadable {
                    s.unreadable_confirmed = unreadable;
                    changed = true;
                }
            }
        }
        changed
    }

    /// A view's reconcilable items as `(ns, name) → body`: every native secret,
    /// connection, in-flight connect and service (normalized), and the
    /// owner-config records ([`owner_config_items`]). Shared by [`Self::reconcile_from_view`]
    /// and [`ViewBase::of`] so a base and a view are always compared on the
    /// same representation.
    fn view_items(
        view: &crate::storage::plaintext::VaultPlaintextView,
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
        for (id, body) in Self::service_bodies(&view.aux)? {
            out.insert((ItemNs::Service, id), body);
        }
        for (key, body) in owner_config_items(&view.aux)? {
            out.insert(key, body);
        }
        Ok(out)
    }

    /// Reconcile the item rows toward a freshly-decrypted [`VaultPlaintextView`]
    /// (the post-connect / post-write state), applying ONLY the changes with a
    /// monotonic version bump so the sync layer's per-item CAS sees a strictly
    /// higher version (contract §4/§6). Unlike [`seed_items_from_view`] (which
    /// resets every version to 1), this:
    ///   - upserts an item whose sealed value changed, at `current + 1`: a
    ///     secret, connection, in-flight connect or service, and (a vault
    ///     without a keyset) an owner-config record;
    ///   - writes a `tombstone` (also bumped) for one the view no longer has
    ///     (e.g. a completed connect MOVEs its `connecting` entry away →
    ///     tombstone the old row; a key only the legacy row held gets a native
    ///     tombstone, so the legacy entry does not come back).
    ///
    /// This is the daemon-side, single-writer equivalent of "PUT the changed
    /// items" (contract §5 `writeVault` diff). What counts as changed is
    /// relative to the caller's [`ReconcileBase`]: only a view with a known base
    /// can tell "the caller changed/deleted it" from "someone else changed it
    /// since". A same-item conflict resolves per the record's
    /// [`Conflict`] policy ([`crate::storage::item::ITEM_RULES`]). Returns the
    /// ids written and the owner-config changes set aside ([`Reconciled`]).
    pub fn reconcile_from_view<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
        base: ReconcileBase<'_>,
    ) -> Result<Reconciled> {
        let mut out = Reconciled::default();
        // Only what the device may write (the rule table): data records on
        // every keyset; owner-config only on a vault without a keyset. On a
        // keyset owner-config is honored only owner-signed, and this process
        // holds no UIK: an unsigned copy would be dropped by every fold, and
        // re-writing it could clobber an owner-signed row (or replace a dropped
        // one with the safe default). Agents are never emitted at all.
        let has_keyset = self.keyset.uik.is_some();
        let desired: BTreeMap<(ItemNs, String), serde_json::Value> = Self::view_items(view)?
            .into_iter()
            .filter(|((ns, name), _)| {
                crate::storage::item::device_may_write(*ns, name, has_keyset, false)
            })
            .collect();
        // The base each write is made from, recorded on a keep-both row that
        // goes dirty (see [`StoredItem::base`]). `OwnFold`: our own fold now.
        let (now, default_kinds) = self.fold_view_and_defaults::<S>(keys, vault_id)?;
        let own_base = match base {
            ReconcileBase::OwnFold => Some(ViewBase::of(&now)?),
            ReconcileBase::Since(_) => None,
        };
        drop(now);
        let base_digests: &ViewBase = match (base, own_base.as_ref()) {
            (ReconcileBase::Since(b), _) => b,
            (ReconcileBase::OwnFold, Some(b)) => b,
            (ReconcileBase::OwnFold, None) => unreachable!("own base computed above"),
        };

        // An owner-config kind that reads its default is written WHOLE when
        // the caller changes it: once any of its entries is stored, the
        // default no longer applies to the rest.
        let whole_kinds: std::collections::BTreeSet<ItemNs> = match base {
            ReconcileBase::Since(b) => desired
                .iter()
                .filter(|((ns, name), body)| {
                    is_owner_config_ns(*ns)
                        && default_kinds.contains(ns)
                        && !b.unchanged(*ns, name, body)
                })
                .map(|((ns, _), _)| *ns)
                .collect(),
            ReconcileBase::OwnFold => Default::default(),
        };

        // Upsert every desired item the caller changed (vs its base) whose sealed
        // body differs from what we hold (compared normalized).
        for ((ns, name), body) in &desired {
            if let ReconcileBase::Since(b) = base {
                if b.unchanged(*ns, name, body) && !whole_kinds.contains(ns) {
                    continue;
                }
            }
            // `open_item` is unconverted (single-key); id_seed == content here so
            // the read is byte-identical either way. A row this key cannot
            // open is never written over: the change is refused and reported.
            let wire = wire_id_for::<S>(keys.id_seed, *ns, name)?;
            let existing = match self.open_item::<S>(keys, vault_id, *ns, name) {
                Ok(p) => p,
                // Confirmed after a keyset refresh to open under no key a
                // current member holds: this change may go over it.
                Err(_) if self.items.get(&wire).is_some_and(|s| s.unreadable_confirmed) => None,
                Err(_) => {
                    let label =
                        crate::storage::item::record_label(&ItemPayload::live(*ns, name.clone(), body.clone()));
                    out.refused.push((wire, unreadable_refusal(&label)));
                    continue;
                }
            };
            let existing_live = existing.as_ref().filter(|p| !p.is_tombstone());
            let wanted = item_body_digest(*ns, name, body);
            if existing_live.is_some_and(|p| item_body_digest(*ns, name, &p.body) == wanted) {
                continue;
            }
            let payload = ItemPayload::live(*ns, name.clone(), body.clone());
            let policy = crate::storage::item::conflict_policy(*ns, name);
            let row = self
                .items
                .get(&wire)
                .map(|s| (s.version, s.version > s.synced_version));
            // §4 same-item conflict: the caller changed it AND the stored row no
            // longer matches the base (a pull changed or deleted it meanwhile,
            // e.g. during a connect's token exchange). Their body equal to the
            // base (normalized) is no conflict: ours applies.
            if let (ReconcileBase::Since(b), Some(_)) = (base, row) {
                let theirs = existing_live.map(|p| item_body_digest(*ns, name, &p.body));
                if theirs.as_ref() != b.digest(*ns, name) {
                    match policy {
                        // THEIRS stays at the canonical id; OURS becomes its
                        // conflict copy, a dirty record of its own name
                        // (console parity); their delete stands.
                        Conflict::KeepBoth => {
                            match self.keep_conflict_copy::<S>(keys, vault_id, &payload) {
                                Ok(Some(copy)) => out.changed.push(copy),
                                Ok(None) => {}
                                Err(e) => out.refused.push((wire.clone(), e.to_string())),
                            }
                            continue;
                        }
                        // Never overwritten: ours is not written and is
                        // reported for a re-run.
                        Conflict::OwnerConfig => {
                            out.set_aside
                                .push((wire.clone(), crate::storage::item::record_label(&payload)));
                            continue;
                        }
                        Conflict::TakeWriter => {}
                    }
                }
            }
            let was_clean = row.is_none_or(|(_, dirty)| !dirty);
            let (id, _v) = self.seal_and_bump::<S>(keys, vault_id, *ns, name, &payload)?;
            if was_clean && policy == Conflict::KeepBoth {
                if let Some(s) = self.items.get_mut(&id) {
                    s.base = base_digests.digest(*ns, name).map(digest_hex);
                }
            }
            out.changed.push(id);
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
        let mut drop_keys: Vec<(ItemNs, String)> = Vec::new();
        drop_keys.extend(mine.native_secrets.keys().map(|n| (ItemNs::Secret, n.clone())));
        drop_keys.extend(mine.aux.connections.keys().map(|n| (ItemNs::Connection, n.clone())));
        drop_keys.extend(mine.aux.connecting.keys().map(|n| (ItemNs::Connecting, n.clone())));
        // A service the caller dropped (a native item, or a legacy-only entry
        // of the `services` record) gets a native tombstone, which hides the
        // legacy entry of its id.
        drop_keys.extend(mine.aux.services.keys().map(|n| (ItemNs::Service, n.clone())));
        // Owner-config records the caller dropped (a policy category or
        // connection entry, a store, the retention), where the device may
        // write them.
        drop_keys.extend(
            owner_config_items(&mine.aux)?
                .into_iter()
                .map(|(k, _)| k)
                .filter(|(ns, name)| {
                    crate::storage::item::device_may_write(*ns, name, has_keyset, true)
                }),
        );
        for (ns, name) in drop_keys {
            if !removed(ns, &name) {
                continue;
            }
            // A key read from a legacy row may have a native row this key
            // cannot open: never written over.
            if !self.writable::<S>(keys, vault_id, ns, &name)? {
                let label =
                    crate::storage::item::record_label(&ItemPayload::tombstone(ns, name.clone()));
                out.refused.push((
                    wire_id_for::<S>(keys.id_seed, ns, &name)?,
                    unreadable_refusal(&label),
                ));
                continue;
            }
            let (iid, _v) = self.seal_and_bump::<S>(
                keys,
                vault_id,
                ns,
                &name,
                &ItemPayload::tombstone(ns, name.clone()),
            )?;
            out.changed.push(iid);
        }
        // Agent rows are never written here (no live upsert, no tombstone): a
        // revoke is the console deleting the UIK-signed row.
        Ok(out)
    }

    /// Resolve the KEYSET's [`MembershipTrust`] — the owner-authority anchor state
    /// (design/identity-uik-aik.md §4.3 RESOLVED). This REPLACES the old in-vault
    /// `resolve_verified_membership`, which trusted a membership by single-version
    /// self-consistency and so let any member self-sign `{me: owner}` and
    /// self-promote (finding #1). Role is now rooted at genesis, and the return
    /// distinguishes the three trust states so a missing anchor can NEVER
    /// fail-open to integrity-only on a v2 keyset:
    ///
    /// - `keyset.uik == None` ⇒ [`MembershipTrust::NoUik`] (legacy v1 — integrity-only,
    ///   single-person vaults with no member keys to sign anything).
    /// - `uik` present but `creator_sig_pub` is NOT a valid 32-byte key AND the
    ///   keyset already carries credentials ⇒ [`MembershipTrust::Untrusted`]. This is
    ///   the server-strippable state (`adopt_creator_pin` only pins non-empty), so
    ///   it FAILS CLOSED — callers drop ALL owner-config, not just unsigned.
    /// - `uik` present with a valid 32-byte `creator_pub` ⇒ [`MembershipTrust::Verified`]:
    ///   for each keyset cred, verify its `role_sig` over
    ///   [`crate::identity::role_grant_input`]`(vault_id, user_id, role, generation)`
    ///   under `creator_pub` at the CURRENT `uik.generation` (F3-b generation-
    ///   binding: the grant is bound to the owner-signed DP-S1 role epoch, so a
    ///   stale grant signed at an OLD generation fails here after a re-key bump and
    ///   the cred drops from the owner-set — a colluding server can't replay a
    ///   demoted/offboarded person's grant). A cred that verifies is inserted at its
    ///   `role`; one that fails (empty/forged sig, a role the creator never signed,
    ///   or a grant signed at a different generation) is dropped — it is NOT an
    ///   owner. The creator's OWN cred is included by the SAME rule
    ///   (its role=Owner, self-signed under `creator_pub`); no special case. An
    ///   empty owner-set is a valid `Verified` result (all signed owner-config
    ///   drops). A `uik` with no anchor AND no creds yet is a fresh bootstrap with
    ///   nothing to authorize — `Verified(∅)` (every owner-config and agent row drops).
    fn resolve_membership_trust(&self, vault_id: &str) -> MembershipTrust {
        let Some(uik) = self.keyset.uik.as_ref() else {
            return MembershipTrust::NoUik; // legacy v1 — integrity-only (additive)
        };
        // Resolve the CURRENT root by walking the succession chain from the pinned
        // GENESIS anchor. `None` = the genesis anchor is absent / not 32 bytes: a v2
        // keyset that already carries creds but has NO resolvable root is the
        // server-strippable state → FAIL CLOSED (`Untrusted`); an anchor-less keyset
        // with NO creds is a fresh bootstrap: nothing to authorize → empty Verified
        // set (every owner-config / agent row drops, signed or not).
        if resolve_current_root(uik, vault_id).is_none() {
            return if uik.creds.is_empty() {
                MembershipTrust::Verified(BTreeMap::new())
            } else {
                MembershipTrust::Untrusted
            };
        }
        // Membership anti-rollback (C2): the current re-key proof committed the
        // delegation-log prefix — if the SERVED log doesn't match it, the server
        // rolled the membership back (e.g. omitted a `remove`); the owner-set can't be
        // trusted → FAIL CLOSED. (Owner-signed + generation-ratcheted, so the server
        // can't forge a fresh commitment or serve the current generation with a
        // tampered log.)
        if !membership_prefix_ok(uik, vault_id) {
            return MembershipTrust::Untrusted;
        }
        MembershipTrust::Verified(self.fold_owner_set(vault_id))
    }

    /// §15 leg-B: is `us_id` a VERIFIED member of this vault right now? Answers the
    /// "did the owner offboard me?" question SAFELY, so a caller can drop a lost vault:
    /// - `Some(true)`  = the owner-verified fold seats this id (owner or member).
    /// - `Some(false)` = the fold is TRUSTED (`Verified`) + non-empty and does NOT seat
    ///   this id → an owner-signed removal (or never-granted). The caller MAY drop.
    /// - `None`        = can't decide safely: legacy/`NoUik`, no resolvable root, or a
    ///   rolled-back/`Untrusted` log (a dropped-grant rollback fails `membership_prefix_ok`
    ///   → `Untrusted` here, so it can never masquerade as a removal). The caller PARKS.
    /// Trust comes from [`resolve_membership_trust`], which fails closed — so this never
    /// reports a false removal from a tampered or partial triple.
    pub(crate) fn verified_membership(&self, vault_id: &str, us_id: &str) -> Option<bool> {
        match self.resolve_membership_trust(vault_id) {
            MembershipTrust::Verified(map) if !map.is_empty() => Some(map.contains_key(us_id)),
            _ => None, // NoUik / Untrusted / empty bootstrap → park, never wipe
        }
    }

    /// §15 leg A: verify an owner-signed vault-DELETE tombstone. Returns true iff
    /// `signer` is an OWNER in this vault's fold-owner set AND `sig_b64` is a valid
    /// Ed25519 signature over `identity::vault_tombstone_input(vault_id)` under the
    /// signer's SELF-CERTIFYING pubkey (looked up from the keyset creds; its id must
    /// derive from it). A fmt1/NoUik vault has no fold-owner set → false (the caller
    /// falls back to the legacy unsigned drop under the dual-path flag).
    pub(crate) fn tombstone_verified(&self, vault_id: &str, signer: &str, sig_b64: &str) -> bool {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use crate::storage::plaintext::MemberRole;
        // Authority: only an OWNER may tombstone the vault.
        if self.fold_owner_set(vault_id).get(signer) != Some(&MemberRole::Owner) {
            return false;
        }
        // The signer's verifying key rides the keyset creds; self-certify it (its id
        // must derive from the pubkey) so a poisoned cred row can't seat a phantom key.
        let Some(uik) = self.keyset.uik.as_ref() else {
            return false;
        };
        let Some(cred) = uik.creds.values().find(|c| c.user_id == signer) else {
            return false;
        };
        let Ok(pub32) = <[u8; 32]>::try_from(cred.sig_pub.as_slice()) else {
            return false;
        };
        if crate::identity::derive_id(crate::identity::IdKind::User, &pub32) != signer {
            return false;
        }
        let Some(sig) = STANDARD
            .decode(sig_b64)
            .ok()
            .and_then(|v| <[u8; 64]>::try_from(v.as_slice()).ok())
        else {
            return false;
        };
        crate::identity::verify(&pub32, &crate::identity::vault_tombstone_input(vault_id), &sig)
    }

    /// §15 leg A: is this a legacy fmt1 / NoUik vault (no signed owner set)? Such a vault
    /// has no fold-owner to verify a tombstone against, so the require-signed gate cannot
    /// apply — the caller keeps the legacy UNSIGNED drop for it (fmt1 is being retired; a
    /// fmt2 vault's owner signs the tombstone). Never blocks a legacy delete from propagating.
    pub(crate) fn is_legacy_nouik(&self, vault_id: &str) -> bool {
        matches!(self.resolve_membership_trust(vault_id), MembershipTrust::NoUik)
    }

    /// Compute the current derived OWNER-SET (`user_id → role`) = the FOLD of the
    /// root-signed CHECKPOINT (each cred's `role_sig` @ the current `role_epoch`)
    /// followed by the append-only `delegation_log` (design/identity-uik-aik.md
    /// §4.3, delegation-log-impl-spec.md §0). The checkpoint is verified under the
    /// SUCCESSION-RESOLVED current root (not the raw genesis anchor); each log event
    /// is honored iff its `granter_id` is an Owner in the fold SO FAR (issuance-time
    /// authority) with a valid signature, and a `remove` drops ONLY its subject
    /// (NON-CASCADE). A last-owner removal/demote is ignored (defense in depth; also
    /// gated at write time). Returns an EMPTY map when there is no UIK layer or no
    /// resolvable root (no confirmable owner → callers fail closed).
    pub(crate) fn fold_owner_set(
        &self,
        vault_id: &str,
    ) -> BTreeMap<String, crate::storage::plaintext::MemberRole> {
        use crate::storage::plaintext::MemberRole;
        let mut map: BTreeMap<String, MemberRole> = BTreeMap::new();
        let Some(uik) = self.keyset.uik.as_ref() else {
            return map;
        };
        let Some((root_pub, role_epoch)) = resolve_current_root(uik, vault_id) else {
            return map; // no resolvable root → no confirmable owner
        };
        let root_id = crate::identity::derive_id(crate::identity::IdKind::User, &root_pub);
        // Genesis: the current root is an owner (TOFU-pinned anchor + succession).
        map.insert(root_id.clone(), MemberRole::Owner);
        // Checkpoint: root-signed grants @ the current (succession-derived) role_epoch
        // (depth-1 → a fresh daemon verifies with no history).
        for cred in uik.creds.values() {
            // The root's ownership is the genesis pin — a checkpoint grant must NEVER
            // overwrite/demote it (defense in depth for "the owner-set always contains
            // the root as Owner").
            if cred.user_id == root_id {
                continue;
            }
            // Self-certifying: the cred's `user_id` label MUST derive from its
            // `sig_pub`, so a spoofed `(user_id, sig_pub)` pair can't seat a phantom
            // owner keyed on a label the server chose.
            let Ok(cred_pub) = <[u8; 32]>::try_from(cred.sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &cred_pub) != cred.user_id
            {
                continue;
            }
            let Ok(sig) = <[u8; 64]>::try_from(cred.role_sig.as_slice()) else {
                continue; // no / malformed grant → not in the checkpoint
            };
            let input = crate::identity::role_grant_input(
                vault_id,
                &cred.user_id,
                role_str(cred.role),
                role_epoch,
            );
            if crate::identity::verify(&root_pub, &input, &sig) {
                map.insert(cred.user_id.clone(), cred.role);
            }
        }
        // Delegation log: apply in a DETERMINISTIC total order; only events on the
        // current role_epoch (a pre-compaction replay carries an older epoch → ignored).
        let mut events: Vec<&DelegationEvent> = uik
            .delegation_log
            .iter()
            .filter(|e| e.role_epoch == role_epoch)
            .collect();
        // Sort by (seq, sig) — NOT seq alone: a stable sort by seq leaves same-seq
        // order at the mercy of storage/Vec order, which the server controls, so the
        // three implementations (daemon / backend / browser) could pick different
        // same-seq winners. Breaking the tie on the signature bytes makes the winner
        // deterministic and server-independent.
        events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
        let mut last_seq: Option<u64> = None;
        for e in events {
            if matches!(last_seq, Some(ls) if e.seq <= ls) {
                continue; // a seq already CONSUMED by a validated event
            }
            // Issuance-time authority: the granter must be an Owner in the fold SO FAR.
            // A junk / non-owner event must NOT consume the seq slot (else it could
            // suppress a legitimate same-seq event — the dup guard would then drop the
            // real one), so `last_seq` advances ONLY AFTER full validation below.
            if map.get(&e.granter_id) != Some(&MemberRole::Owner) {
                continue;
            }
            // The granter's verifying key rides INLINE and is SELF-CERTIFYING: it must
            // derive to `granter_id`. This makes the event immune to a poisoned cred row
            // (which lies about `sig_pub`) AND keeps it verifiable after the granter's
            // own cred row is deleted at offboard (so NON-CASCADE survives eviction).
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
            // VALIDATED (owner + self-certifying key + signature): now consume the seq
            // slot, so a later same-seq event is a dup (equivocation) and is dropped.
            last_seq = Some(e.seq);
            // The creator (root) is seated at the base for ISSUANCE-TIME authority (so
            // grants they signed verify), but is a NORMAL owner in the FINAL set: any
            // owner (incl. the creator themselves) can be removed/demoted via the log
            // (creator-offboard is just a `remove`). The ONLY invariant is the
            // owner-set is never EMPTIED — a remove/demote that would drop the LAST
            // owner is ignored (last-owner guard; also enforced at write time in the
            // console). This replaces the old "root is permanently immune" rule.
            let owner_count = |m: &BTreeMap<String, MemberRole>| {
                m.values().filter(|r| **r == MemberRole::Owner).count()
            };
            match e.op.as_str() {
                "remove" => {
                    if map.get(&e.subject_id) == Some(&MemberRole::Owner) && owner_count(&map) <= 1
                    {
                        continue; // last-owner guard: never empty the owner-set
                    }
                    map.remove(&e.subject_id); // NON-CASCADE: only the subject
                }
                "set" => {
                    // A demote (owner → member) of the last owner would empty it → skip.
                    if e.role != MemberRole::Owner
                        && map.get(&e.subject_id) == Some(&MemberRole::Owner)
                        && owner_count(&map) <= 1
                    {
                        continue;
                    }
                    map.insert(e.subject_id.clone(), e.role);
                }
                _ => {} // unknown op → ignore
            }
        }
        map
    }

    /// Fold all **live** items into a [`VaultPlaintextView`] — the per-item
    /// equivalent of today's whole-blob decrypt (`metadata.rs`
    /// `decrypt_vault_view*`, priority 3). Unseals every stored record under
    /// `K`, drops tombstones, and rebuilds the in-memory view by grouping on
    /// `ns` (contract §2). The item id is an HMAC so `(ns, name)` is unknown
    /// from the key alone — the sealed payload carries them; we rebuild the
    /// `SealCtx` from the id bytes (decoded from the base64url row key) + the
    /// stored `version`, so a tampered `version` fails the AEAD.
    ///
    /// This is the LIVE per-item read path: `metadata.rs`'s
    /// `decrypt_vault_view_peritem*` helpers call it, and `open_view_for_grant`
    /// routes any vault with a `vault.per-item.json` through here. The whole-blob
    /// `ciphertext` open is now the FALLBACK for vaults not yet cut over
    /// (daemon-side Enroll/Write that only re-sealed `vault.dat`).
    pub fn fold_view<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
    ) -> Result<crate::storage::plaintext::VaultPlaintextView> {
        Ok(self.fold_view_and_defaults::<S>(keys, vault_id)?.0)
    }

    /// [`Self::fold_view`], and the owner-config kinds that read their
    /// default ([`OwnerConfigFold::apply`]).
    fn fold_view_and_defaults<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
    ) -> Result<(
        crate::storage::plaintext::VaultPlaintextView,
        std::collections::BTreeSet<ItemNs>,
    )> {
        use crate::storage::item::rule;
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};

        // Start from the fresh-vault defaults. Every record is read per its
        // rule in the table (`ITEM_RULES`, its `read`): data records fill
        // their maps; owner-config is collected per kind and applied after the
        // loop (the id map iterates in hash order), native before legacy.
        let mut aux = VaultAux::initial();
        let mut native_secrets: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut native_secret_notes: BTreeMap<String, String> = BTreeMap::new();
        let mut config = OwnerConfigFold::default();
        let mut legacy_services: Option<serde_json::Value> = None;
        // Native `service` items (one per service id): live entries, and the
        // ids a tombstone removes. Overlaid on the legacy `services` record
        // after the loop: a native item wins for its id.
        let mut native_services: BTreeMap<String, crate::service::source::StoredService> =
            BTreeMap::new();
        let mut native_removed: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();

        // D: the verified OWNER-SET authorizes owner-config (owner-only). It is
        // now derived from the KEYSET (creator-rooted role grants), NOT from an
        // in-vault membership — that in-vault path (finding #1) is removed.
        // The three-state [`MembershipTrust`] keeps "legacy v1" (integrity-only,
        // additive) distinct from "v2 anchor stripped" (fail closed) so a missing
        // anchor on a v2 keyset can never fail-open to integrity-only.
        let trust = self.resolve_membership_trust(vault_id);

        // DP-S1: a re-keyed vault (generation > 0) is trusted only if the bump is
        // owner-signed and bound to THIS content key — else refuse to fold it (a
        // backend can't forge a re-key to force an unlock storm / swap content).
        if !verify_rekey_proof(&self.keyset, &trust, vault_id, keys.content) {
            return Err(AppError::Unauthorized(
                "vault re-key generation is unverified (missing/invalid owner signature)".into(),
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
                let (payload, _) = unseal_item_keys::<S>(keys, id_b64, &ctx, &stored.ct)?;
                // A record without a rule is not read: the retired `stores:` /
                // `services:` / `members`, a legacy `aux:agent/<id>` (only
                // native, UIK-signed agent rows authorize), an unknown `aux` or
                // `policy` name (fail closed).
                let Some(r) = rule(payload.ns, &payload.name) else {
                    return Ok(());
                };
                // One address per record: a row counts only at the derived id
                // of its own (ns, name) (an agent's: its ag_id). A conflict
                // copy is a record of its own name (`"<name> (conflict
                // copy)"`) at that name's id, read like any other.
                if wire_id_for::<S>(keys.id_seed, payload.ns, &payload.name)? != *id_b64 {
                    tracing::warn!(vault = %vault_id, ns = %payload.ns.as_str(), wire = %id_b64, "fold: dropping a record that is not at its own id");
                    return Ok(());
                }
                let sig_type = r.signature_type(&payload.name).map(str::to_string);
                let owner_config = |body: serde_json::Value| {
                    fold_owner_config_record(
                        stored.sig.as_deref(),
                        stored.signer.as_deref(),
                        &stored.ct,
                        &self.keyset,
                        vault_id,
                        &raw,
                        payload.ns,
                        sig_type.as_deref().unwrap_or(""),
                        stored.version,
                        body,
                        &trust,
                    )
                };
                let name = payload.name.clone();
                let live = payload.status == crate::storage::item::ItemStatus::Live;
                match r.read {
                    // A data record like a connection (no signature), live or
                    // tombstone: one item per service id.
                    Read::DerivedIdOnlyUnionLegacy => {
                        if !live {
                            native_removed.insert(name);
                        } else {
                            let entry = serde_json::from_value(payload.body).map_err(|e| {
                                AppError::Internal(format!("service '{}' parse: {}", name, e))
                            })?;
                            native_services.insert(name, entry);
                        }
                    }
                    // Native owner-config; with a keyset only owner-signed
                    // (sidecar type = the namespace). A tombstone counts too:
                    // it removes its key, over the legacy row.
                    Read::OwnerSignedWithKeysetNativeWins => {
                        let ty = sig_type.as_deref().unwrap_or("");
                        if !live {
                            if owner_config_tombstone_honored(
                                stored.sig.as_deref(),
                                stored.signer.as_deref(),
                                &stored.ct,
                                &self.keyset,
                                vault_id,
                                &raw,
                                ty,
                                stored.version,
                                &trust,
                            ) {
                                config.native(payload.ns, name, None);
                            }
                            return Ok(());
                        }
                        match owner_config(payload.body) {
                            Some(data) => config.native(payload.ns, name, Some(data)),
                            None => {
                                tracing::warn!(vault = %vault_id, ns = %payload.ns.as_str(), "fold: dropping owner-config — unauthorized/invalid owner signature")
                            }
                        }
                    }
                    _ if !live => {}
                    Read::All => match payload.ns {
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
                        _ => {}
                    },
                    // T2 (design/agent-authz-cleartext-cutover.md): a native
                    // agent item lives at its own cleartext id (wire id ==
                    // ag_id == name, checked above), so the backend ownership
                    // gate on the ag_id cannot be dodged.
                    Read::SignerAuthorizedAndWireIdMatches => {
                        let Some(data) = fold_agent_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
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
                    // LEGACY(aux addressing): `aux:<field>`, whose entries
                    // apply to the keys without an honored native record
                    // ([`OwnerConfigFold::apply`]). C.3: a bad / missing
                    // signature drops it (→ safe default).
                    Read::LegacyWhenNoHonoredNative => {
                        if let Some(data) = owner_config(payload.body) {
                            config.legacy(&name, data);
                        }
                    }
                    // LEGACY(services row): unioned under the native items.
                    Read::LegacyUnionNativeWins => {
                        legacy_services = owner_config(payload.body);
                    }
                    Read::ConsoleOnly => {}
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

        // LEGACY(services row): the services are the union of the legacy
        // `services` record (owner-config, read only; moved to native items by
        // the migration) and the native `service` items; a native tombstone
        // hides the legacy entry of its id, a native live item replaces it.
        // A legacy record that does not parse is skipped like any unreadable
        // record. Drop the legacy half with the legacy record.
        if let Some(v) = legacy_services {
            match serde_json::from_value(v) {
                Ok(services) => aux.services = services,
                Err(e) => {
                    unreadable += 1;
                    tracing::warn!(vault = %vault_id, "fold: skipping the legacy services record: {}", e);
                }
            }
        }
        for id in native_removed {
            aux.services.remove(&id);
        }
        aux.services.extend(native_services);

        if let Ok(mut m) = UNREADABLE_ITEMS.lock() {
            if unreadable > 0 {
                m.insert(vault_id.to_string(), unreadable);
            } else {
                m.remove(vault_id);
            }
        }

        // Owner-config per key: the legacy rows' entries, overlaid by the
        // honored native records; a kind with no entry left: its default.
        let defaults = config.apply(&mut aux)?;

        Ok((
            VaultPlaintextView {
                aux,
                native_secrets,
                native_secret_notes,
            },
            defaults,
        ))
    }

    /// LEGACY(aux addressing, services row): the legacy rows the fold reads,
    /// live, each with the native records its entries become:
    /// `aux:policy` → `policy:` + `policy:category:<tag>` +
    /// `policy:connection:<id>`, `aux:stores` → `store:<id>`,
    /// `aux:store_order` → `store_order:`, `aux:audit_retention_days` →
    /// `audit_retention_days:`, `aux:services` → `service:<id>` (object
    /// form). Each row on its own: one that is absent, unreadable, a
    /// tombstone, not honored or does not parse is left out (and left as it
    /// is). `aux:secret_order` is the console's.
    fn legacy_rows<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        trust: &MembershipTrust,
    ) -> Vec<(&'static str, Vec<Record>)> {
        let mut out = Vec::new();
        for field in [
            "policy",
            "stores",
            "store_order",
            "audit_retention_days",
            "services",
        ] {
            let one = || -> Result<Option<Vec<Record>>> {
                let wire = wire_id_for::<S>(keys.id_seed, ItemNs::Aux, field)?;
                let Some(stored) = self.items.get(&wire) else {
                    return Ok(None);
                };
                let raw = item_id_bytes::<S>(keys.id_seed, ItemNs::Aux.as_str(), field)?;
                let (payload, _) = unseal_item_keys::<S>(
                    keys,
                    &wire,
                    &ItemCtx::new(vault_id, raw, stored.version),
                    &stored.ct,
                )?;
                if payload.is_tombstone() || payload.ns != ItemNs::Aux || payload.name != field {
                    return Ok(None);
                }
                let Some(data) = fold_owner_config_record(
                    stored.sig.as_deref(),
                    stored.signer.as_deref(),
                    &stored.ct,
                    &self.keyset,
                    vault_id,
                    &raw,
                    ItemNs::Aux,
                    field,
                    stored.version,
                    payload.body,
                    trust,
                ) else {
                    return Ok(None);
                };
                if field != "services" {
                    return legacy_field_items(field, data).map(Some);
                }
                let entries: BTreeMap<String, crate::service::source::StoredService> =
                    parse_config("aux.services", data)?;
                entries
                    .iter()
                    .map(|(id, e)| {
                        let body = normalized_body(ItemNs::Service, id, &to_json(e)?);
                        Ok(((ItemNs::Service, id.clone()), body))
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(Some)
            };
            match one() {
                Ok(Some(items)) => out.push((field, items)),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(vault = %vault_id, field, "legacy row left as it is: {}", e)
                }
            }
        }
        out
    }

    /// How the native record at `(ns, name)` reads for the migration (see
    /// [`NativeKey`]).
    fn native_key<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        trust: &MembershipTrust,
        ns: ItemNs,
        name: &str,
    ) -> NativeKey {
        let Ok(wire) = wire_id_for::<S>(keys.id_seed, ns, name) else {
            return NativeKey::Unreadable;
        };
        let Some(stored) = self.items.get(&wire) else {
            return NativeKey::Absent;
        };
        let Ok(raw) = item_id_bytes::<S>(keys.id_seed, ns.as_str(), name) else {
            return NativeKey::Unreadable;
        };
        let Ok((payload, _)) = unseal_item_keys::<S>(
            keys,
            &wire,
            &ItemCtx::new(vault_id, raw, stored.version),
            &stored.ct,
        ) else {
            return NativeKey::Unreadable;
        };
        let honored = payload.ns == ns
            && payload.name == name
            && if !is_owner_config_ns(ns) {
                true // a data record (a service), at its own id
            } else {
                let ty = crate::storage::item::rule(ns, name)
                    .and_then(|r| r.signature_type(name))
                    .unwrap_or("");
                if payload.is_tombstone() {
                    owner_config_tombstone_honored(
                        stored.sig.as_deref(),
                        stored.signer.as_deref(),
                        &stored.ct,
                        &self.keyset,
                        vault_id,
                        &raw,
                        ty,
                        stored.version,
                        trust,
                    )
                } else {
                    fold_owner_config_record(
                        stored.sig.as_deref(),
                        stored.signer.as_deref(),
                        &stored.ct,
                        &self.keyset,
                        vault_id,
                        &raw,
                        ns,
                        ty,
                        stored.version,
                        payload.body,
                        trust,
                    )
                    .is_some()
                }
            };
        if honored {
            NativeKey::Decided {
                on_cloud: stored.synced_version >= stored.version,
            }
        } else {
            NativeKey::NotHonored
        }
    }

    /// LEGACY(aux addressing, services row), step 1 of the migration on a
    /// vault without a keyset: copy every entry of every legacy row the fold
    /// reads ([`Self::legacy_rows`]) to its native record, unsigned, where no
    /// honored native record decides its key yet (one the fold drops is
    /// replaced; an unreadable one is left as it is). The legacy rows stay:
    /// [`Self::retire_legacy_rows`] tombstones one only once every copy is
    /// confirmed on the cloud. The fold reads the same before and after. On a
    /// vault with a keyset this process writes nothing (the owner's console
    /// migrates, signed). Run only after a pull. Returns the item ids written.
    pub fn migrate_legacy_copies<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
    ) -> Vec<String> {
        if self.keyset.uik.is_some() {
            return Vec::new();
        }
        let trust = self.resolve_membership_trust(vault_id);
        let mut changed = Vec::new();
        for (field, items) in self.legacy_rows::<S>(keys, vault_id, &trust) {
            for ((ns, name), body) in items {
                if !matches!(
                    self.native_key::<S>(keys, vault_id, &trust, ns, &name),
                    NativeKey::Absent | NativeKey::NotHonored
                ) {
                    continue;
                }
                let payload = ItemPayload::live(ns, name.clone(), body);
                match self.seal_and_bump::<S>(keys, vault_id, ns, &name, &payload) {
                    Ok((iid, _)) => {
                        self.mark_upgrade(&iid);
                        changed.push(iid)
                    }
                    Err(e) => {
                        tracing::warn!(vault = %vault_id, field, "legacy copy not written: {}", e)
                    }
                }
            }
        }
        changed
    }

    /// LEGACY(aux addressing, services row), step 2: tombstone each legacy
    /// row the fold reads whose every entry is decided by an honored native
    /// record that the cloud holds (`on_cloud`; a device without a cloud:
    /// held locally), so no reader ever sees the legacy row gone before its
    /// copies. A row with a copy still unconfirmed (not pushed yet, failed,
    /// refused) stays live and is retired on a later run. A vault with a
    /// keyset: nothing. Returns the item ids written.
    pub fn retire_legacy_rows<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        on_cloud: bool,
    ) -> Vec<String> {
        if self.keyset.uik.is_some() {
            return Vec::new();
        }
        let trust = self.resolve_membership_trust(vault_id);
        let mut changed = Vec::new();
        for (field, items) in self.legacy_rows::<S>(keys, vault_id, &trust) {
            let all_held = items.iter().all(|((ns, name), _)| {
                matches!(
                    self.native_key::<S>(keys, vault_id, &trust, *ns, name),
                    NativeKey::Decided { on_cloud: held } if held || !on_cloud
                )
            });
            if !all_held {
                continue;
            }
            match self.seal_and_bump::<S>(
                keys,
                vault_id,
                ItemNs::Aux,
                field,
                &ItemPayload::tombstone(ItemNs::Aux, field),
            ) {
                Ok((iid, _)) => {
                    self.mark_upgrade(&iid);
                    changed.push(iid)
                }
                Err(e) => tracing::warn!(vault = %vault_id, field, "legacy row not retired: {}", e),
            }
        }
        changed
    }

    /// Mark the row at `iid` as written by SafeClaw's automatic upgrade.
    fn mark_upgrade(&mut self, iid: &str) {
        if let Some(s) = self.items.get_mut(iid) {
            s.upgrade = true;
        }
    }

    /// Why adopting `incoming` over the local row at `wire` is held back, or
    /// `None` to adopt: it would replace an owner-config record the fold
    /// honors (native or legacy, live or tombstone) with one it does not
    /// honor or cannot read; then the local row is kept, the last honored
    /// value. Only a vault with a keyset has owner-config the fold drops;
    /// without one this is always `None`.
    pub(crate) fn unhonored_replacement<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        wire: &str,
        incoming: &StoredItem,
    ) -> Option<&'static str> {
        if self.keyset.uik.is_none() {
            return None;
        }
        let local = self.items.get(wire)?;
        let trust = self.resolve_membership_trust(vault_id);
        let read = |stored: &StoredItem| -> Option<bool> {
            let raw = aad_id_from_wire::<S>(keys.id_seed, wire).ok()?;
            let (payload, _) = unseal_item_keys::<S>(
                keys,
                wire,
                &ItemCtx::new(vault_id, raw, stored.version),
                &stored.ct,
            )
            .ok()?;
            let r = crate::storage::item::rule(payload.ns, &payload.name)?;
            if r.signed != crate::storage::item::Signed::OwnerWithKeyset
                || wire_id_for::<S>(keys.id_seed, payload.ns, &payload.name).ok()? != wire
            {
                return Some(false);
            }
            let ty = r.signature_type(&payload.name).unwrap_or("");
            Some(if payload.is_tombstone() {
                owner_config_tombstone_honored(
                    stored.sig.as_deref(),
                    stored.signer.as_deref(),
                    &stored.ct,
                    &self.keyset,
                    vault_id,
                    &raw,
                    ty,
                    stored.version,
                    &trust,
                )
            } else {
                fold_owner_config_record(
                    stored.sig.as_deref(),
                    stored.signer.as_deref(),
                    &stored.ct,
                    &self.keyset,
                    vault_id,
                    &raw,
                    payload.ns,
                    ty,
                    stored.version,
                    payload.body,
                    &trust,
                )
                .is_some()
            })
        };
        if read(local) != Some(true) {
            return None;
        }
        match read(incoming) {
            Some(true) => None,
            Some(false) => Some(HELD_NOT_OWNER_SIGNED),
            None => Some(HELD_UNREADABLE),
        }
    }

    /// Whether [`Self::unhonored_replacement`] holds `incoming` back.
    #[cfg(test)]
    pub(crate) fn keeps_honored_owner_config<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        wire: &str,
        incoming: &StoredItem,
    ) -> bool {
        self.unhonored_replacement::<S>(keys, vault_id, wire, incoming)
            .is_some()
    }

    /// Record what each row not yet classified addresses ([`RowKind`]),
    /// reading it with the vault key: a data record at its own derived id is
    /// [`RowKind::Data`]; owner-config, an agent grant, or a row not at its
    /// own address is [`RowKind::Guarded`]. An id is the HMAC of its record's
    /// name, so what it addresses never changes. A row this key cannot open
    /// stays unclassified (read again next time). Ids no longer stored are
    /// forgotten.
    pub fn classify_rows<S: PrimitiveSuite>(&mut self, keys: VaultKeys, vault_id: &str) {
        let items = &self.items;
        self.row_kinds.retain(|id, _| items.contains_key(id));
        let todo: Vec<String> = self
            .items
            .keys()
            .filter(|id| !self.row_kinds.contains_key(*id))
            .cloned()
            .collect();
        for id in todo {
            if crate::storage::item::is_agent_wire_id(&id) {
                self.row_kinds.insert(id, RowKind::Guarded);
                continue;
            }
            let stored = &self.items[&id];
            let Ok(payload) = open_wire_item::<S>(keys, vault_id, &id, stored.version, &stored.ct)
            else {
                continue;
            };
            let data = crate::storage::item::rule(payload.ns, &payload.name).is_some_and(|r| {
                r.conflict != Conflict::OwnerConfig
                    && payload.ns != ItemNs::Agent
                    && wire_id_for::<S>(keys.id_seed, payload.ns, &payload.name)
                        .is_ok_and(|w| w == id)
            });
            self.row_kinds.insert(
                id,
                if data {
                    RowKind::Data
                } else {
                    RowKind::Guarded
                },
            );
        }
    }

    /// Names of live (non-tombstone) items in one namespace. Unreadable items
    /// are skipped with a warning (same fault isolation as the fold).
    #[cfg(test)]
    fn live_names_in_ns<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        want: ItemNs,
    ) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for (id_b64, stored) in &self.items {
            let one: crate::error::Result<()> = (|| {
                // Cleartext agent wire ids recompute their HMAC AAD; blinded decode.
                let raw = aad_id_from_wire::<S>(keys.id_seed, id_b64)?;
                let ctx = ItemCtx::new(vault_id, raw, stored.version);
                let (payload, _) = unseal_item_keys::<S>(keys, id_b64, &ctx, &stored.ct)?;
                if payload.ns == want && !payload.is_tombstone() {
                    out.push(payload.name);
                }
                Ok(())
            })();
            if let Err(e) = one {
                tracing::warn!(item = %id_b64, "live_names_in_ns: skipping unreadable item: {}", e);
            }
        }
        Ok(out)
    }
}

/// A held replacement's reason: not signed by an owner of the vault.
pub const HELD_NOT_OWNER_SIGNED: &str =
    "it is not signed by an owner of this vault; the owner-signed setting stays in force";
/// A held replacement's reason: it cannot be read with the vault key.
pub const HELD_UNREADABLE: &str =
    "it cannot be read with this vault's key; the owner-signed setting stays in force";
/// A held replacement's reason: the vault is locked.
pub const HELD_LOCKED: &str =
    "the vault is locked; it is checked with the vault key at unlock";

/// Read the per-item vault file. `None` if it doesn't exist. (New per-item
/// format; NOT interchangeable with [`read`]'s whole-blob `SealedState`.)
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // Test fixture encodes credential_id with base64url-no-pad to match
    // `decode_credential_id`'s wire format (the WebAuthn convention).
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use tempfile::tempdir;

    #[test]
    fn vault_write_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let v = build_initial(
            b"cred-bytes".to_vec(),
            "x_b64".into(),
            "y_b64".into(),
            "Test Device".into(),
            vec![0u8; 32],
            vec![0u8; 48],
            vec![0u8; 64],
        )
        .unwrap();
        write_atomic(&path, &v).unwrap();
        let loaded = read(&path).unwrap().unwrap();
        assert_eq!(loaded.version, CURRENT_VERSION);
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(loaded.credentials[0].credential_id, b"cred-bytes");
        let pk = find_pubkey(&v, &URL_SAFE_NO_PAD.encode(b"cred-bytes")).unwrap();
        assert_eq!(pk.x, "x_b64");
        assert_eq!(pk.device_name, "Test Device");
    }

    #[test]
    fn decode_keys_data_field_accepts_std_and_url() {
        // The lenient decoder mirrors the frontend's `fromBase64`: accept both
        // STANDARD base64 (frontend `toBase64` for x/y/prf_salt/wrapped_key) and
        // base64url (x25519_pub), padded or not. All four spellings of the same
        // bytes must decode identically.
        let raw: Vec<u8> = vec![
            0xFB, 0xFF, 0xBF, 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B,
        ];
        let std_pad = STANDARD.encode(&raw); // has +, /, and = padding
        assert!(std_pad.contains('+') || std_pad.contains('/'));
        let std_nopad = std_pad.trim_end_matches('=').to_string();
        let url_pad = std_pad.replace('+', "-").replace('/', "_");
        let url_nopad = url_pad.trim_end_matches('=').to_string();
        for s in [&std_pad, &std_nopad, &url_pad, &url_nopad] {
            assert_eq!(decode_keys_data_field(s).unwrap(), raw, "decode {}", s);
        }
    }

    #[test]
    fn per_item_vault_seal_write_read_open_roundtrip() {
        use sudp::primitives::StdPrimitives;
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.per-item.json");
        let k = [0x42u8; 32];
        let vid = "vault-xyz";

        let mut pv = PerItemVault::build_initial(
            b"cred-bytes".to_vec(),
            "x_b64".into(),
            "y_b64".into(),
            "Test Device".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // Seal a secret item into the store, then a tombstone for another.
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
        // The stored key is exactly the contract's base64url item id.
        assert_eq!(
            id,
            item_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap()
        );
        assert_eq!(pv.get_item(&id).unwrap().version, 1);

        // Persist and reload → the sealed ct survives the base64url JSON codec.
        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert_eq!(loaded.keyset.credentials.len(), 1);
        assert_eq!(loaded.items.len(), 1);

        // Open it back through K — the fold the metadata layer will do per row.
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
        assert!(!payload.is_tombstone());

        // A wrong vault id must NOT open (AAD binds the vault).
        assert!(loaded
            .open_item::<StdPrimitives>(
                VaultKeys::single(&k),
                "other-vault",
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN"
            )
            .is_err());

        // Absent item → Ok(None), not an error.
        assert!(loaded
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Secret, "NOPE")
            .unwrap()
            .is_none());
    }

    #[test]
    fn synced_version_tracks_dirty_vs_clean() {
        use sudp::primitives::StdPrimitives;
        let k = [0x21u8; 32];
        let vid = "vault-dirty";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // A fresh local write is DIRTY (never confirmed on cloud).
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

        // Pull/adopt lands CLEAN — the cloud has this exact version by construction.
        let ct = pv.get_item(&id).unwrap().ct.clone();
        pv.put_raw(id.clone(), 1, ct);
        assert_eq!(
            pv.get_item(&id).unwrap().synced_version,
            1,
            "adopted row is clean"
        );

        // A subsequent local bump goes dirty again, KEEPING the confirmed floor.
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
        assert_eq!(
            (s.version, s.synced_version),
            (2, 1),
            "bumped row is dirty above its synced floor"
        );
    }

    #[test]
    fn tombstone_flag_tracks_payload_status() {
        use sudp::primitives::StdPrimitives;
        let k = [0x33u8; 32];
        let vid = "vault-tomb";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // A live write is NOT a tombstone; a deleting write IS one — so the push
        // loop can order writes before deletes.
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
        assert!(
            !pv.get_item(&live).unwrap().tombstone,
            "live row is not a tombstone"
        );

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
        assert!(
            pv.get_item(&dead).unwrap().tombstone,
            "deleting row is a tombstone"
        );

        // Survives the JSON codec (serde-defaulted, so an old store loads false).
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
        // Untagged serde distinguishes the two variants purely by JSON shape:
        // string "all" → All, object { "deny": [...] } → Blocked.

        // Default / "all" round-trips as the bare string; allows everything.
        let all: AgentEntry = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(all.connections.allows("anything"));
        assert!(matches!(all.connections, AgentMask::All(_)), "default = All");
        assert_eq!(
            serde_json::to_value(&AgentEntry::default()).unwrap(),
            serde_json::json!({ "connections": "all" })
        );

        // Blacklist: an object `{ "deny": [...] }` → Blocked; allows everything
        // EXCEPT the denied ids (fail-open — later/unknown ids stay reachable).
        let blk: AgentEntry =
            serde_json::from_value(serde_json::json!({ "connections": { "deny": ["stripe-live"] } }))
                .unwrap();
        assert!(matches!(blk.connections, AgentMask::Blocked { .. }), "object → Blocked");
        assert!(!blk.connections.allows("stripe-live"), "denied conn refused");
        assert!(blk.connections.allows("github-work"), "non-listed conn allowed");
        assert!(
            blk.connections.allows("added-later-conn"),
            "unknown/new conn allowed (fail-open)"
        );
        let back = serde_json::to_value(&blk).unwrap();
        assert_eq!(back, serde_json::json!({ "connections": { "deny": ["stripe-live"] } }));

        // Direct allows() matrix, independent of AgentEntry wrapping.
        assert!(AgentMask::default().allows("x"), "default = All");
        assert!(AgentMask::Blocked { deny: vec!["a".into()] }.allows("b"));
        assert!(!AgentMask::Blocked { deny: vec!["a".into()] }.allows("a"));
        assert!(
            AgentMask::Blocked { deny: vec![] }.allows("anything"),
            "empty deny = allow all"
        );
    }

    // `ReconcileBase`: only a difference from the view's base is the caller's.
    // B was pulled into the store after the base was taken (in neither base nor
    // view) and C was changed by a pull to a newer value the stale base/view
    // still holds the old one of: neither is dropped or reverted under `Since`.
    #[test]
    fn reconcile_is_relative_to_the_base() {
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};
        use sudp::primitives::StdPrimitives;
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
        };
        // The store: A, B (pulled), C at its NEWER pulled value, D.
        let store = || {
            let mut pv = PerItemVault::build_initial(
                b"c".to_vec(),
                "x".into(),
                "y".into(),
                "Dev".into(),
                vec![0u8; 32],
                vec![0u8; 48],
            )
            .unwrap();
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
        // The caller's base predates the pulls (no B, old C); it deletes A and
        // sets D.
        let base = ViewBase::of(&view_of(&[("A", "a"), ("C", "old"), ("D", "d")])).unwrap();
        let view = view_of(&[("C", "old"), ("D", "d2")]);

        let mut pv = store();
        pv.reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(
            live(&pv),
            pairs(&[("B", "b"), ("C", "new"), ("D", "d2")]),
            "only the caller's delete (A) and edit (D) apply; pulled B and C survive"
        );

        // OwnFold: every difference is the caller's.
        let mut pv = store();
        pv.reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::OwnFold)
            .unwrap();
        assert_eq!(live(&pv), pairs(&[("C", "old"), ("D", "d2")]));
    }

    // §4 under `Since`: the caller changed K while a pull changed K too (the
    // stored row no longer matches the base). A keep-both ns keeps THEIRS at the
    // canonical id and OURS as its DIRTY conflict copy, the record "K
    // (conflict copy)"; owner-config is never written over (reported).
    // Idempotent.
    #[test]
    fn reconcile_keeps_both_on_a_concurrent_same_item_change() {
        use crate::storage::item::{self as il};
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};
        use sudp::primitives::StdPrimitives;
        let k = [0x57u8; 32];
        let vid = "vault-kb";
        let keys = VaultKeys::single(&k);
        let view_of = |k_val: &str, days: u32| {
            let mut aux = VaultAux::initial();
            aux.audit_retention_days = Some(days);
            VaultPlaintextView {
                aux,
                native_secrets: [("K".to_string(), k_val.as_bytes().to_vec())].into(),
                native_secret_notes: Default::default(),
            }
        };
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        // The store holds THEIR values (pulled after the base): K, retention 14.
        pv.seed_items_from_view::<StdPrimitives>(keys, vid, &view_of("theirs", 14))
            .unwrap();
        for s in pv.items.values_mut() {
            s.synced_version = s.version;
        }
        let k_id = il::wire_id_for::<StdPrimitives>(&k, ItemNs::Secret, "K").unwrap();
        let their_k = pv.get_item(&k_id).unwrap().clone();

        // The caller read the base (K "base", 7) and changed both.
        let base = ViewBase::of(&view_of("base", 7)).unwrap();
        let view = view_of("ours", 30);
        let reconciled = pv
            .reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();

        // K: theirs untouched (still clean); ours is a dirty local conflict copy.
        let k_now = pv.get_item(&k_id).unwrap();
        assert_eq!(
            (k_now.version, k_now.synced_version, k_now.ct.clone()),
            (their_k.version, their_k.version, their_k.ct.clone())
        );
        // The copy is a record of its own name at that name's id: dirty, a
        // create on the next push.
        let copy_id =
            il::wire_id_for::<StdPrimitives>(&k, ItemNs::Secret, &il::conflict_copy_name("K"))
                .unwrap();
        let copy = pv.get_item(&copy_id).expect("local conflict copy").clone();
        assert_eq!((copy.version, copy.synced_version), (1, 0));
        let folded = pv.fold_view::<StdPrimitives>(keys, vid).unwrap();
        assert_eq!(folded.native_secrets["K"], b"theirs");
        assert_eq!(folded.native_secrets[&il::conflict_copy_name("K")], b"ours");
        // Owner-config: never written over theirs, also without a keyset. Ours
        // is not written and is reported for a re-run.
        assert_eq!(folded.aux.audit_retention_days, Some(14));
        let r_id = il::wire_id_for::<StdPrimitives>(&k, ItemNs::AuditRetentionDays, "").unwrap();
        assert_eq!(
            reconciled.set_aside,
            [(r_id.clone(), "audit_retention_days".to_string())]
        );
        let theirs_r = pv.get_item(&r_id).unwrap();
        assert_eq!(
            theirs_r.version, theirs_r.synced_version,
            "theirs untouched"
        );
        assert!(reconciled.changed.contains(&copy_id));
        assert!(!reconciled.changed.contains(&r_id));

        // Idempotent: a second reconcile adds no second copy (the same
        // content is already there).
        let n = pv.items.len();
        let again = pv
            .reconcile_from_view::<StdPrimitives>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(pv.items.len(), n);
        assert_eq!(again.set_aside.len(), 1, "still reported");
    }

    // keep_both, the base rule: the stored row changed since the caller's base
    // but its body equals the base (normalized: e.g. another device only
    // copied a legacy plain-text service entry to a native item in the object
    // form) is no conflict: ours applies, and the dirty row records the base
    // it was made from (the push applies the same rule to a 409).
    #[test]
    fn reconcile_applies_ours_when_theirs_equals_the_base() {
        use crate::service::source::StoredService;
        use crate::storage::item::{self as il};
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x58u8; 32];
        let vid = "vault-base";
        let keys = VaultKeys::single(&k);
        let text = |host: &str| format!("[service]\nid = \"acme\"\nhosts = [\"{host}\"]\n");
        let view_with = |entry: StoredService| {
            let mut aux = VaultAux::initial();
            aux.services.insert("acme".into(), entry);
            VaultPlaintextView {
                aux,
                native_secrets: Default::default(),
                native_secret_notes: Default::default(),
            }
        };
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        // Another device copied the entry (plain text in our base) as a native
        // item in the object form; we pulled it.
        pv.seal_and_bump::<S>(
            keys,
            vid,
            ItemNs::Service,
            "acme",
            &ItemPayload::live(
                ItemNs::Service,
                "acme",
                serde_json::json!({ "service": text("a.old") }),
            ),
        )
        .unwrap();
        for s in pv.items.values_mut() {
            s.synced_version = s.version;
        }
        let base = ViewBase::of(&view_with(StoredService::from(text("a.old")))).unwrap();
        let ours = view_with(StoredService::new(text("a.new"), None, None));
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &ours, ReconcileBase::Since(&base))
            .unwrap();
        assert!(r.set_aside.is_empty());
        let id = il::wire_id_for::<S>(&k, ItemNs::Service, "acme").unwrap();
        assert_eq!(r.changed, [id.clone()], "ours applied, no conflict copy");
        let row = pv.get_item(&id).unwrap();
        assert!(row.version > row.synced_version, "dirty");
        assert_eq!(
            row.base.as_deref(),
            Some(
                il::body_digest_hex(ItemNs::Service, "acme", &serde_json::json!(text("a.old")))
                    .as_str()
            ),
            "the base it was made from"
        );
        assert_eq!(
            pv.open_item::<S>(keys, vid, ItemNs::Service, "acme")
                .unwrap()
                .unwrap()
                .body,
            serde_json::json!({ "service": text("a.new") })
        );
        // A second change before the push keeps the first base.
        let ours2 = view_with(StoredService::new(text("a.newer"), None, None));
        let base2 = ViewBase::of(&ours).unwrap();
        pv.reconcile_from_view::<S>(keys, vid, &ours2, ReconcileBase::Since(&base2))
            .unwrap();
        assert_eq!(
            pv.get_item(&id).unwrap().base.as_deref(),
            Some(
                il::body_digest_hex(ItemNs::Service, "acme", &serde_json::json!(text("a.old")))
                    .as_str()
            )
        );
        // A plain-text entry in a view is written in the object form.
        let plain = view_with(StoredService::from(text("a.plain")));
        let base3 = ViewBase::of(&pv.fold_view::<S>(keys, vid).unwrap()).unwrap();
        pv.reconcile_from_view::<S>(keys, vid, &plain, ReconcileBase::Since(&base3))
            .unwrap();
        assert_eq!(
            pv.open_item::<S>(keys, vid, ItemNs::Service, "acme")
                .unwrap()
                .unwrap()
                .body,
            serde_json::json!({ "service": text("a.plain") })
        );
    }

    // The daemon NEVER writes authorized-agents rows (any spelling, live or
    // tombstone): it holds no UIK, so it cannot sign one. Seed + reconcile from a
    // view that carries agents emit only config; dropping an agent from the view
    // writes no tombstone; and the seal primitive itself refuses agent rows.
    #[test]
    fn daemon_never_writes_agent_rows() {
        use crate::storage::plaintext::{AgentEntry, AgentMask, VaultAux};
        use sudp::primitives::StdPrimitives;
        let k = [0x55u8; 32];
        let vid = "vault-t1";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // Seed from a view with policy + TWO agents.
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
        aux.agents.insert("ag_bob".into(), AgentEntry::default());
        let view = crate::storage::plaintext::VaultPlaintextView {
            aux,
            native_secrets: std::collections::BTreeMap::new(),
            native_secret_notes: std::collections::BTreeMap::new(),
        };
        pv.seed_items_from_view::<StdPrimitives>(VaultKeys::single(&k), vid, &view)
            .unwrap();
        let items_after_seed = pv.items.len();

        // Config round-trips (NoUik keyset: integrity-only); agents were NOT written.
        let folded = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert_eq!(folded.aux.policy.as_ref().unwrap().timeout, Some(222));
        assert!(
            folded.aux.agents.is_empty(),
            "daemon seed wrote no agent rows"
        );
        let aux_names = pv
            .live_names_in_ns::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Aux)
            .unwrap();
        assert!(
            !aux_names.iter().any(|n| n.starts_with("agent/")),
            "no legacy aux:agent rows"
        );
        assert!(
            pv.live_names_in_ns::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Agent)
                .unwrap()
                .is_empty(),
            "no native agent rows"
        );

        // Reconcile from a view that still carries agents (and then one that drops
        // one): no agent row is upserted, and no tombstone is written.
        let changed = pv
            .reconcile_from_view::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                &view,
                ReconcileBase::OwnFold,
            )
            .unwrap()
            .changed;
        assert!(
            changed.is_empty(),
            "agents in the view write nothing: {:?}",
            changed
        );
        let mut view2 = crate::storage::plaintext::VaultPlaintextView {
            aux: view.aux.clone(),
            native_secrets: view.native_secrets.clone(),
            native_secret_notes: view.native_secret_notes.clone(),
        };
        view2.aux.agents.remove("ag_bob");
        let changed = pv
            .reconcile_from_view::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                &view2,
                ReconcileBase::OwnFold,
            )
            .unwrap()
            .changed;
        assert!(changed.is_empty(), "dropping an agent writes no tombstone");
        assert_eq!(pv.items.len(), items_after_seed);

        // The seal primitive refuses agent rows in BOTH spellings, live or tombstone.
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
        assert_eq!(
            pv.items.len(),
            items_after_seed,
            "refused writes stored nothing"
        );
    }

    /// T2 cutover — native `ns=Agent` items address by the CLEARTEXT ag_id: the row
    /// PK == the ag_id (so the backend can gate the write by ownership), while the
    /// seal AAD stays the HMAC. Proves the daemon seal/open/enumerate half of the
    /// scheme (the signed fold path is covered by the FE↔daemon parity vector + e2e).
    #[test]
    fn native_agent_cleartext_seal_open_roundtrip() {
        use crate::storage::plaintext::AgentEntry;
        use sudp::primitives::StdPrimitives;
        let k = [0x66u8; 32];
        let vid = "vault-agent-ct";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        let ag = "ag_abcdefghijklmnopqrstuvwxyz234567";
        let body = serde_json::to_value(AgentEntry::default()).unwrap();
        // The daemon never writes agent rows; land one the way the PULL path does
        // (console-sealed ct at wire == ag_id, AAD = the HMAC id).
        let id = wire_id_for::<StdPrimitives>(&k, ItemNs::Agent, ag).unwrap();
        assert_eq!(
            id.as_str(),
            ag,
            "native agent item addresses by the cleartext ag_id"
        );
        let ctx = ItemCtx::for_item::<StdPrimitives>(&k, vid, ItemNs::Agent, ag, 1).unwrap();
        let ct = seal_item::<StdPrimitives>(
            &k,
            &ctx,
            &ItemPayload::live(ItemNs::Agent, ag.to_string(), body),
        )
        .unwrap();
        pv.put_raw_signed(id, 1, ct, None, None);
        // open_item finds it by (ns,name) and unseals via the recomputed HMAC AAD.
        let opened = pv
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Agent, ag)
            .unwrap()
            .expect("native cleartext agent item opens");
        assert_eq!(opened.ns, ItemNs::Agent);
        assert_eq!(opened.name.as_str(), ag);
        // the cleartext-aware enumerate lists it under the agent ns.
        let names = pv
            .live_names_in_ns::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Agent)
            .unwrap();
        assert!(
            names.contains(&ag.to_string()),
            "cleartext agent shows in live_names_in_ns(Agent)"
        );
    }

    /// Notes ride a secret's body; the fold splits them off, and a daemon-side
    /// rewrite of the VALUE (an OAuth refresh, `sc set`) re-attaches them, so the
    /// daemon never silently drops what the user wrote.
    #[test]
    fn secret_notes_survive_a_daemon_value_rewrite() {
        use sudp::primitives::StdPrimitives;
        let k = [0x43u8; 32];
        let vid = "vault-notes";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
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
            view.native_secrets.get("TOKEN").map(Vec::as_slice),
            Some(&b"old"[..])
        );
        assert_eq!(
            view.native_secret_notes.get("TOKEN").map(String::as_str),
            Some("prod key")
        );
        assert!(!view.native_secret_notes.contains_key("PLAIN"));

        // The daemon rewrites only the value.
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
        // A note-less secret keeps the original bare-string shape.
        let plain = pv
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Secret, "PLAIN")
            .unwrap()
            .unwrap();
        assert_eq!(plain.body, serde_json::Value::String("p".into()));
    }

    #[test]
    fn fold_view_rebuilds_secrets_connections_and_aux() {
        use sudp::primitives::StdPrimitives;
        let k = [0x42u8; 32];
        let vid = "vault-fold";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // A live secret, a tombstoned secret (must be dropped), a connection,
        // and an aux store_order override.
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "OPENAI_KEY",
            1,
            &ItemPayload::secret_live("OPENAI_KEY", "sk-live"),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "GONE",
            2,
            &ItemPayload::tombstone(ItemNs::Secret, "GONE"),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Connection,
            "gmail",
            1,
            &ItemPayload::live(
                ItemNs::Connection,
                "gmail",
                serde_json::json!({ "service": "gmail" }),
            ),
        )
        .unwrap();
        // LEGACY(aux addressing): a row an earlier version wrote.
        pv.plant::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Aux,
            "store_order",
            1,
            &ItemPayload::live(
                ItemNs::Aux,
                "store_order",
                serde_json::json!(["native-secrets", "gcp-1"]),
            ),
        )
        .unwrap();

        let view = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert_eq!(
            view.resolve_value_native("OPENAI_KEY"),
            Some(&b"sk-live"[..])
        );
        assert_eq!(
            view.native_secrets.get("GONE"),
            None,
            "tombstone must be dropped"
        );
        assert_eq!(
            view.aux
                .connections
                .get("gmail")
                .and_then(|c| c.service.as_deref()),
            Some("gmail")
        );
        assert_eq!(view.aux.store_order, vec!["native-secrets", "gcp-1"]);
        assert_eq!(view.aux.version, 4);
    }

    #[test]
    fn v1_keyset_has_no_uik_layer() {
        // A classic keyset built by `build_initial` is v1: `uik` is `None`, so
        // `is_uik()` is false and `wrapped_key` is the plain `Wrap(K)`.
        let pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        assert!(!pv.is_uik());
        assert!(pv.keyset.uik.is_none());
    }

    #[test]
    fn v2_keyset_store_unlock_roundtrip() {
        // Build a v2 (`custody → UIK → K`) keyset through the storage accessors,
        // persist it (serde round-trip), then reproduce the browser's unlock:
        // custody-unwrap the UIK root from `wrapped_key`, derive the member's
        // `user_id`, look up its K-seal, and open `K`. This is the storage-layer
        // proof that the v2 fields survive disk and compose back into `K`.
        use crate::crypto::vault_key::{seal_k_to_uik, unwrap_uik_root, wrap_uik_root, UikRoot};

        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.per-item.json");
        let vid = "vault-v2";

        // Owner mints (here: fixed) a UIK root; custody `W_c` from the passkey PRF.
        let root = [0x33u8; 32];
        let uik = UikRoot::from_root(root);
        let w_c = [0x55u8; 32];
        let cid: Vec<u8> = b"cred-v2".to_vec();

        // v2 keyset: `wrapped_key` = Wrap_{W_c}(UIK root), NOT Wrap(K).
        let wrapped_root = wrap_uik_root(&w_c, &cid, &root).unwrap();
        let mut pv = PerItemVault::build_initial(
            cid.clone(),
            "x".into(),
            "y".into(),
            "Owner Device".into(),
            vec![0u8; 32],
            wrapped_root,
        )
        .unwrap();

        // K sealed to the owner's UIK enc pubkey → this credential's seal.
        let k = [0x9au8; 32];
        let enc_pub = uik.encryption_public().unwrap();
        let (encapped, ct) = seal_k_to_uik(&enc_pub, vid, &k).unwrap();
        let cid_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cid);
        let sig_pub = uik.signing().public_bytes().to_vec();
        pv.set_uik_cred(
            cid_b64.clone(),
            uik.user_id(),
            sig_pub.clone(),
            enc_pub.clone(),
            encapped,
            ct,
            crate::storage::plaintext::MemberRole::Owner,
            Vec::new(),
        );
        assert!(pv.is_uik(), "seal promotes the keyset to v2");

        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert!(loaded.is_uik());

        // Unlock (browser's role): recover the root from custody, then open K
        // from the acting credential's own seal.
        let recovered_root =
            unwrap_uik_root(&w_c, &cid, &loaded.keyset.credentials[0].wrapped_key).unwrap();
        let ruik = UikRoot::from_root(*recovered_root);
        assert_eq!(ruik.user_id(), uik.user_id());
        let entry = loaded
            .uik_cred(&cid_b64)
            .expect("acting credential carries its own seal");
        assert_eq!(entry.user_id, uik.user_id());
        assert_eq!(entry.sig_pub, sig_pub, "signing pubkey survives disk");
        let opened = ruik.open_k(vid, &entry.k_encapped, &entry.k_ct).unwrap();
        assert_eq!(&opened[..], &k[..]);

        // An unknown credential has no seal; offboarding drops the member's rows.
        assert!(loaded.uik_cred("unknown-cid").is_none());
        let mut pv2 = loaded;
        assert_eq!(pv2.remove_uik_member(&uik.user_id()), 1);
        assert!(pv2.uik_cred(&cid_b64).is_none());
    }

    #[test]
    fn config_signature_verify_accept_reject() {
        // C.3: owner-config integrity. A valid UIK signature from a PUBLISHED
        // member key is honored; a tampered version/name, a forged signer, or a
        // malformed wrapper is dropped; an unsigned (legacy) body passes through.
        use crate::crypto::vault_key::UikRoot;
        use base64::engine::general_purpose::STANDARD;

        let vault = "vault-cfg";
        let uik = UikRoot::from_root([0x33u8; 32]);
        let sign_pub = uik.signing().public_bytes();

        // Keyset that KNOWS this member's sig_pub (the C.1 anchor).
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        pv.set_uik_cred(
            "cid1".into(),
            uik.user_id(),
            sign_pub.to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            crate::storage::plaintext::MemberRole::Member,
            Vec::new(),
        );

        let data = serde_json::json!({ "timeout": 30, "default": { "read": "ask" } });
        let version = 7u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let signer_id = crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub);
        let input = crate::identity::config_sig_input(
            vault,
            "policy",
            version,
            Some(&canonical),
            &signer_id,
        );
        let sig = uik.signing().sign(&input);
        let signed = |d: &serde_json::Value, s: &[u8; 64], pk: &[u8; 32]| {
            serde_json::json!({
                "data": d,
                "uik_sig": STANDARD.encode(s),
                "uik_sign_pub": STANDARD.encode(pk),
            })
        };
        let wrapper = signed(&data, &sig, &sign_pub);

        // --- C (integrity-only, MembershipTrust::NoUik = legacy v1) ---
        // Valid → honored (returns inner data).
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            Some(data.clone()),
        );
        // Wrong version → sig no longer matches → DROP.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version + 1,
                &MembershipTrust::NoUik
            ),
            None,
        );
        // Wrong config name → DROP.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "stores",
                version,
                &MembershipTrust::NoUik
            ),
            None,
        );
        // Unsigned (legacy raw) → honored unchanged (additive).
        assert_eq!(
            unwrap_verified_config(
                data.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            Some(data.clone()),
        );
        // Malformed wrapper (uik_sig present but not base64) → DROP (fail-closed).
        let bad = serde_json::json!({ "data": data, "uik_sig": "!!!", "uik_sign_pub": "!!!" });
        assert_eq!(
            unwrap_verified_config(
                bad,
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            None
        );
        // Forged: a real signature from a key NOT in the keyset → DROP.
        let stranger = UikRoot::from_root([0x44u8; 32]);
        let s_pub = stranger.signing().public_bytes();
        let s_id = crate::identity::derive_id(crate::identity::IdKind::User, &s_pub);
        let s_input =
            crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &s_id);
        let s_sig = stranger.signing().sign(&s_input);
        assert_eq!(
            unwrap_verified_config(
                signed(&data, &s_sig, &s_pub),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            None,
        );

        // --- D (role authorization, MembershipTrust::Verified owner-set) ---
        use crate::storage::plaintext::MemberRole;
        let uid = uik.user_id();
        // Signer is an OWNER in the owner-set → honored.
        let owner_set: std::collections::BTreeMap<String, MemberRole> =
            [(uid.clone(), MemberRole::Owner)].into_iter().collect();
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(owner_set)
            ),
            Some(data.clone()),
        );
        // Signer is only a MEMBER (not owner) → DROP (can't rewrite owner config).
        let member_set: std::collections::BTreeMap<String, MemberRole> =
            [(uid.clone(), MemberRole::Member)].into_iter().collect();
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(member_set)
            ),
            None,
        );
        // Signer absent from the owner-set entirely → DROP.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(std::collections::BTreeMap::new())
            ),
            None,
        );
        // Unsigned legacy-raw body on a v2 (Verified) keyset → DROP: any K-holding
        // member could have written it (only NoUik honors raw config).
        let owner_set2: std::collections::BTreeMap<String, MemberRole> =
            [(uid.clone(), MemberRole::Owner)].into_iter().collect();
        assert_eq!(
            unwrap_verified_config(
                data.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(owner_set2)
            ),
            None,
            "Verified drops unsigned owner-config",
        );

        // --- E (MembershipTrust::Untrusted = v2 anchor stripped) fails CLOSED ---
        // Even a VALID owner-signed wrapper is dropped when the keyset carries no
        // valid creator anchor (a colluding server could have stripped it), and so
        // is legacy-raw config — everything falls to safe defaults.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Untrusted
            ),
            None,
            "Untrusted drops even a valid owner signature",
        );
        assert_eq!(
            unwrap_verified_config(
                data.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Untrusted
            ),
            None,
            "Untrusted drops legacy-raw config too (no integrity-only downgrade)",
        );
    }

    /// Re-keys the owner's console has not finished: rows still under a
    /// previous content key read through the previous keys the member's own
    /// keyset row carries (opened at unlock with the current key, newest
    /// first), each only for the rows that existed, exactly so, when it was
    /// retired. A row under a retired key that it does not list (sealed after
    /// it retired) is not honored and never written over. A row read through a previous key
    /// is never written back under it: a reconcile leaves it as it is, and a
    /// change to it is sealed under the current key.
    #[test]
    fn rows_a_rekey_has_not_moved_read_through_the_previous_keys() {
        use crate::storage::item::{seal_prev_content_keys, vault_key_bundle};
        type S = sudp::primitives::StdPrimitives;
        let fx = rekeyed_fixture();
        let vid = fx.vault;
        let c_older = [0x4du8; 32];
        let mut pv = fx.pv.clone();
        let old = VaultKeys {
            id_seed: &fx.id_seed,
            content: &fx.c_old,
            prev: &[],
        };
        let older = VaultKeys {
            content: &c_older,
            ..old
        };
        let bundle = vault_key_bundle(&fx.id_seed, &fx.c_new);
        let current = VaultKeys::from_material(&bundle);
        let old_id = pv
            .plant::<S>(old, vid, ItemNs::Secret, "OLD", 3, &ItemPayload::secret_live("OLD", "o"))
            .unwrap();
        let new_id = pv
            .plant::<S>(current, vid, ItemNs::Secret, "NEW", 1, &ItemPayload::secret_live("NEW", "n"))
            .unwrap();
        let older_id = pv
            .plant::<S>(older, vid, ItemNs::Secret, "OLDER", 2, &ItemPayload::secret_live("OLDER", "x"))
            .unwrap();
        // Sealed under the retired key after it retired: listed nowhere.
        let planted_id = pv
            .plant::<S>(old, vid, ItemNs::Secret, "PLANTED", 5, &ItemPayload::secret_live("PLANTED", "p"))
            .unwrap();
        for s in pv.items.values_mut() {
            s.synced_version = s.version;
        }
        let (old_ct, older_ct) = (pv.items[&old_id].ct.clone(), pv.items[&older_id].ct.clone());
        pv.set_uik_prev_content_ct(
            "cid-creator",
            seal_prev_content_keys::<S>(
                &fx.c_new,
                vid,
                1,
                &[
                    (&fx.c_old, &[(old_id.as_str(), 3, old_ct.as_slice())]),
                    (&c_older, &[(older_id.as_str(), 2, older_ct.as_slice())]),
                ],
            ),
        );

        // Unlock: the grant's root opens the bundle and, from the member's own
        // row, the previous keys with their rows.
        let material = crate::server::handlers::metadata::acquire_k_from_keyset(
            &pv.keyset,
            &fx.root,
            b"another-cred",
            vid,
        )
        .unwrap();
        assert!(material.len() > 64);
        let keys = VaultKeys::from_material(&material);
        let view = pv.fold_view::<S>(keys, vid).unwrap();
        assert_eq!(view.native_secrets["OLD"], b"o");
        assert_eq!(view.native_secrets["OLDER"], b"x");
        assert_eq!(view.native_secrets["NEW"], b"n");
        assert!(!view.native_secrets.contains_key("PLANTED"), "not honored");
        // Without them, only the current key reads.
        let view = pv.fold_view::<S>(current, vid).unwrap();
        assert!(!view.native_secrets.contains_key("OLD"));
        assert!(!view.native_secrets.contains_key("OLDER"));
        // A seal for another generation does not open: the bundle alone.
        let mut stale = pv.clone();
        stale.set_uik_prev_content_ct(
            "cid-creator",
            seal_prev_content_keys::<S>(
                &fx.c_new,
                vid,
                2,
                &[(&fx.c_old, &[(old_id.as_str(), 3, old_ct.as_slice())])],
            ),
        );
        let m = crate::server::handlers::metadata::acquire_k_from_keyset(
            &stale.keyset,
            &fx.root,
            b"another-cred",
            vid,
        )
        .unwrap();
        assert_eq!(m.len(), 64);

        // The unlisted row is never written over: a change to it is refused
        // with the note, the row left as it is.
        let planted = pv.items[&planted_id].clone();
        let view = pv.fold_view::<S>(keys, vid).unwrap();
        let base = ViewBase::of(&view).unwrap();
        let mut mine = pv.fold_view::<S>(keys, vid).unwrap();
        mine.native_secrets.insert("PLANTED".into(), b"mine".to_vec());
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &mine, ReconcileBase::Since(&base))
            .unwrap();
        assert!(r.changed.is_empty());
        assert_eq!(r.refused.len(), 1);
        assert!(r.refused[0].1.contains("changed with a vault key this device does not have"));
        assert_eq!(pv.items[&planted_id].ct, planted.ct);

        // Nothing changed: nothing is written, the old row stays as it is.
        let before = pv.items[&old_id].clone();
        let view = pv.fold_view::<S>(keys, vid).unwrap();
        let base = ViewBase::of(&view).unwrap();
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &view, ReconcileBase::Since(&base))
            .unwrap();
        assert!(r.changed.is_empty() && r.refused.is_empty());
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &view, ReconcileBase::OwnFold)
            .unwrap();
        assert!(r.changed.is_empty() && r.refused.is_empty());
        // Another row changed: the old one is still not touched.
        let mut changed = pv.fold_view::<S>(keys, vid).unwrap();
        changed.native_secrets.insert("NEW".into(), b"n2".to_vec());
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &changed, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(r.changed, vec![new_id.clone()]);
        assert_eq!(pv.items[&old_id].ct, before.ct);
        assert_eq!(pv.items[&old_id].version, before.version);
        // The old row changed: written at its next version under the current key.
        let base = ViewBase::of(&changed).unwrap();
        changed.native_secrets.insert("OLD".into(), b"o2".to_vec());
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &changed, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(r.changed, vec![old_id.clone()]);
        assert_eq!(pv.items[&old_id].version, 4);
        let got = pv
            .open_item::<S>(current, vid, ItemNs::Secret, "OLD")
            .unwrap()
            .unwrap();
        assert_eq!(got.body, serde_json::json!("o2"));
    }

    #[test]
    fn dps1_content_rotation_preserves_ids_and_forward_secrecy() {
        // DP-S1 (team-shared-vault-security-model.md §3.2): a re-key rotates the
        // CONTENT key while the ID-SEED stays fixed. Item ids therefore survive
        // the re-key (sync sees content updates, not delete-all+add-all), and a
        // departed member holding only the OLD content key cannot open the
        // re-sealed bodies (forward secrecy).
        use crate::storage::item::{vault_key_bundle, VaultKeys};
        use sudp::primitives::StdPrimitives;

        let vid = "vault-rekey";
        let seed = [0x11u8; 32]; // stable id-seed (never rotates)
        let c_old = [0x22u8; 32]; // pre-re-key content key (a departed member's)
        let c_new = [0x33u8; 32]; // post-re-key content key

        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // Seal a secret at the stable id-seed, under the NEW content key (the
        // post-re-key state).
        let vk_new = VaultKeys {
            id_seed: &seed,
            content: &c_new,
            prev: &[],
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

        // The row lands at the id-seed-derived id — INDEPENDENT of the content
        // key (so a re-key that changes only content leaves the id fixed).
        let id_from_seed =
            item_id::<StdPrimitives>(&seed, ItemNs::Secret.as_str(), "TOKEN").unwrap();
        assert!(
            pv.items.contains_key(&id_from_seed),
            "id derives from id-seed"
        );

        // A current member (new content key) reads it.
        let got = pv
            .open_item::<StdPrimitives>(vk_new, vid, ItemNs::Secret, "TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(got.body, serde_json::Value::String("sk-new".into()));

        // A departed member with the OLD content key: SAME id-seed → the id
        // resolves (row found), but the old content key CANNOT unseal the body
        // sealed under the new content key → forward secrecy.
        let vk_old = VaultKeys {
            id_seed: &seed,
            content: &c_old,
            prev: &[],
        };
        assert!(
            pv.open_item::<StdPrimitives>(vk_old, vid, ItemNs::Secret, "TOKEN")
                .is_err(),
            "old content key must not open a re-sealed body"
        );

        // The 64-byte bundle `id_seed ‖ content` splits back via `from_material`
        // (the daemon's acquire → fold path).
        let bundle = vault_key_bundle(&seed, &c_new);
        let vk = VaultKeys::from_material(&bundle);
        assert_eq!(vk.id_seed, &seed[..]);
        assert_eq!(vk.content, &c_new[..]);
        let got2 = pv
            .open_item::<StdPrimitives>(vk, vid, ItemNs::Secret, "TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(got2.body, serde_json::Value::String("sk-new".into()));
    }

    #[test]
    fn rekey_proof_verify_accept_reject() {
        // E.3d: a re-keyed keyset (generation > 0) is trusted only with a valid
        // owner-signed proof bound to the actual content key.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;

        let vault = "vault-rk";
        let owner = UikRoot::from_root([0x55u8; 32]);
        let owner_sig_pub = owner.signing().public_bytes().to_vec();
        let owner_id = owner.user_id();
        let content = [0xABu8; 32];
        let gen = 1u64;
        let commit = rekey_commitment(&content).to_vec();
        // Empty delegation log at re-key → membership commitment over 0 events.
        let membership = crate::identity::membership_commitment(&[]).to_vec();
        let input = crate::identity::rekey_sig_input(vault, gen, &commit, &owner_id, 0, &membership);
        let sig = owner.signing().sign(&input).to_vec();

        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        pv.set_uik_cred(
            "cid1".into(),
            owner_id.clone(),
            owner_sig_pub.clone(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            Vec::new(),
        );
        {
            let uik = pv.keyset.uik.as_mut().unwrap();
            uik.generation = gen;
            uik.rekey_proof = Some(RekeyProof {
                generation: gen,
                k_commitment: commit.clone(),
                sig: sig.clone(),
                signer_id: owner_id.clone(),
                membership_len: 0,
                membership_hash: membership.clone(),
            });
        }
        let owner_trust = MembershipTrust::Verified(
            [(owner_id.clone(), MemberRole::Owner)]
                .into_iter()
                .collect(),
        );

        // Valid owner-signed proof, correct content → accept.
        assert!(verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
        // Wrong content key → commitment mismatch → reject (anti content-swap).
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &[0x00u8; 32]
        ));
        // Signer is only a member (not owner) → reject.
        let member_trust = MembershipTrust::Verified(
            [(owner_id.clone(), MemberRole::Member)]
                .into_iter()
                .collect(),
        );
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &member_trust,
            vault,
            &content
        ));
        // Untrusted (v2 anchor stripped) → can't confirm owner → reject.
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &MembershipTrust::Untrusted,
            vault,
            &content
        ));
        // generation mismatch (proof says 1, keyset says 2) → reject.
        pv.keyset.uik.as_mut().unwrap().generation = 2;
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
        pv.keyset.uik.as_mut().unwrap().generation = gen;
        // Missing proof on a re-keyed keyset → reject (forged bump).
        pv.keyset.uik.as_mut().unwrap().rekey_proof = None;
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
        // gen 0 (never re-keyed) → trivially accepted.
        pv.keyset.uik.as_mut().unwrap().generation = 0;
        assert!(verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
    }

    /// A re-keyed vault (generation 1): a v2 keyset pinned to its creator, the
    /// creator's cred (`cid-creator`) holding a real K-seal of the key bundle
    /// `id_seed ‖ c_new`, and the owner-signed proof of the re-key to `c_new`
    /// from `c_old`. No items, no previous content keys on the cred.
    pub(crate) struct Rekeyed {
        pub vault: &'static str,
        /// The creator's UIK root (the secret a grant delivers).
        pub root: [u8; 32],
        pub id_seed: [u8; 32],
        pub c_old: [u8; 32],
        pub c_new: [u8; 32],
        pub pv: PerItemVault,
    }

    impl Rekeyed {
        /// The key material the creator's unlock retains: `id_seed ‖ c_new`.
        pub fn material(&self) -> Vec<u8> {
            crate::storage::item::vault_key_bundle(&self.id_seed, &self.c_new)
        }
    }

    #[cfg(test)]
    pub(crate) fn rekeyed_fixture() -> Rekeyed {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let vault = "vault-rekeyed";
        let root = [0x11u8; 32];
        let creator = UikRoot::from_root(root);
        let creator_id = creator.user_id();
        let (id_seed, c_old, c_new) = ([0x5au8; 32], [0x6bu8; 32], [0x7cu8; 32]);
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        let enc_pub = creator.encryption_public().unwrap();
        let bundle = crate::storage::item::vault_key_bundle(&id_seed, &c_new);
        let (k_encapped, k_ct) =
            crate::crypto::vault_key::seal_k_to_uik(&enc_pub, vault, &bundle).unwrap();
        pv.set_uik_cred(
            "cid-creator".into(),
            creator_id.clone(),
            creator.signing().public_bytes().to_vec(),
            enc_pub,
            k_encapped,
            k_ct,
            MemberRole::Owner,
            Vec::new(),
        );
        let commit = rekey_commitment(&c_new).to_vec();
        let membership = crate::identity::membership_commitment(&[]).to_vec();
        let input =
            crate::identity::rekey_sig_input(vault, 1, &commit, &creator_id, 0, &membership);
        let uik = pv.keyset.uik.as_mut().unwrap();
        uik.creator_sig_pub = creator.signing().public_bytes().to_vec();
        uik.generation = 1;
        uik.rekey_proof = Some(RekeyProof {
            generation: 1,
            k_commitment: commit,
            sig: creator.signing().sign(&input).to_vec(),
            signer_id: creator_id,
            membership_len: 0,
            membership_hash: membership,
        });
        Rekeyed {
            vault,
            root,
            id_seed,
            c_old,
            c_new,
            pv,
        }
    }

    /// Shared setup for the role-on-keyset fixtures: a v2 keyset pinned to a
    /// creator, a creator cred (Owner, self-signed) and a member cred. Returns the
    /// vault, keyset holder, both roots, and their ids.
    #[cfg(test)]
    pub(crate) fn role_fixture_creator_cred() -> (
        &'static str,
        crate::crypto::vault_key::UikRoot,
        crate::crypto::vault_key::UikRoot,
        String,
        String,
        PerItemVault,
    ) {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let vault = "vault-role";
        let creator = UikRoot::from_root([0x11u8; 32]);
        let member = UikRoot::from_root([0x22u8; 32]);
        let creator_id = creator.user_id();
        let member_id = member.user_id();
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        // Creator cred: role=Owner, self-signed under the creator key (the root),
        // at the keyset's generation (0 for this gen-0 fixture — F3-b).
        let creator_grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault,
            &creator_id,
            "owner",
            0,
        ));
        pv.set_uik_cred(
            "cid-creator".into(),
            creator_id.clone(),
            creator.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            creator_grant.to_vec(),
        );
        // Pin the root anchor = the creator's signing pubkey.
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = creator.signing().public_bytes().to_vec();
        (vault, creator, member, creator_id, member_id, pv)
    }

    #[test]
    fn role_on_keyset_owner_config_accept_reject() {
        // Owner-authority (design/identity-uik-aik.md §4.3): role is a
        // CREATOR-signed attribute on the keyset cred. The owner-set is derived
        // from the keyset (each cred's role_sig verified against the pinned creator
        // pubkey); config signed by an owner is honored, config signed by a mere
        // member is dropped.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // A member cred: role=Member, CREATOR-signed at the keyset generation (0).
        let member_grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "member", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            member_grant.to_vec(),
        );

        // Owner-set from the keyset: Verified {creator→Owner, member→Member}.
        let MembershipTrust::Verified(owner_set) = pv.resolve_membership_trust(vault) else {
            panic!("pinned creator ⇒ MembershipTrust::Verified");
        };
        assert_eq!(owner_set.get(&creator_id), Some(&MemberRole::Owner));
        assert_eq!(owner_set.get(&member_id), Some(&MemberRole::Member));
        let trust = MembershipTrust::Verified(owner_set);

        // Config signed by an owner (creator) honored; by a member dropped.
        let data = serde_json::json!({ "timeout": 30 });
        let version = 4u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let signed = |signer: &UikRoot| -> serde_json::Value {
            let sid = signer.user_id();
            let input =
                crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &sid);
            let sig = signer.signing().sign(&input);
            serde_json::json!({
                "data": data,
                "uik_sig": STANDARD.encode(sig),
                "uik_sign_pub": STANDARD.encode(signer.signing().public_bytes()),
            })
        };
        assert_eq!(
            unwrap_verified_config(
                signed(&creator),
                &pv.keyset,
                vault,
                "policy",
                version,
                &trust
            ),
            Some(data.clone()),
            "owner-signed config honored",
        );
        assert_eq!(
            unwrap_verified_config(
                signed(&member),
                &pv.keyset,
                vault,
                "policy",
                version,
                &trust
            ),
            None,
            "member-signed owner-config dropped (not an owner)",
        );
    }

    /// Land an agent row the way the PULL path does (console-sealed ct + the wire
    /// sidecar sig/signer): `ns = Agent` ⇒ native row at wire id == ag_id; `ns = Aux`
    /// with `name = "agent/<ag_id>"` ⇒ the legacy blinded spelling. `signer = Some`
    /// adds a valid A1.2 sidecar sig (type `"agent"`, over the ct + HMAC id bytes).
    #[allow(clippy::too_many_arguments)]
    fn put_agent_row(
        pv: &mut PerItemVault,
        k: &[u8; 32],
        vault: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        body: serde_json::Value,
        signer: Option<&crate::crypto::vault_key::UikRoot>,
    ) {
        use sudp::primitives::StdPrimitives;
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

    #[test]
    fn agent_grant_authz_self_owner_and_forged() {
        // §11.1 authorized-agents table, end-to-end through `fold_view` on a v2
        // (Verified) keyset. A NATIVE row is honored iff it carries a valid sidecar
        // item-sig whose signer is the row's `owner` (self-service) or any owner
        // (override). A member admitting SOMEONE ELSE'S agent, an outsider, an
        // UNSIGNED row, a row with only a legacy in-body wrapper, and EVERY legacy
        // `aux:agent/*` row (even owner-signed) all drop.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use sudp::primitives::StdPrimitives;

        let (vault, creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();
        // Add a member cred (role=Member, creator-signed at gen 0).
        let member_grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "member", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            member_grant.to_vec(),
        );
        assert!(
            matches!(
                pv.resolve_membership_trust(vault),
                MembershipTrust::Verified(_)
            ),
            "pinned creator ⇒ Verified"
        );
        let outsider = UikRoot::from_root([0x99u8; 32]); // never published to the keyset
        let k = [0x5au8; 32];
        let v = 3u64;
        let ag = |c: char| format!("ag_{}", c.to_string().repeat(32));
        let grant = |owner_id: &str| serde_json::json!({ "owner": owner_id, "connections": "all" });

        // honored: member admits their OWN agent; creator (owner) admits the member's.
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('a'),
            v,
            grant(&member_id),
            Some(&member),
        );
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('b'),
            v,
            grant(&member_id),
            Some(&creator),
        );
        // dropped: member admits an agent declared OWNED BY the creator.
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('c'),
            v,
            grant(&creator_id),
            Some(&member),
        );
        // dropped: outsider (not a keyset cred) self-admits.
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('d'),
            v,
            grant(&outsider.user_id()),
            Some(&outsider),
        );
        // dropped: UNSIGNED native row (any K-holding member could write it).
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Agent,
            &ag('e'),
            v,
            grant(&member_id),
            None,
        );
        // dropped: native row carrying ONLY a legacy in-body wrapper, even creator-signed.
        let data = grant(&member_id);
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let cfg = format!("agent/{}", ag('f'));
        let input =
            crate::identity::config_sig_input(vault, &cfg, v, Some(&canonical), &creator_id);
        let wrapper = serde_json::json!({
            "data": data,
            "uik_sig": STANDARD.encode(creator.signing().sign(&input)),
            "uik_sign_pub": STANDARD.encode(creator.signing().public_bytes()),
        });
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
        // dropped: legacy blinded `aux:agent/<id>` rows, unsigned AND owner-signed.
        let legacy_g = format!("agent/{}", ag('g'));
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Aux,
            &legacy_g,
            v,
            grant(&member_id),
            None,
        );
        let legacy_h = format!("agent/{}", ag('h'));
        put_agent_row(
            &mut pv,
            &k,
            vault,
            ItemNs::Aux,
            &legacy_h,
            v,
            grant(&member_id),
            Some(&creator),
        );

        let view = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vault)
            .unwrap();
        let got: Vec<String> = view.aux.agents.keys().cloned().collect();
        assert_eq!(
            got,
            vec![ag('a'), ag('b')],
            "only signed+authorized native rows"
        );
        assert_eq!(view.aux.agents[&ag('a')].owner, member_id);

        // Untrusted (anchor stripped) drops even a validly-signed native row.
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = Vec::new();
        assert!(matches!(
            pv.resolve_membership_trust(vault),
            MembershipTrust::Untrusted
        ));
        let view = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vault)
            .unwrap();
        assert!(view.aux.agents.is_empty(), "Untrusted folds no agent rows");
    }

    #[test]
    fn nouik_agent_rows_integrity_only_and_legacy_ignored() {
        // Legacy fmt1 (NoUik, single person, no member keys): a plain unsigned
        // NATIVE row is honored on integrity (K) alone; a legacy `aux:agent/*` row
        // is still ignored.
        use crate::storage::plaintext::AgentEntry;
        use sudp::primitives::StdPrimitives;
        let k = [0x5bu8; 32];
        let vid = "vault-nouik-agent";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        assert!(pv.is_legacy_nouik(vid));
        let native = "ag_abcdefghijklmnopqrstuvwxyz234567";
        let legacy_ag = "ag_765432zyxwvutsrqponmlkjihgfedcba";
        let body = serde_json::to_value(AgentEntry::default()).unwrap();
        put_agent_row(
            &mut pv,
            &k,
            vid,
            ItemNs::Agent,
            native,
            1,
            body.clone(),
            None,
        );
        let legacy = format!("agent/{}", legacy_ag);
        put_agent_row(&mut pv, &k, vid, ItemNs::Aux, &legacy, 1, body, None);
        let view = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert!(
            view.aux.agents.contains_key(native),
            "NoUik: unsigned native row honored"
        );
        assert!(
            !view.aux.agents.contains_key(legacy_ag),
            "legacy aux:agent row ignored"
        );
        assert_eq!(view.aux.agents.len(), 1);
    }

    #[test]
    fn verify_record_sidecar_sig_accept_and_reject() {
        // A1.2 sidecar verify: a keyset member signs record_signature_input over the
        // record's ciphertext; the daemon re-verifies from the wire sig+signer.
        use crate::crypto::vault_key::UikRoot;
        use base64::engine::general_purpose::STANDARD;
        let (vault, creator, _member, creator_id, _member_id, pv) = role_fixture_creator_cred();
        let outsider = UikRoot::from_root([0x77u8; 32]); // not a keyset cred
        let ct = b"pretend-sealed-ciphertext-bytes";
        let id_raw = [0x09u8; 32];
        let sign = |signer: &UikRoot, ty: &str, body: &[u8]| -> String {
            let input = crate::identity::record_signature_input(
                ty, &id_raw, 4, vault, body, true, &signer.user_id());
            STANDARD.encode(signer.signing().sign(&input))
        };
        // Valid: creator (a keyset member) signs "policy" over ct → signer id back.
        let good = sign(&creator, "policy", ct);
        assert_eq!(
            verify_record_sidecar_sig(ct, &pv.keyset, vault, &id_raw, "policy", 4, true, &good, &creator_id),
            Some(creator_id.clone()),
        );
        // Tampered type: signed "policy", verified as "secret" → reject.
        assert_eq!(
            verify_record_sidecar_sig(ct, &pv.keyset, vault, &id_raw, "secret", 4, true, &good, &creator_id),
            None, "record_type is bound",
        );
        // Tampered ct: signature was over `ct`, verify over a different body → reject.
        assert_eq!(
            verify_record_sidecar_sig(b"other-ct", &pv.keyset, vault, &id_raw, "policy", 4, true, &good, &creator_id),
            None, "ciphertext is bound",
        );
        // Outsider (not a keyset cred) → reject even with a valid self-signature.
        let bad = sign(&outsider, "policy", ct);
        assert_eq!(
            verify_record_sidecar_sig(ct, &pv.keyset, vault, &id_raw, "policy", 4, true, &bad, &outsider.user_id()),
            None, "non-member signer rejected",
        );
    }

    #[test]
    fn role_self_promote_blocked() {
        // THE finding-#1 regression test. A member's cred claims role=Owner with a
        // role_sig it signed ITSELF (not the creator). Under the creator-rooted
        // owner-set, that grant fails verification against the pinned creator
        // pubkey — the member is NOT an owner and its owner-config is dropped. This
        // FAILS under the old single-version self-consistent membership (which trusted
        // `{me: owner}` self-signed) and PASSES under owner-authority.
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, _creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // ATTACK: the member cred claims role=Owner, role_sig = the MEMBER
        // self-signing the owner grant (NOT creator-signed).
        let self_grant = member.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "owner", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            self_grant.to_vec(),
        );

        // The self-promoting member is NOT in the owner-set (grant fails under the
        // pinned creator pubkey); the creator still is.
        let MembershipTrust::Verified(owner_set) = pv.resolve_membership_trust(vault) else {
            panic!("pinned creator ⇒ MembershipTrust::Verified");
        };
        assert_eq!(
            owner_set.get(&creator_id),
            Some(&MemberRole::Owner),
            "creator remains owner"
        );
        assert!(
            !owner_set.contains_key(&member_id),
            "self-signed owner grant rejected (finding #1)"
        );
        let trust = MembershipTrust::Verified(owner_set);

        // A config item signed by the self-promoting member is DROPPED.
        let data = serde_json::json!({ "timeout": 99 });
        let version = 2u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let sid = member.user_id();
        let input =
            crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &sid);
        let sig = member.signing().sign(&input);
        let wrapper = serde_json::json!({
            "data": data,
            "uik_sig": STANDARD.encode(sig),
            "uik_sign_pub": STANDARD.encode(member.signing().public_bytes()),
        });
        assert_eq!(
            unwrap_verified_config(wrapper, &pv.keyset, vault, "policy", version, &trust),
            None,
            "self-promoted member cannot rewrite owner config",
        );
    }

    #[test]
    fn untrusted_v2_no_anchor_drops_member_config() {
        // HIGH-severity fail-open regression: a v2 keyset (UIK layer present, ≥1
        // cred) whose `creator_sig_pub` a colluding server STRIPPED must FAIL
        // CLOSED — `resolve_membership_trust` returns `Untrusted`, and even a VALID
        // member-signed owner-config item is dropped (never downgraded to
        // integrity-only, which is what honored it before this fix).
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, _creator, member, _creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // A member cred is present (so the keyset is a real v2 keyset with creds).
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            Vec::new(),
        );
        // ATTACK: the server stripped the genesis anchor from every /keys row, so
        // it was never pinned — `creator_sig_pub` is empty.
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = Vec::new();

        // v2 keyset with creds but no anchor ⇒ Untrusted (fail closed). We thread
        // the trust RESOLVED from the keyset (not a hardcoded state) so this test
        // exercises the exact vulnerable path: pre-fix, `resolve_*` returned the
        // `None` membership and `unwrap_verified_config` honored the member config.
        let trust = pv.resolve_membership_trust(vault);
        assert!(
            matches!(&trust, MembershipTrust::Untrusted),
            "stripped anchor on a v2 keyset with creds ⇒ Untrusted",
        );

        // A member signs owner-config with a VALID signature (member IS a keyset
        // cred, so the integrity/known check passes) — under the old code this fell
        // through the empty-membership branch and was HONORED. It MUST now be dropped.
        let data = serde_json::json!({ "timeout": 1 });
        let version = 3u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let sid = member.user_id();
        let input =
            crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &sid);
        let sig = member.signing().sign(&input);
        let wrapper = serde_json::json!({
            "data": data,
            "uik_sig": STANDARD.encode(sig),
            "uik_sign_pub": STANDARD.encode(member.signing().public_bytes()),
        });
        assert_eq!(
            unwrap_verified_config(wrapper, &pv.keyset, vault, "policy", version, &trust),
            None,
            "no-anchor v2: member-signed owner-config dropped (fail closed)",
        );
    }

    #[test]
    fn role_grant_role_epoch_bound() {
        // Two-counter model (delegation-log-impl-spec.md §0): a root-signed
        // checkpoint grant binds `role_epoch` (the role-checkpoint epoch), ORTHOGONAL
        // to `generation` (the K-rotation epoch). Proven here on a NON-ROOT member
        // (the creator is always an owner via the genesis pin, so demotion-by-replay
        // is only meaningful for a granted member):
        //   (1) a `generation` (K-eviction) bump ALONE leaves the owner-set intact —
        //       role authority is decoupled from content-key rotation;
        //   (2) a `role_epoch` bump (compaction) WITHOUT a re-signed grant DROPS the
        //       stale checkpoint grant — a colluding server replaying a demoted/
        //       removed person's pre-compaction grant cannot keep them in;
        //   (3) re-signing at the new `role_epoch` (what compaction does for a
        //       survivor) restores them.
        use crate::storage::plaintext::MemberRole;

        let (vault, creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // Grant the MEMBER an OWNER role at role_epoch 0 (creator/root-signed).
        let grant0 = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "owner", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            grant0.to_vec(),
        );

        let owners = |pv: &PerItemVault| match pv.resolve_membership_trust(vault) {
            MembershipTrust::Verified(m) => m,
            _ => panic!("pinned creator ⇒ MembershipTrust::Verified"),
        };

        // Baseline: both the root creator and the granted member are owners @epoch 0.
        let os = owners(&pv);
        assert_eq!(os.get(&creator_id), Some(&MemberRole::Owner));
        assert_eq!(
            os.get(&member_id),
            Some(&MemberRole::Owner),
            "member granted owner @role_epoch 0 is an owner",
        );

        // (1) A K-rotation bumps `generation` but NOT `role_epoch`: owner-set intact.
        pv.keyset.uik.as_mut().unwrap().generation = 5;
        let os = owners(&pv);
        assert_eq!(
            os.get(&member_id),
            Some(&MemberRole::Owner),
            "a generation (K-eviction) bump alone leaves the owner-set intact (⊥)",
        );

        // (2) A compaction (root-signed SELF-succession to epoch 1) advances the
        // derived `role_epoch` WITHOUT re-signing the member's grant — the exact
        // stale-grant replay a colluding server attempts. The member's grant drops;
        // the root creator stays (genesis pin, not a checkpoint grant).
        push_compaction(&mut pv, vault, &creator, 1);
        let os = owners(&pv);
        assert!(
            !os.contains_key(&member_id),
            "stale grant (signed @role_epoch 0) is DROPPED @role_epoch 1 — replay defeated",
        );
        assert_eq!(
            os.get(&creator_id),
            Some(&MemberRole::Owner),
            "the root creator is an owner by the genesis pin, immune to grant replay",
        );

        // (3) Re-sign the member's grant @role_epoch 1 (what compaction does for a
        // survivor) → restored.
        let grant1 = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "owner", 1,
        ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .creds
            .get_mut("cid-member")
            .expect("fixture member cred")
            .role_sig = grant1.to_vec();
        assert_eq!(
            owners(&pv).get(&member_id),
            Some(&MemberRole::Owner),
            "re-signing the grant @role_epoch 1 restores the owner",
        );
    }

    /// Append a signed delegation event to the keyset log (test helper).
    fn push_event(
        pv: &mut PerItemVault,
        vault: &str,
        signer: &crate::crypto::vault_key::UikRoot,
        op: &str,
        subject_id: &str,
        role: crate::storage::plaintext::MemberRole,
        seq: u64,
        role_epoch: u64,
    ) {
        let granter_id = signer.user_id();
        let granter_sig_pub = signer.signing().public_bytes().to_vec();
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
        pv.keyset
            .uik
            .as_mut()
            .expect("v2 keyset")
            .delegation_log
            .push(DelegationEvent {
                op: op.into(),
                subject_id: subject_id.into(),
                role,
                granter_id,
                granter_sig_pub,
                seq,
                role_epoch,
                sig: sig.to_vec(),
            });
    }

    /// Push a root-signed SELF-succession (a pure COMPACTION): advances the derived
    /// `role_epoch` to `epoch` without changing the root. `root` must be the CURRENT
    /// root. This is how a compaction is expressed — the role-checkpoint epoch is
    /// derived from the root-signed succession chain, never a forgeable scalar.
    fn push_compaction(
        pv: &mut PerItemVault,
        vault: &str,
        root: &crate::crypto::vault_key::UikRoot,
        epoch: u64,
    ) {
        let root_id = root.user_id();
        let root_pub = root.signing().public_bytes();
        let sig = root.signing().sign(&crate::identity::root_succession_input(
            vault, &root_id, &root_id, &root_pub, epoch,
        ));
        pv.keyset
            .uik
            .as_mut()
            .expect("v2 keyset")
            .root_succession
            .push(RootSuccession {
                old_root_id: root_id.clone(),
                new_root_id: root_id,
                new_root_sig_pub: root_pub.to_vec(),
                role_epoch: epoch,
                sig: sig.to_vec(),
            });
    }

    /// Give a principal a keyset cred with sig_pub published but NO checkpoint grant
    /// (empty role_sig) — so its authority can come ONLY from delegation events.
    fn cred_no_grant(
        pv: &mut PerItemVault,
        cid: &str,
        who: &crate::crypto::vault_key::UikRoot,
        id: &str,
    ) {
        use crate::storage::plaintext::MemberRole;
        pv.set_uik_cred(
            cid.into(),
            id.into(),
            who.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            Vec::new(),
        );
    }

    fn owner_set(
        pv: &PerItemVault,
        vault: &str,
    ) -> BTreeMap<String, crate::storage::plaintext::MemberRole> {
        match pv.resolve_membership_trust(vault) {
            MembershipTrust::Verified(m) => m,
            other => panic!(
                "expected Verified, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn delegation_event_grant_and_non_cascade() {
        // The core of the full delegation model (design/identity-uik-aik.md §4.3):
        //   - ANY owner (not just the root) can grant via a signed event (SPKI
        //     delegation bit): the root adds A, then A adds B.
        //   - Removing A is NON-CASCADE: B (whom A added) stays an owner, because the
        //     fact "A WAS an owner when A signed" survives A's later removal.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        cred_no_grant(&mut pv, "cid-a", &a, &a_id);
        cred_no_grant(&mut pv, "cid-b", &b, &b_id);

        // A/B have no checkpoint grant → not owners yet.
        assert!(!owner_set(&pv, vault).contains_key(&a_id));

        // seq 1: root sets A → owner.
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        assert_eq!(
            owner_set(&pv, vault).get(&a_id),
            Some(&MemberRole::Owner),
            "root grants A via event",
        );
        // seq 2: A (a NON-root owner) sets B → owner (egalitarian delegation).
        push_event(&mut pv, vault, &a, "set", &b_id, MemberRole::Owner, 2, 0);
        assert_eq!(
            owner_set(&pv, vault).get(&b_id),
            Some(&MemberRole::Owner),
            "a non-root owner can grant (delegation bit)",
        );
        // seq 3: root removes A → A dropped, B STAYS (non-cascade).
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &a_id,
            MemberRole::Member,
            3,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(!os.contains_key(&a_id), "A removed");
        assert_eq!(
            os.get(&b_id),
            Some(&MemberRole::Owner),
            "NON-CASCADE: removing A does not drop B (whom A added)",
        );
    }

    #[test]
    fn delegation_event_by_non_owner_rejected() {
        // A member (not an owner) signs `set self owner` — the fold ignores it
        // (granter is not an owner-so-far), so self-promotion via the log is blocked.
        use crate::storage::plaintext::MemberRole;
        let (vault, _creator, member, _cid, member_id, mut pv) = role_fixture_creator_cred();
        cred_no_grant(&mut pv, "cid-member", &member, &member_id);
        push_event(
            &mut pv,
            vault,
            &member,
            "set",
            &member_id,
            MemberRole::Owner,
            1,
            0,
        );
        assert!(
            !owner_set(&pv, vault).contains_key(&member_id),
            "a non-owner's delegation event is ignored (no self-promote via the log)",
        );
    }

    #[test]
    fn delegation_log_dup_seq_replay_rejected() {
        // Two events sharing a `seq` (a reorder/replay attempt): only the first (by
        // sort order) applies; the second is dropped by the monotone-seq guard.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _cid, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        cred_no_grant(&mut pv, "cid-a", &a, &a_id);
        cred_no_grant(&mut pv, "cid-b", &b, &b_id);
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        // Second event REUSES seq 1 → rejected.
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &b_id,
            MemberRole::Owner,
            1,
            0,
        );
        let os = owner_set(&pv, vault);
        // The deterministic (seq, sig) tiebreak keeps EXACTLY ONE seq-1 event; for
        // these fixed keys A's grant signature sorts first, so A applies and B is
        // dropped (the winner is server-independent — same on every implementation).
        assert_eq!(
            os.get(&a_id),
            Some(&MemberRole::Owner),
            "the (seq,sig)-first seq-1 event applies"
        );
        assert!(
            !os.contains_key(&b_id),
            "a duplicate seq is dropped (replay / equivocation guard)"
        );
    }

    #[test]
    fn junk_same_seq_event_does_not_suppress_legit() {
        // Re-audit C1 fix: `last_seq` advances ONLY after an event passes the owner +
        // signature checks, so a well-formed-but-INVALID event that shares a legit
        // event's `seq` (and sorts first — sig = all-zeros) cannot consume the slot and
        // make the dup guard drop the real one. Without the fix a colluding server (no
        // key) could void a `remove` this way and resurrect a removed owner.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _cid, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        cred_no_grant(&mut pv, "cid-a", &a, &a_id);
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        assert_eq!(
            owner_set(&pv, vault).get(&a_id),
            Some(&MemberRole::Owner),
            "A granted @seq1",
        );
        // Junk @seq2: valid owner granter + self-certifying pubkey, but a ZERO signature
        // (sorts FIRST among seq-2 events). It must fail the sig check WITHOUT consuming
        // seq 2.
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .delegation_log
            .push(DelegationEvent {
                op: "set".into(),
                subject_id: "us_ghost".into(),
                role: MemberRole::Owner,
                granter_id: creator.user_id(),
                granter_sig_pub: creator.signing().public_bytes().to_vec(),
                seq: 2,
                role_epoch: 0,
                sig: vec![0u8; 64],
            });
        // The root's REAL `remove A` also at seq 2.
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &a_id,
            MemberRole::Member,
            2,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(
            !os.contains_key(&a_id),
            "the junk seq-2 event did NOT suppress the real remove — A is removed",
        );
        assert!(
            !os.contains_key("us_ghost"),
            "the junk event itself never applied",
        );
    }

    #[test]
    fn event_verifies_via_inline_key_without_cred_row() {
        // Re-audit X2 fix (NON-CASCADE survives offboard): a delegation event carries
        // the granter's signing pubkey INLINE (self-certifying), so it stays verifiable
        // even when the granter has NO cred row in the keyset (their row was deleted at
        // offboard). Here A is an owner ONLY via a log event (no cred at all), and A's
        // grant of B still verifies — so removing A (deleting A's row) would not drop B.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _cid, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        cred_no_grant(&mut pv, "cid-b", &b, &b_id); // B has a cred; A has NONE
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        push_event(&mut pv, vault, &a, "set", &b_id, MemberRole::Owner, 2, 0);
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.get(&a_id),
            Some(&MemberRole::Owner),
            "A is an owner via the log with no cred row",
        );
        assert_eq!(
            os.get(&b_id),
            Some(&MemberRole::Owner),
            "A's grant of B verifies via A's INLINE key — non-cascade survives A having no cred row",
        );
    }

    #[test]
    fn root_succession_transfers_root_and_offboards_creator() {
        // A root transfer (creator offboard): the current root signs a succession to
        // a NEW root, which re-cuts the checkpoint @role_epoch 1. Afterwards the new
        // root is the owner authority and the old creator (not re-granted) is gone.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let newroot = UikRoot::from_root([0x55u8; 32]);
        let newroot_id = newroot.user_id();
        let nr_pub = newroot.signing().public_bytes();
        // Current (genesis) root signs the succession → newroot @role_epoch 1.
        let succ_sig = creator
            .signing()
            .sign(&crate::identity::root_succession_input(
                vault,
                &creator_id,
                &newroot_id,
                &nr_pub,
                1,
            ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .root_succession
            .push(RootSuccession {
                old_root_id: creator_id.clone(),
                new_root_id: newroot_id.clone(),
                new_root_sig_pub: nr_pub.to_vec(),
                role_epoch: 1,
                sig: succ_sig.to_vec(),
            });
        // The succession cert ALREADY derives role_epoch 1 (no separate stored
        // scalar). The NEW root re-cuts the checkpoint @epoch 1 (its own owner grant +
        // a cred); the creator's @epoch-0 grant is now stale.
        let nr_grant = newroot.signing().sign(&crate::identity::role_grant_input(
            vault,
            &newroot_id,
            "owner",
            1,
        ));
        pv.set_uik_cred(
            "cid-newroot".into(),
            newroot_id.clone(),
            nr_pub.to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            nr_grant.to_vec(),
        );
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.get(&newroot_id),
            Some(&MemberRole::Owner),
            "succession installs the new root as the owner authority",
        );
        assert!(
            !os.contains_key(&creator_id),
            "the offboarded creator is no longer an owner after transfer",
        );
    }

    #[test]
    fn forged_succession_does_not_advance_root() {
        // A succession NOT signed by the current root (here: signed by a member) does
        // NOT advance the root — the creator stays root, the attacker's key isn't
        // installed. Fail-closed forward.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, _creator, member, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let evil = UikRoot::from_root([0x66u8; 32]);
        let evil_id = evil.user_id();
        let evil_pub = evil.signing().public_bytes();
        // `member` (NOT the root) signs the succession → verify under the root fails.
        let bad_sig = member
            .signing()
            .sign(&crate::identity::root_succession_input(
                vault,
                &creator_id,
                &evil_id,
                &evil_pub,
                1,
            ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .root_succession
            .push(RootSuccession {
                old_root_id: creator_id.clone(),
                new_root_id: evil_id.clone(),
                new_root_sig_pub: evil_pub.to_vec(),
                role_epoch: 1,
                sig: bad_sig.to_vec(),
            });
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.get(&creator_id),
            Some(&MemberRole::Owner),
            "a forged succession is ignored; the creator stays root",
        );
        assert!(
            !os.contains_key(&evil_id),
            "the attacker's key is not installed as root"
        );
    }

    #[test]
    fn last_owner_cannot_be_removed() {
        // The owner-set can never be EMPTIED (last-owner guard, replacing the old
        // "root is permanently immune" rule). Here the creator is the ONLY owner, so a
        // `remove` or a demote targeting them is ignored — they stay.
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &creator_id,
            MemberRole::Member,
            1,
            0,
        );
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &creator_id,
            MemberRole::Member,
            2,
            0,
        );
        assert_eq!(
            owner_set(&pv, vault).get(&creator_id),
            Some(&MemberRole::Owner),
            "the last owner (here the creator) can't be removed or demoted away",
        );
    }

    #[test]
    fn creator_removable_when_another_owner_exists() {
        // Creator-offboard is just a `remove` (no two-party dance): once there is
        // ANOTHER owner, the creator can be removed via the log like anyone. Their
        // historical grants survive (they were seated at the base for issuance-time
        // authority), so whoever they added stays — the creator just leaves.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &creator_id,
            MemberRole::Member,
            2,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(
            !os.contains_key(&creator_id),
            "the creator can leave (be removed) once another owner exists",
        );
        assert_eq!(
            os.get(&a_id),
            Some(&MemberRole::Owner),
            "the successor owner (added by the creator) stays after the creator leaves",
        );
    }

    #[test]
    fn membership_rollback_is_rejected() {
        // Part 2 (anti-rollback): the current re-key proof commits the delegation-log
        // PREFIX (owner-signed). If a colluding server serves the current generation
        // but a ROLLED-BACK log (an event omitted), the prefix no longer hashes to the
        // committed value → the whole owner-set is distrusted (fail closed), so the
        // server can't un-remove someone by serving an old log at the current gen.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        // creator adds A via a delegation event (seq 1).
        let gsig = creator
            .signing()
            .sign(&crate::identity::delegation_event_input(
                vault,
                "set",
                &a_id,
                "owner",
                &creator_id,
                1,
                0,
            ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .delegation_log
            .push(DelegationEvent {
                op: "set".into(),
                subject_id: a_id.clone(),
                role: MemberRole::Owner,
                granter_id: creator_id.clone(),
                granter_sig_pub: creator.signing().public_bytes().to_vec(),
                seq: 1,
                role_epoch: 0,
                sig: gsig.to_vec(),
            });
        // A re-key (gen 1) commits the membership prefix = [that event's sig].
        let membership = crate::identity::membership_commitment(&[gsig.as_slice()]);
        let commit = rekey_commitment(&[0x01u8; 32]).to_vec();
        let rk_sig = creator
            .signing()
            .sign(&crate::identity::rekey_sig_input(
                vault,
                1,
                &commit,
                &creator_id,
                1,
                &membership,
            ))
            .to_vec();
        {
            let uik = pv.keyset.uik.as_mut().unwrap();
            uik.generation = 1;
            uik.rekey_proof = Some(RekeyProof {
                generation: 1,
                k_commitment: commit,
                sig: rk_sig,
                signer_id: creator_id.clone(),
                membership_len: 1,
                membership_hash: membership.to_vec(),
            });
        }
        // Happy path: the committed log is present → Verified, A is an owner.
        assert!(
            matches!(pv.resolve_membership_trust(vault), MembershipTrust::Verified(_)),
            "matching log prefix → Verified",
        );
        assert_eq!(owner_set(&pv, vault).get(&a_id), Some(&MemberRole::Owner));
        // Rollback: the server drops the committed event → prefix mismatch → Untrusted
        // (the owner-set is NOT silently recomputed without it).
        pv.keyset.uik.as_mut().unwrap().delegation_log.clear();
        assert!(
            matches!(pv.resolve_membership_trust(vault), MembershipTrust::Untrusted),
            "a rolled-back log (committed event omitted) is rejected → Untrusted",
        );
    }

    /// A v1 store holding a legacy `services` record with `entries`.
    fn v1_with_legacy_services(
        keys: VaultKeys,
        vault: &str,
        entries: serde_json::Value,
    ) -> PerItemVault {
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        pv.plant::<sudp::primitives::StdPrimitives>(
            keys,
            vault,
            ItemNs::Aux,
            "services",
            1,
            &ItemPayload::live(ItemNs::Aux, "services".to_string(), entries),
        )
        .unwrap();
        pv
    }

    fn svc_entry(id: &str, host: &str) -> serde_json::Value {
        serde_json::json!({ "service": format!("[service]\nid = \"{id}\"\nhosts = [\"{host}\"]\n") })
    }

    /// Services are the union of the legacy record and the native `service`
    /// items: a native item replaces the legacy entry of its id, a native
    /// tombstone hides it, a native-only item is added. A native item read at
    /// another address than its own derived id is not a service.
    #[test]
    fn services_fold_unions_legacy_and_native_items() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x5au8; 32];
        let keys = VaultKeys::single(&k);
        let vault = "vault-v1";
        let mut pv = v1_with_legacy_services(
            keys,
            vault,
            serde_json::json!({ "a": svc_entry("a", "a.old"), "b": svc_entry("b", "b.dev") }),
        );
        let put = |pv: &mut PerItemVault, p: ItemPayload| {
            let name = p.name.clone();
            pv.seal_and_bump::<S>(keys, vault, ItemNs::Service, &name, &p)
                .unwrap();
        };
        put(
            &mut pv,
            ItemPayload::live(ItemNs::Service, "a", svc_entry("a", "a.new")),
        );
        put(&mut pv, ItemPayload::tombstone(ItemNs::Service, "b"));
        put(
            &mut pv,
            ItemPayload::live(ItemNs::Service, "c", svc_entry("c", "c.dev")),
        );
        // A `service` payload sealed at another id is not read as that service.
        let elsewhere =
            ItemCtx::for_item::<S>(keys.id_seed, vault, ItemNs::Service, "zz", 1).unwrap();
        let ct = seal_item::<S>(
            keys.content,
            &elsewhere,
            &ItemPayload::live(ItemNs::Service, "d", svc_entry("d", "d.dev")),
        )
        .unwrap();
        pv.put_raw(elsewhere.item_id_b64(), 1, ct);
        // Nor one that names another id (`a`) at `zz2`'s address.
        let elsewhere =
            ItemCtx::for_item::<S>(keys.id_seed, vault, ItemNs::Service, "zz2", 1).unwrap();
        let ct = seal_item::<S>(
            keys.content,
            &elsewhere,
            &ItemPayload::live(ItemNs::Service, "a", svc_entry("a", "evil.dev")),
        )
        .unwrap();
        pv.put_raw(elsewhere.item_id_b64(), 1, ct);
        let services = pv.fold_view::<S>(keys, vault).unwrap().aux.services;
        assert_eq!(services.keys().collect::<Vec<_>>(), ["a", "c"]);
        assert_eq!(
            serde_json::to_value(&services["a"]).unwrap(),
            svc_entry("a", "a.new")
        );
    }

    /// A same-item conflict on a service keeps both, like a connection: the
    /// daemon's write over a row that changed since its base leaves theirs at
    /// the canonical id and puts ours beside it as the record `"<id>
    /// (conflict copy)"` at that name's own id, dirty, so the push sends it as
    /// a create. The copy folds under its own name and no service is loaded
    /// from it.
    #[test]
    fn service_conflict_keeps_both_and_the_copy_is_not_used() {
        use crate::storage::item::conflict_copy_name;
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x5au8; 32];
        let keys = VaultKeys::single(&k);
        let (vault, _, _, _, _, mut pv) = role_fixture_creator_cred();
        let mut view = pv.fold_view::<S>(keys, vault).unwrap();
        let entry = |host: &str| -> crate::service::source::StoredService {
            serde_json::from_value(svc_entry("acme", host)).unwrap()
        };
        view.aux.services.insert("acme".into(), entry("a.base"));
        pv.reconcile_from_view::<S>(keys, vault, &view, ReconcileBase::OwnFold)
            .unwrap();
        let base = ViewBase::of(&pv.fold_view::<S>(keys, vault).unwrap()).unwrap();
        // Theirs lands (a pull) after our base was taken.
        let theirs = ItemPayload::live(ItemNs::Service, "acme", svc_entry("acme", "a.theirs"));
        let (canon, their_version) = pv
            .seal_and_bump::<S>(keys, vault, ItemNs::Service, "acme", &theirs)
            .unwrap();
        // Ours, from the base.
        let mut ours_view = pv.fold_view::<S>(keys, vault).unwrap();
        ours_view
            .aux
            .services
            .insert("acme".into(), entry("a.ours"));
        pv.reconcile_from_view::<S>(keys, vault, &ours_view, ReconcileBase::Since(&base))
            .unwrap();

        let copy_id =
            wire_id_for::<S>(keys.id_seed, ItemNs::Service, &conflict_copy_name("acme")).unwrap();
        let copy = pv.get_item(&copy_id).expect("ours kept as a conflict copy");
        assert_eq!(copy.synced_version, 0, "dirty: pushed as a create");
        assert_eq!(
            pv.get_item(&canon).unwrap().version,
            their_version,
            "theirs stays"
        );
        let services = pv.fold_view::<S>(keys, vault).unwrap().aux.services;
        assert_eq!(
            serde_json::to_value(&services["acme"]).unwrap(),
            svc_entry("acme", "a.theirs")
        );
        let copy_name = conflict_copy_name("acme");
        assert_eq!(copy_name, "acme (conflict copy)");
        assert_eq!(
            serde_json::to_value(&services[&copy_name]).unwrap(),
            svc_entry("acme", "a.ours")
        );
        let (_, skipped) = crate::service::vault_custom_services(
            &services,
            &crate::service::ServiceRegistry::load(),
        );
        assert!(skipped
            .iter()
            .any(|(id, why)| id == &copy_name && why == crate::service::CONFLICT_COPY_REASON));
        // A later write of the view never rewrites or deletes the copy.
        let before = pv.items.len();
        let mut again = pv.fold_view::<S>(keys, vault).unwrap();
        let base = ViewBase::of(&again).unwrap();
        again.aux.services.insert("other".into(), entry("o.dev"));
        pv.reconcile_from_view::<S>(keys, vault, &again, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(pv.items.len(), before + 1, "only `other` was written");
    }

    /// Native service items are data records: written unsigned by the daemon's
    /// reconcile on every keyset (a v2 keyset too, where they are honored
    /// unsigned), never as the legacy record; a dropped service, legacy-only
    /// included, becomes a native tombstone.
    #[test]
    fn reconcile_writes_services_as_native_items_on_every_keyset() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x5au8; 32];
        let keys = VaultKeys::single(&k);
        let (v2_vault, _, _, _, _, v2) = role_fixture_creator_cred();
        let v1_vault = "vault-v1";
        let v1 = v1_with_legacy_services(
            keys,
            v1_vault,
            serde_json::json!({ "old": svc_entry("old", "o.dev") }),
        );
        for (vault, mut pv) in [(v1_vault, v1), (v2_vault, v2)] {
            let legacy_id = wire_id_for::<S>(keys.id_seed, ItemNs::Aux, "services").unwrap();
            let legacy_before = pv.items.get(&legacy_id).map(|r| (r.version, r.ct.clone()));
            let mut view = pv.fold_view::<S>(keys, vault).unwrap();
            let base = ViewBase::of(&view).unwrap();
            view.aux.services.insert(
                "acme".into(),
                serde_json::from_value(svc_entry("acme", "a.dev")).unwrap(),
            );
            view.aux.services.remove("old");
            pv.reconcile_from_view::<S>(keys, vault, &view, ReconcileBase::Since(&base))
                .unwrap();

            let acme = wire_id_for::<S>(keys.id_seed, ItemNs::Service, "acme").unwrap();
            let row = &pv.items[&acme];
            assert!(
                row.sig.is_none() && row.signer.is_none(),
                "{vault}: unsigned"
            );
            assert!(
                row.version > row.synced_version,
                "{vault}: dirty, pushed by the sync"
            );
            assert_eq!(
                pv.items.get(&legacy_id).map(|r| (r.version, r.ct.clone())),
                legacy_before,
                "{vault}: the legacy record is never rewritten"
            );
            let services = pv.fold_view::<S>(keys, vault).unwrap().aux.services;
            assert_eq!(services.keys().collect::<Vec<_>>(), ["acme"], "{vault}");
        }
    }

    /// Seal `payload` at `(ns, name)` version 1 and sign it as `signer`
    /// (sidecar, record type `ty`): a row an owner's console wrote.
    pub(crate) fn plant_signed(
        pv: &mut PerItemVault,
        keys: VaultKeys,
        vault: &str,
        signer: &crate::crypto::vault_key::UikRoot,
        ty: &str,
        payload: &ItemPayload,
    ) -> String {
        use base64::engine::general_purpose::STANDARD;
        type S = sudp::primitives::StdPrimitives;
        let ctx =
            ItemCtx::for_item::<S>(keys.id_seed, vault, payload.ns, &payload.name, 1).unwrap();
        let ct = seal_item::<S>(keys.content, &ctx, payload).unwrap();
        let input = crate::identity::record_signature_input(
            ty,
            ctx.id_bytes(),
            1,
            vault,
            &ct,
            !payload.is_tombstone(),
            &signer.user_id(),
        );
        let sig = STANDARD.encode(signer.signing().sign(&input));
        pv.put_raw_signed(ctx.item_id_b64(), 1, ct, Some(sig), Some(signer.user_id()));
        ctx.item_id_b64()
    }

    /// LEGACY(services row) migration, on a vault without a keyset: every
    /// entry the fold reads from the legacy record without a native row is
    /// copied to a native item (object form); the legacy record is
    /// tombstoned once every copy is held; the same services are read.
    /// Idempotent. A vault with a keyset is the owner's console's: nothing is
    /// written.
    #[test]
    fn legacy_services_migrate_to_native_items() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x5au8; 32];
        let keys = VaultKeys::single(&k);
        let fold =
            |pv: &PerItemVault, vault: &str| pv.fold_view::<S>(keys, vault).unwrap().aux.services;

        // v1: `a` already native (wins), `b` legacy-only and plain text (moves).
        let vault = "vault-v1";
        let mut v1 = v1_with_legacy_services(
            keys,
            vault,
            serde_json::json!({ "a": svc_entry("a", "a.old"), "b": "[service]\nid = \"b\"\n" }),
        );
        v1.seal_and_bump::<S>(
            keys,
            vault,
            ItemNs::Service,
            "a",
            &ItemPayload::live(ItemNs::Service, "a", svc_entry("a", "a.new")),
        )
        .unwrap();
        let before: Vec<String> = fold(&v1, vault).keys().cloned().collect();
        let a_id = wire_id_for::<S>(keys.id_seed, ItemNs::Service, "a").unwrap();
        let a_version = v1.items[&a_id].version;
        let changed = v1.migrate_legacy_copies::<S>(keys, vault);
        assert_eq!(changed.len(), 1, "b copied");
        let changed = v1.retire_legacy_rows::<S>(keys, vault, false);
        assert_eq!(changed.len(), 1, "the legacy record tombstoned");
        assert_eq!(v1.items[&a_id].version, a_version, "the native item wins");
        assert!(v1
            .open_item::<S>(keys, vault, ItemNs::Aux, "services")
            .unwrap()
            .unwrap()
            .is_tombstone());
        assert_eq!(
            v1.open_item::<S>(keys, vault, ItemNs::Service, "b")
                .unwrap()
                .unwrap()
                .body,
            serde_json::json!({ "service": "[service]\nid = \"b\"\n" })
        );
        let after = fold(&v1, vault);
        assert_eq!(after.keys().cloned().collect::<Vec<_>>(), before);
        assert_eq!(
            serde_json::to_value(&after["a"]).unwrap(),
            svc_entry("a", "a.new")
        );
        assert!(v1.migrate_legacy_copies::<S>(keys, vault).is_empty());
        assert!(v1.retire_legacy_rows::<S>(keys, vault, false).is_empty());

        // v2 with an owner-signed legacy record: read, but left to the console.
        let (vault, creator, _, _, _, mut v2) = role_fixture_creator_cred();
        plant_signed(
            &mut v2,
            keys,
            vault,
            &creator,
            "services",
            &ItemPayload::live(
                ItemNs::Aux,
                "services",
                serde_json::json!({ "x": svc_entry("x", "x.dev") }),
            ),
        );
        assert!(fold(&v2, vault).contains_key("x"));
        let n = v2.items.len();
        assert!(v2.migrate_legacy_copies::<S>(keys, vault).is_empty());
        assert!(v2.retire_legacy_rows::<S>(keys, vault, false).is_empty());
        assert_eq!(v2.items.len(), n, "nothing written with a keyset");
        // An unsigned legacy record on a v2 keyset is not read at all.
        let (vault, _, _, _, _, mut v2u) = role_fixture_creator_cred();
        v2u.plant::<S>(
            keys,
            vault,
            ItemNs::Aux,
            "services",
            1,
            &ItemPayload::live(
                ItemNs::Aux,
                "services",
                serde_json::json!({ "y": svc_entry("y", "y.dev") }),
            ),
        )
        .unwrap();
        assert!(fold(&v2u, vault).is_empty());
    }

    /// A policy with every part, stores, store order and retention, for the
    /// owner-config tests.
    fn full_aux() -> crate::storage::plaintext::VaultAux {
        let mut aux = crate::storage::plaintext::VaultAux::initial();
        aux.policy = Some(
            serde_json::from_value(serde_json::json!({
                "timeout": 120,
                "default": { "read": "allow", "write": "ask", "ttl": 60 },
                "categories": {
                    "ai": { "read": "allow", "write": "allow" },
                    "payments": { "write": "deny" }
                },
                "connections": {
                    "gmail": { "default": { "write": "ask" } },
                    "stripe-work": { "rules": { "pay": { "level": "deny" } } }
                }
            }))
            .unwrap(),
        );
        aux.stores.insert(
            "gcp-1".into(),
            serde_json::from_value(serde_json::json!({
                "kind": "gcp-sm", "category": "value", "project_id": "p1"
            }))
            .unwrap(),
        );
        aux.store_order = vec!["native-secrets".into(), "gcp-1".into()];
        aux.audit_retention_days = Some(30);
        aux
    }

    /// The owner-config fields as JSON, to compare two views.
    fn config_json(aux: &crate::storage::plaintext::VaultAux) -> serde_json::Value {
        serde_json::json!({
            "policy": aux.policy,
            "stores": aux.stores,
            "store_order": aux.store_order,
            "audit_retention_days": aux.audit_retention_days,
        })
    }

    /// A store on a vault without a keyset.
    fn v1_store() -> PerItemVault {
        PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap()
    }

    /// A row this key cannot open is never written over: a change that
    /// would (an upsert of its record, the native tombstone that removes a
    /// legacy-only service) is refused and reported, the row is left as it
    /// is, and every other change still applies.
    #[test]
    fn a_row_that_cannot_be_read_is_never_written_over() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x66u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-unreadable";
        let mut pv = v1_store();
        pv.plant::<S>(
            keys,
            vid,
            ItemNs::Aux,
            "services",
            1,
            &ItemPayload::live(
                ItemNs::Aux,
                "services",
                serde_json::json!({ "acme": svc_entry("acme", "a.dev") }),
            ),
        )
        .unwrap();
        // Rows sealed under another key at `service:acme` and `secret:B`.
        let garbage = vec![7u8; 60];
        let svc_wire = wire_id_for::<S>(&k, ItemNs::Service, "acme").unwrap();
        let b_wire = wire_id_for::<S>(&k, ItemNs::Secret, "B").unwrap();
        pv.put_raw(svc_wire.clone(), 3, garbage.clone());
        pv.put_raw(b_wire.clone(), 2, garbage.clone());
        let view = pv.fold_view::<S>(keys, vid).unwrap();
        assert!(view.aux.services.contains_key("acme"), "the legacy entry reads");
        let base = ViewBase::of(&view).unwrap();
        let mut changed = pv.fold_view::<S>(keys, vid).unwrap();
        changed.aux.services.remove("acme");
        changed.native_secrets.insert("B".into(), b"new".to_vec());
        changed.native_secrets.insert("C".into(), b"c".to_vec());
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &changed, ReconcileBase::Since(&base))
            .unwrap();
        let refused: Vec<&String> = r.refused.iter().map(|(id, _)| id).collect();
        assert_eq!(refused.len(), 2, "{:?}", r.refused);
        assert!(refused.contains(&&svc_wire) && refused.contains(&&b_wire));
        assert!(r
            .refused
            .iter()
            .all(|(_, why)| why.contains("changed with a vault key this device does not have")));
        for (wire, v) in [(&svc_wire, 3), (&b_wire, 2)] {
            let row = pv.get_item(wire).unwrap();
            assert_eq!((row.version, &row.ct), (v, &garbage), "left as it is");
        }
        // The rest applied.
        assert_eq!(r.changed.len(), 1);
        assert_eq!(pv.fold_view::<S>(keys, vid).unwrap().native_secrets["C"], b"c");

        // After a keyset refresh, with keys of the current generation, both
        // still open under no key this member holds: confirmed, and the same
        // change now goes over them at their next versions.
        assert!(pv.confirm_unreadable::<S>(keys, vid));
        assert!(pv.get_item(&svc_wire).unwrap().unreadable_confirmed);
        assert!(!pv.confirm_unreadable::<S>(keys, vid), "nothing new");
        let view = pv.fold_view::<S>(keys, vid).unwrap();
        let base = ViewBase::of(&view).unwrap();
        let mut changed = pv.fold_view::<S>(keys, vid).unwrap();
        changed.aux.services.remove("acme");
        changed.native_secrets.insert("B".into(), b"new".to_vec());
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &changed, ReconcileBase::Since(&base))
            .unwrap();
        assert!(r.refused.is_empty(), "{:?}", r.refused);
        assert_eq!(pv.get_item(&svc_wire).unwrap().version, 4);
        assert!(pv.get_item(&svc_wire).unwrap().tombstone);
        assert_eq!(pv.get_item(&b_wire).unwrap().version, 3);
        assert!(!pv.get_item(&b_wire).unwrap().unreadable_confirmed);
        let after = pv.fold_view::<S>(keys, vid).unwrap();
        assert_eq!(after.native_secrets["B"], b"new");
        assert!(!after.aux.services.contains_key("acme"));

        // Keys of an earlier generation (a session from before the key
        // changed) confirm nothing.
        let fx = rekeyed_fixture();
        let mut stale = fx.pv.clone();
        stale.put_raw(svc_wire.clone(), 3, garbage.clone());
        let old_bundle = crate::storage::item::vault_key_bundle(&fx.id_seed, &fx.c_old);
        assert!(!stale.confirm_unreadable::<S>(VaultKeys::from_material(&old_bundle), fx.vault));
        assert!(!stale.get_item(&svc_wire).unwrap().unreadable_confirmed);
    }

    /// Owner-config is written at its native records, one per edit unit
    /// (`policy:`, `policy:category:<tag>`, `policy:connection:<id>`,
    /// `store:<id>`, `store_order:`, `audit_retention_days:`), and the fold
    /// reassembles exactly the same fields. Nothing at `aux:*`. On a keyset
    /// vault this process writes no owner-config.
    #[test]
    fn owner_config_round_trips_through_its_native_records() {
        use crate::storage::plaintext::VaultPlaintextView;
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x61u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-cfg";
        let view = VaultPlaintextView {
            aux: full_aux(),
            native_secrets: Default::default(),
            native_secret_notes: Default::default(),
        };
        // Seed (enroll) and reconcile both write the native records.
        let mut seeded = v1_store();
        seeded.seed_items_from_view::<S>(keys, vid, &view).unwrap();
        let mut reconciled = v1_store();
        reconciled
            .reconcile_from_view::<S>(keys, vid, &view, ReconcileBase::OwnFold)
            .unwrap();
        for pv in [&seeded, &reconciled] {
            let folded = pv.fold_view::<S>(keys, vid).unwrap();
            assert_eq!(config_json(&folded.aux), config_json(&view.aux));
            for (ns, name) in [
                (ItemNs::Policy, ""),
                (ItemNs::Policy, "category:ai"),
                (ItemNs::Policy, "category:payments"),
                (ItemNs::Policy, "connection:gmail"),
                (ItemNs::Policy, "connection:stripe-work"),
                (ItemNs::Store, "native-secrets"),
                (ItemNs::Store, "gcp-1"),
                (ItemNs::StoreOrder, ""),
                (ItemNs::AuditRetentionDays, ""),
            ] {
                assert!(
                    pv.open_item::<S>(keys, vid, ns, name).unwrap().is_some(),
                    "{ns:?}:{name}"
                );
            }
            for field in ["policy", "stores", "store_order", "audit_retention_days"] {
                assert!(pv
                    .open_item::<S>(keys, vid, ItemNs::Aux, field)
                    .unwrap()
                    .is_none());
            }
            assert_eq!(
                pv.open_item::<S>(keys, vid, ItemNs::Policy, "")
                    .unwrap()
                    .unwrap()
                    .body,
                serde_json::json!({ "timeout": 120, "default": { "read": "allow", "write": "ask", "ttl": 60 } }),
                "the policy's own fields only"
            );
        }
        // An edit is one record: dropping a category tombstones only it.
        let mut pv = reconciled;
        let base = ViewBase::of(&pv.fold_view::<S>(keys, vid).unwrap()).unwrap();
        let mut edited = pv.fold_view::<S>(keys, vid).unwrap();
        edited
            .aux
            .policy
            .as_mut()
            .unwrap()
            .categories
            .remove("payments");
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &edited, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(
            r.changed,
            [wire_id_for::<S>(&k, ItemNs::Policy, "category:payments").unwrap()]
        );
        assert_eq!(
            config_json(&pv.fold_view::<S>(keys, vid).unwrap().aux),
            config_json(&edited.aux)
        );

        // A keyset vault: no owner-config is written by this process.
        let (vault, _, _, _, _, mut v2) = role_fixture_creator_cred();
        let r = v2
            .reconcile_from_view::<S>(keys, vault, &view, ReconcileBase::OwnFold)
            .unwrap();
        assert!(r.changed.is_empty(), "{:?}", r.changed);
        assert!(v2
            .seal_and_bump::<S>(
                keys,
                vault,
                ItemNs::Policy,
                "",
                &ItemPayload::live(ItemNs::Policy, "", serde_json::json!({})),
            )
            .is_err());
    }

    /// The fold reads owner-config per key: an honored native record (live or
    /// tombstone) wins its key; every other key comes from the legacy row.
    /// A half-finished migration (some native policy records written, the
    /// legacy row still live) reads the full, correct policy. An unknown
    /// `policy` name is ignored. On a keyset vault an unsigned native record
    /// is not honored (its key falls back to the legacy row); an owner-signed
    /// one wins.
    #[test]
    fn owner_config_reads_native_first_per_key() {
        use crate::storage::plaintext::VaultAux;
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x62u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-half";
        let legacy = full_aux();
        let legacy_policy = serde_json::to_value(&legacy.policy).unwrap();
        let mut pv = v1_store();
        pv.plant::<S>(
            keys,
            vid,
            ItemNs::Aux,
            "policy",
            1,
            &ItemPayload::live(ItemNs::Aux, "policy", legacy_policy.clone()),
        )
        .unwrap();
        pv.plant::<S>(
            keys,
            vid,
            ItemNs::Aux,
            "stores",
            1,
            &ItemPayload::live(
                ItemNs::Aux,
                "stores",
                serde_json::to_value(&legacy.stores).unwrap(),
            ),
        )
        .unwrap();
        pv.plant::<S>(
            keys,
            vid,
            ItemNs::Aux,
            "audit_retention_days",
            1,
            &ItemPayload::live(ItemNs::Aux, "audit_retention_days", serde_json::json!(30)),
        )
        .unwrap();
        // The legacy rows alone read as before.
        let only_legacy = pv.fold_view::<S>(keys, vid).unwrap().aux;
        assert_eq!(
            serde_json::to_value(&only_legacy.policy).unwrap(),
            legacy_policy
        );
        assert_eq!(only_legacy.stores.len(), 2);

        // Half-finished: the global part and one category written natively
        // (with new values), one connection deleted natively; the rest only
        // in the legacy row.
        let put = |pv: &mut PerItemVault, ns: ItemNs, name: &str, p: ItemPayload| {
            pv.seal_and_bump::<S>(keys, vid, ns, name, &p).unwrap();
        };
        put(
            &mut pv,
            ItemNs::Policy,
            "",
            ItemPayload::live(ItemNs::Policy, "", serde_json::json!({ "timeout": 300 })),
        );
        put(
            &mut pv,
            ItemNs::Policy,
            "category:ai",
            ItemPayload::live(
                ItemNs::Policy,
                "category:ai",
                serde_json::json!({ "write": "ask" }),
            ),
        );
        put(
            &mut pv,
            ItemNs::Policy,
            "connection:gmail",
            ItemPayload::tombstone(ItemNs::Policy, "connection:gmail"),
        );
        put(
            &mut pv,
            ItemNs::Store,
            "gcp-1",
            ItemPayload::tombstone(ItemNs::Store, "gcp-1"),
        );
        // An unknown policy name is ignored, whatever it holds.
        pv.plant::<S>(
            keys,
            vid,
            ItemNs::Policy,
            "rules:pay",
            1,
            &ItemPayload::live(
                ItemNs::Policy,
                "rules:pay",
                serde_json::json!({ "level": "allow" }),
            ),
        )
        .unwrap();
        let aux: VaultAux = pv.fold_view::<S>(keys, vid).unwrap().aux;
        let mut want =
            serde_json::from_value::<crate::core::policy::Policy>(legacy_policy.clone()).unwrap();
        want.timeout = Some(300);
        want.default = None; // the native global part has none: it wins
        want.categories.insert(
            "ai".into(),
            serde_json::from_value(serde_json::json!({ "write": "ask" })).unwrap(),
        );
        want.connections.remove("gmail");
        assert_eq!(
            serde_json::to_value(&aux.policy).unwrap(),
            serde_json::to_value(Some(&want)).unwrap(),
            "native keys win, every other key from the legacy row"
        );
        assert!(aux
            .policy
            .as_ref()
            .unwrap()
            .categories
            .contains_key("payments"));
        assert!(aux
            .policy
            .as_ref()
            .unwrap()
            .connections
            .contains_key("stripe-work"));
        assert_eq!(
            aux.stores.keys().collect::<Vec<_>>(),
            ["native-secrets"],
            "a native tombstone hides the legacy store"
        );
        assert_eq!(
            aux.audit_retention_days,
            Some(30),
            "legacy, no native record"
        );

        // A keyset vault: an unsigned native record is not honored; an
        // owner-signed one wins its key.
        let (vault, creator, _, _, _, mut v2) = role_fixture_creator_cred();
        plant_signed(
            &mut v2,
            keys,
            vault,
            &creator,
            "policy",
            &ItemPayload::live(ItemNs::Aux, "policy", legacy_policy.clone()),
        );
        v2.plant::<S>(
            keys,
            vault,
            ItemNs::Policy,
            "",
            1,
            &ItemPayload::live(ItemNs::Policy, "", serde_json::json!({ "timeout": 1 })),
        )
        .unwrap();
        let read = v2.fold_view::<S>(keys, vault).unwrap().aux.policy.unwrap();
        assert_eq!(read.timeout, Some(120), "unsigned native: not honored");
        plant_signed(
            &mut v2,
            keys,
            vault,
            &creator,
            "policy",
            &ItemPayload::live(
                ItemNs::Policy,
                "category:ai",
                serde_json::json!({ "write": "deny" }),
            ),
        );
        plant_signed(
            &mut v2,
            keys,
            vault,
            &creator,
            "policy",
            &ItemPayload::tombstone(ItemNs::Policy, "connection:gmail"),
        );
        let read = v2.fold_view::<S>(keys, vault).unwrap().aux.policy.unwrap();
        assert_eq!(
            serde_json::to_value(&read.categories["ai"]).unwrap(),
            serde_json::json!({ "write": "deny" }),
            "owner-signed native wins its key"
        );
        assert!(
            !read.connections.contains_key("gmail"),
            "a signed tombstone wins"
        );
        assert!(read.categories.contains_key("payments"));
    }

    /// Defaults and first writes: a kind with no native record and no legacy
    /// row reads its default (the native-secrets store); its first write
    /// writes the whole kind, so adding a store keeps the default one; once a
    /// native record of the kind exists there is no implicit default.
    /// Removing a key that only the legacy row holds writes a native
    /// tombstone, so the legacy entry does not come back.
    #[test]
    fn owner_config_first_write_and_legacy_only_removal() {
        use crate::storage::plaintext::NATIVE_SECRETS_ID;
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x64u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-first";
        let gcp: crate::storage::plaintext::Store =
            serde_json::from_value(serde_json::json!({ "kind": "gcp-sm", "category": "value" }))
                .unwrap();

        // No owner-config record at all: the defaults.
        let mut pv = v1_store();
        let view = pv.fold_view::<S>(keys, vid).unwrap();
        assert_eq!(
            view.aux.stores.keys().collect::<Vec<_>>(),
            [NATIVE_SECRETS_ID]
        );
        // Add a store: the whole kind is written, the default store stays.
        let base = ViewBase::of(&view).unwrap();
        let mut added = pv.fold_view::<S>(keys, vid).unwrap();
        added.aux.stores.insert("gcp-1".into(), gcp.clone());
        pv.reconcile_from_view::<S>(keys, vid, &added, ReconcileBase::Since(&base))
            .unwrap();
        assert!(pv
            .open_item::<S>(keys, vid, ItemNs::Store, NATIVE_SECRETS_ID)
            .unwrap()
            .is_some());
        assert_eq!(
            pv.fold_view::<S>(keys, vid)
                .unwrap()
                .aux
                .stores
                .keys()
                .collect::<Vec<_>>(),
            ["gcp-1", NATIVE_SECRETS_ID]
        );

        // A native store record alone: no implicit default.
        let mut only = v1_store();
        only.seal_and_bump::<S>(
            keys,
            vid,
            ItemNs::Store,
            "gcp-1",
            &ItemPayload::live(ItemNs::Store, "gcp-1", serde_json::to_value(&gcp).unwrap()),
        )
        .unwrap();
        assert_eq!(
            only.fold_view::<S>(keys, vid)
                .unwrap()
                .aux
                .stores
                .keys()
                .collect::<Vec<_>>(),
            ["gcp-1"]
        );

        // Remove a store only the legacy row holds: a native tombstone.
        let mut legacy = v1_store();
        let mut stores = crate::storage::plaintext::VaultAux::initial().stores;
        stores.insert("gcp-1".into(), gcp);
        legacy
            .plant::<S>(
                keys,
                vid,
                ItemNs::Aux,
                "stores",
                1,
                &ItemPayload::live(
                    ItemNs::Aux,
                    "stores",
                    serde_json::to_value(&stores).unwrap(),
                ),
            )
            .unwrap();
        let view = legacy.fold_view::<S>(keys, vid).unwrap();
        let base = ViewBase::of(&view).unwrap();
        let mut removed = legacy.fold_view::<S>(keys, vid).unwrap();
        removed.aux.stores.remove("gcp-1");
        legacy
            .reconcile_from_view::<S>(keys, vid, &removed, ReconcileBase::Since(&base))
            .unwrap();
        assert!(legacy
            .open_item::<S>(keys, vid, ItemNs::Store, "gcp-1")
            .unwrap()
            .unwrap()
            .is_tombstone());
        assert_eq!(
            legacy
                .fold_view::<S>(keys, vid)
                .unwrap()
                .aux
                .stores
                .keys()
                .collect::<Vec<_>>(),
            [NATIVE_SECRETS_ID],
            "the legacy entry does not come back; the other one still reads"
        );
    }

    /// Mark every dirty row of `pv` as pushed (the cloud now holds it),
    /// except `keep_dirty`.
    fn mark_pushed(pv: &mut PerItemVault, keep_dirty: &[&str]) {
        for (id, row) in pv.items.iter_mut() {
            if !keep_dirty.contains(&id.as_str()) {
                row.synced_version = row.version;
            }
        }
    }

    /// LEGACY(aux addressing) migration on a vault without a keyset. Step 1
    /// copies every entry of every legacy row the fold reads to its native
    /// record (a key that already has an honored native record keeps it);
    /// the legacy rows stay. Step 2 tombstones a legacy row only once every
    /// one of its copies is held on the cloud: a copy that did not land
    /// keeps its row live. The fold reads the same throughout; `aux:secret_order`
    /// (the console's) is never touched. Idempotent. A keyset vault: nothing.
    #[test]
    fn legacy_rows_are_retired_only_after_their_copies_land() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x63u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-mig";
        let legacy = full_aux();
        let mut pv = v1_store();
        for (field, body) in [
            ("policy", serde_json::to_value(&legacy.policy).unwrap()),
            ("stores", serde_json::to_value(&legacy.stores).unwrap()),
            (
                "store_order",
                serde_json::to_value(&legacy.store_order).unwrap(),
            ),
            ("audit_retention_days", serde_json::json!(30)),
            ("secret_order", serde_json::json!(["A", "B"])),
            (
                "services",
                serde_json::json!({ "acme": svc_entry("acme", "a.dev") }),
            ),
        ] {
            pv.plant::<S>(
                keys,
                vid,
                ItemNs::Aux,
                field,
                1,
                &ItemPayload::live(ItemNs::Aux, field, body),
            )
            .unwrap();
        }
        // Half-finished already: one native category with another value.
        pv.seal_and_bump::<S>(
            keys,
            vid,
            ItemNs::Policy,
            "category:ai",
            &ItemPayload::live(
                ItemNs::Policy,
                "category:ai",
                serde_json::json!({ "write": "deny" }),
            ),
        )
        .unwrap();
        mark_pushed(&mut pv, &[]);
        let ai_id = wire_id_for::<S>(&k, ItemNs::Policy, "category:ai").unwrap();
        let ai_version = pv.items[&ai_id].version;
        let read = |pv: &PerItemVault| {
            let v = pv.fold_view::<S>(keys, vid).unwrap();
            (
                config_json(&v.aux),
                serde_json::to_value(&v.aux.services).unwrap(),
            )
        };
        let before = read(&pv);
        let secret_order_id = wire_id_for::<S>(&k, ItemNs::Aux, "secret_order").unwrap();
        let secret_order_row = pv.items[&secret_order_id].clone();
        let legacy_live = |pv: &PerItemVault, field: &str| {
            !pv.open_item::<S>(keys, vid, ItemNs::Aux, field)
                .unwrap()
                .unwrap()
                .is_tombstone()
        };

        // Step 1: policy root + payments + 2 connections (ai kept); stores: 2;
        // store_order; retention; the service. No legacy row is touched.
        let copies = pv.migrate_legacy_copies::<S>(keys, vid);
        assert_eq!(copies.len(), 4 + 2 + 1 + 1 + 1, "{copies:?}");
        assert_eq!(
            pv.items[&ai_id].version, ai_version,
            "a native key keeps its record"
        );
        // Each copy is marked as written by SafeClaw's automatic upgrade.
        assert!(copies.iter().all(|id| pv.items[id].upgrade));
        assert!(!pv.items[&ai_id].upgrade);
        for field in [
            "policy",
            "stores",
            "store_order",
            "audit_retention_days",
            "services",
        ] {
            assert!(
                legacy_live(&pv, field),
                "aux:{field} stays until its copies land"
            );
        }
        assert_eq!(read(&pv), before, "the same configuration is read");

        // Nothing pushed yet: nothing retired.
        assert!(pv.retire_legacy_rows::<S>(keys, vid, true).is_empty());
        // Every copy landed but `store_order:` (an error, a refusal, a
        // conflict left for later): its legacy row stays live, the others go.
        let order_id = wire_id_for::<S>(&k, ItemNs::StoreOrder, "").unwrap();
        mark_pushed(&mut pv, &[order_id.as_str()]);
        let retired = pv.retire_legacy_rows::<S>(keys, vid, true);
        assert_eq!(retired.len(), 4, "{retired:?}");
        assert!(retired.iter().all(|id| pv.items[id].upgrade));
        assert!(legacy_live(&pv, "store_order"));
        for field in ["policy", "stores", "audit_retention_days", "services"] {
            assert!(!legacy_live(&pv, field), "aux:{field} retired");
        }
        assert_eq!(read(&pv), before);
        // A later run, once it landed, retires it.
        mark_pushed(&mut pv, &[]);
        assert_eq!(pv.retire_legacy_rows::<S>(keys, vid, true).len(), 1);
        assert!(!legacy_live(&pv, "store_order"));
        let row = &pv.items[&secret_order_id];
        assert!(row.version == secret_order_row.version && row.ct == secret_order_row.ct);
        assert_eq!(read(&pv), before, "the same configuration is read");
        mark_pushed(&mut pv, &[]);
        assert!(
            pv.migrate_legacy_copies::<S>(keys, vid).is_empty(),
            "idempotent"
        );
        assert!(
            pv.retire_legacy_rows::<S>(keys, vid, true).is_empty(),
            "idempotent"
        );
        // A person's later write of a record is theirs, not the upgrade's.
        let (iid, _) = pv
            .seal_and_bump::<S>(
                keys,
                vid,
                ItemNs::AuditRetentionDays,
                "",
                &ItemPayload::live(ItemNs::AuditRetentionDays, "", serde_json::json!(60)),
            )
            .unwrap();
        assert!(!pv.items[&iid].upgrade);

        // Each row on its own: an unparseable `aux:services` or
        // `aux:store_order` is left as it is and blocks nothing else.
        let mut bad = v1_store();
        for (field, body) in [
            ("store_order", serde_json::json!({ "not": "a list" })),
            ("services", serde_json::json!("not a map")),
            ("audit_retention_days", serde_json::json!(7)),
        ] {
            bad.plant::<S>(
                keys,
                vid,
                ItemNs::Aux,
                field,
                1,
                &ItemPayload::live(ItemNs::Aux, field, body),
            )
            .unwrap();
        }
        assert_eq!(bad.migrate_legacy_copies::<S>(keys, vid).len(), 1);
        assert_eq!(bad.retire_legacy_rows::<S>(keys, vid, false).len(), 1);
        assert!(!bad
            .open_item::<S>(keys, vid, ItemNs::Aux, "store_order")
            .unwrap()
            .unwrap()
            .is_tombstone());
        assert!(!bad
            .open_item::<S>(keys, vid, ItemNs::Aux, "services")
            .unwrap()
            .unwrap()
            .is_tombstone());

        // A keyset vault: the owner's console migrates; nothing is written here.
        let (vault, creator, _, _, _, mut v2) = role_fixture_creator_cred();
        plant_signed(
            &mut v2,
            keys,
            vault,
            &creator,
            "policy",
            &ItemPayload::live(
                ItemNs::Aux,
                "policy",
                serde_json::to_value(&legacy.policy).unwrap(),
            ),
        );
        let n = v2.items.len();
        assert!(v2.migrate_legacy_copies::<S>(keys, vault).is_empty());
        assert!(v2.retire_legacy_rows::<S>(keys, vault, false).is_empty());
        assert_eq!(v2.items.len(), n);
        assert!(v2.fold_view::<S>(keys, vault).unwrap().aux.policy.is_some());
    }

    /// A row counts only at the derived id of its own (ns, name), whatever
    /// its name: one anywhere else is never read, a "copy"-named one
    /// included. A conflict copy is the record of its own name at that name's
    /// id: it folds like any record, and a tombstone there removes it.
    #[test]
    fn rows_count_only_at_their_own_address_copies_included() {
        use crate::storage::item::{conflict_copy_name, seal_wire_item};
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x5au8; 32];
        let keys = VaultKeys::single(&k);
        let vault = "vault-v1";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        // Rows away from their own address (planted at another name's id).
        let elsewhere = [
            ItemPayload::live(
                ItemNs::Policy,
                String::new(),
                serde_json::json!({ "timeout": 1 }),
            ),
            ItemPayload::live(
                ItemNs::Store,
                "gcp-1 (conflict copy)".to_string(),
                serde_json::json!({ "kind": "gcp-sm", "category": "value" }),
            ),
            ItemPayload::live(
                ItemNs::Connecting,
                "gmail".to_string(),
                serde_json::json!({ "service": "gmail" }),
            ),
            ItemPayload::live(ItemNs::Secret, conflict_copy_name("A"), serde_json::json!("v")),
        ];
        for (i, ours) in elsewhere.iter().enumerate() {
            let wire = wire_id_for::<S>(&k, ItemNs::Secret, &format!("other-{}", i)).unwrap();
            let ct = seal_wire_item::<S>(keys, vault, &wire, 1, ours).unwrap();
            pv.put_raw(wire, 1, ct);
        }
        let view = pv.fold_view::<S>(keys, vault).unwrap();
        assert!(view.aux.policy.is_none());
        assert!(!view.aux.stores.contains_key("gcp-1 (conflict copy)"));
        assert!(view.aux.connecting.is_empty());
        assert!(view.native_secrets.is_empty());

        // A copy at its own name's id folds; its removal sticks.
        let copy = conflict_copy_name("A");
        pv.seal_and_bump::<S>(
            keys,
            vault,
            ItemNs::Secret,
            &copy,
            &ItemPayload::secret_live(copy.clone(), "ours"),
        )
        .unwrap();
        let view = pv.fold_view::<S>(keys, vault).unwrap();
        assert_eq!(view.native_secrets[&copy], b"ours");
        let base = ViewBase::of(&view).unwrap();
        let mut removed = pv.fold_view::<S>(keys, vault).unwrap();
        removed.native_secrets.remove(&copy);
        let r = pv
            .reconcile_from_view::<S>(keys, vault, &removed, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(r.changed.len(), 1);
        for _ in 0..2 {
            let view = pv.fold_view::<S>(keys, vault).unwrap();
            assert!(!view.native_secrets.contains_key(&copy), "removal sticks");
            let base = ViewBase::of(&view).unwrap();
            let again = pv
                .reconcile_from_view::<S>(keys, vault, &view, ReconcileBase::Since(&base))
                .unwrap();
            assert!(again.changed.is_empty());
        }
        // The same for a connection copy.
        let conn = conflict_copy_name("gmail");
        pv.seal_and_bump::<S>(
            keys,
            vault,
            ItemNs::Connection,
            &conn,
            &ItemPayload::live(
                ItemNs::Connection,
                conn.clone(),
                serde_json::json!({ "service": "gmail" }),
            ),
        )
        .unwrap();
        let view = pv.fold_view::<S>(keys, vault).unwrap();
        assert!(view.aux.connections.contains_key(&conn));
        let base = ViewBase::of(&view).unwrap();
        let mut removed = pv.fold_view::<S>(keys, vault).unwrap();
        removed.aux.connections.remove(&conn);
        pv.reconcile_from_view::<S>(keys, vault, &removed, ReconcileBase::Since(&base))
            .unwrap();
        let view = pv.fold_view::<S>(keys, vault).unwrap();
        assert!(!view.aux.connections.contains_key(&conn), "removal sticks");
    }

    /// The old in-body owner wrapper `{data, uik_sig, uik_sign_pub}` over
    /// `data`, signed by `signer` as `config_name` at `version`.
    pub(crate) fn in_body_signed(
        vault: &str,
        signer: &crate::crypto::vault_key::UikRoot,
        config_name: &str,
        version: u64,
        data: &serde_json::Value,
    ) -> serde_json::Value {
        use base64::engine::general_purpose::STANDARD;
        let canonical = crate::crypto::canonical::canonicalize(data);
        let input = crate::identity::config_sig_input(
            vault,
            config_name,
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

    /// Native owner-config is sidecar-only: an owner's in-body wrapper counts
    /// only on a legacy `aux:<field>` row. The same wrapper re-sealed at
    /// `policy:connection:<id>` (its signature is not bound to that name)
    /// is not honored, so it cannot erase that connection's rules. Without a
    /// keyset, a native body claiming a signature is not honored either.
    #[test]
    fn native_owner_config_is_sidecar_only() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x71u8; 32];
        let keys = VaultKeys::single(&k);
        let (vault, creator, _, _, _, mut pv) = role_fixture_creator_cred();
        let legacy = serde_json::to_value(&full_aux().policy).unwrap();
        let wrapper = in_body_signed(vault, &creator, "policy", 1, &legacy);
        pv.plant::<S>(
            keys,
            vault,
            ItemNs::Aux,
            "policy",
            1,
            &ItemPayload::live(ItemNs::Aux, "policy", wrapper.clone()),
        )
        .unwrap();
        let rules = |pv: &PerItemVault| {
            let p = pv.fold_view::<S>(keys, vault).unwrap().aux.policy.unwrap();
            serde_json::to_value(&p.connections["stripe-work"]).unwrap()
        };
        let before = rules(&pv);
        assert_eq!(
            before,
            serde_json::json!({ "rules": { "pay": { "level": "deny" } } }),
            "the legacy row's in-body owner signature is honored"
        );
        // A member replays it as a native record, at the version it was signed at.
        for name in ["connection:stripe-work", ""] {
            pv.plant::<S>(
                keys,
                vault,
                ItemNs::Policy,
                name,
                1,
                &ItemPayload::live(ItemNs::Policy, name, wrapper.clone()),
            )
            .unwrap();
        }
        assert_eq!(rules(&pv), before, "the replayed wrapper is not honored");
        assert_eq!(
            pv.fold_view::<S>(keys, vault)
                .unwrap()
                .aux
                .policy
                .unwrap()
                .timeout,
            Some(120)
        );

        // No keyset: a plain native body is honored, one claiming a signature not.
        let vid = "vault-v1";
        let mut v1 = v1_store();
        v1.seal_and_bump::<S>(
            keys,
            vid,
            ItemNs::Policy,
            "",
            &ItemPayload::live(ItemNs::Policy, "", serde_json::json!({ "timeout": 5 })),
        )
        .unwrap();
        v1.plant::<S>(
            keys,
            vid,
            ItemNs::Policy,
            "category:ai",
            1,
            &ItemPayload::live(
                ItemNs::Policy,
                "category:ai",
                in_body_signed(
                    vid,
                    &creator,
                    "policy",
                    1,
                    &serde_json::json!({ "write": "deny" }),
                ),
            ),
        )
        .unwrap();
        let p = v1.fold_view::<S>(keys, vid).unwrap().aux.policy.unwrap();
        assert_eq!(p.timeout, Some(5));
        assert!(p.categories.is_empty());
    }

    /// A record is identified by its address: a row at the derived id of its
    /// own (ns, name) is that record whatever its name, so a connection
    /// really named "gmail (conflict copy)" keeps its policy, migrated or
    /// not, and a secret named like a copy is read under that name. A record
    /// of any kind at another record's address (secret, legacy row) is not
    /// read.
    #[test]
    fn records_are_identified_by_address_not_by_name() {
        use crate::storage::item::conflict_copy_name;
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x72u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-copies";
        let named = conflict_copy_name("gmail");
        let mut pv = v1_store();
        let legacy_policy = serde_json::json!({
            "connections": { named.clone(): { "default": { "write": "deny" } } }
        });
        pv.plant::<S>(
            keys,
            vid,
            ItemNs::Aux,
            "policy",
            1,
            &ItemPayload::live(ItemNs::Aux, "policy", legacy_policy),
        )
        .unwrap();
        pv.seal_and_bump::<S>(
            keys,
            vid,
            ItemNs::Connection,
            &named,
            &ItemPayload::live(
                ItemNs::Connection,
                named.clone(),
                serde_json::json!({ "service": "gmail" }),
            ),
        )
        .unwrap();
        let read = |pv: &PerItemVault| pv.fold_view::<S>(keys, vid).unwrap();
        let level = |pv: &PerItemVault| {
            serde_json::to_value(&read(pv).aux.policy.unwrap().connections[&named]).unwrap()
        };
        let want = serde_json::json!({ "default": { "write": "deny" } });
        assert!(read(&pv).aux.connections.contains_key(&named));
        assert_eq!(level(&pv), want, "legacy");
        // Migrated: its native record is at its own id and is read.
        assert_eq!(pv.migrate_legacy_copies::<S>(keys, vid).len(), 2);
        assert_eq!(pv.retire_legacy_rows::<S>(keys, vid, false).len(), 1);
        assert_eq!(level(&pv), want, "migrated");

        // A secret named like a copy, at its own id, is read under its name.
        pv.seal_and_bump::<S>(
            keys,
            vid,
            ItemNs::Secret,
            &conflict_copy_name("A"),
            &ItemPayload::secret_live(conflict_copy_name("A"), "real"),
        )
        .unwrap();
        assert_eq!(read(&pv).native_secrets[&conflict_copy_name("A")], b"real");

        // A record sealed at another record's address is not read: a secret
        // `B` at `Z`'s, a legacy row at another field's.
        let at = |ns, name: &str| ItemCtx::for_item::<S>(keys.id_seed, vid, ns, name, 1).unwrap();
        let z = at(ItemNs::Secret, "Z");
        let ct = seal_item::<S>(keys.content, &z, &ItemPayload::secret_live("B", "b")).unwrap();
        pv.put_raw(z.item_id_b64(), 1, ct);
        let other = at(ItemNs::Aux, "stores");
        let ct = seal_item::<S>(
            keys.content,
            &other,
            &ItemPayload::live(ItemNs::Aux, "audit_retention_days", serde_json::json!(9)),
        )
        .unwrap();
        pv.put_raw(other.item_id_b64(), 1, ct);
        let v = read(&pv);
        assert!(!v.native_secrets.contains_key("B"));
        assert_eq!(v.aux.audit_retention_days, None);
    }

    /// Defaults, one rule: a kind reads its default iff no entry survives the
    /// per-key merge (no live native record, no legacy entry a native
    /// tombstone does not remove). A tombstone alone never cancels a default:
    /// a tombstoned `store_order:` is the default order (so secrets still
    /// resolve). A legacy `aux:stores = {}` and empty-key policy entries
    /// read the same before and after the migration. A change to a kind that
    /// reads its default writes the whole kind.
    #[test]
    fn a_kind_reads_its_default_only_when_no_entry_survives() {
        use crate::storage::plaintext::{VaultAux, NATIVE_SECRETS_ID};
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x73u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "vault-defaults";
        let defaults = VaultAux::initial();
        let read = |pv: &PerItemVault| pv.fold_view::<S>(keys, vid).unwrap().aux;
        let tomb = |pv: &mut PerItemVault, ns: ItemNs, name: &str| {
            pv.seal_and_bump::<S>(keys, vid, ns, name, &ItemPayload::tombstone(ns, name))
                .unwrap();
        };
        let legacy = |pv: &mut PerItemVault, field: &str, body: serde_json::Value| {
            pv.plant::<S>(
                keys,
                vid,
                ItemNs::Aux,
                field,
                1,
                &ItemPayload::live(ItemNs::Aux, field, body),
            )
            .unwrap();
        };

        // Tombstones alone.
        let mut pv = v1_store();
        tomb(&mut pv, ItemNs::StoreOrder, "");
        tomb(&mut pv, ItemNs::Store, "gcp-1");
        tomb(&mut pv, ItemNs::AuditRetentionDays, "");
        tomb(&mut pv, ItemNs::Policy, "");
        let aux = read(&pv);
        assert_eq!(aux.store_order, defaults.store_order, "the default order");
        assert_eq!(config_json(&aux), config_json(&defaults));

        // A legacy row whose every entry a native tombstone removes.
        let mut pv = v1_store();
        legacy(&mut pv, "store_order", serde_json::json!(["gcp-1"]));
        legacy(
            &mut pv,
            "stores",
            serde_json::json!({ "gcp-1": { "kind": "gcp-sm", "category": "value" } }),
        );
        tomb(&mut pv, ItemNs::StoreOrder, "");
        tomb(&mut pv, ItemNs::Store, "gcp-1");
        assert_eq!(config_json(&read(&pv)), config_json(&defaults));

        // Adding a store then writes the whole kind: the default store stays.
        let base = ViewBase::of(&pv.fold_view::<S>(keys, vid).unwrap()).unwrap();
        let mut added = pv.fold_view::<S>(keys, vid).unwrap();
        added.aux.stores.insert(
            "gcp-2".into(),
            serde_json::from_value(serde_json::json!({ "kind": "gcp-sm", "category": "value" }))
                .unwrap(),
        );
        pv.reconcile_from_view::<S>(keys, vid, &added, ReconcileBase::Since(&base))
            .unwrap();
        assert_eq!(
            read(&pv).stores.keys().collect::<Vec<_>>(),
            ["gcp-2", NATIVE_SECRETS_ID]
        );

        // Before and after the migration: `aux:stores = {}`, `aux:store_order
        // = []`, a null retention, empty-key categories and connections.
        let mut pv = v1_store();
        legacy(&mut pv, "stores", serde_json::json!({}));
        legacy(&mut pv, "store_order", serde_json::json!([]));
        legacy(&mut pv, "audit_retention_days", serde_json::Value::Null);
        legacy(
            &mut pv,
            "policy",
            serde_json::json!({
                "timeout": 10,
                "categories": { "": { "write": "deny" }, "ai": { "write": "ask" } },
                "connections": { "": { "default": { "read": "deny" } } }
            }),
        );
        let before = config_json(&read(&pv));
        assert_eq!(
            before["stores"],
            serde_json::to_value(&defaults.stores).unwrap()
        );
        assert_eq!(before["store_order"], serde_json::json!([]));
        assert_eq!(
            before["policy"],
            serde_json::json!({ "timeout": 10, "categories": { "ai": { "write": "ask" } } })
        );
        pv.migrate_legacy_copies::<S>(keys, vid);
        pv.retire_legacy_rows::<S>(keys, vid, false);
        for field in ["stores", "store_order", "audit_retention_days", "policy"] {
            assert!(pv
                .open_item::<S>(keys, vid, ItemNs::Aux, field)
                .unwrap()
                .unwrap()
                .is_tombstone());
        }
        assert_eq!(
            config_json(&read(&pv)),
            before,
            "the same after the migration"
        );
    }

    /// The last honored owner-config value is kept: on a vault with a
    /// keyset, a row the fold would not honor (an unsigned tombstone over an
    /// owner-signed legacy `aux:policy`, an unsigned native record over an
    /// owner-signed one) or cannot read never replaces an honored one; an
    /// owner-signed row does. Not owner-config, or no keyset: always adopted.
    #[test]
    fn honored_owner_config_is_kept_over_an_unhonored_row() {
        use sudp::primitives::StdPrimitives;
        type S = StdPrimitives;
        let k = [0x74u8; 32];
        let keys = VaultKeys::single(&k);
        let (vault, creator, member, _, _, mut pv) = role_fixture_creator_cred();
        let legacy = serde_json::to_value(&full_aux().policy).unwrap();
        pv.plant::<S>(
            keys,
            vault,
            ItemNs::Aux,
            "policy",
            1,
            &ItemPayload::live(
                ItemNs::Aux,
                "policy",
                in_body_signed(vault, &creator, "policy", 1, &legacy),
            ),
        )
        .unwrap();
        let wire = wire_id_for::<S>(keys.id_seed, ItemNs::Aux, "policy").unwrap();
        // An incoming row at version 2, as sealed by `seal` and signed by `by`.
        let incoming = |p: &ItemPayload, by: Option<&crate::crypto::vault_key::UikRoot>| {
            let mut scratch = role_fixture_creator_cred().5;
            let id = match by {
                Some(s) => {
                    let ctx =
                        ItemCtx::for_item::<S>(keys.id_seed, vault, p.ns, &p.name, 2).unwrap();
                    let ct = seal_item::<S>(keys.content, &ctx, p).unwrap();
                    let ty = crate::storage::item::rule(p.ns, &p.name)
                        .and_then(|r| r.signature_type(&p.name))
                        .unwrap();
                    let input = crate::identity::record_signature_input(
                        ty,
                        ctx.id_bytes(),
                        2,
                        vault,
                        &ct,
                        !p.is_tombstone(),
                        &s.user_id(),
                    );
                    use base64::engine::general_purpose::STANDARD;
                    let sig = STANDARD.encode(s.signing().sign(&input));
                    scratch.put_raw_signed(ctx.item_id_b64(), 2, ct, Some(sig), Some(s.user_id()));
                    ctx.item_id_b64()
                }
                None => scratch
                    .plant::<S>(keys, vault, p.ns, &p.name, 2, p)
                    .unwrap(),
            };
            scratch.items[&id].clone()
        };
        let tomb = ItemPayload::tombstone(ItemNs::Aux, "policy");
        assert!(pv.keeps_honored_owner_config::<S>(keys, vault, &wire, &incoming(&tomb, None)));
        assert!(pv.keeps_honored_owner_config::<S>(
            keys,
            vault,
            &wire,
            &incoming(&tomb, Some(&member))
        ));
        assert!(!pv.keeps_honored_owner_config::<S>(
            keys,
            vault,
            &wire,
            &incoming(&tomb, Some(&creator))
        ));
        let mut unreadable = incoming(&tomb, Some(&creator));
        unreadable.ct[5] ^= 1;
        assert!(pv.keeps_honored_owner_config::<S>(keys, vault, &wire, &unreadable));
        // Each says why.
        assert_eq!(
            pv.unhonored_replacement::<S>(keys, vault, &wire, &unreadable),
            Some(HELD_UNREADABLE)
        );
        assert_eq!(
            pv.unhonored_replacement::<S>(keys, vault, &wire, &incoming(&tomb, Some(&member))),
            Some(HELD_NOT_OWNER_SIGNED)
        );

        // A native record signed by an owner, replaced unsigned.
        let cat = ItemPayload::live(
            ItemNs::Policy,
            "category:ai",
            serde_json::json!({ "write": "deny" }),
        );
        let cat_wire = plant_signed(&mut pv, keys, vault, &creator, "policy", &cat);
        let cat2 = ItemPayload::live(
            ItemNs::Policy,
            "category:ai",
            serde_json::json!({ "write": "allow" }),
        );
        assert!(pv.keeps_honored_owner_config::<S>(keys, vault, &cat_wire, &incoming(&cat2, None)));
        assert!(!pv.keeps_honored_owner_config::<S>(
            keys,
            vault,
            &cat_wire,
            &incoming(&cat2, Some(&creator))
        ));

        // Not owner-config: adopted.
        let s_wire = pv
            .plant::<S>(
                keys,
                vault,
                ItemNs::Secret,
                "A",
                1,
                &ItemPayload::secret_live("A", "a"),
            )
            .unwrap();
        let s2 = incoming(&ItemPayload::tombstone(ItemNs::Secret, "A"), None);
        assert!(!pv.keeps_honored_owner_config::<S>(keys, vault, &s_wire, &s2));

        // No keyset: never.
        let vid = "vault-v1";
        let mut v1 = v1_store();
        let w = v1
            .plant::<S>(
                keys,
                vid,
                ItemNs::Aux,
                "policy",
                1,
                &ItemPayload::live(ItemNs::Aux, "policy", legacy),
            )
            .unwrap();
        let ctx = ItemCtx::for_item::<S>(keys.id_seed, vid, ItemNs::Aux, "policy", 2).unwrap();
        let t = StoredItem {
            version: 2,
            ct: seal_item::<S>(keys.content, &ctx, &tomb).unwrap(),
            synced_version: 2,
            tombstone: false,
            sig: None,
            signer: None,
            base: None,
            upgrade: false,
            generation: None,
            unreadable_confirmed: false,
        };
        assert!(!v1.keeps_honored_owner_config::<S>(keys, vid, &w, &t));
    }
}
