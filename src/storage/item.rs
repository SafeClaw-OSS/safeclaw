//! Per-item vault records — the SafeClaw-owned layer over sudp's generic
//! per-record seal/unseal primitive ([`sudp::state`] `record`).
//!
//! Division of labour (see `wt-merge-spec/docs/PER_ITEM_SYNC.md` + the build
//! contract §1–§2):
//!
//! - **sudp** does the AEAD only: [`seal_record`] / [`unseal_record`], binding
//!   `AAD = domain ‖ vault ‖ id ‖ version`. It never derives the id, compares
//!   versions, merges, or GCs.
//! - **SafeClaw (this module)** owns everything else: the opaque **item id**
//!   (HMAC of `ns ‖ name` under a K-derived subkey), the [`SealCtx`] build, the
//!   JSON payload shape `{ns,name,status,body}`, and where a conflict copy
//!   lands (an ordinary record, [`conflict_copy_slot`]). The
//!   version comparison / merge / tombstone / GC policy lives in `sync.rs`.
//!
//! ## Cross-language parity (the recurring bug)
//!
//! The item id and the sealed payload are produced in the browser (TS
//! `@sudp-protocol/authorizer` + `lib/vault-grant.ts`) **and** here, so the
//! derivations MUST be byte-identical. In particular **all binary-in-JSON is
//! base64url-**no-pad**, never std-base64** — one helper ([`URL_SAFE_NO_PAD`]),
//! used everywhere. The [`tests::pinned_item_id_parity_vector`] test pins the
//! fixed contract vector; the TS side pins the same string.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sudp::primitives::{Kdf, PrimitiveSuite};
use sudp::state::{seal_record, unseal_record, SealCtx};

use crate::error::{AppError, Result};

/// HKDF `info` label for the item-id subkey. Byte-identical to the TS side.
const ITEM_ID_INFO: &[u8] = b"safeclaw/item-id/v1";

/// `SealCtx.domain` for a **content** item — distinct from the future
/// `"keyset"` domain (cross-domain confusion is caught by sudp's AAD binding).
pub const ITEM_DOMAIN: &str = "item";

type HmacSha256 = Hmac<Sha256>;

/// Append a length-prefixed field: `u32_be(len) ‖ bytes` (contract §1 `lp(x)`).
/// Length-prefixing removes splicing ambiguity between adjacent variable
/// fields (`ns="ab",name="c"` vs `ns="a",name="bc"`).
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Derive the item-id subkey
/// `K_id = HKDF-SHA256(ikm = K, salt = "", info = "safeclaw/item-id/v1")`.
///
/// Uses the SAME `Kdf` the daemon's suite already uses for sealing
/// ([`PrimitiveSuite::Kdf`] = HKDF-SHA-256 under `StdPrimitives`), so there is
/// exactly one HKDF on both sides. Domain-separated from sudp's internal
/// `K_aead` (info `"sudp/v1/item"`) so the id subkey never shares raw bytes
/// with the AEAD key.
pub fn derive_item_id_key<S: PrimitiveSuite>(k: &[u8]) -> Result<[u8; 32]> {
    S::Kdf::derive_32(k, &[], ITEM_ID_INFO)
        .map_err(|e| AppError::Internal(format!("item-id key derive: {}", e)))
}

/// Raw 32-byte item id:
/// `HMAC-SHA256(K_id, lp(utf8(ns)) ‖ lp(utf8(name)))` (contract §1).
///
/// One-way (cloud never learns the name) and deterministic (two writers naming
/// the same logical key land on the same row → concurrency is *detectable*).
pub fn item_id_bytes<S: PrimitiveSuite>(k: &[u8], ns: &str, name: &str) -> Result<[u8; 32]> {
    let k_id = derive_item_id_key::<S>(k)?;
    let mut msg = Vec::with_capacity(8 + ns.len() + name.len());
    push_lp(&mut msg, ns.as_bytes());
    push_lp(&mut msg, name.as_bytes());
    Ok(hmac32(&k_id, &msg))
}

/// Wire / row-PK / URL form of an item id: `base64url_nopad(item_id_bytes)`.
pub fn item_id<S: PrimitiveSuite>(k: &[u8], ns: &str, name: &str) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(item_id_bytes::<S>(k, ns, name)?))
}

/// Blinded row-id for a vault AUX config item ([`ItemNs::Aux`], given `name`)
/// under vault key `k`, using the standard primitive suite. A NEUTRAL primitive
/// (the same derivation a personal vault uses for its own aux items); exposed so
/// the closed team overlay can compute the shared-vault owner lock-list without
/// pulling the primitive suite. The POLICY (which aux names are owner-gated) stays
/// in the overlay. See team-edition §9.
pub fn aux_item_id(k: &[u8], name: &str) -> Result<String> {
    item_id::<sudp::primitives::StdPrimitives>(k, ItemNs::Aux.as_str(), name)
}

// ── Cleartext agent-authz item ids (T2 / aux→agent cutover) ──────────────────
// An authorized-agents item is addressed by its CLEARTEXT `ag_id` (not a blinded
// HMAC), so the backend can read the ag_id off the wire id and gate the write by
// ownership — see design/agent-authz-cleartext-cutover.md. The seal/sig AAD is
// STILL the HMAC `item_id_bytes(k,"agent",ag_id)` (unchanged 32 bytes); only the
// WIRE string (row PK / URL) differs. Recognition is collision-proof by LENGTH:
// `ag_id` = `"ag_"` + 32 base32 chars = 35 (identity::derive_id); every blinded
// item id is 43-char base64url. Disjoint sets — no prefix guessing can misfire.

/// Length of a cleartext agent wire id: `"ag_"` (3) + 32 base32 chars.
pub const AGENT_WIRE_ID_LEN: usize = 35;

/// True iff `wire_id` is a cleartext agent-authz item id (`ag_…`, 35 chars).
pub fn is_agent_wire_id(wire_id: &str) -> bool {
    wire_id.len() == AGENT_WIRE_ID_LEN && wire_id.starts_with("ag_")
}

/// The WIRE id (row PK / URL) for `(ns, name)`, per the namespace's
/// [`Address`] in [`ITEM_RULES`]: the cleartext name (`agent` ⇒ the ag_id) or
/// the blinded base64url HMAC.
pub fn wire_id_for<S: PrimitiveSuite>(k: &[u8], ns: ItemNs, name: &str) -> Result<String> {
    match ns.address() {
        Address::CleartextWireHmacAad => Ok(name.to_string()),
        Address::Blinded => item_id::<S>(k, ns.as_str(), name),
    }
}

/// Reconstruct the 32-byte seal/sig AAD id from a stored WIRE id. Blinded ids are
/// base64url of the 32 AAD bytes (decode). A cleartext agent wire id IS the ag_id,
/// so recompute its HMAC `item_id_bytes(k,"agent",ag_id)` — the SAME bytes the
/// writer sealed under. Mirrors the FE read path (`unsealItem`).
pub fn aad_id_from_wire<S: PrimitiveSuite>(k: &[u8], wire_id: &str) -> Result<[u8; 32]> {
    if is_agent_wire_id(wire_id) {
        item_id_bytes::<S>(k, ItemNs::Agent.as_str(), wire_id)
    } else {
        let raw = URL_SAFE_NO_PAD
            .decode(wire_id.as_bytes())
            .map_err(|e| AppError::Internal(format!("item id base64url decode: {}", e)))?;
        <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| AppError::Internal("item id is not 32 bytes".into()))
    }
}

/// `HMAC-SHA256(key, msg)` → 32 bytes.
fn hmac32(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The two per-vault keys the item layer needs, split for DP-S1 re-key
/// (team-shared-vault-security-model.md §3.2). `id_seed` derives the **stable**
/// item-id key (`derive_item_id_key`) so item ids survive a re-key; `content` is
/// the AEAD key for item bodies, which **rotates** on re-key. A gen-0 vault
/// (never re-keyed) has `id_seed == content == K`, so [`VaultKeys::single`] keeps
/// every pre-re-key call site a one-line wrap and byte-identical in behavior.
#[derive(Clone, Copy)]
pub struct VaultKeys<'a> {
    /// Stable across re-key → item ids never change (sync sees content updates,
    /// not delete-all + add-all).
    pub id_seed: &'a [u8],
    /// The current generation's content-encryption key (rotates on re-key).
    /// Every write seals under it.
    pub content: &'a [u8],
    /// The vault's previous content keys, newest first, each with the rows
    /// that existed when it was retired, when this member's keyset row
    /// carries them ([`open_prev_content_keys`]); empty otherwise. Encoded
    /// as [`PrevKey`]s back to back. Reads only: a key opens only the rows
    /// it lists ([`unseal_item_keys`]); nothing is ever sealed under one.
    /// The owner's console moves such rows.
    pub prev: &'a [u8],
}

impl<'a> VaultKeys<'a> {
    /// A gen-0 (never-re-keyed) vault: id-seed and content are the same key `K`.
    pub fn single(k: &'a [u8]) -> Self {
        Self {
            id_seed: k,
            content: k,
            prev: &[],
        }
    }

    /// Interpret acquired key material into the split view:
    ///   - **32 bytes** = a v1 single `K` → `single` (id == content);
    ///   - **64 bytes** = a v2 DP-S1 bundle `id_seed(32) ‖ content_key(32)` →
    ///     the two halves (id_seed stable, content rotates on re-key);
    ///   - **more** = that bundle and the vault's previous content keys with
    ///     their rows ([`material_with_prev`]); a section that does not parse
    ///     is none.
    /// The daemon retains the acquired material and rebuilds this on each fold.
    pub fn from_material(material: &'a [u8]) -> Self {
        let bundle = 2 * SINGLE_KEY_LEN;
        if material.len() < bundle {
            return Self::single(material);
        }
        let prev = &material[bundle..];
        Self {
            id_seed: &material[..SINGLE_KEY_LEN],
            content: &material[SINGLE_KEY_LEN..bundle],
            prev: if prev_section_ok(prev) { prev } else { &[] },
        }
    }

    /// The previous content keys, newest first.
    pub fn prev_keys(&self) -> impl Iterator<Item = PrevKey<'a>> {
        let mut rest = self.prev;
        std::iter::from_fn(move || {
            let (key, r) = split_prev_key(rest)?;
            rest = r;
            Some(key)
        })
    }
}

/// One previous content key and the rows that existed when it was retired.
/// Encoded `key(32) ‖ u32be(n) ‖ n × (u16be(len) ‖ wire id ‖ u64be(version)
/// ‖ sha256(ct)(32))`.
#[derive(Clone, Copy)]
pub struct PrevKey<'a> {
    pub key: &'a [u8],
    n: u32,
    rows: &'a [u8],
}

impl PrevKey<'_> {
    /// Whether the row at `wire` (its id as `/items` carries it) at `version`
    /// with ciphertext digest `ct_sha256` (SHA-256 of the row's decoded ct
    /// bytes) existed when this key was retired: the only rows it opens.
    pub fn lists(&self, wire: &str, version: u64, ct_sha256: &[u8; 32]) -> bool {
        let mut rest = self.rows;
        for _ in 0..self.n {
            let Some((w, v, h, r)) = split_listed_row(rest) else {
                return false;
            };
            if v == version && h == ct_sha256 && w == wire.as_bytes() {
                return true;
            }
            rest = r;
        }
        false
    }
}

/// Length of one listed row's ciphertext digest.
const ROW_DIGEST_LEN: usize = 32;

fn split_listed_row(b: &[u8]) -> Option<(&[u8], u64, &[u8], &[u8])> {
    let len = u16::from_be_bytes(b.get(..2)?.try_into().ok()?) as usize;
    let wire = b.get(2..2 + len)?;
    let version = u64::from_be_bytes(b.get(2 + len..10 + len)?.try_into().ok()?);
    let digest = b.get(10 + len..10 + len + ROW_DIGEST_LEN)?;
    Some((wire, version, digest, &b[10 + len + ROW_DIGEST_LEN..]))
}

fn split_prev_key(b: &[u8]) -> Option<(PrevKey<'_>, &[u8])> {
    let key = b.get(..SINGLE_KEY_LEN)?;
    let n = u32::from_be_bytes(b.get(SINGLE_KEY_LEN..SINGLE_KEY_LEN + 4)?.try_into().ok()?);
    let start = &b[SINGLE_KEY_LEN + 4..];
    let mut rest = start;
    for _ in 0..n {
        rest = split_listed_row(rest)?.3;
    }
    let rows = &start[..start.len() - rest.len()];
    Some((PrevKey { key, n, rows }, rest))
}

fn prev_section_ok(mut b: &[u8]) -> bool {
    while !b.is_empty() {
        match split_prev_key(b) {
            Some((_, rest)) => b = rest,
            None => return false,
        }
    }
    true
}

/// SHA-256 of a row's decoded ciphertext bytes, as a retired key's list
/// names the row.
pub fn ct_sha256(ct: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(ct).into()
}

/// Length of a single vault key `K` (a v1 vault: id-seed and content key in
/// one), the only key a whole-blob `vault.dat` is sealed under.
pub const SINGLE_KEY_LEN: usize = 32;

/// `SealCtx.domain` of a vault's previous content keys, sealed under the
/// current content key on its members' keyset rows.
pub const PREV_CONTENT_KEYS_DOMAIN: &str = "prev_content_keys";

/// The seal context of the previous content keys: the domain
/// [`PREV_CONTENT_KEYS_DOMAIN`], the vault id, an empty id, and the current
/// generation (`u64` big-endian). Byte-identical to the console's.
fn prev_content_keys_ctx<'a>(vault: &'a [u8], version: &'a [u8; 8]) -> SealCtx<'a> {
    SealCtx {
        domain: PREV_CONTENT_KEYS_DOMAIN,
        vault,
        id: &[],
        version,
    }
}

/// The plaintext of the previous content keys, newest first: compact JSON
/// `{"v":1,"keys":[{"k":"<std base64 of the 32-byte key>","items":[["<wire
/// id>",<version>,"<std base64 SHA-256 of the row's decoded ct bytes>"],…]},…]}`,
/// `items` = every row of the vault (tombstones included) when the re-key
/// retired that key, sorted by wire id then version.
#[derive(Serialize, Deserialize)]
struct PrevContentKeys {
    v: u64,
    keys: Vec<PrevKeyEntry>,
}

#[derive(Serialize, Deserialize)]
struct PrevKeyEntry {
    k: String,
    items: Vec<(String, u64, String)>,
}

impl Drop for PrevKeyEntry {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k);
    }
}

/// Open a vault's previous content keys (`uik_prev_content_ct`, decoded):
/// sealed with the item AEAD under the current content key `content` for this
/// vault and the current `generation`. Returns them encoded as
/// [`PrevKey`]s, newest first, in a zeroized buffer of exactly their size.
/// `Err` unless it opens to version 1 with every key 32 bytes and every row
/// digest 32 bytes. What fails to parse is said only as a malformed list:
/// the plaintext holds key material.
pub fn open_prev_content_keys<S: PrimitiveSuite>(
    content: &[u8],
    vault_id: &str,
    generation: u64,
    sealed: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use base64::engine::general_purpose::STANDARD;
    let bad = |why: &str| AppError::Unauthorized(format!("previous content keys: {}", why));
    let version = generation.to_be_bytes();
    let pt = zeroize::Zeroizing::new(
        unseal_record::<S>(
            content,
            &prev_content_keys_ctx(vault_id.as_bytes(), &version),
            sealed,
        )
        .map_err(|_| bad("they do not open"))?,
    );
    let parsed: PrevContentKeys = serde_json::from_slice(&pt).map_err(|_| bad("malformed list"))?;
    if parsed.v != 1 {
        return Err(bad("malformed list"));
    }
    // The exact size, so the buffer never grows (no copy of a key is left
    // behind in a freed allocation).
    let mut size = 0usize;
    for entry in &parsed.keys {
        u32::try_from(entry.items.len()).map_err(|_| bad("malformed list"))?;
        size += SINGLE_KEY_LEN + 4;
        for (wire, _, _) in &entry.items {
            u16::try_from(wire.len()).map_err(|_| bad("malformed list"))?;
            size += 2 + wire.len() + 8 + ROW_DIGEST_LEN;
        }
    }
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(size));
    for entry in &parsed.keys {
        let key = zeroize::Zeroizing::new(
            STANDARD
                .decode(&entry.k)
                .map_err(|_| bad("malformed list"))?,
        );
        if key.len() != SINGLE_KEY_LEN {
            return Err(bad("malformed list"));
        }
        out.extend_from_slice(&key);
        out.extend_from_slice(&(entry.items.len() as u32).to_be_bytes());
        for (wire, version, digest) in &entry.items {
            let digest = STANDARD.decode(digest).map_err(|_| bad("malformed list"))?;
            if digest.len() != ROW_DIGEST_LEN {
                return Err(bad("malformed list"));
            }
            out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            out.extend_from_slice(wire.as_bytes());
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&digest);
        }
    }
    debug_assert_eq!(out.len(), size);
    Ok(out)
}

/// Seal a vault's previous content keys (newest first, each with the rows it
/// retired with: wire id, version, decoded ct) the way an owner does. This
/// process never seals them (the owner's console does); tests only.
#[cfg(test)]
pub fn seal_prev_content_keys<S: PrimitiveSuite>(
    content: &[u8],
    vault_id: &str,
    generation: u64,
    keys: &[(&[u8], &[(&str, u64, &[u8])])],
) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    let version = generation.to_be_bytes();
    let pt = serde_json::to_vec(&PrevContentKeys {
        v: 1,
        keys: keys
            .iter()
            .map(|(k, rows)| PrevKeyEntry {
                k: STANDARD.encode(k),
                items: rows
                    .iter()
                    .map(|(w, v, ct)| (w.to_string(), *v, STANDARD.encode(ct_sha256(ct))))
                    .collect(),
            })
            .collect(),
    })
    .unwrap();
    seal_record::<S>(
        content,
        &prev_content_keys_ctx(vault_id.as_bytes(), &version),
        &pt,
    )
    .expect("seal previous content keys")
}

/// The key material a member keeps: the key `bundle` (`id_seed ‖ content`),
/// followed by the vault's previous content keys and their rows when
/// `sealed_prev` (this member's own keyset row's `uik_prev_content_ct`) opens
/// under the bundle's content key for this vault at `generation`
/// ([`VaultKeys::from_material`] splits it back). Anything else (none
/// carried, a single key, a seal that does not open) is the bundle alone:
/// only the current key reads.
pub fn material_with_prev<S: PrimitiveSuite>(
    bundle: zeroize::Zeroizing<Vec<u8>>,
    vault_id: &str,
    generation: u64,
    sealed_prev: &[u8],
) -> zeroize::Zeroizing<Vec<u8>> {
    if sealed_prev.is_empty() || bundle.len() != 2 * SINGLE_KEY_LEN {
        return bundle;
    }
    match open_prev_content_keys::<S>(&bundle[SINGLE_KEY_LEN..], vault_id, generation, sealed_prev) {
        Ok(prev) => {
            let mut out = zeroize::Zeroizing::new(Vec::with_capacity(bundle.len() + prev.len()));
            out.extend_from_slice(&bundle);
            out.extend_from_slice(&prev);
            out
        }
        Err(e) => {
            tracing::warn!(vault = %vault_id, generation, "this member's previous content keys do not open ({}); reading with the current key only", e);
            bundle
        }
    }
}

/// Concatenate a DP-S1 key bundle: `id_seed(32) ‖ content_key(32)` = 64 bytes,
/// the plaintext a v2 keyset seals to a member's UIK. Mirror on the browser side
/// (lib/uik-crypto.ts). `VaultKeys::from_material` is the inverse.
pub fn vault_key_bundle(id_seed: &[u8], content_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id_seed.len() + content_key.len());
    out.extend_from_slice(id_seed);
    out.extend_from_slice(content_key);
    out
}

/// Owns the byte buffers a [`SealCtx`] borrows, so callers can build a sealing
/// context for one item + version without lifetime juggling.
///
/// `vault` = the vault id's UTF-8 bytes; `id` = the **32 raw** HMAC bytes (NOT
/// the base64url string); `version` = `u64` big-endian.
pub struct ItemCtx {
    vault: Vec<u8>,
    id: [u8; 32],
    version: [u8; 8],
}

impl ItemCtx {
    /// Build from an already-derived raw id.
    pub fn new(vault_id: &str, id_bytes: [u8; 32], version: u64) -> Self {
        Self {
            vault: vault_id.as_bytes().to_vec(),
            id: id_bytes,
            version: version.to_be_bytes(),
        }
    }

    /// Build for an item addressed by `(ns, name)`, deriving its id from `K`.
    pub fn for_item<S: PrimitiveSuite>(
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
    ) -> Result<Self> {
        Ok(Self::new(
            vault_id,
            item_id_bytes::<S>(k, ns.as_str(), name)?,
            version,
        ))
    }

    /// The borrowed sudp [`SealCtx`] for this item at this version.
    pub fn seal_ctx(&self) -> SealCtx<'_> {
        SealCtx {
            domain: ITEM_DOMAIN,
            vault: &self.vault,
            id: &self.id,
            version: &self.version,
        }
    }

    /// The raw 32-byte id.
    pub fn id_bytes(&self) -> &[u8; 32] {
        &self.id
    }

    /// The version this context binds.
    pub fn version(&self) -> u64 {
        u64::from_be_bytes(self.version)
    }

    /// The base64url-nopad wire id (row PK / URL) for this item.
    pub fn item_id_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.id)
    }
}

/// Namespace of a content item — selects how `body` is interpreted (contract §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemNs {
    /// `body` = the secret string, or `{ value, notes }` when the secret
    /// carries user notes (see [`secret_body`] / [`parse_secret_body`]).
    Secret,
    /// `body` = `{ service, config }`.
    Connection,
    /// `body` = `{ service, config, code, verifier }`.
    Connecting,
    /// LEGACY(aux addressing) owner-config address: `ns = "aux"`, `name` =
    /// the `VaultAux` field. Written only as the tombstone the migration
    /// leaves after copying it to its native records ([`ITEM_RULES`]); the
    /// fold reads `aux:<field>` only while its kind has no honored native
    /// record, and `aux:services` unioned under the native `service` items.
    /// Remove once every vault is migrated.
    Aux,
    /// `body` = [`AgentEntry`] (reach mask); `name` = agent id. Team §8.1.
    Agent,
    /// One vault service definition (`name` = the service id): `body` =
    /// `{ service, policy?, source? }`, the object form of an `aux.services`
    /// entry. A data record like a connection ([`ITEM_RULES`]): member-
    /// writable, unsigned, read only at its own derived id, and a same-item
    /// conflict keeps both (`"<id> (conflict copy)"`). The fold unions these
    /// with the legacy `services` record, a native item (or tombstone) winning
    /// for its id.
    Service,
    /// Owner-config, one record per edit unit, reassembled into the
    /// [`Policy`] tree by the fold: `policy:` (empty name) = `{timeout,
    /// default}`, `policy:category:<tag>` = that tag's `Levels`,
    /// `policy:connection:<connection_id>` = that connection's
    /// `ConnectionPolicy`. Any other name is ignored.
    Policy,
    /// Owner-config: one store (`name` = the store id, `body` = the `Store`).
    Store,
    /// Owner-config singleton: `body` = the store-order list.
    #[serde(rename = "store_order")]
    StoreOrder,
    /// Owner-config singleton: `body` = retention days (integer).
    #[serde(rename = "audit_retention_days")]
    AuditRetentionDays,
    /// The console's secret order (singleton); this process ignores it.
    #[serde(rename = "secret_order")]
    SecretOrder,
    /// RETIRED `stores:` singleton (stores are `store:<id>`): parsed, never
    /// read or written.
    Stores,
    /// RETIRED `services:` singleton (services are `service:<id>`): parsed,
    /// never read or written.
    Services,
    /// RETIRED in-vault membership (roles ride the keyset): parsed, never
    /// read or written.
    Members,
}

/// The authority a record's SIGNER carries, for the §A1.4/A2 role×type write
/// policy. A principal that authors a record is EITHER a human (UIK — an owner or
/// a plain member) OR the device (DIK) making an automatic, no-human-present write
/// (OAuth refresh / connect). Agents (AIK) never author records — they USE the
/// vault through the broker — so there is no agent writer role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterRole {
    /// A human UIK that is an OWNER of the vault.
    Owner,
    /// A human UIK that is a non-owner MEMBER.
    Member,
    /// The DIK — the daemon's automatic writes on behalf of its account. Bounded
    /// to data records (an owner-config or agent-authz change is a deliberate
    /// human act, never an automatic one).
    Device,
}

impl ItemNs {
    /// How this namespace is addressed: the [`Address`] of its rules in
    /// [`ITEM_RULES`] (every rule of one namespace shares it); a namespace with
    /// no rule is blinded.
    pub fn address(self) -> Address {
        ITEM_RULES
            .iter()
            .find(|r| r.ns == self)
            .map(|r| r.address)
            .unwrap_or(Address::Blinded)
    }

    /// The lowercase wire string (matches the serde rename and the TS side).
    pub fn as_str(self) -> &'static str {
        match self {
            ItemNs::Secret => "secret",
            ItemNs::Connection => "connection",
            ItemNs::Connecting => "connecting",
            ItemNs::Aux => "aux",
            ItemNs::Agent => "agent",
            ItemNs::Service => "service",
            ItemNs::Policy => "policy",
            ItemNs::Store => "store",
            ItemNs::Stores => "stores",
            ItemNs::StoreOrder => "store_order",
            ItemNs::AuditRetentionDays => "audit_retention_days",
            ItemNs::SecretOrder => "secret_order",
            ItemNs::Services => "services",
            ItemNs::Members => "members",
        }
    }

    /// §A1.4/A2 role×type write authorization: may a principal with `role` write
    /// the record `(self, name)`? It follows the record's rule in
    /// [`ITEM_RULES`] ([`ItemRule::write_allowed`]): `is_own_agent` applies
    /// only to `agent` (the signer is the agent's declared owner) and
    /// `has_keyset` only to owner-config (the device writes it on a vault
    /// without a keyset). A tombstone is a write too; the legacy `aux` rows
    /// take only the migration's tombstone ([`ItemRule::migration_tombstone_allowed`]).
    /// Fail-CLOSED: a record without a rule (the retired `stores:` /
    /// `services:` / `members`, an unknown or `agent/` `aux` name, an unknown
    /// `policy` name) is written by nobody (A1.4 "未知 type → 默认拒").
    pub fn write_allowed(
        self,
        name: &str,
        role: WriterRole,
        is_own_agent: bool,
        has_keyset: bool,
    ) -> bool {
        rule(self, name).is_some_and(|r| r.write_allowed(role, is_own_agent, has_keyset))
    }
}

// ── The item-namespace rule table ────────────────────────────────────────────
// ONE table decides, per record type, how it is addressed, who may write it,
// what signs it, how a same-item conflict resolves and what a reader accepts.
// The console holds the same table; both sides assert the canonical text of it
// ([`canonical_rule_table`]), so a change must land on both sides at once.

/// How a record type is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    /// Wire id = AAD id = `HMAC(K_id, lp(ns) ‖ lp(name))` (base64url).
    Blinded,
    /// Wire id = the cleartext name; the seal/sig AAD stays the blinded HMAC.
    CleartextWireHmacAad,
}

/// A principal that may write (or tombstone) a record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// A vault owner.
    Owner,
    /// The member an agent belongs to, for that agent only.
    OwnMember,
    /// Any member, owners included.
    Member,
    /// The device: the daemon's automatic writes and the writes it makes after
    /// a person approves.
    Device,
    /// The device, on a vault without a keyset only.
    DeviceWithoutKeyset,
    /// Only the tombstone the migration writes after copying a legacy row to
    /// its native records: an owner on a vault with a keyset, anyone (the
    /// device included) without one.
    MigrationTombstoneOnly,
}

/// What signs a record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signed {
    /// Never signed.
    None,
    /// The writer's sidecar signature, record type `agent`.
    WriterAgent,
    /// On a vault with a keyset: an owner's sidecar signature, record type =
    /// the namespace (`policy`, `store`, `store_order`,
    /// `audit_retention_days`; a legacy `aux` row: its field name). Without a
    /// keyset: unsigned.
    OwnerWithKeyset,
}

/// How a same-item conflict resolves (the console applies the same rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    /// Theirs stays canonical; ours becomes `"<name> (conflict copy)"`. Our
    /// edit against their delete: the delete stands, ours becomes the copy.
    /// Their body equal to our base (normalized) is no conflict: ours applies.
    KeepBoth,
    /// Ours is written over theirs.
    TakeWriter,
    /// Never overwritten, never re-sealed: ours is set aside and the user is
    /// told it changed elsewhere meanwhile.
    OwnerConfig,
}

/// What a reader accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    /// Every record.
    All,
    /// Only a record whose signer may write it and whose wire id is its name.
    SignerAuthorizedAndWireIdMatches,
    /// A native owner-config record: with a keyset only owner-signed, else
    /// any. Its kind is read from the native records alone once any of them
    /// is honored.
    OwnerSignedWithKeysetNativeWins,
    /// A legacy `aux:<field>` row (same signature rule), read only while its
    /// kind has no honored native record; never mixed with native ones.
    LegacyWhenNoHonoredNative,
    /// The console's; this process ignores it.
    ConsoleOnly,
    /// The legacy services record: read, unioned under the native items (a
    /// native item or tombstone wins for its id).
    LegacyUnionNativeWins,
    /// Only a record at its own derived id (a conflict copy is a record of
    /// its own name), unioned with the legacy services record, native first.
    DerivedIdOnlyUnionLegacy,
}

/// Which names of its namespace a rule covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {
    /// Every name; the key shows the placeholder.
    Any(&'static str),
    /// Exactly this name (`""` for a singleton, an `aux` field).
    Exact(&'static str),
    /// `<prefix><non-empty rest>`; the key shows the prefix and the placeholder.
    Prefixed(&'static str, &'static str),
}

impl Name {
    pub fn matches(self, name: &str) -> bool {
        match self {
            Name::Any(_) => true,
            Name::Exact(n) => n == name,
            Name::Prefixed(p, _) => name.strip_prefix(p).is_some_and(|rest| !rest.is_empty()),
        }
    }

    fn key_part(self) -> String {
        match self {
            Name::Any(placeholder) => placeholder.to_string(),
            Name::Exact(n) => n.to_string(),
            Name::Prefixed(p, placeholder) => format!("{}{}", p, placeholder),
        }
    }
}

/// One row of [`ITEM_RULES`].
#[derive(Debug, Clone, Copy)]
pub struct ItemRule {
    pub ns: ItemNs,
    pub name: Name,
    pub address: Address,
    pub writers: &'static [Writer],
    pub signed: Signed,
    pub conflict: Conflict,
    pub read: Read,
}

const fn data_record(ns: ItemNs, placeholder: &'static str, conflict: Conflict) -> ItemRule {
    ItemRule {
        ns,
        name: Name::Any(placeholder),
        address: Address::Blinded,
        writers: &[Writer::Member, Writer::Device],
        signed: Signed::None,
        conflict,
        read: Read::All,
    }
}

/// A native owner-config record.
const fn owner_config(ns: ItemNs, name: Name) -> ItemRule {
    ItemRule {
        ns,
        name,
        address: Address::Blinded,
        writers: &[Writer::Owner, Writer::DeviceWithoutKeyset],
        signed: Signed::OwnerWithKeyset,
        conflict: Conflict::OwnerConfig,
        read: Read::OwnerSignedWithKeysetNativeWins,
    }
}

/// LEGACY(aux addressing): an `aux:<field>` row, written only as the
/// migration's tombstone, read only while its kind has no honored native
/// record.
const fn legacy_aux(field: &'static str) -> ItemRule {
    ItemRule {
        ns: ItemNs::Aux,
        name: Name::Exact(field),
        address: Address::Blinded,
        writers: &[Writer::MigrationTombstoneOnly],
        signed: Signed::OwnerWithKeyset,
        conflict: Conflict::OwnerConfig,
        read: Read::LegacyWhenNoHonoredNative,
    }
}

/// THE rule table (design: item-namespace table). Every per-record decision
/// in this crate reads it: [`wire_id_for`], [`ItemNs::write_allowed`], what
/// this process writes, the sync's conflict decision and the fold's read
/// rules.
pub const ITEM_RULES: [ItemRule; 18] = [
    data_record(ItemNs::Secret, "<KEY>", Conflict::KeepBoth),
    data_record(ItemNs::Connection, "<id>", Conflict::KeepBoth),
    data_record(ItemNs::Connecting, "<id>", Conflict::TakeWriter),
    ItemRule {
        read: Read::DerivedIdOnlyUnionLegacy,
        ..data_record(ItemNs::Service, "<id>", Conflict::KeepBoth)
    },
    ItemRule {
        ns: ItemNs::Agent,
        name: Name::Any("<ag_id>"),
        address: Address::CleartextWireHmacAad,
        writers: &[Writer::Owner, Writer::OwnMember],
        signed: Signed::WriterAgent,
        conflict: Conflict::TakeWriter,
        read: Read::SignerAuthorizedAndWireIdMatches,
    },
    owner_config(ItemNs::Policy, Name::Exact("")),
    owner_config(ItemNs::Policy, Name::Prefixed(POLICY_CATEGORY, "<tag>")),
    owner_config(
        ItemNs::Policy,
        Name::Prefixed(POLICY_CONNECTION, "<connection_id>"),
    ),
    owner_config(ItemNs::Store, Name::Any("<id>")),
    owner_config(ItemNs::StoreOrder, Name::Exact("")),
    owner_config(ItemNs::AuditRetentionDays, Name::Exact("")),
    ItemRule {
        ns: ItemNs::SecretOrder,
        name: Name::Exact(""),
        address: Address::Blinded,
        writers: &[Writer::Member],
        signed: Signed::None,
        conflict: Conflict::TakeWriter,
        read: Read::ConsoleOnly,
    },
    ItemRule {
        read: Read::LegacyUnionNativeWins,
        ..legacy_aux("services")
    },
    legacy_aux("policy"),
    legacy_aux("stores"),
    legacy_aux("store_order"),
    legacy_aux("audit_retention_days"),
    ItemRule {
        signed: Signed::None,
        conflict: Conflict::TakeWriter,
        ..legacy_aux("secret_order")
    },
];

/// `policy:category:<tag>`: a tag's default levels.
pub const POLICY_CATEGORY: &str = "category:";
/// `policy:connection:<connection_id>`: a connection's policy.
pub const POLICY_CONNECTION: &str = "connection:";

/// The rule for the record `(ns, name)`, if the table has one.
pub fn rule(ns: ItemNs, name: &str) -> Option<&'static ItemRule> {
    ITEM_RULES
        .iter()
        .find(|r| r.ns == ns && r.name.matches(name))
}

/// The conflict policy of `(ns, name)`. A record without a rule is written
/// by nobody; were one ever dirty, it is never overwritten.
pub fn conflict_policy(ns: ItemNs, name: &str) -> Conflict {
    rule(ns, name).map_or(Conflict::OwnerConfig, |r| r.conflict)
}

/// True when the device (this process) may write `(ns, name)` (`tombstone`:
/// the write is a tombstone) on a vault with (`has_keyset`) or without a
/// keyset. A record without a rule: never.
pub fn device_may_write(ns: ItemNs, name: &str, has_keyset: bool, tombstone: bool) -> bool {
    rule(ns, name).is_some_and(|r| {
        r.write_allowed(WriterRole::Device, false, has_keyset)
            || (tombstone && r.migration_tombstone_allowed(WriterRole::Device, has_keyset))
    })
}

impl ItemRule {
    /// `ns:name` (`ns:<placeholder>` for a rule covering many names).
    pub fn key(&self) -> String {
        format!("{}:{}", self.ns.as_str(), self.name.key_part())
    }

    /// May a principal with `role` write this record (live, or a tombstone)?
    /// See [`Writer`]; the migration's tombstone of a legacy row is
    /// [`Self::migration_tombstone_allowed`].
    pub fn write_allowed(&self, role: WriterRole, is_own_agent: bool, has_keyset: bool) -> bool {
        self.writers.iter().any(|w| match w {
            Writer::Owner => role == WriterRole::Owner,
            Writer::OwnMember => role == WriterRole::Member && is_own_agent,
            Writer::Member => matches!(role, WriterRole::Owner | WriterRole::Member),
            Writer::Device => role == WriterRole::Device,
            Writer::DeviceWithoutKeyset => role == WriterRole::Device && !has_keyset,
            Writer::MigrationTombstoneOnly => false,
        })
    }

    /// May a principal with `role` write the migration's tombstone of this
    /// (legacy) record: an owner with a keyset, anyone without.
    pub fn migration_tombstone_allowed(&self, role: WriterRole, has_keyset: bool) -> bool {
        self.writers.contains(&Writer::MigrationTombstoneOnly)
            && (!has_keyset || role == WriterRole::Owner)
    }

    /// The sidecar record type a signature of the record named `name` is made
    /// over, when the record is signed: `agent`, or for owner-config the
    /// namespace (a legacy `aux` row: its field name).
    pub fn signature_type<'a>(&self, name: &'a str) -> Option<&'a str> {
        match self.signed {
            Signed::None => None,
            Signed::WriterAgent => Some("agent"),
            Signed::OwnerWithKeyset if self.ns == ItemNs::Aux => Some(name),
            Signed::OwnerWithKeyset => Some(self.ns.as_str()),
        }
    }

    fn canonical_json(&self) -> String {
        let s = |v: &str| serde_json::Value::String(v.to_string()).to_string();
        let writers: Vec<String> = self.writers.iter().map(|w| s(w.as_str())).collect();
        format!(
            "{{\"key\":{},\"address\":{},\"writers\":[{}],\"signed\":{},\"conflict\":{},\"read\":{}}}",
            s(&self.key()),
            s(self.address.as_str()),
            writers.join(","),
            s(self.signed.as_str()),
            s(self.conflict.as_str()),
            s(self.read.as_str()),
        )
    }
}

impl Address {
    pub fn as_str(self) -> &'static str {
        match self {
            Address::Blinded => "blinded",
            Address::CleartextWireHmacAad => "cleartext_wire_hmac_aad",
        }
    }
}

impl Writer {
    pub fn as_str(self) -> &'static str {
        match self {
            Writer::Owner => "owner",
            Writer::OwnMember => "own_member",
            Writer::Member => "member",
            Writer::Device => "device",
            Writer::DeviceWithoutKeyset => "device_without_keyset",
            Writer::MigrationTombstoneOnly => "migration_tombstone_only",
        }
    }
}

impl Signed {
    pub fn as_str(self) -> &'static str {
        match self {
            Signed::None => "none",
            Signed::WriterAgent => "writer:agent",
            Signed::OwnerWithKeyset => "owner_with_keyset",
        }
    }
}

impl Conflict {
    pub fn as_str(self) -> &'static str {
        match self {
            Conflict::KeepBoth => "keep_both",
            Conflict::TakeWriter => "take_writer",
            Conflict::OwnerConfig => "owner_config",
        }
    }
}

impl Read {
    pub fn as_str(self) -> &'static str {
        match self {
            Read::All => "all",
            Read::SignerAuthorizedAndWireIdMatches => "signer_authorized_and_wire_id_matches",
            Read::OwnerSignedWithKeysetNativeWins => "owner_signed_with_keyset_native_wins",
            Read::LegacyWhenNoHonoredNative => "legacy_when_no_honored_native",
            Read::ConsoleOnly => "console_only",
            Read::LegacyUnionNativeWins => "legacy_union_native_wins",
            Read::DerivedIdOnlyUnionLegacy => "derived_id_only_union_legacy",
        }
    }
}

/// The canonical text of [`ITEM_RULES`]: a compact JSON array (no spaces),
/// sorted by `key`, each object's fields in the order key, address, writers,
/// signed, conflict, read. The console asserts the same text.
pub fn canonical_rule_table() -> String {
    let mut rows: Vec<(String, String)> = ITEM_RULES
        .iter()
        .map(|r| (r.key(), r.canonical_json()))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let rows: Vec<String> = rows.into_iter().map(|(_, j)| j).collect();
    format!("[{}]", rows.join(","))
}

/// A body as compared and written, so the same content written by any client
/// compares equal: a `service` entry in its object form `{service, policy?,
/// source?}` (the plain-string form written before sources is `{service:
/// <text>}`; a null `policy` / `source` is absent); an owner-config record
/// (`name` picks its type) as its typed value (an absent or null field and
/// an unknown one are the same); a body that does not parse, and every other
/// body, is itself.
pub fn normalized_body(ns: ItemNs, name: &str, body: &serde_json::Value) -> serde_json::Value {
    match ns {
        ItemNs::Service => match body {
            serde_json::Value::String(s) => serde_json::json!({ "service": s }),
            serde_json::Value::Object(o) => serde_json::Value::Object(
                o.iter()
                    .filter(|(k, v)| !(v.is_null() && matches!(k.as_str(), "policy" | "source")))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            other => other.clone(),
        },
        ItemNs::Policy | ItemNs::Store | ItemNs::StoreOrder | ItemNs::AuditRetentionDays => {
            crate::storage::sealed_vault::owner_config_typed(ns, name, body)
                .unwrap_or_else(|| body.clone())
        }
        _ => body.clone(),
    }
}

/// SHA-256 of the JCS form (sorted keys) of the [`normalized_body`].
pub fn body_digest(ns: ItemNs, name: &str, body: &serde_json::Value) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(crate::crypto::canonical::canonicalize(&normalized_body(
        ns, name, body,
    )))
    .into()
}

/// Hex of a [`body_digest`] (as a dirty row records its base).
pub fn body_digest_hex(ns: ItemNs, name: &str, body: &serde_json::Value) -> String {
    body_digest(ns, name, body)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// The record a set-aside change concerns, as the user knows it: an `aux`
/// field by its name, a singleton by its namespace, anything else as
/// `<namespace> <name>`.
pub fn record_label(p: &ItemPayload) -> String {
    match p.ns {
        ItemNs::Aux => p.name.clone(),
        ns if p.name.is_empty() => ns.as_str().to_string(),
        ns => format!("{} {}", ns.as_str(), p.name),
    }
}

/// Item lifecycle status. A tombstone carries `body: null` (contract §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemStatus {
    Live,
    Tombstone,
}

/// The object form of a `secret` body: the value plus the user's free-text
/// notes (1Password's item `notesPlain`). STRICT: exactly these fields, both
/// strings, so a body from a future shape (or a malformed one) is an error,
/// never half-read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretBodyObject {
    value: String,
    #[serde(default)]
    notes: Option<String>,
}

/// Encode a `secret` body. Without notes it stays the bare value string (the
/// original shape, byte-for-byte), so a vault that never uses notes is
/// unchanged; with notes it is `{ "value": …, "notes": … }`. Empty notes count
/// as none.
pub fn secret_body(value: &str, notes: Option<&str>) -> serde_json::Value {
    match notes.filter(|n| !n.is_empty()) {
        None => serde_json::Value::String(value.to_string()),
        Some(n) => serde_json::json!({ "value": value, "notes": n }),
    }
}

/// Decode a `secret` body into `(value, notes)`. Accepts exactly the two
/// shapes [`secret_body`] writes; anything else (a number, an object with an
/// unknown or non-string field) is an error the caller surfaces, not a guess.
pub fn parse_secret_body(body: &serde_json::Value) -> Result<(String, Option<String>)> {
    match body {
        serde_json::Value::String(s) => Ok((s.clone(), None)),
        serde_json::Value::Object(_) => {
            let o: SecretBodyObject = serde_json::from_value(body.clone())
                .map_err(|e| AppError::Internal(format!("secret body: {}", e)))?;
            Ok((o.value, o.notes.filter(|n| !n.is_empty())))
        }
        _ => Err(AppError::Internal(
            "secret body is neither a string nor { value, notes }".into(),
        )),
    }
}

/// The sealed JSON payload of a content item (contract §2). This is exactly the
/// plaintext handed to [`seal_record`]; the cloud never sees it (it can't even
/// tell a tombstone from a live item — `status` is inside the ct).
///
/// `body` is the ns-specific value, or JSON `null` for a tombstone. We keep it
/// as an untyped [`serde_json::Value`] because the shape varies by `ns` and we
/// never byte-compare cts (random nonce per seal) — plain serde is fine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemPayload {
    pub ns: ItemNs,
    pub name: String,
    pub status: ItemStatus,
    /// The value (`secret` string / `connection` object / owner-config part) or
    /// `null` for a tombstone. Always serialized (including `null`).
    #[serde(default)]
    pub body: serde_json::Value,
}

impl ItemPayload {
    /// A live payload with an arbitrary JSON body.
    pub fn live(ns: ItemNs, name: impl Into<String>, body: serde_json::Value) -> Self {
        Self {
            ns,
            name: name.into(),
            status: ItemStatus::Live,
            body,
        }
    }

    /// A live `secret` payload (`body` = the string value, no notes).
    pub fn secret_live(name: impl Into<String>, value: &str) -> Self {
        Self::live(
            ItemNs::Secret,
            name,
            serde_json::Value::String(value.to_string()),
        )
    }

    /// A tombstone for `(ns, name)` — `status = tombstone`, `body = null`.
    pub fn tombstone(ns: ItemNs, name: impl Into<String>) -> Self {
        Self {
            ns,
            name: name.into(),
            status: ItemStatus::Tombstone,
            body: serde_json::Value::Null,
        }
    }

    /// True iff this payload is a tombstone (the sync layer drops the local item).
    pub fn is_tombstone(&self) -> bool {
        matches!(self.status, ItemStatus::Tombstone)
    }

    /// Serialize to the sealed-plaintext JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(AppError::from)
    }

    /// Parse from sealed-plaintext JSON bytes.
    pub fn from_json_bytes(b: &[u8]) -> Result<Self> {
        serde_json::from_slice(b).map_err(AppError::from)
    }
}

/// Seal an [`ItemPayload`] for `(vault, id, version)` under `K` using the
/// daemon's primitive suite. Output is sudp's per-record layout
/// `suite(1) ‖ nonce(24) ‖ ct ‖ tag(16)`.
pub fn seal_item<S: PrimitiveSuite>(
    k: &[u8],
    ctx: &ItemCtx,
    payload: &ItemPayload,
) -> Result<Vec<u8>> {
    let pt = payload.to_json_bytes()?;
    seal_record::<S>(k, &ctx.seal_ctx(), &pt)
        .map_err(|e| AppError::Internal(format!("seal item: {}", e)))
}

/// Unseal a sealed item ct back to its [`ItemPayload`]. The `version` bound in
/// `ctx` MUST equal the one the ct was sealed under (sudp's AAD binding), so a
/// tampered plaintext `version` sidecar can't lie — a mismatch is an
/// `Unauthorized` here.
pub fn unseal_item<S: PrimitiveSuite>(
    k: &[u8],
    ctx: &ItemCtx,
    sealed: &[u8],
) -> Result<ItemPayload> {
    let pt = unseal_record::<S>(k, &ctx.seal_ctx(), sealed)
        .map_err(|e| AppError::Unauthorized(format!("unseal item: {}", e)))?;
    ItemPayload::from_json_bytes(&pt)
}

/// Unseal the stored row at `wire` (its id as `/items` carries it) under
/// `keys`: with the current content key, else (a row a re-key has not moved
/// yet) with a previous key this member holds that lists this row at this
/// version with this ciphertext (it existed, exactly so, when that key was
/// retired), newest first. A row that opens only under a previous key that
/// does not list it is unreadable. The flag: it opened only under a previous
/// key. Every read of a row goes through here; every write seals under
/// `keys.content`, so a row read through a previous key is never written
/// back under it.
pub fn unseal_item_keys<S: PrimitiveSuite>(
    keys: VaultKeys,
    wire: &str,
    ctx: &ItemCtx,
    sealed: &[u8],
) -> Result<(ItemPayload, bool)> {
    match unseal_item::<S>(keys.content, ctx, sealed) {
        Ok(p) => Ok((p, false)),
        Err(e) if keys.prev.is_empty() => Err(e),
        Err(e) => {
            let digest = ct_sha256(sealed);
            keys.prev_keys()
                .filter(|prev| prev.lists(wire, ctx.version(), &digest))
                .find_map(|prev| unseal_item::<S>(prev.key, ctx, sealed).ok())
                .map(|p| (p, true))
                .ok_or(e)
        }
    }
}

/// Open a dirty row of this device's own (a change it sealed and has not
/// sent yet) at `wire`: with the current content key, else with any
/// previous key this member holds. A retired key's list names the rows the
/// vault held, which a change made here after that never is; this device
/// knows its own change.
pub fn open_own_wire_item<S: PrimitiveSuite>(
    keys: VaultKeys,
    vault_id: &str,
    wire: &str,
    version: u64,
    sealed: &[u8],
) -> Result<ItemPayload> {
    let raw = aad_id_from_wire::<S>(keys.id_seed, wire)?;
    let ctx = ItemCtx::new(vault_id, raw, version);
    match unseal_item::<S>(keys.content, &ctx, sealed) {
        Ok(p) => Ok(p),
        Err(e) => keys
            .prev_keys()
            .find_map(|prev| unseal_item::<S>(prev.key, &ctx, sealed).ok())
            .ok_or(e),
    }
}

/// Open a stored/pulled row addressed by its WIRE id (row PK) at `version`:
/// recover the 32-byte AAD id ([`aad_id_from_wire`], stable id-seed) and unseal
/// it ([`unseal_item_keys`]). The one read used by the push-side 409
/// reconcile for both OUR local row and THEIR fresh cloud row.
pub fn open_wire_item<S: PrimitiveSuite>(
    keys: VaultKeys,
    vault_id: &str,
    wire_id: &str,
    version: u64,
    sealed: &[u8],
) -> Result<ItemPayload> {
    let raw = aad_id_from_wire::<S>(keys.id_seed, wire_id)?;
    unseal_item_keys::<S>(keys, wire_id, &ItemCtx::new(vault_id, raw, version), sealed)
        .map(|(p, _)| p)
}

/// Seal `payload` for the row at WIRE id `wire_id` at `version` (the inverse of
/// [`open_wire_item`]) — re-sealing an existing row at a fresh CAS version.
pub fn seal_wire_item<S: PrimitiveSuite>(
    keys: VaultKeys,
    vault_id: &str,
    wire_id: &str,
    version: u64,
    payload: &ItemPayload,
) -> Result<Vec<u8>> {
    let raw = aad_id_from_wire::<S>(keys.id_seed, wire_id)?;
    seal_item::<S>(keys.content, &ItemCtx::new(vault_id, raw, version), payload)
}

const CONFLICT_COPY_SUFFIX: &str = " (conflict copy)";

/// Copy levels a record may reach (`"<name> (conflict copy)"` nested at most
/// this many times); a conflict past them is refused, never written over.
pub const MAX_COPY_LEVELS: usize = 3;

/// Display name of a conflict copy: `"<name> (conflict copy)"` (console parity).
pub fn conflict_copy_name(name: &str) -> String {
    format!("{}{}", name, CONFLICT_COPY_SUFFIX)
}

/// True for a name [`conflict_copy_name`] produced.
pub fn is_conflict_copy_name(name: &str) -> bool {
    name.ends_with(CONFLICT_COPY_SUFFIX)
}

/// How many copy levels `name` carries.
fn copy_level(name: &str) -> usize {
    let mut n = 0;
    let mut rest = name;
    while let Some(r) = rest.strip_suffix(CONFLICT_COPY_SUFFIX) {
        n += 1;
        rest = r;
    }
    n
}

/// The row at a candidate copy's address, as [`conflict_copy_slot`] sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowAt {
    /// No row.
    Absent,
    /// A tombstone at `version`.
    Removed { version: u64 },
    /// A live row whose normalized body digests to `digest`.
    Live { digest: [u8; 32] },
    /// A row this key cannot open.
    Unreadable,
}

/// Where a keep-both conflict copy goes ([`conflict_copy_slot`]).
#[derive(Debug, Clone)]
pub enum CopySlot {
    /// Write `payload` at `wire`, a create (`base_version` `None`) or over the
    /// tombstone at `base_version`.
    Write {
        payload: ItemPayload,
        wire: String,
        base_version: Option<u64>,
    },
    /// The copy is already there (same content): nothing to write.
    Same { wire: String },
}

/// Keep-both (§4): OURS is kept as the record `"<name> (conflict copy)"`, an
/// ordinary record at that name's own derived id. A live row there with the
/// same content is the same copy; with other content the copy goes one level
/// down (`"<name> (conflict copy) (conflict copy)"`), at most
/// [`MAX_COPY_LEVELS`] in all; a tombstone there is written over at its next
/// version. A row that cannot be read is never written over, and a conflict
/// past the last level is refused: both `Err`. `at(wire)` reads the row at
/// an address.
pub fn conflict_copy_slot<S: PrimitiveSuite>(
    id_seed: &[u8],
    ours: &ItemPayload,
    mut at: impl FnMut(&str) -> RowAt,
) -> Result<CopySlot> {
    let mut name = ours.name.clone();
    while copy_level(&name) < MAX_COPY_LEVELS {
        name = conflict_copy_name(&name);
        let wire = wire_id_for::<S>(id_seed, ours.ns, &name)?;
        let payload = ItemPayload::live(ours.ns, name.clone(), ours.body.clone());
        match at(&wire) {
            RowAt::Absent => {
                return Ok(CopySlot::Write {
                    payload,
                    wire,
                    base_version: None,
                })
            }
            RowAt::Removed { version } => {
                return Ok(CopySlot::Write {
                    payload,
                    wire,
                    base_version: Some(version),
                })
            }
            RowAt::Live { digest } if digest == body_digest(ours.ns, &name, &ours.body) => {
                return Ok(CopySlot::Same { wire })
            }
            RowAt::Live { .. } => {}
            RowAt::Unreadable => {
                return Err(AppError::Conflict(format!(
                    "{} '{}': the record at '{}' cannot be read with this vault's key, so no copy is written over it",
                    ours.ns.as_str(),
                    ours.name,
                    name
                )))
            }
        }
    }
    Err(AppError::Conflict(format!(
        "{} '{}': {} conflict copies of it already differ; resolve them in the console",
        ours.ns.as_str(),
        ours.name,
        MAX_COPY_LEVELS
    )))
}

/// [`RowAt`] of a stored row opened under `keys` (`None`: no row).
pub fn row_at<S: PrimitiveSuite>(
    keys: VaultKeys,
    vault_id: &str,
    wire: &str,
    row: Option<(u64, &[u8])>,
) -> RowAt {
    let Some((version, ct)) = row else {
        return RowAt::Absent;
    };
    match open_wire_item::<S>(keys, vault_id, wire, version, ct) {
        Ok(p) if p.is_tombstone() => RowAt::Removed { version },
        Ok(p) => RowAt::Live {
            digest: body_digest(p.ns, &p.name, &p.body),
        },
        Err(_) => RowAt::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sudp::primitives::StdPrimitives;

    #[test]
    fn secret_body_round_trips_both_shapes() {
        // No notes (or empty notes) keeps the original bare-string body.
        assert_eq!(secret_body("v", None), serde_json::json!("v"));
        assert_eq!(secret_body("v", Some("")), serde_json::json!("v"));
        assert_eq!(
            parse_secret_body(&secret_body("v", None)).unwrap(),
            ("v".into(), None)
        );
        // With notes it is the object form, and decodes back losslessly.
        let b = secret_body("v", Some("line1\nline2"));
        assert_eq!(
            b,
            serde_json::json!({ "value": "v", "notes": "line1\nline2" })
        );
        assert_eq!(
            parse_secret_body(&b).unwrap(),
            ("v".into(), Some("line1\nline2".into()))
        );
        // `notes` is optional in the object form; empty normalizes to none.
        assert_eq!(
            parse_secret_body(&serde_json::json!({ "value": "v" })).unwrap(),
            ("v".into(), None)
        );
        assert_eq!(
            parse_secret_body(&serde_json::json!({ "value": "v", "notes": "" })).unwrap(),
            ("v".into(), None)
        );
    }

    #[test]
    fn secret_body_rejects_every_other_shape() {
        for bad in [
            serde_json::json!(null),
            serde_json::json!(42),
            serde_json::json!(["v"]),
            serde_json::json!({}),                             // no value
            serde_json::json!({ "value": 1 }),                 // non-string value
            serde_json::json!({ "value": "v", "notes": 1 }),   // non-string notes
            serde_json::json!({ "value": "v", "extra": "x" }), // unknown field
        ] {
            assert!(parse_secret_body(&bad).is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn write_allowed_role_x_type() {
        use ItemNs::*;
        use WriterRole::*;
        // Data records: every writer principal (owner / member / device), any keyset.
        for ns in [Secret, Connection, Connecting, Service] {
            for role in [Owner, Member, Device] {
                for ks in [false, true] {
                    assert!(ns.write_allowed("x", role, false, ks), "{ns:?} by {role:?}");
                }
            }
        }
        // Owner-config: an owner; the device only on a vault without a
        // keyset; never a plain member.
        for (ns, name) in [
            (Policy, ""),
            (Policy, "category:ai"),
            (Policy, "connection:gmail"),
            (Store, "native-secrets"),
            (StoreOrder, ""),
            (AuditRetentionDays, ""),
        ] {
            for ks in [false, true] {
                assert!(
                    ns.write_allowed(name, Owner, false, ks),
                    "{ns:?}:{name} owner"
                );
                assert!(
                    !ns.write_allowed(name, Member, false, ks),
                    "{ns:?}:{name} member"
                );
            }
            assert!(
                ns.write_allowed(name, Device, false, false),
                "{ns:?}:{name} v1"
            );
            assert!(
                !ns.write_allowed(name, Device, false, true),
                "{ns:?}:{name} keyset"
            );
        }
        // Unknown policy names and named singletons: nobody.
        for (ns, name) in [
            (Policy, "other:x"),
            (Policy, "category:"),
            (StoreOrder, "x"),
            (AuditRetentionDays, "x"),
        ] {
            assert!(
                !ns.write_allowed(name, Owner, false, false),
                "{ns:?}:{name}"
            );
        }
        // The console's secret order: members only.
        assert!(SecretOrder.write_allowed("", Member, false, true));
        assert!(!SecretOrder.write_allowed("", Device, false, false));
        // Legacy `aux` rows: no live write by anyone; only the migration's
        // tombstone (an owner with a keyset, anyone without).
        for field in [
            "policy",
            "stores",
            "store_order",
            "audit_retention_days",
            "secret_order",
            "services",
        ] {
            let r = rule(Aux, field).unwrap();
            for role in [Owner, Member, Device] {
                for ks in [false, true] {
                    assert!(!Aux.write_allowed(field, role, false, ks), "aux:{field}");
                }
                assert!(r.migration_tombstone_allowed(role, false), "aux:{field} v1");
            }
            assert!(r.migration_tombstone_allowed(Owner, true));
            assert!(!r.migration_tombstone_allowed(Device, true));
            assert!(!r.migration_tombstone_allowed(Member, true));
            assert!(device_may_write(Aux, field, false, true), "v1 tombstone");
            assert!(!device_may_write(Aux, field, false, false), "never live");
            assert!(
                !device_may_write(Aux, field, true, true),
                "keyset: the owner's"
            );
        }
        assert!(!rule(Secret, "x")
            .unwrap()
            .migration_tombstone_allowed(Device, false));
        // Authorized-agents table: any owner; the agent's OWN member; not others.
        assert!(Agent.write_allowed("ag", Owner, false, true), "any owner");
        assert!(
            Agent.write_allowed("ag", Member, true, true),
            "their OWN agent"
        );
        assert!(
            !Agent.write_allowed("ag", Member, false, true),
            "someone else's agent"
        );
        assert!(
            !Agent.write_allowed("ag", Device, true, false),
            "device never"
        );
        assert!(!device_may_write(Agent, "ag", false, true));
        // Retired / unknown: fail-closed.
        for ns in [Stores, Services, Members] {
            assert!(!ns.write_allowed("", Owner, false, true), "{ns:?} retired");
        }
        assert!(
            !Aux.write_allowed("agent/ag_x", Owner, false, false),
            "no rule"
        );
        assert!(!device_may_write(Aux, "agent/ag_x", false, true), "no rule");
        assert!(!Aux.write_allowed("other", Device, false, false), "no rule");
    }

    /// THE canonical text of the item-namespace rule table. The console
    /// asserts the same text, verbatim: a change to the table must change
    /// both sides.
    #[test]
    fn rule_table_matches_the_canonical_text() {
        const CANONICAL: &str = r#"[{"key":"agent:<ag_id>","address":"cleartext_wire_hmac_aad","writers":["owner","own_member"],"signed":"writer:agent","conflict":"take_writer","read":"signer_authorized_and_wire_id_matches"},{"key":"audit_retention_days:","address":"blinded","writers":["owner","device_without_keyset"],"signed":"owner_with_keyset","conflict":"owner_config","read":"owner_signed_with_keyset_native_wins"},{"key":"aux:audit_retention_days","address":"blinded","writers":["migration_tombstone_only"],"signed":"owner_with_keyset","conflict":"owner_config","read":"legacy_when_no_honored_native"},{"key":"aux:policy","address":"blinded","writers":["migration_tombstone_only"],"signed":"owner_with_keyset","conflict":"owner_config","read":"legacy_when_no_honored_native"},{"key":"aux:secret_order","address":"blinded","writers":["migration_tombstone_only"],"signed":"none","conflict":"take_writer","read":"legacy_when_no_honored_native"},{"key":"aux:services","address":"blinded","writers":["migration_tombstone_only"],"signed":"owner_with_keyset","conflict":"owner_config","read":"legacy_union_native_wins"},{"key":"aux:store_order","address":"blinded","writers":["migration_tombstone_only"],"signed":"owner_with_keyset","conflict":"owner_config","read":"legacy_when_no_honored_native"},{"key":"aux:stores","address":"blinded","writers":["migration_tombstone_only"],"signed":"owner_with_keyset","conflict":"owner_config","read":"legacy_when_no_honored_native"},{"key":"connecting:<id>","address":"blinded","writers":["member","device"],"signed":"none","conflict":"take_writer","read":"all"},{"key":"connection:<id>","address":"blinded","writers":["member","device"],"signed":"none","conflict":"keep_both","read":"all"},{"key":"policy:","address":"blinded","writers":["owner","device_without_keyset"],"signed":"owner_with_keyset","conflict":"owner_config","read":"owner_signed_with_keyset_native_wins"},{"key":"policy:category:<tag>","address":"blinded","writers":["owner","device_without_keyset"],"signed":"owner_with_keyset","conflict":"owner_config","read":"owner_signed_with_keyset_native_wins"},{"key":"policy:connection:<connection_id>","address":"blinded","writers":["owner","device_without_keyset"],"signed":"owner_with_keyset","conflict":"owner_config","read":"owner_signed_with_keyset_native_wins"},{"key":"secret:<KEY>","address":"blinded","writers":["member","device"],"signed":"none","conflict":"keep_both","read":"all"},{"key":"secret_order:","address":"blinded","writers":["member"],"signed":"none","conflict":"take_writer","read":"console_only"},{"key":"service:<id>","address":"blinded","writers":["member","device"],"signed":"none","conflict":"keep_both","read":"derived_id_only_union_legacy"},{"key":"store:<id>","address":"blinded","writers":["owner","device_without_keyset"],"signed":"owner_with_keyset","conflict":"owner_config","read":"owner_signed_with_keyset_native_wins"},{"key":"store_order:","address":"blinded","writers":["owner","device_without_keyset"],"signed":"owner_with_keyset","conflict":"owner_config","read":"owner_signed_with_keyset_native_wins"}]"#;
        assert_eq!(canonical_rule_table(), CANONICAL);
    }

    /// The table's lookups: one rule per key; a pattern rule covers every
    /// name (a conflict copy's too), a prefixed rule its prefix with a
    /// non-empty rest, an exact rule its name; the device writes only records
    /// that need no signature where it writes them.
    #[test]
    fn rule_lookup_and_device_writes() {
        let keys: std::collections::BTreeSet<String> = ITEM_RULES.iter().map(|r| r.key()).collect();
        assert_eq!(keys.len(), ITEM_RULES.len(), "one rule per key");
        assert_eq!(
            rule(ItemNs::Secret, "A (conflict copy)").unwrap().key(),
            "secret:<KEY>"
        );
        assert_eq!(rule(ItemNs::Policy, "").unwrap().key(), "policy:");
        assert_eq!(
            rule(ItemNs::Policy, "category:ai").unwrap().key(),
            "policy:category:<tag>"
        );
        assert_eq!(
            rule(ItemNs::Policy, "connection:gmail-work").unwrap().key(),
            "policy:connection:<connection_id>"
        );
        assert!(rule(ItemNs::Policy, "category:").is_none());
        assert!(rule(ItemNs::Policy, "rules:x").is_none(), "unknown prefix");
        assert!(rule(ItemNs::Policy, " (conflict copy)").is_none());
        assert_eq!(rule(ItemNs::Store, "x").unwrap().key(), "store:<id>");
        assert_eq!(rule(ItemNs::Aux, "policy").unwrap().key(), "aux:policy");
        for ns in [ItemNs::Stores, ItemNs::Services, ItemNs::Members] {
            assert!(rule(ns, "").is_none(), "{ns:?} retired");
        }
        assert_eq!(conflict_policy(ItemNs::Service, "x"), Conflict::KeepBoth);
        assert_eq!(conflict_policy(ItemNs::Store, "x"), Conflict::OwnerConfig);
        assert_eq!(
            conflict_policy(ItemNs::Policy, "category:ai"),
            Conflict::OwnerConfig
        );
        assert_eq!(
            conflict_policy(ItemNs::Aux, "stores"),
            Conflict::OwnerConfig
        );
        assert_eq!(
            conflict_policy(ItemNs::Connecting, "x"),
            Conflict::TakeWriter
        );
        assert_eq!(ItemNs::Agent.address(), Address::CleartextWireHmacAad);
        assert_eq!(ItemNs::Aux.address(), Address::Blinded);
        for (ns, name, ty) in [
            (ItemNs::Policy, "", "policy"),
            (ItemNs::Policy, "connection:gmail", "policy"),
            (ItemNs::Store, "native-secrets", "store"),
            (ItemNs::StoreOrder, "", "store_order"),
            (ItemNs::AuditRetentionDays, "", "audit_retention_days"),
            (ItemNs::Aux, "store_order", "store_order"),
            (ItemNs::Agent, "ag_x", "agent"),
        ] {
            assert_eq!(rule(ns, name).unwrap().signature_type(name), Some(ty));
        }
        assert_eq!(rule(ItemNs::Secret, "x").unwrap().signature_type("x"), None);
        for r in &ITEM_RULES {
            for ks in [false, true] {
                if r.write_allowed(WriterRole::Device, false, ks) {
                    let unsigned =
                        r.signed == Signed::None || (r.signed == Signed::OwnerWithKeyset && !ks);
                    assert!(unsigned, "{} written by the device unsigned", r.key());
                }
            }
        }
    }

    /// A service body compares in its object form: the plain-string entry is
    /// `{service: <text>}`, a null policy / source is absent. An owner-config
    /// body compares as its typed value (a null or unknown field is absent),
    /// so the same content from the console and from this process is equal.
    /// Other bodies are compared as they are.
    #[test]
    fn bodies_compare_normalized() {
        let plain = serde_json::json!("[service]\nid = \"a\"\n");
        let object = serde_json::json!({ "service": "[service]\nid = \"a\"\n" });
        let nulls = serde_json::json!({ "service": "[service]\nid = \"a\"\n", "policy": null, "source": null });
        assert_eq!(normalized_body(ItemNs::Service, "a", &plain), object);
        assert_eq!(normalized_body(ItemNs::Service, "a", &nulls), object);
        assert_eq!(
            body_digest(ItemNs::Service, "a", &plain),
            body_digest(ItemNs::Service, "a", &object)
        );
        assert_eq!(body_digest_hex(ItemNs::Service, "a", &nulls).len(), 64);
        assert_ne!(
            body_digest(ItemNs::Secret, "a", &plain),
            body_digest(ItemNs::Secret, "a", &object)
        );
        // Owner-config: same content, written two ways.
        for (ns, name, a, b) in [
            (
                ItemNs::Policy,
                "",
                serde_json::json!({ "timeout": 30, "default": { "read": "allow", "ttl": null } }),
                serde_json::json!({ "default": { "read": "allow" }, "timeout": 30 }),
            ),
            (
                ItemNs::Policy,
                "category:ai",
                serde_json::json!({ "write": "ask", "read": null }),
                serde_json::json!({ "write": "ask" }),
            ),
            (
                ItemNs::Policy,
                "connection:gmail",
                serde_json::json!({ "default": { "write": "ask" }, "rules": {} }),
                serde_json::json!({ "default": { "write": "ask" } }),
            ),
            (
                ItemNs::Store,
                "gcp-1",
                serde_json::json!({ "kind": "gcp-sm", "category": "value", "items": {} }),
                serde_json::json!({ "category": "value", "kind": "gcp-sm" }),
            ),
        ] {
            assert_eq!(
                body_digest(ns, name, &a),
                body_digest(ns, name, &b),
                "{ns:?}:{name}"
            );
        }
        assert_ne!(
            body_digest(
                ItemNs::Policy,
                "category:ai",
                &serde_json::json!({ "write": "ask" })
            ),
            body_digest(
                ItemNs::Policy,
                "category:ai",
                &serde_json::json!({ "write": "deny" })
            )
        );
        // A body that does not parse compares as it is.
        let odd = serde_json::json!({ "write": 7 });
        assert_eq!(normalized_body(ItemNs::Policy, "category:ai", &odd), odd);
    }

    /// THE pinned cross-language parity vector (build contract §1).
    ///
    /// `K = 0x42 * 32 ; ns = "secret" ; name = "GMAIL_REFRESH_TOKEN"`.
    /// The frontend TS `item_id` MUST produce this exact base64url-nopad string.
    /// If this ever changes, the derivation drifted — do NOT edit the expected
    /// value to make it pass; find why Rust ↔ TS diverged.
    #[test]
    fn pinned_item_id_parity_vector() {
        let k = [0x42u8; 32];
        let id = item_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap();
        assert_eq!(id, "25fAyYNRxgkF3WqLCKweefkv-JCd5UECrQP7LCgApiQ");
    }

    /// The cleartext agent wire-id scheme (design/agent-authz-cleartext-cutover):
    /// the wire id IS the ag_id, but its seal/sig AAD is the SAME HMAC the blinded
    /// scheme derives for (ns=agent, name=ag_id). Blinded ids stay 43-char base64url
    /// and are decoded; the two id spaces are disjoint by length (35 vs 43). The FE
    /// mirror (lib/vault-items.ts) must agree byte-for-byte.
    #[test]
    fn agent_cleartext_wire_id_scheme() {
        let k = [0x42u8; 32];
        // ag_id = "ag_" + 32 lowercase base32 chars = 35 chars.
        let ag = "ag_abcdefghijklmnopqrstuvwxyz234567";
        assert_eq!(ag.len(), AGENT_WIRE_ID_LEN);
        assert!(is_agent_wire_id(ag));
        // wire id for an agent item is the ag_id verbatim.
        assert_eq!(wire_id_for::<StdPrimitives>(&k, ItemNs::Agent, ag).unwrap(), ag);
        // its AAD reconstructs to the SAME HMAC the writer sealed under.
        assert_eq!(
            aad_id_from_wire::<StdPrimitives>(&k, ag).unwrap(),
            item_id_bytes::<StdPrimitives>(&k, "agent", ag).unwrap(),
        );
        // Cross-lang PINNED — the FE (lib/vault-items.ts assertItemVectors) pins the
        // identical string. A drift here would silently drop agent rows on one side.
        assert_eq!(
            item_id::<StdPrimitives>(&k, "agent", ag).unwrap(),
            "9s_KpuijM0bNw-GnGuEAB5Jf0gupmsycI8H46UdSnow"
        );
        // a blinded secret id is 43 chars, NOT an agent id, and round-trips by decode.
        let blinded = item_id::<StdPrimitives>(&k, "secret", "X").unwrap();
        assert_eq!(blinded.len(), 43);
        assert!(!is_agent_wire_id(&blinded));
        assert_eq!(
            aad_id_from_wire::<StdPrimitives>(&k, &blinded).unwrap(),
            item_id_bytes::<StdPrimitives>(&k, "secret", "X").unwrap(),
        );
        // wire id for a non-agent ns is the blinded base64url.
        assert_eq!(wire_id_for::<StdPrimitives>(&k, ItemNs::Secret, "X").unwrap(), blinded);
    }

    /// Pin `K_id` too (cross-checked against an independent Python HKDF that
    /// also reproduces sudp's own `sudp/v1/item` conformance vector).
    #[test]
    fn pinned_item_id_subkey() {
        let k = [0x42u8; 32];
        let k_id = derive_item_id_key::<StdPrimitives>(&k).unwrap();
        let hex: String = k_id.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "5f1809d9cc658a4aa4f4dd5a2b5974fff833eacfabfd30f13ae8c5b1ed070c15"
        );
    }

    #[test]
    fn seal_unseal_item_roundtrip() {
        let k = [0x42u8; 32];
        let id = item_id_bytes::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap();
        let ctx = ItemCtx::new("vault-1", id, 1);
        let payload = ItemPayload::secret_live("GMAIL_REFRESH_TOKEN", "ya29.secret-value");
        let sealed = seal_item::<StdPrimitives>(&k, &ctx, &payload).unwrap();
        assert_eq!(sealed[0], 0x01, "sudp record suite tag");
        let opened = unseal_item::<StdPrimitives>(&k, &ctx, &sealed).unwrap();
        assert_eq!(opened.ns, ItemNs::Secret);
        assert_eq!(opened.name, "GMAIL_REFRESH_TOKEN");
        assert_eq!(
            opened.body,
            serde_json::Value::String("ya29.secret-value".into())
        );
        assert!(!opened.is_tombstone());
    }

    #[test]
    fn tombstone_roundtrips_with_null_body() {
        let k = [0x42u8; 32];
        let id = item_id_bytes::<StdPrimitives>(&k, "secret", "OLD").unwrap();
        let ctx = ItemCtx::new("v", id, 5);
        let tomb = ItemPayload::tombstone(ItemNs::Secret, "OLD");
        let sealed = seal_item::<StdPrimitives>(&k, &ctx, &tomb).unwrap();
        let opened = unseal_item::<StdPrimitives>(&k, &ctx, &sealed).unwrap();
        assert!(opened.is_tombstone());
        assert_eq!(opened.body, serde_json::Value::Null);
    }

    /// The AAD binds `version`; opening under a different version fails. This is
    /// what makes the plaintext CAS `version` un-forgeable relative to `ct`.
    #[test]
    fn wrong_version_ctx_fails_unseal() {
        let k = [0x42u8; 32];
        let id = item_id_bytes::<StdPrimitives>(&k, "secret", "X").unwrap();
        let sealed = seal_item::<StdPrimitives>(
            &k,
            &ItemCtx::new("v", id, 1),
            &ItemPayload::secret_live("X", "y"),
        )
        .unwrap();
        assert!(unseal_item::<StdPrimitives>(&k, &ItemCtx::new("v", id, 2), &sealed).is_err());
    }

    /// A keep-both conflict copy is an ordinary record `"<name> (conflict
    /// copy)"` at that name's own derived id: written there when absent or
    /// removed (over the tombstone's version), the same copy when the content
    /// is already there, one level down when other content is there, refused
    /// past [`MAX_COPY_LEVELS`] or over a row that cannot be read.
    #[test]
    fn a_conflict_copy_is_a_record_of_its_own_name() {
        let k = [0x42u8; 32];
        let ours = ItemPayload::secret_live("T", "mine");
        let id = |name: &str| item_id::<StdPrimitives>(&k, "secret", name).unwrap();
        let mine = body_digest(ItemNs::Secret, "T (conflict copy)", &serde_json::json!("mine"));
        let other = body_digest(ItemNs::Secret, "x", &serde_json::json!("other"));
        let slot = |rows: &dyn Fn(&str) -> RowAt| {
            conflict_copy_slot::<StdPrimitives>(&k, &ours, |w| rows(w))
        };
        // Absent: a create at "T (conflict copy)".
        match slot(&|_| RowAt::Absent).unwrap() {
            CopySlot::Write {
                payload,
                wire,
                base_version,
            } => {
                assert_eq!(payload.name, "T (conflict copy)");
                assert_eq!(wire, id("T (conflict copy)"));
                assert_eq!(base_version, None);
                assert_eq!(payload.body, serde_json::json!("mine"));
            }
            s => panic!("{s:?}"),
        }
        // Removed: written over the tombstone at its next version.
        assert!(matches!(
            slot(&|_| RowAt::Removed { version: 4 }).unwrap(),
            CopySlot::Write { base_version: Some(4), .. }
        ));
        // The same content there: nothing to write.
        assert!(matches!(
            slot(&|_| RowAt::Live { digest: mine }).unwrap(),
            CopySlot::Same { .. }
        ));
        // Other content there: one level down.
        let first = id("T (conflict copy)");
        match slot(&|w| {
            if w == first {
                RowAt::Live { digest: other }
            } else {
                RowAt::Absent
            }
        })
        .unwrap()
        {
            CopySlot::Write { payload, wire, .. } => {
                assert_eq!(payload.name, "T (conflict copy) (conflict copy)");
                assert_eq!(wire, id("T (conflict copy) (conflict copy)"));
            }
            s => panic!("{s:?}"),
        }
        // Every level taken by other content: refused, nothing written over.
        let e = slot(&|_| RowAt::Live { digest: other }).unwrap_err();
        assert!(e.to_string().contains("3 conflict copies"), "{e}");
        // A copy of a copy counts its levels: two more at most.
        let deep = ItemPayload::secret_live("T (conflict copy) (conflict copy)", "mine");
        let e = conflict_copy_slot::<StdPrimitives>(&k, &deep, |w| {
            if w == id("T (conflict copy) (conflict copy) (conflict copy)") {
                RowAt::Live { digest: other }
            } else {
                RowAt::Absent
            }
        })
        .unwrap_err();
        assert!(e.to_string().contains("conflict copies"), "{e}");
        // A row that cannot be read is never written over.
        let e = slot(&|_| RowAt::Unreadable).unwrap_err();
        assert!(e.to_string().contains("cannot be read"), "{e}");
    }

    /// `seal_wire_item` / `open_wire_item` round-trip a re-seal at a fresh version
    /// for the row's existing wire id (the reapply path).
    #[test]
    fn wire_item_reseal_roundtrip() {
        let k = [0x42u8; 32];
        let keys = VaultKeys::single(&k);
        let wire = item_id::<StdPrimitives>(&k, "policy", "").unwrap();
        let p = ItemPayload::live(ItemNs::Policy, "", serde_json::json!({"a": 1}));
        let ct = seal_wire_item::<StdPrimitives>(keys, "v", &wire, 7, &p).unwrap();
        let back = open_wire_item::<StdPrimitives>(keys, "v", &wire, 7, &ct).unwrap();
        assert_eq!(back.ns, ItemNs::Policy);
        assert_eq!(back.body, serde_json::json!({"a": 1}));
        assert!(open_wire_item::<StdPrimitives>(keys, "v", &wire, 6, &ct).is_err());
    }

    #[test]
    fn ns_str_matches_serde() {
        // as_str() must equal the serde-serialized tag (both feed the id HMAC
        // / the wire on the two sides).
        for ns in [
            ItemNs::Secret,
            ItemNs::Connection,
            ItemNs::Connecting,
            ItemNs::Aux,
            ItemNs::Agent,
            ItemNs::Service,
            ItemNs::Policy,
            ItemNs::Store,
            ItemNs::StoreOrder,
            ItemNs::AuditRetentionDays,
            ItemNs::SecretOrder,
            ItemNs::Stores,
            ItemNs::Services,
            ItemNs::Members,
        ] {
            let json = serde_json::to_value(ns).unwrap();
            assert_eq!(json, serde_json::Value::String(ns.as_str().to_string()));
        }
    }

    /// The previous content keys a keyset row carries: the item AEAD under
    /// the current content key, AAD {domain "prev_content_keys", vault, id
    /// empty, version u64be(current generation)}, over the compact JSON
    /// `{"v":1,"keys":[{"k":<std base64 key>,"items":[[<wire id>,<version>,<std
    /// base64 SHA-256 of the row's ct>],…]},…]}`, newest first. They open here
    /// in that order with their rows; another generation, vault, content key
    /// or domain does not open them, and anything but version 1 with 32-byte
    /// keys and 32-byte row digests is refused as a malformed list.
    #[test]
    fn prev_content_keys_format() {
        use base64::engine::general_purpose::STANDARD;
        let content = [0x7cu8; 32];
        let (n1, n2) = ([0x6bu8; 32], [0x5cu8; 32]);
        let vault = "vlt_prev_vector";
        let (ct_a, ct_b, ct_c) = (b"ct-a".as_slice(), b"ct-b".as_slice(), b"ct-c".as_slice());
        let r1: &[(&str, u64, &[u8])] = &[
            ("ag_abcdefghijklmnopqrstuvwxyz234567", 2, ct_a),
            ("aaaa", 1, ct_b),
            ("aaaa", 3, ct_c),
        ];
        let r2: &[(&str, u64, &[u8])] = &[];
        let sealed = seal_prev_content_keys::<StdPrimitives>(&content, vault, 3, &[(&n1, r1), (&n2, r2)]);
        // The plaintext, byte for byte.
        let version = 3u64.to_be_bytes();
        let pt = unseal_record::<StdPrimitives>(
            &content,
            &prev_content_keys_ctx(vault.as_bytes(), &version),
            &sealed,
        )
        .unwrap();
        let h = |ct: &[u8]| STANDARD.encode(ct_sha256(ct));
        assert_eq!(
            String::from_utf8(pt).unwrap(),
            format!(
                r#"{{"v":1,"keys":[{{"k":"{}","items":[["ag_abcdefghijklmnopqrstuvwxyz234567",2,"{}"],["aaaa",1,"{}"],["aaaa",3,"{}"]]}},{{"k":"{}","items":[]}}]}}"#,
                STANDARD.encode(n1),
                h(ct_a),
                h(ct_b),
                h(ct_c),
                STANDARD.encode(n2)
            )
        );
        let section = open_prev_content_keys::<StdPrimitives>(&content, vault, 3, &sealed).unwrap();
        let mut material = vault_key_bundle(&[1u8; 32], &content);
        material.extend_from_slice(&section);
        let keys = VaultKeys::from_material(&material);
        let prev: Vec<PrevKey> = keys.prev_keys().collect();
        assert_eq!(prev.len(), 2);
        assert_eq!((prev[0].key, prev[1].key), (&n1[..], &n2[..]));
        assert!(prev[0].lists("ag_abcdefghijklmnopqrstuvwxyz234567", 2, &ct_sha256(ct_a)));
        assert!(prev[0].lists("aaaa", 1, &ct_sha256(ct_b)));
        assert!(prev[0].lists("aaaa", 3, &ct_sha256(ct_c)));
        // All three must match.
        assert!(!prev[0].lists("aaaa", 1, &ct_sha256(ct_c)), "another ciphertext");
        assert!(!prev[0].lists("aaaa", 2, &ct_sha256(ct_b)), "another version");
        assert!(!prev[0].lists("aaab", 1, &ct_sha256(ct_b)), "another row");
        assert!(!prev[1].lists("aaaa", 1, &ct_sha256(ct_b)), "another key");
        assert!(open_prev_content_keys::<StdPrimitives>(&content, vault, 4, &sealed).is_err());
        assert!(open_prev_content_keys::<StdPrimitives>(&content, "vlt_other", 3, &sealed).is_err());
        assert!(open_prev_content_keys::<StdPrimitives>(&n1, vault, 3, &sealed).is_err());
        let seal_json = |domain: &str, json: &str| {
            seal_record::<StdPrimitives>(
                &content,
                &SealCtx {
                    domain,
                    vault: vault.as_bytes(),
                    id: &[],
                    version: &version,
                },
                json.as_bytes(),
            )
            .unwrap()
        };
        let open = |sealed: &[u8]| open_prev_content_keys::<StdPrimitives>(&content, vault, 3, sealed);
        let malformed = |sealed: &[u8]| {
            open(sealed).err().map(|e| e.to_string()).is_some_and(|e| e.ends_with("previous content keys: malformed list"))
        };
        // Another domain does not open.
        let other_domain = seal_json("prev_content_key", r#"{"v":1,"keys":[]}"#);
        assert!(open(&other_domain).is_err());
        // Earlier shapes (never released), another version, a key or a row
        // digest of another length: a malformed list, said as only that.
        let k1 = STANDARD.encode(n1);
        for json in [
            format!(r#"{{"v":1,"keys":["{}"]}}"#, k1),
            format!(r#"{{"v":1,"keys":[{{"k":"{}","items":[["aaaa",1]]}}]}}"#, k1),
            format!(r#"{{"v":2,"keys":[{{"k":"{}","items":[]}}]}}"#, k1),
            format!(r#"{{"v":1,"keys":[{{"k":"{}","items":[]}}]}}"#, STANDARD.encode([1u8; 16])),
            format!(r#"{{"v":1,"keys":[{{"k":"{}","items":[["aaaa",1,"{}"]]}}]}}"#, k1, STANDARD.encode([1u8; 16])),
            format!(r#"{{"v":1,"keys":[{{"k":"not base64!","items":[]}}]}}"#),
        ] {
            assert!(malformed(&seal_json(PREV_CONTENT_KEYS_DOMAIN, &json)), "{}", json);
        }
        let none = seal_json(PREV_CONTENT_KEYS_DOMAIN, r#"{"v":1,"keys":[]}"#);
        assert!(open(&none).unwrap().is_empty());
    }

    /// The console's vector (`testdata/prev-keys-vector.json`, made by
    /// running the console's own code): its sealed list opens here to its
    /// plaintext, and the keys and rows read from it are exactly the ones the
    /// console was given (newest first, rows sorted by wire id then version),
    /// each row's digest the SHA-256 of its decoded ct. If this fails, the
    /// two sides diverged: do not edit the vector.
    #[test]
    fn prev_content_keys_console_vector() {
        use base64::engine::general_purpose::STANDARD;
        let v: serde_json::Value =
            serde_json::from_str(include_str!("testdata/prev-keys-vector.json")).unwrap();
        let vault = v["vault_id"].as_str().unwrap();
        let generation = v["generation"].as_u64().unwrap();
        assert_eq!(generation, 3);
        let content = STANDARD
            .decode(v["current_content_key_b64"].as_str().unwrap())
            .unwrap();
        let sealed = STANDARD.decode(v["sealed_b64"].as_str().unwrap()).unwrap();
        let version = generation.to_be_bytes();
        let pt = unseal_record::<StdPrimitives>(
            &content,
            &prev_content_keys_ctx(vault.as_bytes(), &version),
            &sealed,
        )
        .unwrap();
        assert_eq!(std::str::from_utf8(&pt).unwrap(), v["plaintext"].as_str().unwrap());

        // What the console was given: keys newest first, each with its rows
        // as [wire id, version, std b64 digest], here sorted as the list is.
        type Row = (String, u64, String);
        let given: Vec<(String, Vec<Row>)> = v["prev_keys_newest_first"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let mut rows: Vec<Row> = e["items_as_given"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        let r = r.as_array().unwrap();
                        assert_eq!(r.len(), 3, "[wire id, version, digest]");
                        (
                            r[0].as_str().unwrap().to_string(),
                            r[1].as_u64().unwrap(),
                            r[2].as_str().unwrap().to_string(),
                        )
                    })
                    .collect();
                rows.sort();
                (e["k"].as_str().unwrap().to_string(), rows)
            })
            .collect();
        assert_eq!(given.len(), 3);

        // What this side reads from the sealed list.
        let section =
            open_prev_content_keys::<StdPrimitives>(&content, vault, generation, &sealed).unwrap();
        let mut material = vault_key_bundle(&[0u8; 32], &content);
        material.extend_from_slice(&section);
        let keys = VaultKeys::from_material(&material);
        assert_eq!(keys.content, &content[..]);
        let read: Vec<(String, Vec<Row>)> = keys
            .prev_keys()
            .map(|p| {
                let mut rows = Vec::new();
                let mut rest = p.rows;
                for _ in 0..p.n {
                    let (w, ver, h, r) = split_listed_row(rest).unwrap();
                    rows.push((std::str::from_utf8(w).unwrap().to_string(), ver, STANDARD.encode(h)));
                    rest = r;
                }
                assert!(rest.is_empty());
                (STANDARD.encode(p.key), rows)
            })
            .collect();
        assert_eq!(read, given);

        // Each digest is the SHA-256 of the row's decoded ct, and a key lists
        // a row only at its version with that ct.
        let cts = v["listed_row_cts_b64url"].as_object().unwrap();
        let prev: Vec<PrevKey> = keys.prev_keys().collect();
        for (p, (_, rows)) in prev.iter().zip(&given) {
            for (wire, ver, digest) in rows {
                let ct = URL_SAFE_NO_PAD
                    .decode(cts[&format!("{wire}@{ver}")].as_str().unwrap().trim_end_matches('='))
                    .unwrap();
                assert_eq!(STANDARD.encode(ct_sha256(&ct)), *digest, "{wire}@{ver}");
                assert!(p.lists(wire, *ver, &ct_sha256(&ct)));
                assert!(!p.lists(wire, ver + 1, &ct_sha256(&ct)));
                assert!(!p.lists(wire, *ver, &ct_sha256(b"another ct")));
            }
        }
        // A row listed under one key only is not listed under the others.
        let only_newest = URL_SAFE_NO_PAD
            .decode(cts["25fAyYNRxgkF3WqLCKweefkv-JCd5UECrQP7LCgApiQ@4"].as_str().unwrap())
            .unwrap();
        let wire = "25fAyYNRxgkF3WqLCKweefkv-JCd5UECrQP7LCgApiQ";
        assert!(prev[0].lists(wire, 4, &ct_sha256(&only_newest)));
        assert!(!prev[1].lists(wire, 4, &ct_sha256(&only_newest)));
        assert!(!prev[2].lists(wire, 4, &ct_sha256(&only_newest)));
    }

    /// Key material with the previous content keys splits back into the
    /// bundle and the keys, newest first; a read tries the current key, then
    /// each previous key that lists the row at its version with its
    /// ciphertext; a row a key does not list so is unreadable under it; a
    /// write never seals under one. This device's own change opens under
    /// any key it holds.
    #[test]
    fn material_with_prev_reads_only_the_rows_a_key_retired_with() {
        let (seed, older, old, new) = ([1u8; 32], [4u8; 32], [2u8; 32], [3u8; 32]);
        let vault = "vlt_m";
        let ctx = |name: &str, v: u64| {
            ItemCtx::for_item::<StdPrimitives>(&seed, vault, ItemNs::Secret, name, v).unwrap()
        };
        let (a, b) = (ctx("A", 1).item_id_b64(), ctx("B", 1).item_id_b64());
        let p = |name: &str| ItemPayload::secret_live(name, "x");
        let under = |k: &[u8], name: &str, v: u64| seal_item::<StdPrimitives>(k, &ctx(name, v), &p(name)).unwrap();
        // The rows as the vault held them when each key retired.
        let (a_old, b_older) = (under(&old, "A", 1), under(&older, "B", 1));
        let bundle = zeroize::Zeroizing::new(vault_key_bundle(&seed, &new));
        let sealed = seal_prev_content_keys::<StdPrimitives>(
            &new,
            vault,
            2,
            &[(&old, &[(a.as_str(), 1, a_old.as_slice())]), (&older, &[(b.as_str(), 1, b_older.as_slice())])],
        );
        // No seal, a seal for another generation: the bundle alone.
        for (gen, s) in [(2u64, &[][..]), (3, sealed.as_slice())] {
            let m = material_with_prev::<StdPrimitives>(bundle.clone(), vault, gen, s);
            assert_eq!(m.len(), 64);
            assert!(VaultKeys::from_material(&m).prev.is_empty());
        }
        let m = material_with_prev::<StdPrimitives>(bundle.clone(), vault, 2, &sealed);
        let keys = VaultKeys::from_material(&m);
        assert_eq!((keys.id_seed, keys.content), (&seed[..], &new[..]));
        let ks: Vec<&[u8]> = keys.prev_keys().map(|k| k.key).collect();
        assert_eq!(ks, vec![&old[..], &older[..]]);
        // A section that does not parse is none; material below a bundle is one key.
        let mut torn = m.to_vec();
        torn.pop();
        assert!(VaultKeys::from_material(&torn).prev.is_empty());
        assert_eq!(VaultKeys::from_material(&m[..40]).content.len(), 40);

        let read = |name: &str, wire: &str, v: u64, ct: &[u8]| {
            unseal_item_keys::<StdPrimitives>(keys, wire, &ctx(name, v), ct).map(|(_, prev)| prev)
        };
        assert!(!read("A", &a, 1, &under(&new, "A", 1)).unwrap());
        // Listed under the key that sealed it, this very ciphertext: read.
        assert!(read("A", &a, 1, &a_old).unwrap());
        assert!(read("B", &b, 1, &b_older).unwrap());
        // Another ciphertext of the same row and version (sealed again under
        // the retired key), another version, another row, or listed under
        // another key: unreadable.
        assert!(read("A", &a, 1, &under(&old, "A", 1)).is_err());
        assert!(read("A", &a, 2, &under(&old, "A", 2)).is_err());
        assert!(read("B", &b, 1, &under(&old, "B", 1)).is_err());
        assert!(read("A", &a, 1, &under(&older, "A", 1)).is_err());
        assert!(read("A", &a, 1, &under(&[9u8; 32], "A", 1)).is_err());
        let current_only = VaultKeys { prev: &[], ..keys };
        assert!(unseal_item_keys::<StdPrimitives>(current_only, &a, &ctx("A", 1), &a_old).is_err());
        // This device's own change, sealed under a key it held: it opens it.
        let own = under(&old, "A", 2);
        assert!(open_own_wire_item::<StdPrimitives>(keys, vault, &a, 2, &own).is_ok());
        assert!(open_own_wire_item::<StdPrimitives>(keys, vault, &a, 2, &under(&[9u8; 32], "A", 2)).is_err());
        // A write under these keys seals under the current key.
        let written = seal_wire_item::<StdPrimitives>(keys, vault, &a, 2, &p("A")).unwrap();
        assert!(open_wire_item::<StdPrimitives>(current_only, vault, &a, 2, &written).is_ok());
    }
}
