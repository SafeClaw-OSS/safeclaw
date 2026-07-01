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
    item_id, item_id_bytes, seal_item, unseal_item, ItemCtx, ItemNs, ItemPayload,
};

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
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    let pk = vault.registry.get::<WebAuthn>(&cid_bytes).ok().flatten()?;
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
    };
    Ok(SealedState {
        version: CURRENT_VERSION,
        registry,
        credentials: vec![sealed_cred],
        ciphertext,
    })
}

/// Rotate the acting credential's `(prf_salt, wrapped_key)` after a Write and
/// replace the body ciphertext. Used by the write handler.
pub fn replace_after_write(
    vault: &mut SealedVault,
    credential_id_b64: &str,
    new_prf_salt: Vec<u8>,
    new_wrapped_key: Vec<u8>,
    new_ciphertext: Vec<u8>,
) -> Result<()> {
    let cid_bytes = decode_credential_id(credential_id_b64)?;
    let cred = vault
        .credentials
        .iter_mut()
        .find(|c| c.credential_id == cid_bytes)
        .ok_or_else(|| AppError::Unauthorized("unknown credential for write".into()))?;
    cred.prf_salt = new_prf_salt;
    cred.wrapped_key = new_wrapped_key;
    vault.ciphertext = new_ciphertext;
    Ok(())
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
                }],
                keyset_version: 0,
            },
            items: BTreeMap::new(),
            items_seq: 0,
        })
    }

    /// Borrow a stored item by its base64url id.
    pub fn get_item(&self, item_id_b64: &str) -> Option<&StoredItem> {
        self.items.get(item_id_b64)
    }

    /// Insert or replace a raw sealed item (used by the pull/adopt path — the ct
    /// is already sealed by whoever wrote the cloud row).
    pub fn put_raw(&mut self, item_id_b64: String, version: u64, ct: Vec<u8>) {
        self.items.insert(item_id_b64, StoredItem { version, ct });
    }

    /// Drop a stored item outright (local GC of a fully-propagated tombstone).
    pub fn remove_item(&mut self, item_id_b64: &str) -> Option<StoredItem> {
        self.items.remove(item_id_b64)
    }

    /// The current CAS version of item `(ns, name)`, or `0` if absent — i.e.
    /// the `base_version` a new write should CAS against (contract §6).
    pub fn item_version<S: PrimitiveSuite>(&self, k: &[u8], ns: ItemNs, name: &str) -> Result<u64> {
        let id = item_id::<S>(k, ns.as_str(), name)?;
        Ok(self.items.get(&id).map(|s| s.version).unwrap_or(0))
    }

    /// Seal `payload` for `(ns, name)` at the NEXT version (current + 1) under
    /// `K` and upsert it — the monotonic-bump write the connect / write paths
    /// use so an offline peer's CAS sees a strictly higher version (contract
    /// §6). Returns `(item_id_b64, new_version)`.
    pub fn seal_and_bump<S: PrimitiveSuite>(
        &mut self,
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        payload: &ItemPayload,
    ) -> Result<(String, u64)> {
        let next = self.item_version::<S>(k, ns, name)? + 1;
        let id = self.seal_and_upsert::<S>(k, vault_id, ns, name, next, payload)?;
        Ok((id, next))
    }

    /// Seal `payload` for `(ns, name)` at `version` under `K` and upsert it,
    /// returning the base64url item id. Bridges the item.rs primitives
    /// (contract §1/§2) into the local store.
    pub fn seal_and_upsert<S: PrimitiveSuite>(
        &mut self,
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        payload: &ItemPayload,
    ) -> Result<String> {
        let ctx = ItemCtx::for_item::<S>(k, vault_id, ns, name, version)?;
        let ct = seal_item::<S>(k, &ctx, payload)?;
        let id = ctx.item_id_b64();
        self.items.insert(id.clone(), StoredItem { version, ct });
        Ok(id)
    }

    /// Unseal one stored item addressed by `(ns, name)` under `K`. `Ok(None)` if
    /// no such item is stored. The stored `version` is fed into the `SealCtx`,
    /// so a tampered version would fail the AEAD (contract §6).
    pub fn open_item<S: PrimitiveSuite>(
        &self,
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
    ) -> Result<Option<ItemPayload>> {
        let id = item_id::<S>(k, ns.as_str(), name)?;
        let Some(stored) = self.items.get(&id) else {
            return Ok(None);
        };
        let raw = item_id_bytes::<S>(k, ns.as_str(), name)?;
        let ctx = ItemCtx::new(vault_id, raw, stored.version);
        Ok(Some(unseal_item::<S>(k, &ctx, &stored.ct)?))
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
        k: &[u8],
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
    ) -> Result<()> {
        // native secrets → one `secret` item each.
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            let payload = ItemPayload::secret_live(name.clone(), &value);
            self.seal_and_upsert::<S>(k, vault_id, ItemNs::Secret, name, 1, &payload)?;
        }
        // established connections → one `connection` item each.
        for (conn_id, conn) in &view.aux.connections {
            let body = serde_json::to_value(conn).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connection, conn_id.clone(), body);
            self.seal_and_upsert::<S>(k, vault_id, ItemNs::Connection, conn_id, 1, &payload)?;
        }
        // in-flight connects → one `connecting` item each.
        for (conn_id, c) in &view.aux.connecting {
            let body = serde_json::to_value(c).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connecting, conn_id.clone(), body);
            self.seal_and_upsert::<S>(k, vault_id, ItemNs::Connecting, conn_id, 1, &payload)?;
        }
        // aux subtrees → one `aux` item each (only the modeled names).
        let stores = serde_json::to_value(&view.aux.stores).map_err(AppError::from)?;
        self.seal_and_upsert::<S>(
            k, vault_id, ItemNs::Aux, "stores", 1,
            &ItemPayload::live(ItemNs::Aux, "stores", stores),
        )?;
        let store_order = serde_json::to_value(&view.aux.store_order).map_err(AppError::from)?;
        self.seal_and_upsert::<S>(
            k, vault_id, ItemNs::Aux, "store_order", 1,
            &ItemPayload::live(ItemNs::Aux, "store_order", store_order),
        )?;
        if let Some(policy) = &view.aux.policy {
            let body = serde_json::to_value(policy).map_err(AppError::from)?;
            self.seal_and_upsert::<S>(
                k, vault_id, ItemNs::Aux, "policy", 1,
                &ItemPayload::live(ItemNs::Aux, "policy", body),
            )?;
        }
        if let Some(days) = view.aux.audit_retention_days {
            self.seal_and_upsert::<S>(
                k, vault_id, ItemNs::Aux, "audit_retention_days", 1,
                &ItemPayload::live(ItemNs::Aux, "audit_retention_days", serde_json::json!(days)),
            )?;
        }
        Ok(())
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
    /// items" (contract §5 `writeVault` diff). Returns the ids that changed.
    pub fn reconcile_from_view<S: PrimitiveSuite>(
        &mut self,
        k: &[u8],
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
    ) -> Result<Vec<String>> {
        let mut changed: Vec<String> = Vec::new();

        // Build the desired (ns, name) → body set from the view.
        let mut desired: BTreeMap<(ItemNs, String), serde_json::Value> = BTreeMap::new();
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            desired.insert((ItemNs::Secret, name.clone()), serde_json::Value::String(value));
        }
        for (id, conn) in &view.aux.connections {
            desired.insert(
                (ItemNs::Connection, id.clone()),
                serde_json::to_value(conn).map_err(AppError::from)?,
            );
        }
        for (id, c) in &view.aux.connecting {
            desired.insert(
                (ItemNs::Connecting, id.clone()),
                serde_json::to_value(c).map_err(AppError::from)?,
            );
        }
        for (name, body) in [
            ("stores", serde_json::to_value(&view.aux.stores).map_err(AppError::from)?),
            ("store_order", serde_json::to_value(&view.aux.store_order).map_err(AppError::from)?),
        ] {
            desired.insert((ItemNs::Aux, name.to_string()), body);
        }
        if let Some(policy) = &view.aux.policy {
            desired.insert(
                (ItemNs::Aux, "policy".to_string()),
                serde_json::to_value(policy).map_err(AppError::from)?,
            );
        }
        if let Some(days) = view.aux.audit_retention_days {
            desired.insert((ItemNs::Aux, "audit_retention_days".to_string()), serde_json::json!(days));
        }

        // Upsert every desired item whose sealed body differs from what we hold.
        for ((ns, name), body) in &desired {
            let existing = self.open_item::<S>(k, vault_id, *ns, name)?;
            let same = existing
                .as_ref()
                .map(|p| !p.is_tombstone() && &p.body == body)
                .unwrap_or(false);
            if same {
                continue;
            }
            let payload = ItemPayload::live(*ns, name.clone(), body.clone());
            let (id, _v) = self.seal_and_bump::<S>(k, vault_id, *ns, name, &payload)?;
            changed.push(id);
        }

        // Tombstone secret/connection/connecting rows the view dropped. Our own
        // folded view gives the currently-live (ns, name) set; tombstone any not
        // in `desired` (a completed connect MOVEs its `connecting` entry, so the
        // old connecting row must become a tombstone).
        let mine = self.fold_view::<S>(k, vault_id)?;
        for name in mine.native_secrets.keys() {
            if !desired.contains_key(&(ItemNs::Secret, name.clone())) {
                let (id, _v) = self.seal_and_bump::<S>(
                    k, vault_id, ItemNs::Secret, name,
                    &ItemPayload::tombstone(ItemNs::Secret, name.clone()),
                )?;
                changed.push(id);
            }
        }
        for id in mine.aux.connections.keys() {
            if !desired.contains_key(&(ItemNs::Connection, id.clone())) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    k, vault_id, ItemNs::Connection, id,
                    &ItemPayload::tombstone(ItemNs::Connection, id.clone()),
                )?;
                changed.push(iid);
            }
        }
        for id in mine.aux.connecting.keys() {
            if !desired.contains_key(&(ItemNs::Connecting, id.clone())) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    k, vault_id, ItemNs::Connecting, id,
                    &ItemPayload::tombstone(ItemNs::Connecting, id.clone()),
                )?;
                changed.push(iid);
            }
        }

        Ok(changed)
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
    /// NOTE: not yet called by the live handlers — `metadata.rs` still opens the
    /// whole-blob `ciphertext`. This is the ready target for that cut-over.
    pub fn fold_view<S: PrimitiveSuite>(
        &self,
        k: &[u8],
        vault_id: &str,
    ) -> Result<crate::storage::plaintext::VaultPlaintextView> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};

        // Start from the fresh-vault defaults; aux items OVERRIDE their subtree,
        // secret/connection/connecting items fill their maps.
        let mut aux = VaultAux::initial();
        let mut native_secrets: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        for (id_b64, stored) in &self.items {
            let raw_vec = URL_SAFE_NO_PAD
                .decode(id_b64.as_bytes())
                .map_err(|e| AppError::Internal(format!("item id base64url decode: {}", e)))?;
            let raw: [u8; 32] = raw_vec
                .as_slice()
                .try_into()
                .map_err(|_| AppError::Internal("item id is not 32 bytes".into()))?;
            let ctx = ItemCtx::new(vault_id, raw, stored.version);
            let payload = unseal_item::<S>(k, &ctx, &stored.ct)?;
            if payload.is_tombstone() {
                continue;
            }
            let name = payload.name;
            match payload.ns {
                ItemNs::Secret => {
                    let s = payload.body.as_str().ok_or_else(|| {
                        AppError::Internal(format!("secret item '{}' body is not a string", name))
                    })?;
                    native_secrets.insert(name, s.as_bytes().to_vec());
                }
                ItemNs::Connection => {
                    let conn = serde_json::from_value(payload.body)
                        .map_err(|e| AppError::Internal(format!("connection '{}' parse: {}", name, e)))?;
                    aux.connections.insert(name, conn);
                }
                ItemNs::Connecting => {
                    let c = serde_json::from_value(payload.body)
                        .map_err(|e| AppError::Internal(format!("connecting '{}' parse: {}", name, e)))?;
                    aux.connecting.insert(name, c);
                }
                ItemNs::Aux => {
                    // One aux item per subtree (contract §2). Unknown names are
                    // ignored (forward-compat with aux subtrees we don't model).
                    match name.as_str() {
                        "stores" => {
                            aux.stores = serde_json::from_value(payload.body)
                                .map_err(|e| AppError::Internal(format!("aux.stores parse: {}", e)))?;
                        }
                        "store_order" => {
                            aux.store_order = serde_json::from_value(payload.body)
                                .map_err(|e| AppError::Internal(format!("aux.store_order parse: {}", e)))?;
                        }
                        "policy" => {
                            aux.policy = Some(serde_json::from_value(payload.body).map_err(|e| {
                                AppError::Internal(format!("aux.policy parse: {}", e))
                            })?);
                        }
                        "audit_retention_days" => {
                            aux.audit_retention_days =
                                serde_json::from_value(payload.body).map_err(|e| {
                                    AppError::Internal(format!("aux.audit_retention_days parse: {}", e))
                                })?;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(VaultPlaintextView { aux, native_secrets })
    }
}

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
mod tests {
    use super::*;
    // Test fixture encodes credential_id with base64url-no-pad to match
    // `decode_credential_id`'s wire format (the WebAuthn convention).
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
                &k,
                vid,
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN",
                1,
                &ItemPayload::secret_live("GMAIL_REFRESH_TOKEN", "ya29.value"),
            )
            .unwrap();
        // The stored key is exactly the contract's base64url item id.
        assert_eq!(id, item_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap());
        assert_eq!(pv.get_item(&id).unwrap().version, 1);

        // Persist and reload → the sealed ct survives the base64url JSON codec.
        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert_eq!(loaded.keyset.credentials.len(), 1);
        assert_eq!(loaded.items.len(), 1);

        // Open it back through K — the fold the metadata layer will do per row.
        let payload = loaded
            .open_item::<StdPrimitives>(&k, vid, ItemNs::Secret, "GMAIL_REFRESH_TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(payload.body, serde_json::Value::String("ya29.value".into()));
        assert!(!payload.is_tombstone());

        // A wrong vault id must NOT open (AAD binds the vault).
        assert!(loaded
            .open_item::<StdPrimitives>(&k, "other-vault", ItemNs::Secret, "GMAIL_REFRESH_TOKEN")
            .is_err());

        // Absent item → Ok(None), not an error.
        assert!(loaded
            .open_item::<StdPrimitives>(&k, vid, ItemNs::Secret, "NOPE")
            .unwrap()
            .is_none());
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
            &k, vid, ItemNs::Secret, "OPENAI_KEY", 1,
            &ItemPayload::secret_live("OPENAI_KEY", "sk-live"),
        ).unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            &k, vid, ItemNs::Secret, "GONE", 2,
            &ItemPayload::tombstone(ItemNs::Secret, "GONE"),
        ).unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            &k, vid, ItemNs::Connection, "gmail", 1,
            &ItemPayload::live(
                ItemNs::Connection, "gmail",
                serde_json::json!({ "service": "gmail", "config": {} }),
            ),
        ).unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            &k, vid, ItemNs::Aux, "store_order", 1,
            &ItemPayload::live(
                ItemNs::Aux, "store_order",
                serde_json::json!(["native-secrets", "native-files", "gcp-1"]),
            ),
        ).unwrap();

        let view = pv.fold_view::<StdPrimitives>(&k, vid).unwrap();
        assert_eq!(view.resolve_value_native("OPENAI_KEY"), Some(&b"sk-live"[..]));
        assert_eq!(view.native_secrets.get("GONE"), None, "tombstone must be dropped");
        assert_eq!(
            view.aux.connections.get("gmail").map(|c| c.service.as_str()),
            Some("gmail")
        );
        assert_eq!(view.aux.store_order, vec!["native-secrets", "native-files", "gcp-1"]);
        assert_eq!(view.aux.version, 3);
    }
}
