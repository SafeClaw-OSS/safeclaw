//! v3 vault plaintext shape — per `docs/STORES_AND_ITEMS.md`.
//!
//! Physical layout (Design B): the decrypted protected state `M` =
//! `sudp::state::ProtectedState { targets, peers, aux }` carries:
//!
//! - `M.targets` — `native-secrets` item values. sudp's `TargetValue`
//!   zero-on-drop + b64-binary-safe encoding give us byte-safe storage
//!   for the only store kind that holds authoritative bytes locally.
//! - `M.aux`     — everything else (stores configuration, store_order,
//!   per-store items metadata for non-byte-storing stores). Parsed into
//!   [`VaultAux`].
//! - `M.peers`   — sudp-internal credential rewrap map. Untouched here.
//!
//! The doc's `vault.enc` example is a *logical* view that merges these
//! two physical pools; runtime code goes through [`VaultPlaintextView`]
//! to query items by name with resolution-order semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sudp::state::ProtectedState;

use crate::error::{AppError, Result};

/// Current schema version. Hard-fail on any other value.
pub const PLAINTEXT_VERSION: u32 = 3;

/// Reserved store IDs. These two stores are always present in every vault.
pub const NATIVE_SECRETS_ID: &str = "native-secrets";
pub const NATIVE_FILES_ID: &str = "native-files";

/// Reserved kind strings, equal to the reserved store IDs.
pub const NATIVE_SECRETS_KIND: &str = "native-secrets";
pub const NATIVE_FILES_KIND: &str = "native-files";

/// Category — value (bytes resolvable to a single secret string) vs file
/// (blob retrieved by id). Declared per-store, not per-item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Value,
    File,
}

/// A single store record inside `aux.stores`. `kind` selects the adapter;
/// `items` holds adapter-specific item metadata (shape varies by kind).
/// Adapter-specific config fields live alongside in `extra` for forward-
/// compat with stores we don't have parse rules for yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub kind: String,
    pub category: Category,
    /// Per-item metadata. For `native-secrets`, this map is empty in `aux`
    /// because byte values physically live in `ProtectedState.targets`.
    /// For `native-files`, values are `{ blob_id, size }`. For external
    /// stores (gcp / 1p / aws — Phase 2+), shape is adapter-defined.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub items: BTreeMap<String, serde_json::Value>,
    /// Adapter-specific configuration (e.g. `project_id` for gcp).
    /// Preserved verbatim on round-trip so unknown fields don't drop.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `aux` payload — everything inside `ProtectedState.aux` for v3 vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAux {
    pub version: u32,
    pub stores: BTreeMap<String, Store>,
    pub store_order: Vec<String>,
}

impl VaultAux {
    /// Build the minimal initial aux for a freshly enrolled vault: both
    /// reserved stores present and empty, with the default order
    /// `[native-secrets, native-files]`.
    pub fn initial() -> Self {
        let mut stores = BTreeMap::new();
        stores.insert(
            NATIVE_SECRETS_ID.to_string(),
            Store {
                kind: NATIVE_SECRETS_KIND.to_string(),
                category: Category::Value,
                items: BTreeMap::new(),
                extra: serde_json::Map::new(),
            },
        );
        stores.insert(
            NATIVE_FILES_ID.to_string(),
            Store {
                kind: NATIVE_FILES_KIND.to_string(),
                category: Category::File,
                items: BTreeMap::new(),
                extra: serde_json::Map::new(),
            },
        );
        Self {
            version: PLAINTEXT_VERSION,
            stores,
            store_order: vec![NATIVE_SECRETS_ID.to_string(), NATIVE_FILES_ID.to_string()],
        }
    }
}

/// Runtime view of a decrypted vault. Merges the two physical pools
/// (`targets` and `aux`) so callers can ask resolution-order questions
/// without caring about layout.
#[derive(Debug)]
pub struct VaultPlaintextView {
    pub aux: VaultAux,
    /// Native-secrets items: `item_name → raw bytes`. Materialised from
    /// `ProtectedState.targets`. Stored as owned bytes (not `TargetValue`)
    /// because the view's lifetime is the request, not the protocol
    /// boundary — sudp's zeroize is preserved up to the moment we copy.
    pub native_secrets: BTreeMap<String, Vec<u8>>,
}

impl VaultPlaintextView {
    /// Parse from an opened `ProtectedState`. Hard-fails on `version != 3`.
    pub fn from_protected_state(m: &ProtectedState) -> Result<Self> {
        let aux: VaultAux = serde_json::from_value(m.aux.clone())
            .map_err(|e| AppError::Internal(format!("vault aux parse: {}", e)))?;
        if aux.version != PLAINTEXT_VERSION {
            return Err(AppError::Internal(format!(
                "vault plaintext version {} (expected {}) — vault is from an older binary; re-enroll required",
                aux.version, PLAINTEXT_VERSION
            )));
        }
        let mut native_secrets = BTreeMap::new();
        for (name, val) in m.targets.iter() {
            native_secrets.insert(name.clone(), val.as_bytes().to_vec());
        }
        Ok(VaultPlaintextView { aux, native_secrets })
    }

    /// Synchronous resolve restricted to `native-secrets`. Used by the
    /// unlock cache-bootstrap path that runs inside a non-async section.
    /// Other store kinds (gcp/1p/aws) require async I/O — use
    /// [`Self::resolve_value_async`] to walk those.
    pub fn resolve_value_native(&self, item_name: &str) -> Option<&[u8]> {
        for store_id in &self.aux.store_order {
            let Some(store) = self.aux.stores.get(store_id) else {
                continue;
            };
            if store.category != Category::Value {
                continue;
            }
            if store.kind == NATIVE_SECRETS_KIND {
                if let Some(bytes) = self.native_secrets.get(item_name) {
                    return Some(bytes.as_slice());
                }
            }
            // External adapter kinds are skipped here; caller that needs
            // them should use the async path.
        }
        None
    }

    /// Resolve a value-category item by name through the full store_order
    /// using the v3 adapter dispatch. First match wins; errors from a
    /// configured store propagate (no silent fallback). `Ok(None)` means
    /// no store has the item.
    pub async fn resolve_value_async(
        &self,
        item_name: &str,
    ) -> crate::error::Result<Option<Vec<u8>>> {
        for store_id in &self.aux.store_order {
            let Some(store) = self.aux.stores.get(store_id) else {
                continue;
            };
            if store.category != Category::Value {
                continue;
            }
            let adapter = crate::store::build_adapter(store_id, store, self)?;
            if let Some(bytes) = adapter.resolve(item_name).await? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_protected_state(aux_json: serde_json::Value, targets: &[(&str, &[u8])]) -> ProtectedState {
        let mut m = ProtectedState::new();
        m.aux = aux_json;
        for (k, v) in targets {
            m.put_target(k.to_string(), v.to_vec());
        }
        m
    }

    #[test]
    fn parse_minimal_aux_succeeds() {
        let m = build_protected_state(
            serde_json::json!({
                "version": 3,
                "stores": {
                    "native-secrets": { "kind": "native-secrets", "category": "value" },
                    "native-files":   { "kind": "native-files",   "category": "file"  }
                },
                "store_order": ["native-secrets", "native-files"]
            }),
            &[("openai_api_key", b"sk-test")],
        );
        let view = VaultPlaintextView::from_protected_state(&m).unwrap();
        assert_eq!(view.aux.version, 3);
        assert_eq!(view.aux.store_order, vec!["native-secrets", "native-files"]);
        assert_eq!(view.resolve_value_native("openai_api_key"), Some(&b"sk-test"[..]));
        assert_eq!(view.resolve_value_native("nonexistent"), None);
    }

    #[test]
    fn parse_wrong_version_rejected() {
        let m = build_protected_state(
            serde_json::json!({
                "version": 2,
                "stores": {},
                "store_order": []
            }),
            &[],
        );
        let err = VaultPlaintextView::from_protected_state(&m).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("version 2"), "got: {}", msg);
    }

    #[test]
    fn initial_aux_round_trips() {
        let aux = VaultAux::initial();
        let json = serde_json::to_value(&aux).unwrap();
        let aux2: VaultAux = serde_json::from_value(json).unwrap();
        assert_eq!(aux2.version, 3);
        assert!(aux2.stores.contains_key("native-secrets"));
        assert!(aux2.stores.contains_key("native-files"));
        assert_eq!(aux2.store_order.len(), 2);
    }
}
