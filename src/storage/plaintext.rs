//! v4 vault plaintext shape — per `docs/STORES_AND_ITEMS.md`.
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

use crate::core::policy::Policy;
use crate::error::{AppError, Result};

/// Current schema version. Hard-fail on any other value.
pub const PLAINTEXT_VERSION: u32 = 4;

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

/// An **established** connection — an instance of a service (TYPE) the user has
/// connected. Keyed (in `VaultAux.connections`) by `connection_id`: a slug that
/// is the user's handle AND the routing/cache/audit unit. `== service_id` for
/// the default (unprefixed) connection; a distinct slug for a named one
/// (see `docs/CONNECTION_SCHEMA.md` §2).
///
/// Status is **DERIVED**, never stored: present in `connections` with its
/// required secret(s) present → Connected; a required secret missing → Partly
/// configured. There is no status field to drift out of sync.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Connection {
    /// The service (TYPE) this instantiates, or `None` for a **raw** connection
    /// (`sc set K --host h`) that references no service and anchors its own
    /// `hosts`. When set, hosts derive from the service (SSoT); an instance may
    /// only PIN exact FQDNs within a service's `*.suffix` wildcards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The connection's anchored hosts. Required for a raw connection (the
    /// egress anchor). For a service-backed connection: `None` when the service
    /// declares exact hosts only (derived, no stored copy); the pinned exact
    /// FQDNs (⊆ the service's `*.suffix` entries) when the service is wildcard.
    /// Enforced exact-FQDN at egress; never a bare `*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// The UPPERCASE secret KEY names this connection uses. **REQUIRED for a raw
    /// connection** (`service: None`) — it answers "which secrets" directly, so
    /// discovery and cache-bootstrap read it instead of reverse-indexing the
    /// native-secrets namespace by casing. **OMITTED (`None`) for a service-backed
    /// connection**: its secrets derive from the service's declared `secrets`
    /// (including the oauth2 refresh-token KEY). One canonical answer, no drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
}

/// An **in-flight** connect handshake — everything the daemon needs to redeem
/// the OAuth code and produce the durable secret. On a successful exchange the
/// daemon writes the secret and **MOVES** the entry into `connections` (dropping
/// it here) — there is never a partial/duplicate record.
///
/// Relayed to the daemon *through the sealed vault* to stay cloud-blind: the
/// browser drives consent, seals `{ service, hosts?, oauth2: { code, code_verifier } }`
/// here, and the daemon (not the backend) performs the code→token exchange. The
/// generic identity (`service`, `hosts`) is top-level; the mechanism handshake
/// state nests under the mechanism key (`oauth2`) so a future auth mechanism
/// nests under ITS key without the schema getting messy. `redirect_uri` is NOT
/// here — it's a fixed property of the OAuth client, held in the provider config.
/// Mirrors the frontend `lib/vault-grant.ts` `Connecting` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connecting {
    /// The service (TYPE) being instantiated.
    pub service: String,
    /// Exact FQDNs pinned at connect for a `*.suffix` wildcard service, carried
    /// through to the established [`Connection`] on exchange. Omitted (`None`)
    /// for an exact-hosts service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// OAuth2 (RFC 6749 authorization_code + RFC 7636 PKCE) handshake state.
    /// Nested under the mechanism key — mirrors the service.toml `[oauth2]`.
    pub oauth2: ConnectingOAuth2,
}

/// The oauth2 handshake temps of an in-flight connect (RFC 6749 / 7636). These
/// are flow-standard, not per-service, so they live here rather than in the
/// service.toml `[oauth2]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectingOAuth2 {
    /// The single-use authorization code from the loopback redirect (RFC 6749).
    pub code: String,
    /// The PKCE code_verifier (RFC 7636) the browser generated for this flow.
    pub code_verifier: String,
    /// Terminal exchange failure — set by the daemon when the code→token
    /// exchange fails non-recoverably (`invalid_grant`: the authorization code
    /// expired or was already used). The console renders "connection failed,
    /// reconnect" instead of a perpetual "connecting". Absent while the connect
    /// is still in flight (transient errors leave this unset so the next sync
    /// retries). Cleared when a fresh connect overwrites the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The vault address of a connection's secret role (CONNECTION_SCHEMA.md §3):
/// the **bare** mainstream name for the default connection (`conn_id ==
/// service_id`, 1:1 with env/GCP import), or `<conn_id>:<ROLE>` for a **named**
/// one. The `:` delimiter is invalid in env-var names, so a namespaced key can
/// never masquerade as an env var. One rule, applied everywhere a connection's
/// secret is written (connect) or read (broker / cache bootstrap), so the two
/// can't drift.
pub fn secret_address(conn_id: &str, service_id: &str, role: &str) -> String {
    if conn_id == service_id {
        role.to_string()
    } else {
        format!("{conn_id}:{role}")
    }
}

/// `aux` payload — everything inside `ProtectedState.aux` for v4 vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAux {
    pub version: u32,
    pub stores: BTreeMap<String, Store>,
    pub store_order: Vec<String>,
    /// The policy tree — risk map, default floors, per-category, and per-
    /// connection user policy (PROTOCOL.md §5.2 / §6.4 `M.policy`). Absent on
    /// fresh vaults → daemon uses `Policy::default()`. Replaces the old split
    /// `policy_defaults` + `service_state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    /// In-flight connects, keyed by `connection_id`. Each carries everything the
    /// daemon needs to redeem the OAuth code; on exchange the entry MOVEs to
    /// `connections`. Sparse — empty when nothing is mid-handshake. See
    /// [`Connecting`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connecting: BTreeMap<String, Connecting>,
    /// Established connections, keyed by `connection_id`. Sparse. Status is
    /// derived (see [`Connection`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connections: BTreeMap<String, Connection>,
    /// Audit log retention in days. `None` = keep forever; integer = drop
    /// rows older than this on the next `GET /v/{vid}/approvals` call.
    /// Frontend offers 7 / 30 / 90 / forever; the daemon clamps to a
    /// sensible range during prune.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_retention_days: Option<u32>,
    /// Per-vault custom service definitions: `service_id → verbatim v4
    /// service.toml source`. Validated (v4 schema, provider ∈ shipped
    /// `_providers`, no tool-named sections) at unlock before it can broker,
    /// and again at author time. Sparse — empty when the user authored none. A
    /// custom service is folded into the catalog exactly like a compiled one;
    /// it never shadows a built-in id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, String>,
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
            policy: None,
            connecting: BTreeMap::new(),
            connections: BTreeMap::new(),
            audit_retention_days: None,
            services: BTreeMap::new(),
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
    /// Parse from an opened `ProtectedState`. Hard-fails on `version != 4`.
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
        for (name, val) in m.secrets.iter() {
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
            m.put_secret(k.to_string(), v.to_vec());
        }
        m
    }

    #[test]
    fn parse_minimal_aux_succeeds() {
        let m = build_protected_state(
            serde_json::json!({
                "version": 4,
                "stores": {
                    "native-secrets": { "kind": "native-secrets", "category": "value" },
                    "native-files":   { "kind": "native-files",   "category": "file"  }
                },
                "store_order": ["native-secrets", "native-files"]
            }),
            &[("openai_api_key", b"sk-test")],
        );
        let view = VaultPlaintextView::from_protected_state(&m).unwrap();
        assert_eq!(view.aux.version, 4);
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
        assert_eq!(aux2.version, 4);
        assert!(aux2.stores.contains_key("native-secrets"));
        assert!(aux2.stores.contains_key("native-files"));
        assert_eq!(aux2.store_order.len(), 2);
    }
}
