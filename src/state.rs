//! Top-level application state.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::approval::ApprovalStore;
use crate::audit::AuditRegistry;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::VaultDir;

/// Broadcast payload for the per-vault SSE channel. The receiver-side filter
/// is on `vault_id`; subscribers belonging to other vaults drop the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub vault_id: String,
    pub approval_id: String,
    /// One of "pending" | "approved" | "rejected".
    pub kind: String,
    /// Summary of the approved Operation (act.kind, target, scope) — present
    /// for pending. Frontend uses it to render the request card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_summary: Option<Value>,
    /// Cached upstream response for broker (Use) approvals after approve —
    /// `{status, headers, body, body_base64}` JSON. Present for approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_preview: Option<Value>,
    /// Rejection reason — present for rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Broadcast channel capacity. Lagging subscribers (typically tabs sleeping
/// in a background pinch) will drop events older than this — they reconnect
/// fresh and lose history, which is acceptable for a watcher UI.
const EVENT_CHANNEL_CAPACITY: usize = 128;

// ── Vault state (H3 / PROTOCOL.md §6.3) ──────────────────────────────────────
//
// Per-vault runtime state. Daemon boots Locked; user runs the SUDP
// `Custom("vault-unlock")` op to transition Unlocked (and side-effect a
// per-service secrets_cache bootstrap for `allow`-policy services). No auto-
// lock timer — that would break the `allow` invariant ("once unlocked, no
// further friction during the session"). Lock is always user-initiated via
// `Custom("vault-lock")` op.

/// A cached secret value with optional expiry. Per PROTOCOL.md §6.2,
/// memory residence is policy-driven:
///   - `allow` services → `expires_at = None` (lives the whole unlocked
///     session, populated at unlock bootstrap)
///   - `ask` services → `expires_at = Some(unix_secs)`, filled after
///     `approval-confirm` with the matched rule's `ttl`
///   - `ask-always` services → never cached (entry simply absent)
///
/// `cache_lookup` does lazy eviction: an entry past its `expires_at`
/// is removed and treated as a miss. No active sweeper today —
/// expired bytes linger in memory until the next lookup, which is
/// acceptable since the daemon already holds plaintexts for all
/// allow-level services anyway.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: Vec<u8>,
    /// `None` = never expires within the unlocked session (allow-level).
    /// `Some(t)` = expires at unix-second `t` (ask-level TTL).
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SecretsCache {
    /// service_id → cached auth value with per-entry expiry. Filled by:
    ///   - unlock bootstrap (only services whose default read level is
    ///     `allow` — see `bootstrap_cache_from_view`)
    ///   - post-approval insert from `approve_op` for `ask` and `allow`-
    ///     cache-miss paths (the secret was fresh-decrypted under the
    ///     grant's W_c during forward; we re-use it for subsequent
    ///     requests up to the policy TTL).
    /// `ask-always` services are deliberately absent (PROTOCOL.md §6.2
    /// "ask-always 服务: 永不进 cache").
    pub entries: HashMap<String, CacheEntry>,
    /// service_id → { secret_name → bytes } for every `{{secret.NAME}}` an
    /// `allow`-level recipe references. Populated at unlock bootstrap so the
    /// allow fast-path can render *multi-secret* recipes (e.g. a Twilio-style
    /// `account_sid` + `auth_token` pair) without a vault view — which only
    /// exists behind a fresh grant. Single-secret recipes get a one-entry
    /// map; oauth recipes get no entry (their token comes from `oauth_access`).
    /// Lives the whole unlocked session (allow semantics); wiped on lock.
    pub allow_secrets: HashMap<String, HashMap<String, Vec<u8>>>,
    /// The effective policy tree — the vault's `aux.policy` overlaid on the
    /// compiled-in `Policy::default()` at unlock/refresh (so unset parts use
    /// safe defaults). Holds the risk map, default floors, per-category, and
    /// per-connection user policy. Built-in per-service rules are NOT cached
    /// here — they're read live from the recipe registry at eval and merged
    /// with this tree's `connections.<id>.rules`. Rebuilt on every vault write
    /// → a `risk` / map edit is realtime on the next request.
    pub policy: crate::core::policy::Policy,
    /// Audit log retention in days. Snapshot of `aux.audit_retention_days`
    /// at unlock. `None` = keep forever. Used by `GET /v/{vid}/approvals` to
    /// opportunistically prune old rows before listing.
    pub audit_retention_days: Option<u32>,
    /// Honors the `ask` (vs `ask-always`) semantic: after the user approves
    /// an Ask-level op, the daemon caches the approval so subsequent
    /// requests *of the same scope* within the TTL fast-path without
    /// re-prompting. `ask-always` never lands here; `allow` doesn't need it.
    ///
    /// Key shape: `(connection_id, rule_id, method)`. The grant is bound to:
    ///   - the **connection** — approving account A's send never fast-paths B;
    ///   - the matched **policy rule** — which carries the path scope, so a
    ///     grant can never reach beyond the rule the user's approval matched;
    ///   - the **HTTP method** — so approving a read (GET) never silently
    ///     authorizes a later write (POST/DELETE) inside the window.
    /// A category-/connection-default Ask (no rule matched) is deliberately
    /// **not cached** — it has no author-defined path scope to bound a grant,
    /// so it re-prompts every request. Value: Unix-epoch-second expiry.
    ///
    /// Lives in the same memory window as the rest of the cache: dropped on
    /// lock (which zero-outs the entire cache via Default drop). Daemon
    /// restart also blows it away (vaults boot Locked, cache starts empty).
    pub rule_approvals: HashMap<(String, String, String), u64>,
    /// Item names present in the decrypted `native-secrets` kv (names only,
    /// never values). Surface for `GET /v/{vid}/keys-known` so the frontend
    /// can decide which services are "reachable" without paying for an
    /// external-store roundtrip. Populated at unlock; cleared on lock.
    pub native_keys: HashSet<String>,
    /// External stores' adapter inputs, snapshotted at unlock so live
    /// `list()` calls from `GET /v/{vid}/keys-known` can rebuild adapters
    /// without re-decrypting the vault. Value: (store record from aux,
    /// resolved credential bytes from native-secrets). Sparse — only
    /// kinds with an adapter (today: gcp-secret-manager) populate.
    ///
    /// F-19: credential bytes (GCP SA JSON with RSA private key) are wrapped
    /// in `Zeroizing` so they are zeroed on drop when the vault is locked.
    pub external_stores: HashMap<String, (crate::storage::plaintext::Store, zeroize::Zeroizing<Vec<u8>>)>,
    /// Derived OAuth access_tokens, keyed by service_id. These are the
    /// short-lived bearer values minted by exchanging the long-lived
    /// `refresh_token` (which lives in `entries`) at the provider's
    /// /token endpoint. **Never persisted to vault** — the design says
    /// only the immutable refresh_token enters the vault; the
    /// access_token is derived state that's allowed to evaporate on
    /// lock / daemon restart (next /use just re-mints it).
    ///
    /// `expires_at` tracks the provider-reported expiry (with a 60s
    /// safety margin baked in at insert time). `cache_lookup`'s
    /// generic eviction doesn't apply here — `oauth_access_lookup`
    /// has its own lazy eviction below.
    ///
    /// Keyed by **connection_id** (not service): two Gmail accounts mint and
    /// cache independent access tokens.
    pub oauth_access: HashMap<String, CacheEntry>,
    /// Routing snapshot: `connection_id → { service, config }`, taken from
    /// `aux.connections` at unlock (CONNECTION_SCHEMA.md §6). A request at
    /// `/use/<conn>` resolves its service through this map (falling back to
    /// `conn` itself when absent — an unconnected service IS its own default
    /// connection). `config` feeds `{{connection.<param>}}` slots. Wiped on lock.
    ///
    /// NOTE on the maps above (`entries`, `allow_secrets`, `oauth_access`,
    /// `rule_approvals`): for connection-routed `/use`/`/stream` the daemon keys
    /// them by **connection_id**, so two connections of one service never share a
    /// cache slot. Policy is likewise per-connection (`policy.connections.<id>`),
    /// while the built-in rules it merges come from the shared service recipe.
    pub connections: HashMap<String, crate::storage::plaintext::Connection>,
}

#[derive(Debug)]
pub enum VaultState {
    Locked,
    Unlocked {
        cache: SecretsCache,
        /// Retained state key `K` (zeroized on drop). Held for the unlocked
        /// session so a sealed blob pulled from cloud sync can be re-decrypted
        /// and the cache refreshed WITHOUT another passkey (Slice 3 realtime
        /// sync — matches 1Password's "vault key resident while unlocked").
        /// Dropped (wiped) on lock/delete along with the rest of this variant.
        state_key: zeroize::Zeroizing<Vec<u8>>,
        /// Unix epoch seconds when this Unlocked state began. Informational
        /// only today (no auto-lock); kept for future audit / debug.
        #[allow(dead_code)]
        unlocked_at: u64,
    },
}

pub struct AppState {
    pub config: Config,
    pub vaults: VaultDir,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    pub services: ServiceRegistry,
    pub events: broadcast::Sender<ApprovalEvent>,
    /// Per-vault Locked/Unlocked state. Absent entry = Locked. Lives entirely
    /// in process memory; daemon restart returns all vaults to Locked.
    pub vault_states: Mutex<HashMap<String, VaultState>>,
    /// Per-vault audit log (PROTOCOL.md §5.3). Connections opened lazily on
    /// first write/query per vault. Survives daemon restarts — unlike
    /// `approvals` / `vault_states` which are in-memory only.
    pub audits: AuditRegistry,
    /// Daemon HPKE outer-envelope keypair (PROTOCOL.md §4.2.1 M1). Loaded
    /// once at startup, used to open pending-passkey seals (cross-device
    /// add-passkey) and — in future — `[HPKE: MUST]` grant submissions.
    pub sc: crate::crypto::envelope::ScKeyPair,
    /// Per-vault async mutex serializing vault.dat read-modify-write cycles.
    /// Two concurrent approve calls on the same vault both read the pre-write
    /// state and race to rename the tmpfile — the second write wins silently.
    /// Holding this lock for the full approve lifetime prevents that race.
    /// Uses tokio::sync::Mutex so it can be held across await points.
    pub vault_write_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-vault SSE connection semaphore (cap = MAX_SSE_PER_VAULT).
    /// OwnedSemaphorePermit is stored in each live stream; dropping the
    /// stream drops the permit, automatically releasing the slot.
    pub sse_semaphores: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// Account-level set of broker-authorizing agent-key HASHES (sha256 hex),
    /// synced from the cloud (`/api/vault/agents/hashes`). This is the SOLE
    /// broker auth (agent ≡ api-key): a presented key is valid iff sha256(key)
    /// is a member. Empty ⇒ reject (a paired daemon requires an agent key; an
    /// unpaired/local-only daemon has no broker plane to gate). See
    /// [[project_vault_agent_architecture_2026_06_25]].
    pub agent_key_hashes: Mutex<std::collections::HashSet<String>>,
    /// OAuth connections whose refresh_token was rejected (`invalid_grant`) at
    /// /use — surfaced via `/registry` as `needs_reauth` so the console prompts a
    /// reconnect. Keyed by `(vault_id, connection_id)`. In-memory + self-healing:
    /// cleared on a successful refresh or a fresh connect; a still-dead token
    /// re-marks on the next use.
    pub oauth_reauth_needed: Mutex<std::collections::HashSet<(String, String)>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let vaults = VaultDir::new(&config.state_dir);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let audits = AuditRegistry::new(vaults.clone());
        let sc = crate::crypto::envelope::ScKeyPair::load_or_generate()
            .expect("sc_sk load/generate failed — check ~/.safeclaw/crypto perms");
        Self {
            config,
            vaults,
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            services: ServiceRegistry::load(),
            events,
            vault_states: Mutex::new(HashMap::new()),
            audits,
            sc,
            vault_write_locks: Mutex::new(HashMap::new()),
            sse_semaphores: Mutex::new(HashMap::new()),
            agent_key_hashes: Mutex::new(std::collections::HashSet::new()),
            oauth_reauth_needed: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Replace the synced account-level agent-key hash-set (sha256 hex).
    pub fn set_agent_key_hashes(&self, hashes: std::collections::HashSet<String>) {
        *self.agent_key_hashes.lock().unwrap() = hashes;
    }

    /// Emit an event into the broadcast channel. Silently swallows the "no
    /// active subscribers" case (it's normal — happens before any /try tab is
    /// connected).
    pub fn emit_event(&self, ev: ApprovalEvent) {
        let _ = self.events.send(ev);
    }

    /// True iff this vault is currently Locked (including "never unlocked
    /// since process boot").
    pub fn is_vault_locked(&self, vault_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        !matches!(states.get(vault_id), Some(VaultState::Unlocked { .. }))
    }

    /// Transition a vault to Unlocked with the given bootstrap cache and the
    /// retained state key `K`. Overwrites any prior state (a fresh unlock
    /// invalidates the previous cache + key).
    pub fn unlock_vault(
        &self,
        vault_id: String,
        cache: SecretsCache,
        state_key: zeroize::Zeroizing<Vec<u8>>,
    ) {
        let unlocked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        states.insert(vault_id, VaultState::Unlocked { cache, state_key, unlocked_at });
    }

    /// Clone the retained state key `K` for an Unlocked vault, or `None` when
    /// the vault is Locked. Used by the cloud-sync refresh to re-decrypt a
    /// freshly-pulled sealed blob without a passkey.
    pub fn cloned_state_key(&self, vault_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { state_key, .. }) => Some(state_key.clone()),
            _ => None,
        }
    }

    /// Transition a vault to Locked, zeroing any cached secrets.
    pub fn lock_vault(&self, vault_id: &str) {
        let mut states = self.vault_states.lock().unwrap();
        states.insert(vault_id.to_string(), VaultState::Locked);
    }

    /// Retention setting for this vault's audit log. `None` when the vault
    /// is locked (so the daemon has no view into aux) OR when the user
    /// hasn't configured a retention (keep-forever default). The audit
    /// list handler treats both cases the same: skip prune.
    pub fn audit_retention_days(&self, vault_id: &str) -> Option<u32> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.audit_retention_days,
            _ => None,
        }
    }

    /// Resolve a `connection_id` to its service (recipe) for an Unlocked vault
    /// (CONNECTION_SCHEMA.md §6). An explicit `aux.connections` entry names its
    /// `service`; otherwise the connection IS its own default — `conn == service`
    /// — which keeps `/use/<service>` working for unconnected/API-key services
    /// and the default OAuth connection. Locked vault → falls back to `conn`
    /// (the caller's locked-gate rejects before any real use).
    pub fn resolve_connection_service(&self, vault_id: &str, conn: &str) -> String {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .connections
                .get(conn)
                .map(|c| c.service.clone())
                .unwrap_or_else(|| conn.to_string()),
            _ => conn.to_string(),
        }
    }

    /// The per-connection config slot values (`{{connection.<param>}}` sources)
    /// for an Unlocked vault, or `None` when the connection has no explicit
    /// record / no config (the common default case).
    pub fn connection_config(
        &self,
        vault_id: &str,
        conn: &str,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .connections
                .get(conn)
                .map(|c| c.config.clone())
                .filter(|m| !m.is_empty()),
            _ => None,
        }
    }

    /// Look up a cached auth value for `(vault, connection)`. Returns None if
    /// the vault is Locked, the connection isn't bootstrapped/cached, the
    /// vault has never been unlocked, OR the entry's `expires_at` is in
    /// the past (lazy eviction).
    pub fn cache_lookup(&self, vault_id: &str, conn_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.entries.get(conn_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                // Lazy eviction: TTL-expired entries are dropped here so
                // ask connections correctly fall back to the pending-op flow
                // once their cache window closes.
                cache.entries.remove(conn_id);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Look up the full `{ secret_name → bytes }` map an allow-level recipe
    /// needs to render its templates. Returns `None` if the vault is locked
    /// or the service wasn't bootstrapped with a named-secret set (e.g. an
    /// oauth recipe, or one resolved post-approval). The allow fast-path
    /// falls back to a single-secret map keyed by the primary in that case.
    pub fn cache_lookup_secrets(
        &self,
        vault_id: &str,
        conn_id: &str,
    ) -> Option<HashMap<String, Vec<u8>>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                cache.allow_secrets.get(conn_id).cloned()
            }
            _ => None,
        }
    }

    /// Insert (or overwrite) a cached auth value with optional TTL.
    /// `expires_at = None` means "live until lock" (allow-level
    /// semantics). `Some(t)` is unix-second expiry for ask-level
    /// TTL caching. No-op when the vault is locked at the time of
    /// the call (shouldn't happen on the approve-time write path,
    /// but defensive — `approve_op` runs concurrently with locks).
    pub fn cache_insert(
        &self,
        vault_id: &str,
        conn_id: &str,
        value: Vec<u8>,
        expires_at: Option<u64>,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.entries.insert(
                conn_id.to_string(),
                CacheEntry { value, expires_at },
            );
        }
    }

    /// Look up AND remove a cached auth value for `(vault, connection)` —
    /// single-use consumption. The streaming captive-portal path uses this for
    /// `ask-always` services so each streamed operation (e.g. a `cargo publish`)
    /// burns its approval and the next one re-prompts for a fresh passkey.
    /// Honors TTL expiry like [`Self::cache_lookup`]; `None` when locked /
    /// absent / expired.
    pub fn cache_take(&self, vault_id: &str, conn_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.entries.remove(conn_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                return None;
            }
        }
        Some(entry.value)
    }

    /// Look up a cached OAuth `access_token` for `(vault, service)`.
    /// Returns `None` if locked, never minted, or past its expiry.
    /// Lazily evicts expired entries (same shape as `cache_lookup`).
    pub fn oauth_access_lookup(&self, vault_id: &str, conn_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.oauth_access.get(conn_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                cache.oauth_access.remove(conn_id);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Store a freshly-minted OAuth `access_token`. `expires_at` should
    /// be the provider-reported absolute expiry minus a small safety
    /// margin (the broker uses ~60s) so we refresh before the upstream
    /// would reject. No-op when the vault is locked at the time of
    /// the call.
    pub fn oauth_access_insert(
        &self,
        vault_id: &str,
        conn_id: &str,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.oauth_access.insert(
                conn_id.to_string(),
                CacheEntry {
                    value,
                    expires_at: Some(expires_at),
                },
            );
        }
    }

    /// Mark an OAuth connection's refresh_token as dead (invalid_grant at /use).
    /// Surfaced via `/registry` as `needs_reauth` so the console prompts reconnect.
    pub fn oauth_mark_reauth(&self, vault_id: &str, conn_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .insert((vault_id.to_string(), conn_id.to_string()));
    }

    /// Clear a connection's reauth flag (a refresh succeeded).
    pub fn oauth_clear_reauth(&self, vault_id: &str, conn_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .remove(&(vault_id.to_string(), conn_id.to_string()));
    }

    /// True iff `(vault, conn)`'s refresh_token was flagged dead.
    pub fn oauth_needs_reauth(&self, vault_id: &str, conn_id: &str) -> bool {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .contains(&(vault_id.to_string(), conn_id.to_string()))
    }

    /// Clear ALL reauth flags for a vault (a fresh connect just landed; any
    /// still-dead token re-marks on the next /use).
    pub fn oauth_clear_reauth_vault(&self, vault_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .retain(|(v, _)| v != vault_id);
    }

    /// Evaluate the per-request policy decision for `(vault, connection,
    /// service, method, path, body)`. Returns `None` when the vault is Locked
    /// or never unlocked (caller should treat that as "vault locked").
    ///
    /// Returned tuple: `(effective_level, matched_rule_id, ttl_seconds)`.
    ///
    /// Resolution (PROTOCOL.md §6.4):
    ///   - merge the service recipe's built-in rules with this connection's
    ///     user rules (`cache.policy.connections[conn].rules`),
    ///   - most-restrictive matching rule wins (deny-override), its `risk`
    ///     resolved through the live risk map (`cache.policy.risk`),
    ///   - else connection / category / global default floor, else ask-always,
    ///   - **active `ask` approvals** — if the decision is `Ask`, a rule
    ///     matched, AND the `(connection, rule_id, method)` triple is in the
    ///     unexpired rule_approvals cache, downgrades to `Allow` so the
    ///     request fast-paths. Connection-default Ask (no rule) never caches.
    pub fn evaluate_request_policy(
        &self,
        vault_id: &str,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Option<(crate::core::policy::AccessLevel, Option<String>, Option<u64>)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        // Built-in rules come from the connection's *service* recipe (static);
        // the user's per-connection edits/additions (`aux.policy.connections.
        // <id>.rules`) merge on top. The merge is per-connection so two
        // connections of the same service can be policed independently.
        let conn_policy = cache.policy.connections.get(connection_id);
        let empty_rules = std::collections::HashMap::new();
        let built_in = self
            .services
            .default_policy_rules(service_id)
            .unwrap_or_default();
        let rules = crate::core::policy::merge_rules(
            &built_in,
            conn_policy.map(|c| &c.rules).unwrap_or(&empty_rules),
        );
        // Connection default floor (when no rule matches): user's per-connection
        // override field-wise over the recipe's `[default]`.
        let recipe_levels = self.services.default_policy_levels(service_id);
        let connection_levels = crate::core::policy::merge_levels(
            conn_policy.and_then(|c| c.default.as_ref()),
            recipe_levels.as_ref(),
        );
        // The risk map + category/global floors live in `cache.policy` (the
        // user's `aux.policy` overlaid on compiled defaults at refresh). Read
        // live here → a risk-map edit is realtime on the next request.
        let category = self.services.default_category(service_id);
        let (level, matched_rule, ttl) = crate::core::policy::evaluate_with_match(
            method,
            path,
            body,
            Some(&rules),
            connection_levels.as_ref(),
            &cache.policy,
            Some(category),
        );

        // Cache hit honors the `ask`-with-TTL semantic, but the grant is
        // scoped to the matched rule AND the HTTP method: a prior approval
        // for the same (service, rule, method), not yet expired, downgrades
        // this Ask to Allow so the request fast-paths without a passkey
        // prompt. Two deliberate bounds keep a window from over-reaching:
        //   - No rule matched (category-/service-default Ask) → never a hit:
        //     there is no author-defined path scope to bound the grant.
        //   - Method is part of the key → approving a GET cannot fast-path a
        //     later POST/DELETE inside the window.
        // Passive cleanup: if expired, drop the entry instead of returning a
        // hit. `ask-always` and `deny` never consult or write the cache;
        // `allow` doesn't need to.
        if level == crate::core::policy::AccessLevel::Ask {
            if let Some(rule_id) = matched_rule.clone() {
                // The grant is scoped to the **connection** (not the service):
                // approving account A's send never fast-paths account B's.
                let key = (connection_id.to_string(), rule_id, method.to_string());
                if let Some(&exp) = cache.rule_approvals.get(&key) {
                    if exp > now {
                        return Some((
                            crate::core::policy::AccessLevel::Allow,
                            matched_rule,
                            ttl,
                        ));
                    } else {
                        cache.rule_approvals.remove(&key);
                    }
                }
            }
        }

        Some((level, matched_rule, ttl))
    }

    /// Record an `ask`-level approval into the per-vault TTL cache. Called
    /// from approve.rs when a Use op was approved AND the decision that
    /// created it was Ask (not AskAlways). `ttl_seconds` is the level's
    /// `ttl` falling back to `Policy.timeout` or a safe 300s default.
    ///
    /// The grant is scoped to `(service, rule_id, method)`. Two bounds:
    ///   - `rule_id == None` (category-/service-default Ask, no rule matched)
    ///     is **not recorded** — without an author-defined path scope a grant
    ///     would blanket the whole service, so such ops re-prompt every time.
    ///   - `method` is part of the key, so approving one verb never lets a
    ///     different verb fast-path inside the window.
    ///
    /// No-op when the vault is locked at the moment of the call — that
    /// shouldn't happen in practice (the approve happens while the
    /// vault is unlocked) but we don't want to panic if it does.
    pub fn record_ask_approval(
        &self,
        vault_id: &str,
        connection_id: &str,
        rule_id: Option<String>,
        method: &str,
        ttl_seconds: u64,
    ) {
        // No rule scope → not cacheable (see doc above).
        let Some(rule_id) = rule_id else { return };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.rule_approvals.insert(
                (connection_id.to_string(), rule_id, method.to_string()),
                now + ttl_seconds,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn test_state() -> AppState {
        let cfg = Config {
            state_dir: PathBuf::from(format!("/tmp/safeclaw-test-{}", std::process::id())),
            port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            admin_key: None,
            relay_url: None,
        };
        AppState::new(cfg)
    }

    fn unlock_with_empty_cache(state: &AppState, vault_id: &str) {
        state.unlock_vault(
            vault_id.to_string(),
            SecretsCache::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );
    }

    #[test]
    fn cache_insert_no_expiry_persists_lookups() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.cache_insert("v1", "svc", b"secret".to_vec(), None);
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"secret".to_vec()));
        // Multiple lookups still hit (no eviction without expiry).
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"secret".to_vec()));
    }

    #[test]
    fn cache_take_consumes_single_use() {
        // Backs the streaming captive-portal `ask-always` path: each stream
        // burns its approval so the next one re-prompts for a fresh passkey.
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.cache_insert("v1", "svc", b"tok".to_vec(), None);
        // First take returns the value …
        assert_eq!(state.cache_take("v1", "svc"), Some(b"tok".to_vec()));
        // … and removes it: a second take and a plain lookup both miss.
        assert_eq!(state.cache_take("v1", "svc"), None);
        assert_eq!(state.cache_lookup("v1", "svc"), None);
    }

    #[test]
    fn cache_take_honors_expiry() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.cache_insert("v1", "svc", b"stale".to_vec(), Some(0));
        // Expired entry is not returned (and is consumed/dropped).
        assert_eq!(state.cache_take("v1", "svc"), None);
    }

    #[test]
    fn cache_lookup_evicts_expired_entry() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        // Already-expired entry.
        state.cache_insert("v1", "svc", b"secret".to_vec(), Some(0));
        assert_eq!(state.cache_lookup("v1", "svc"), None);
        // Subsequent insert with valid TTL should succeed (lazy eviction
        // dropped the stale entry; nothing leaks across).
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        state.cache_insert("v1", "svc", b"new".to_vec(), Some(future));
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"new".to_vec()));
    }

    #[test]
    fn cache_lookup_returns_none_when_locked() {
        let state = test_state();
        // Never unlocked.
        assert_eq!(state.cache_lookup("v1", "svc"), None);
        // Insert into a locked vault should be a no-op too.
        state.cache_insert("v1", "svc", b"x".to_vec(), None);
        assert_eq!(state.cache_lookup("v1", "svc"), None);
    }

    /// Security regression: an `ask` approval is scoped to (service, rule,
    /// method). Approving a GET must NOT silently fast-path a later POST,
    /// even within the TTL window — closes the standing-authority hole where
    /// a single approval blanket-authorized every verb on a service.
    #[test]
    fn ask_grant_is_scoped_to_method_and_rule() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Policy, RiskTier, RuleConfig};

        // Inject the test rules as the connection's user rules (medium → ask).
        // "gh" has no recipe, so built-in is empty and these are the only rules.
        let ask_rule = |pat: &str| RuleConfig {
            match_pattern: Some(pat.to_string()),
            risk: Some(RiskTier::Medium),
            ttl: Some(60),
            ..Default::default()
        };
        let mut rules = std::collections::HashMap::new();
        rules.insert("read".to_string(), ask_rule("GET /x"));
        rules.insert("write".to_string(), ask_rule("POST /x"));
        let mut policy = Policy::default();
        policy
            .connections
            .insert("gh".to_string(), ConnectionPolicy { default: None, rules });

        let state = test_state();
        let vid = "v-scope";
        let mut cache = SecretsCache::default();
        cache.policy = policy;
        state.unlock_vault(vid.to_string(), cache, zeroize::Zeroizing::new(Vec::new()));

        // Baseline: GET resolves to Ask under the "read" rule. (Default
        // connection: connection_id == service_id == "gh".)
        let (lvl, rule, _) = state
            .evaluate_request_policy(vid, "gh", "gh", "GET", "/x", None)
            .unwrap();
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(rule.as_deref(), Some("read"));

        // User approves that GET.
        state.record_ask_approval(vid, "gh", Some("read".to_string()), "GET", 60);

        // The same GET now fast-paths (the feature still works).
        let (lvl, _, _) = state
            .evaluate_request_policy(vid, "gh", "gh", "GET", "/x", None)
            .unwrap();
        assert_eq!(lvl, AccessLevel::Allow, "approved GET should fast-path");

        // A POST is a DIFFERENT verb/rule — the GET approval must not cover it.
        let (lvl, rule, _) = state
            .evaluate_request_policy(vid, "gh", "gh", "POST", "/x", None)
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "approving a GET must never fast-path a POST"
        );
        assert_eq!(rule.as_deref(), Some("write"));

        // A category-default Ask (no rule) is never recorded, so it can never
        // produce a fast-path — record is a no-op for rule_id == None.
        state.record_ask_approval(vid, "gh", None, "GET", 60);
    }
}
