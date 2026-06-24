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
///     `approval-confirm` with the matched rule's `ask_ttl`
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
    /// service_id → effective ordered rule list. Built at unlock time by
    /// merging the service's built-in rules with the user's sparse
    /// `aux.service_state.<svc>.rule_overrides`. The /use handler walks
    /// this list (longest-match-wins per `core::policy::evaluate_policy`)
    /// to decide the approval level for each incoming request.
    pub policy_rules: HashMap<String, Vec<crate::core::policy::PolicyRule>>,
    /// User's global policy defaults (per-category + global levels) snapshot.
    /// Layered on top of the daemon's compiled-in `PolicyDefaults::default()`
    /// during evaluation. Absent → fall back to compiled defaults.
    pub policy_defaults: Option<crate::core::policy::PolicyDefaults>,
    /// Audit log retention in days. Snapshot of `aux.audit_retention_days`
    /// at unlock. `None` = keep forever. Used by `GET /v/{vid}/approvals` to
    /// opportunistically prune old rows before listing.
    pub audit_retention_days: Option<u32>,
    /// Honors the `ask` (vs `ask-always`) semantic: after the user approves
    /// an Ask-level op, the daemon caches `(service, matched_rule_id) →
    /// expires_at` so subsequent requests within the TTL fast-path without
    /// re-prompting. `ask-always` never lands here; `allow` doesn't need it.
    ///
    /// Key shape: `(service_id, Option<rule_id>)`. `None` covers the case
    /// where no per-rule matched and the approval was driven by category-
    /// default Ask — the cache covers that whole category-default decision
    /// for the service. Value: Unix-epoch-second expiry.
    ///
    /// Lives in the same memory window as the rest of the cache: dropped on
    /// lock (which zero-outs the entire cache via Default drop). Daemon
    /// restart also blows it away (vaults boot Locked, cache starts empty).
    pub rule_approvals: HashMap<(String, Option<String>), u64>,
    /// User-authored per-service basic R/W. Snapshot of every populated
    /// `aux.service_state.<svc>.levels` at unlock. Layered above the
    /// service's registry-declared default in `evaluate` so a user pick
    /// like "GitHub: R: Allow" takes effect even when no rule matches.
    pub service_levels: HashMap<String, crate::core::policy::ServiceLevels>,
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
    pub oauth_access: HashMap<String, CacheEntry>,
}

#[derive(Debug)]
pub enum VaultState {
    Locked,
    Unlocked {
        cache: SecretsCache,
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
        }
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

    /// Transition a vault to Unlocked with the given bootstrap cache.
    /// Overwrites any prior state (a fresh unlock invalidates the previous
    /// cache).
    pub fn unlock_vault(&self, vault_id: String, cache: SecretsCache) {
        let unlocked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        states.insert(vault_id, VaultState::Unlocked { cache, unlocked_at });
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

    /// Look up a cached auth value for `(vault, service)`. Returns None if
    /// the vault is Locked, the service isn't bootstrapped/cached, the
    /// vault has never been unlocked, OR the entry's `expires_at` is in
    /// the past (lazy eviction).
    pub fn cache_lookup(&self, vault_id: &str, service_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.entries.get(service_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                // Lazy eviction: TTL-expired entries are dropped here so
                // ask services correctly fall back to the pending-op flow
                // once their cache window closes.
                cache.entries.remove(service_id);
                return None;
            }
        }
        Some(entry.value.clone())
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
        service_id: &str,
        value: Vec<u8>,
        expires_at: Option<u64>,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.entries.insert(
                service_id.to_string(),
                CacheEntry { value, expires_at },
            );
        }
    }

    /// Look up a cached OAuth `access_token` for `(vault, service)`.
    /// Returns `None` if locked, never minted, or past its expiry.
    /// Lazily evicts expired entries (same shape as `cache_lookup`).
    pub fn oauth_access_lookup(&self, vault_id: &str, service_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.oauth_access.get(service_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                cache.oauth_access.remove(service_id);
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
        service_id: &str,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.oauth_access.insert(
                service_id.to_string(),
                CacheEntry {
                    value,
                    expires_at: Some(expires_at),
                },
            );
        }
    }

    /// Evaluate the per-request policy decision for `(vault, service,
    /// method, path, body)`. Returns `None` when the vault is Locked or
    /// never unlocked (caller should treat that as "vault locked").
    ///
    /// Returned tuple: `(effective_level, matched_rule_id, ttl_seconds)`.
    ///
    /// Honors:
    ///   - user-overridden per-rule levels (`aux.service_state[svc].rule_overrides`)
    ///   - user global policy_defaults (per-category + legacy `levels`)
    ///   - service's compiled-in [policy] levels
    ///   - safe compiled-in defaults at the very end
    ///   - **active `ask` approvals** — if the decision is `Ask` AND the
    ///     `(service, rule_id)` pair is in the unexpired rule_approvals
    ///     cache, downgrades to `Allow` so the request fast-paths.
    pub fn evaluate_request_policy(
        &self,
        vault_id: &str,
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
        let rules = cache.policy_rules.get(service_id);
        // Service-level basic R/W resolves as: user override (this vault's
        // aux.service_state.<svc>.levels) field-wise over the registry-
        // declared default. Either may be absent — `merge_service_levels`
        // returns the meaningful intersection.
        let registry_service_levels = self
            .services
            .get(service_id)
            .and_then(|d| d.policy.as_ref())
            .and_then(|p| p.to_service_levels());
        let user_service_levels = cache.service_levels.get(service_id).cloned();
        let service_levels = crate::core::policy::merge_service_levels(
            user_service_levels.as_ref(),
            registry_service_levels.as_ref(),
        );
        // Layer user's global policy_defaults on top of compiled defaults so
        // a per-category override (e.g. "Use AI models = Ask every time")
        // affects evaluation even when no per-rule entry matches.
        let mut defaults = crate::core::policy::PolicyDefaults::default();
        if let Some(user) = cache.policy_defaults.as_ref() {
            if user.timeout.is_some() {
                defaults.timeout = user.timeout;
            }
            if user.levels.is_some() {
                defaults.levels = user.levels.clone();
            }
            if let Some(user_type_levels) = user.type_levels.as_ref() {
                let merged = defaults.type_levels.get_or_insert_with(Default::default);
                for (k, v) in user_type_levels {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        let category = self.services.default_category(service_id);
        let (level, matched_rule, ttl) = crate::core::policy::evaluate_policy_with_match(
            method,
            path,
            body,
            rules,
            service_levels.as_ref(),
            &defaults,
            Some(category),
        );

        // Cache hit honors the `ask`-with-TTL semantic: a prior approval at
        // the same (service, rule) scope, not yet expired, downgrades this
        // Ask to Allow so the request fast-paths without a passkey prompt.
        // Passive cleanup: if expired, drop the entry instead of returning
        // a hit. `ask-always` and `deny` never consult or write the cache;
        // `allow` doesn't need to.
        if level == crate::core::policy::AccessLevel::Ask {
            let key = (service_id.to_string(), matched_rule.clone());
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

        Some((level, matched_rule, ttl))
    }

    /// Record an `ask`-level approval into the per-vault TTL cache. Called
    /// from approve.rs when a Use op was approved AND the decision that
    /// created it was Ask (not AskAlways). `ttl_seconds` is the level's
    /// `ask_ttl` falling back to `policy.timeout` or a safe 300s default.
    ///
    /// No-op when the vault is locked at the moment of the call — that
    /// shouldn't happen in practice (the approve happens while the
    /// vault is unlocked) but we don't want to panic if it does.
    pub fn record_ask_approval(
        &self,
        vault_id: &str,
        service_id: &str,
        rule_id: Option<String>,
        ttl_seconds: u64,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache
                .rule_approvals
                .insert((service_id.to_string(), rule_id), now + ttl_seconds);
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
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            admin_key: None,
            api_key: None,
            relay_url: None,
        };
        AppState::new(cfg)
    }

    fn unlock_with_empty_cache(state: &AppState, vault_id: &str) {
        state.unlock_vault(vault_id.to_string(), SecretsCache::default());
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
}
