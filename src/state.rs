//! Top-level application state.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::approval::ApprovalStore;
use crate::audit::AuditRegistry;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::TenantDir;

/// Broadcast payload for the per-tenant SSE channel. The receiver-side filter
/// is on `tenant_id`; subscribers belonging to other tenants drop the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub tenant_id: String,
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

#[derive(Debug, Clone, Default)]
pub struct SecretsCache {
    /// service_id → resolved auth value bytes. Populated at unlock for every
    /// service whose required item resolves through the v3 store_order — not
    /// just allow-default services. The per-request evaluator below decides
    /// whether to USE the cached bytes (level=Allow), create a pending op
    /// (Ask / AskAlways), or short-circuit (Deny).
    pub entries: HashMap<String, Vec<u8>>,
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
    pub tenants: TenantDir,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    pub services: ServiceRegistry,
    pub events: broadcast::Sender<ApprovalEvent>,
    /// Per-vault Locked/Unlocked state. Absent entry = Locked. Lives entirely
    /// in process memory; daemon restart returns all vaults to Locked.
    pub vault_states: Mutex<HashMap<String, VaultState>>,
    /// Per-tenant audit log (PROTOCOL.md §5.3). Connections opened lazily on
    /// first write/query per tenant. Survives daemon restarts — unlike
    /// `approvals` / `vault_states` which are in-memory only.
    pub audits: AuditRegistry,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let tenants = TenantDir::new(&config.state_dir);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let audits = AuditRegistry::new(tenants.clone());
        Self {
            config,
            tenants,
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            services: ServiceRegistry::load(),
            events,
            vault_states: Mutex::new(HashMap::new()),
            audits,
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
    /// the vault is Locked, the service isn't bootstrapped, or the vault has
    /// never been unlocked.
    pub fn cache_lookup(&self, vault_id: &str, service_id: &str) -> Option<Vec<u8>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.entries.get(service_id).cloned(),
            _ => None,
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
        let service_levels = self
            .services
            .get(service_id)
            .and_then(|d| d.policy.as_ref())
            .and_then(|p| p.to_service_levels());
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
