use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::approval::ApprovalManager;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::crypto::keys::ServerKeypair;
use crate::policy::{PolicyDefaults, PushSubscription};

/// Elevated session: credential access is cached after approval until TTL expires.
pub struct ElevatedSession {
    /// Unix timestamp when this session expires
    pub expires_at: Instant,
}

/// Vault state — secrets held in memory when unlocked
pub struct VaultState {
    /// Decrypted vault JSON (all services)
    pub secrets: Mutex<Option<serde_json::Value>>,
    /// Service name list (populated at unlock, kept after lock for index queries)
    pub service_names: Mutex<Vec<String>>,
    /// Elevated session cache: service_name → session expiry
    pub elevated_cache: Mutex<HashMap<String, ElevatedSession>>,
    /// Push notification subscriptions (loaded at unlock)
    pub push_subscriptions: Mutex<Vec<PushSubscription>>,
    /// Policy defaults (loaded at unlock)
    pub policy_defaults: Mutex<PolicyDefaults>,
    /// OAuth2 token cache: service_name → (access_token, expires_at_unix_secs)
    pub oauth2_tokens: Mutex<HashMap<String, (String, u64)>>,
}

impl VaultState {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(None),
            service_names: Mutex::new(Vec::new()),
            elevated_cache: Mutex::new(HashMap::new()),
            push_subscriptions: Mutex::new(Vec::new()),
            policy_defaults: Mutex::new(PolicyDefaults::default()),
            oauth2_tokens: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.secrets.lock().unwrap().is_none()
    }

    /// Load decrypted vault JSON into memory.
    /// Parses service names, policy defaults, and push subscriptions.
    pub fn set_secrets(&self, secrets: serde_json::Value) {
        // Extract service names
        let names: Vec<String> = secrets
            .get("services")
            .and_then(|s| s.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();

        // Extract policy defaults
        let policy_defaults = secrets
            .get("policy_defaults")
            .and_then(|v| serde_json::from_value::<PolicyDefaults>(v.clone()).ok())
            .unwrap_or_default();

        // Extract push subscriptions
        let push_subs = secrets
            .get("push_subscriptions")
            .and_then(|v| serde_json::from_value::<Vec<PushSubscription>>(v.clone()).ok())
            .unwrap_or_default();

        *self.service_names.lock().unwrap() = names;
        *self.policy_defaults.lock().unwrap() = policy_defaults;
        *self.push_subscriptions.lock().unwrap() = push_subs;
        *self.secrets.lock().unwrap() = Some(secrets);
    }

    /// Lock the vault — clear all in-memory secrets.
    pub fn lock(&self) {
        *self.secrets.lock().unwrap() = None;
        *self.service_names.lock().unwrap() = Vec::new();
        *self.elevated_cache.lock().unwrap() = HashMap::new();
        *self.push_subscriptions.lock().unwrap() = Vec::new();
        *self.policy_defaults.lock().unwrap() = PolicyDefaults::default();
        *self.oauth2_tokens.lock().unwrap() = HashMap::new();
    }

    pub fn service_names(&self) -> Vec<String> {
        self.service_names.lock().unwrap().clone()
    }

    /// Check if an elevated session is still valid for the given service.
    pub fn check_elevated_session(&self, service: &str) -> bool {
        let cache = self.elevated_cache.lock().unwrap();
        if let Some(session) = cache.get(service) {
            session.expires_at > Instant::now()
        } else {
            false
        }
    }

    /// Store an elevated session for a service with the given TTL (seconds).
    pub fn set_elevated_session(&self, service: &str, ttl_secs: u64) {
        let mut cache = self.elevated_cache.lock().unwrap();
        cache.insert(
            service.to_string(),
            ElevatedSession {
                expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs),
            },
        );
    }

    /// Get the policy defaults currently in memory.
    pub fn get_policy_defaults(&self) -> PolicyDefaults {
        self.policy_defaults.lock().unwrap().clone()
    }
}

// ── AppState ───────────────────────────────────────────────────────────────────

/// Shared application state (Arc-wrapped)
pub struct AppState {
    pub config: Config,
    pub keypair: ServerKeypair,
    pub vault: Arc<VaultState>,
    pub nonces: Arc<Mutex<crate::auth::nonce::NonceStore>>,
    pub start_time: Instant,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub approval_manager: Arc<ApprovalManager>,
    pub audit_log: Arc<AuditLog>,
}

// ── Rate Limiter ───────────────────────────────────────────────────────────────

/// Per-IP rate limiter
pub struct RateLimiter {
    /// ip → (count, window_start)
    buckets: HashMap<String, (u32, Instant)>,
    rate: u32,
}

impl RateLimiter {
    pub fn new(rate: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            rate,
        }
    }

    /// Returns true if request is allowed
    pub fn check(&mut self, ip: &str) -> bool {
        if self.rate == 0 {
            return true;
        }
        let now = Instant::now();
        let entry = self.buckets.entry(ip.to_string()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
            return true;
        }
        entry.0 += 1;
        entry.0 <= self.rate
    }

    /// Clean up stale entries (call periodically)
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, (_, t)| now.duration_since(*t).as_secs() < 120);
    }
}
