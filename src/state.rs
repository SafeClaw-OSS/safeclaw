use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::approval::ApprovalManager;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::crypto::keys::ServerKeypair;
use crate::policy::{PolicyDefaults, PushSubscription};

/// Approval session: credential access is cached after human approval until TTL expires.
pub struct ApprovalSession {
    /// Decrypted auth config for this service (stored as JSON to avoid circular imports).
    pub auth: serde_json::Value,
    /// When this session expires
    pub expires_at: Instant,
}

/// Vault state — secrets held in memory when unlocked
pub struct VaultState {
    /// Decrypted vault JSON (all services)
    pub secrets: Mutex<Option<serde_json::Value>>,
    /// Service name list (populated at unlock, kept after lock for index queries)
    pub service_names: Mutex<Vec<String>>,
    /// Approval session cache: service_name → cached session after human approval
    pub approval_cache: Mutex<HashMap<String, ApprovalSession>>,
    /// Push notification subscriptions (loaded at unlock)
    pub push_subscriptions: Mutex<Vec<PushSubscription>>,
    /// Policy defaults (loaded at unlock)
    pub policy_defaults: Mutex<PolicyDefaults>,
    /// OAuth2 token cache: service_name → (access_token, expires_at_unix_secs)
    pub oauth2_tokens: Mutex<HashMap<String, (String, u64)>>,
    /// VAPID private key (base64url) for Web Push — loaded at unlock, cleared at lock
    pub vapid_private_key: Mutex<Option<String>>,
    /// VAPID public key (base64url) — derived from private key at unlock
    pub vapid_public_key: Mutex<Option<String>>,
    /// Short-lived DEK cache for approved file reads: approval_id → DEK.
    /// Written at approval_confirm, consumed (and zeroized) at file read time.
    pub pending_deks: Mutex<HashMap<String, [u8; 32]>>,
}

/// Returns true if the service JSON has any approval-required access levels,
/// meaning its auth credentials must not be kept in memory at unlock.
fn service_needs_auth_stripped(svc: &serde_json::Value) -> bool {
    let is_sensitive = |s: &str| matches!(s, "ask" | "ask-always");

    if let Some(levels) = svc.get("levels") {
        if levels.get("write").and_then(|v| v.as_str()).map(is_sensitive).unwrap_or(false) {
            return true;
        }
        if levels.get("read").and_then(|v| v.as_str()).map(is_sensitive).unwrap_or(false) {
            return true;
        }
    }
    if let Some(rules) = svc.get("rules").and_then(|r| r.as_array()) {
        for rule in rules {
            if rule.get("level").and_then(|v| v.as_str()).map(is_sensitive).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

impl VaultState {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(None),
            service_names: Mutex::new(Vec::new()),
            approval_cache: Mutex::new(HashMap::new()),
            push_subscriptions: Mutex::new(Vec::new()),
            policy_defaults: Mutex::new(PolicyDefaults::default()),
            oauth2_tokens: Mutex::new(HashMap::new()),
            vapid_private_key: Mutex::new(None),
            vapid_public_key: Mutex::new(None),
            pending_deks: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.secrets.lock().unwrap().is_none()
    }

    /// Load decrypted vault JSON into memory.
    /// Parses service names, policy defaults, and push subscriptions.
    /// Auth is stripped from services whose access level requires approval (ask / ask-always) —
    /// credentials for those services are only available transiently via approval.
    pub fn set_secrets(&self, mut secrets: serde_json::Value) {
        // Auto-inject built-in "files" service (vault file storage, accessed via proxy)
        if let Some(services) = secrets.get_mut("services").and_then(|s| s.as_object_mut()) {
            if !services.contains_key("files") {
                services.insert("files".into(), serde_json::json!({
                    "upstream": "http://localhost:23294/vault/files",
                    "category": "service",
                    "levels": { "read": "ask", "write": "ask" }
                }));
            }
        }

        // Strip auth from approval-required services
        if let Some(services) = secrets.get_mut("services").and_then(|s| s.as_object_mut()) {
            for svc in services.values_mut() {
                if service_needs_auth_stripped(svc) {
                    svc.as_object_mut().map(|m| m.remove("auth"));
                }
            }
        }

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

        // Extract push subscriptions (support both nested and flat key for compat)
        let push_subs = secrets
            .get("notifications")
            .and_then(|n| n.get("subscriptions"))
            .or_else(|| secrets.get("push_subscriptions"))
            .and_then(|v| serde_json::from_value::<Vec<PushSubscription>>(v.clone()).ok())
            .unwrap_or_default();

        // Load VAPID private key and derive public key
        let vapid_priv = secrets
            .get("vapid_private_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        let vapid_pub = vapid_priv.as_deref().and_then(|priv_b64| {
            crate::webpush::vapid_public_key(priv_b64).ok()
        });
        *self.vapid_private_key.lock().unwrap() = vapid_priv;
        *self.vapid_public_key.lock().unwrap() = vapid_pub;

        *self.service_names.lock().unwrap() = names;
        *self.policy_defaults.lock().unwrap() = policy_defaults;
        *self.push_subscriptions.lock().unwrap() = push_subs;
        // Zeroize old secrets before replacing
        {
            let mut guard = self.secrets.lock().unwrap();
            crate::secret_json::zeroize_json_option(&mut *guard);
            *guard = Some(secrets);
        }
    }

    /// Lock the vault — zeroize and clear all in-memory secrets.
    pub fn lock(&self) {
        // Zeroize vault secrets (API keys, OAuth tokens, etc.) before drop
        crate::secret_json::zeroize_json_option(&mut *self.secrets.lock().unwrap());
        *self.service_names.lock().unwrap() = Vec::new();
        *self.approval_cache.lock().unwrap() = HashMap::new();
        *self.push_subscriptions.lock().unwrap() = Vec::new();
        *self.policy_defaults.lock().unwrap() = PolicyDefaults::default();
        *self.oauth2_tokens.lock().unwrap() = HashMap::new();
        // Zeroize VAPID private key string
        {
            use zeroize::Zeroize;
            let mut vpk = self.vapid_private_key.lock().unwrap();
            if let Some(ref mut s) = *vpk { s.zeroize(); }
            *vpk = None;
        }
        *self.vapid_public_key.lock().unwrap() = None;
        {
            use zeroize::Zeroize;
            let mut deks = self.pending_deks.lock().unwrap();
            for dek in deks.values_mut() { dek.zeroize(); }
            deks.clear();
        }
    }

    pub fn service_names(&self) -> Vec<String> {
        self.service_names.lock().unwrap().clone()
    }

    /// Check if an approval session is still valid for the given service.
    /// Returns the cached auth config if valid, or None if expired/absent.
    pub fn check_approval_session(&self, service: &str) -> Option<serde_json::Value> {
        let cache = self.approval_cache.lock().unwrap();
        if let Some(session) = cache.get(service) {
            if session.expires_at > Instant::now() {
                return Some(session.auth.clone());
            }
        }
        None
    }

    /// Store an approval session for a service with the given TTL (seconds).
    pub fn set_approval_session(&self, service: &str, auth: serde_json::Value, ttl_secs: u64) {
        let mut cache = self.approval_cache.lock().unwrap();
        cache.insert(
            service.to_string(),
            ApprovalSession {
                auth,
                expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs),
            },
        );
    }

    /// Remove expired approval sessions from cache (overwrite credentials before dropping).
    pub fn cleanup_expired_sessions(&self) {
        let mut cache = self.approval_cache.lock().unwrap();
        let now = Instant::now();
        // Overwrite auth values before dropping expired sessions
        for session in cache.values_mut() {
            if session.expires_at <= now {
                session.auth = serde_json::Value::Null;
            }
        }
        cache.retain(|_, session| session.expires_at > now);
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
    pub challenges: Arc<Mutex<crate::auth::challenge::ChallengeStore>>,
    pub start_time: Instant,
    pub started_at_ms: u64,  // Unix ms timestamp at startup (for client-side uptime calc)
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub approval_manager: Arc<ApprovalManager>,
    pub audit_log: Arc<AuditLog>,
    // notifications field removed — Web Push replaces polling
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
