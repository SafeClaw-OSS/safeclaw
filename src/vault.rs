//! Vault — encrypted secret store held in memory when unlocked.
//!
//! Separates core secrets from runtime caches. Both are cleared on lock.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::core::policy::PolicyDefaults;
use crate::notify::PushSubscription;

// ── VapidKeypair ─────────────────────────────────────────────────────────────

/// Web Push VAPID signing keypair (base64url-encoded).
pub struct VapidKeypair {
    pub private_key: String,
    pub public_key: String,
}

// ── ApprovalSession ──────────────────────────────────────────────────────────

/// Approval session: credential access is cached after human approval until TTL expires.
pub struct ApprovalSession {
    /// Decrypted auth config for this service (stored as JSON to avoid circular imports).
    pub auth: serde_json::Value,
    /// When this session expires
    pub expires_at: Instant,
}

// ── VaultCache ───────────────────────────────────────────────────────────────

/// Ephemeral runtime caches — all cleared when the vault locks.
/// These are peer to `secrets`, not children of it.
pub struct VaultCache {
    /// OAuth2 token cache: service_name → (access_token, expires_at_unix_secs)
    pub oauth2_tokens: Mutex<HashMap<String, (String, u64)>>,
    /// Approval session cache: service_name → cached session after human approval
    pub approvals: Mutex<HashMap<String, ApprovalSession>>,
    /// Short-lived DEK cache for approved file reads: approval_id → DEK.
    /// Written at approval_confirm, consumed (and zeroized) at file read time.
    pub pending_deks: Mutex<HashMap<String, [u8; 32]>>,
}

impl VaultCache {
    fn new() -> Self {
        Self {
            oauth2_tokens: Mutex::new(HashMap::new()),
            approvals: Mutex::new(HashMap::new()),
            pending_deks: Mutex::new(HashMap::new()),
        }
    }

    fn clear(&self) {
        *self.oauth2_tokens.lock().unwrap() = HashMap::new();

        // Overwrite auth values before dropping
        {
            let mut approvals = self.approvals.lock().unwrap();
            for session in approvals.values_mut() {
                session.auth = serde_json::Value::Null;
            }
            approvals.clear();
        }

        // Zeroize DEKs before dropping
        {
            use zeroize::Zeroize;
            let mut deks = self.pending_deks.lock().unwrap();
            for dek in deks.values_mut() {
                dek.zeroize();
            }
            deks.clear();
        }
    }
}

// ── Vault ────────────────────────────────────────────────────────────────────

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
    // Check rules for any approval-required level
    if let Some(rules) = svc.get("rules").and_then(|r| r.as_array()) {
        for rule in rules {
            if rule.get("level").and_then(|v| v.as_str()).map(is_sensitive).unwrap_or(false) {
                return true;
            }
        }
    }
    // Also check action_levels (user overrides from policy.toml actions)
    if let Some(overrides) = svc.get("action_levels").and_then(|v| v.as_object()) {
        for (_, level) in overrides {
            if level.as_str().map(is_sensitive).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// Vault state — secrets + derived state + runtime caches.
pub struct Vault {
    // ── Core secrets (encrypted at rest) ─────────────────────────────────────
    /// Decrypted vault JSON (all services). None = locked.
    pub secrets: Mutex<Option<serde_json::Value>>,

    // ── Derived state (extracted from secrets at unlock) ─────────────────────
    /// Service name list (populated at unlock)
    pub service_names: Mutex<Vec<String>>,
    /// Policy defaults (loaded at unlock)
    pub policy_defaults: Mutex<PolicyDefaults>,
    /// Push notification subscriptions (loaded at unlock)
    pub push_subscriptions: Mutex<Vec<PushSubscription>>,
    /// VAPID keypair for Web Push (loaded at unlock, zeroized at lock)
    pub vapid: Mutex<Option<VapidKeypair>>,

    // ── Runtime caches (ephemeral, cleared on lock) ─────────────────────────
    pub cache: VaultCache,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(None),
            service_names: Mutex::new(Vec::new()),
            policy_defaults: Mutex::new(PolicyDefaults::default()),
            push_subscriptions: Mutex::new(Vec::new()),
            vapid: Mutex::new(None),
            cache: VaultCache::new(),
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
                    "category": "system",
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
        let vapid = secrets
            .get("vapid_private_key")
            .and_then(|v| v.as_str())
            .and_then(|priv_b64| {
                let pub_b64 = crate::notify::webpush::vapid_public_key(priv_b64).ok()?;
                Some(VapidKeypair {
                    private_key: priv_b64.to_owned(),
                    public_key: pub_b64,
                })
            });
        *self.vapid.lock().unwrap() = vapid;

        *self.service_names.lock().unwrap() = names;
        *self.policy_defaults.lock().unwrap() = policy_defaults;
        *self.push_subscriptions.lock().unwrap() = push_subs;
        // Zeroize old secrets before replacing
        {
            let mut guard = self.secrets.lock().unwrap();
            crate::crypto::zeroize::zeroize_json_option(&mut *guard);
            *guard = Some(secrets);
        }
    }

    /// Lock the vault — zeroize and clear all in-memory secrets.
    pub fn lock(&self) {
        // Zeroize vault secrets (API keys, OAuth tokens, etc.) before drop
        crate::crypto::zeroize::zeroize_json_option(&mut *self.secrets.lock().unwrap());
        *self.service_names.lock().unwrap() = Vec::new();
        *self.push_subscriptions.lock().unwrap() = Vec::new();
        *self.policy_defaults.lock().unwrap() = PolicyDefaults::default();

        // Zeroize VAPID private key
        {
            use zeroize::Zeroize;
            let mut guard = self.vapid.lock().unwrap();
            if let Some(ref mut kp) = *guard {
                kp.private_key.zeroize();
            }
            *guard = None;
        }

        // Clear all runtime caches
        self.cache.clear();
    }

    pub fn service_names(&self) -> Vec<String> {
        self.service_names.lock().unwrap().clone()
    }

    /// Check if an approval session is still valid for the given service.
    /// Returns the cached auth config if valid, or None if expired/absent.
    pub fn check_approval_session(&self, service: &str) -> Option<serde_json::Value> {
        let cache = self.cache.approvals.lock().unwrap();
        if let Some(session) = cache.get(service) {
            if session.expires_at > Instant::now() {
                return Some(session.auth.clone());
            }
        }
        None
    }

    /// Store an approval session for a service with the given TTL (seconds).
    pub fn set_approval_session(&self, service: &str, auth: serde_json::Value, ttl_secs: u64) {
        let mut cache = self.cache.approvals.lock().unwrap();
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
        let mut cache = self.cache.approvals.lock().unwrap();
        let now = Instant::now();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_auth() -> serde_json::Value {
        serde_json::json!({"type": "bearer", "secret": "tok"})
    }

    // ── VaultCache isolation ────────────────────────────────────────────────

    #[test]
    fn cache_clear_zeroizes_all() {
        let vault = Vault::new();
        // Populate all three cache stores
        vault.cache.oauth2_tokens.lock().unwrap()
            .insert("openai".into(), ("tok_abc".into(), 9999999999));
        vault.set_approval_session("github", dummy_auth(), 3600);
        vault.cache.pending_deks.lock().unwrap()
            .insert("dek1".into(), [0xAA; 32]);

        // Lock should clear everything
        vault.lock();

        assert!(vault.cache.oauth2_tokens.lock().unwrap().is_empty());
        assert!(vault.cache.approvals.lock().unwrap().is_empty());
        assert!(vault.cache.pending_deks.lock().unwrap().is_empty());
    }

    #[test]
    fn oauth2_cache_is_independent_per_service() {
        let vault = Vault::new();
        let mut tokens = vault.cache.oauth2_tokens.lock().unwrap();
        tokens.insert("openai".into(), ("tok_a".into(), 100));
        tokens.insert("google".into(), ("tok_b".into(), 200));
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens.get("openai").unwrap().0, "tok_a");
        assert_eq!(tokens.get("google").unwrap().0, "tok_b");
    }

    // ── VapidKeypair lifecycle ──────────────────────────────────────────────

    #[test]
    fn vapid_starts_none() {
        let vault = Vault::new();
        assert!(vault.vapid.lock().unwrap().is_none());
    }

    #[test]
    fn lock_clears_vapid() {
        let vault = Vault::new();
        *vault.vapid.lock().unwrap() = Some(VapidKeypair {
            private_key: "priv_test".into(),
            public_key: "pub_test".into(),
        });
        assert!(vault.vapid.lock().unwrap().is_some());
        vault.lock();
        assert!(vault.vapid.lock().unwrap().is_none());
    }

    // ── Approval session through cache ──────────────────────────────────────

    #[test]
    fn approval_session_uses_cache_struct() {
        let vault = Vault::new();
        vault.set_approval_session("github", dummy_auth(), 3600);
        // Verify it's stored in cache.approvals, not a top-level field
        assert!(vault.cache.approvals.lock().unwrap().contains_key("github"));
        // And accessible via the helper
        assert!(vault.check_approval_session("github").is_some());
    }

    #[test]
    fn cleanup_removes_expired_from_cache() {
        let vault = Vault::new();
        vault.set_approval_session("expired_svc", dummy_auth(), 0); // 0 TTL = already expired
        vault.set_approval_session("valid_svc", dummy_auth(), 3600);
        vault.cleanup_expired_sessions();
        assert!(vault.check_approval_session("expired_svc").is_none());
        assert!(vault.check_approval_session("valid_svc").is_some());
        assert_eq!(vault.cache.approvals.lock().unwrap().len(), 1);
    }
}
