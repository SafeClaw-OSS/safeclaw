use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::config::Config;
use crate::crypto::keys::ServerKeypair;

/// Shared application state (Arc-wrapped)
pub struct AppState {
    pub config: Config,
    pub keypair: ServerKeypair,
    pub vault: Arc<VaultState>,
    pub nonces: Arc<Mutex<crate::auth::nonce::NonceStore>>,
    pub start_time: Instant,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Vault state — secrets held in memory when unlocked
pub struct VaultState {
    pub secrets: Mutex<Option<serde_json::Value>>,
    pub service_names: Mutex<Vec<String>>,
}

impl VaultState {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(None),
            service_names: Mutex::new(Vec::new()),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.secrets.lock().unwrap().is_none()
    }

    pub fn set_secrets(&self, secrets: serde_json::Value) {
        let names: Vec<String> = secrets
            .get("services")
            .and_then(|s| s.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        *self.secrets.lock().unwrap() = Some(secrets);
        *self.service_names.lock().unwrap() = names;
    }

    pub fn lock(&self) {
        *self.secrets.lock().unwrap() = None;
        *self.service_names.lock().unwrap() = Vec::new();
    }

    pub fn service_names(&self) -> Vec<String> {
        self.service_names.lock().unwrap().clone()
    }
}

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
