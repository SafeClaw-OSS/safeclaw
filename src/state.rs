//! Application-level state: AppState (shared across handlers) and RateLimiter.
//!
//! Vault state lives in vault.rs.
//!
//! v2 note: the server no longer holds a long-lived P-256 keypair in memory.
//! Transport confidentiality is TLS-only, and envelope wrapping uses
//! per-credential PRF-derived material rather than a server-held key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::core::approval::ApprovalManager;
use crate::core::audit::AuditLog;
use crate::config::Config;
use crate::service::ServiceRegistry;
use crate::vault::Vault;

// ── AppState ───────────────────────────────────────────────────────────────────

/// Shared application state (Arc-wrapped)
pub struct AppState {
    pub config: Config,
    pub vault: Arc<Vault>,
    pub services: ServiceRegistry,
    pub nonces: Arc<Mutex<crate::passkey::nonce::NonceStore>>,
    pub challenges: Arc<Mutex<crate::passkey::challenge::ChallengeStore>>,
    /// Serializes vault write operations across the process. Cross-process
    /// exclusion is handled by an advisory file lock at the write path.
    pub write_mutex: Arc<Mutex<()>>,
    pub start_time: Instant,
    pub started_at_ms: u64,
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
