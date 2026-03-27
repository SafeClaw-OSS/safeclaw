use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;

/// In-memory challenge store for server-issued challenges.
/// Challenges are random 32-byte values with TTL 5 minutes, single-use.
pub struct ChallengeStore {
    /// challenge_b64 → (issued_at, ip)
    challenges: HashMap<String, (Instant, IpAddr)>,
    /// ip → (count, window_start) for rate limiting
    rate: HashMap<IpAddr, (u32, Instant)>,
}

const TTL_SECS: u64 = 300; // 5 minutes
const RATE_LIMIT: u32 = 60; // per minute per IP

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
            rate: HashMap::new(),
        }
    }

    /// Issue a new challenge. Returns base64-encoded challenge or None if rate limited.
    pub fn issue(&mut self, ip: IpAddr) -> Option<String> {
        // Rate limit check
        let now = Instant::now();
        let entry = self.rate.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
        } else {
            entry.0 += 1;
            if entry.0 > RATE_LIMIT {
                return None;
            }
        }

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let b64 = STANDARD.encode(bytes);
        self.challenges.insert(b64.clone(), (now, ip));
        Some(b64)
    }

    /// Verify and consume a challenge. Returns true if valid.
    pub fn verify(&mut self, challenge_b64: &str) -> bool {
        if let Some((issued_at, _ip)) = self.challenges.remove(challenge_b64) {
            let elapsed = Instant::now().duration_since(issued_at).as_secs();
            elapsed < TTL_SECS
        } else {
            false
        }
    }

    /// Remove expired challenges and stale rate limit entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.challenges.retain(|_, (issued_at, _)| {
            now.duration_since(*issued_at).as_secs() < TTL_SECS
        });
        self.rate.retain(|_, (_, window_start)| {
            now.duration_since(*window_start).as_secs() < 120
        });
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn localhost() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn issue_and_verify() {
        let mut store = ChallengeStore::new();
        let c = store.issue(localhost()).unwrap();
        assert!(store.verify(&c));
        // Second verify should fail (consumed)
        assert!(!store.verify(&c));
    }

    #[test]
    fn expired_challenge_rejected() {
        let mut store = ChallengeStore::new();
        let c = store.issue(localhost()).unwrap();
        // Manually expire it
        if let Some(entry) = store.challenges.get_mut(&c) {
            entry.0 = Instant::now() - std::time::Duration::from_secs(301);
        }
        assert!(!store.verify(&c));
    }

    #[test]
    fn unknown_challenge_rejected() {
        let mut store = ChallengeStore::new();
        assert!(!store.verify("bogus"));
    }

    #[test]
    fn rate_limit_enforced() {
        let mut store = ChallengeStore::new();
        let ip = localhost();
        for _ in 0..60 {
            assert!(store.issue(ip).is_some());
        }
        // 61st should be rate limited
        assert!(store.issue(ip).is_none());
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut store = ChallengeStore::new();
        let c = store.issue(localhost()).unwrap();
        if let Some(entry) = store.challenges.get_mut(&c) {
            entry.0 = Instant::now() - std::time::Duration::from_secs(301);
        }
        store.cleanup();
        assert!(store.challenges.is_empty());
    }
}
