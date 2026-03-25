use std::collections::HashSet;
use std::time::Instant;

/// In-memory nonce tracking with hourly two-set rotation.
///
/// Two-set scheme:
///   - `current`: nonces seen in the current hour window
///   - `previous`: nonces from the previous hour (kept for overlap tolerance)
///
/// A nonce is rejected if present in either set.
/// Every hour: previous ← current, current ← empty.
pub struct NonceStore {
    current: HashSet<Vec<u8>>,
    previous: HashSet<Vec<u8>>,
    last_rotation: Instant,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            last_rotation: Instant::now(),
        }
    }

    /// Check if a nonce is fresh (not seen before), and record it.
    /// Returns true if the nonce is new and accepted, false if already seen.
    pub fn check_and_insert(&mut self, nonce: &[u8]) -> bool {
        self.maybe_rotate();

        if self.current.contains(nonce) || self.previous.contains(nonce) {
            return false;
        }

        self.current.insert(nonce.to_vec());
        true
    }

    fn maybe_rotate(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_rotation).as_secs() >= 3600 {
            self.previous = std::mem::take(&mut self.current);
            self.last_rotation = now;
        }
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}
