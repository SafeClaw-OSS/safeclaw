//! Hashing helper for opaque tokens the daemon must remember without keeping
//! (e.g. redeemed OAuth codes). Agent api keys are retired (§15 W3): an agent
//! authenticates only by its AIK proof of possession, admitted by the account
//! ledger (`principal_ledger::authorize_agent`).

pub(crate) fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{:02x}", b)).collect()
}
