//! Channel binding hash for SafeClaw grants — SafeClaw's multi-domain
//! specialisation of SUDP §5.5 β.
//!
//! ```text
//! op_hash = H(canonical(o))
//! β       = H(domain ‖ 0x00 ‖ r ‖ op_hash)
//! ```
//!
//! SUDP defines β with a single `DS_bind` label. SafeClaw extends this with
//! several pairwise-disjoint domains (setup / setup-overwrite / identity /
//! offline / standard) so that the same `(o, r)` cannot be replayed across
//! contexts. The `0x00` separator after `domain` matches the on-wire format
//! the frontend computes; do not "simplify" it away without a coordinated
//! protocol bump.
//!
//! Hash primitive comes from `sudp::primitives::Sha256` (via the `Hash` trait)
//! so future algorithm changes flow through one place.

use sudp::primitives::{Hash as _, Sha256};

use crate::crypto::canonical;
use crate::error::Result;

/// Default domain separator for grants. Setup gets its own to prevent
/// cross-context replay of a Reveal grant as a Setup grant (or vice versa).
pub const DOMAIN_STANDARD: &[u8] = b"safeclaw/v1/binding";
pub const DOMAIN_SETUP: &[u8] = b"safeclaw/v1/binding-setup";

/// Compute SHA-256 over the request body bytes.
pub fn compute_request_hash(_method: &str, _path: &str, body_bytes: &[u8]) -> [u8; 32] {
    Sha256::hash(body_bytes)
}

/// Compute β = SHA-256(domain ‖ 0x00 ‖ r ‖ op_hash).
pub fn compute_binding(domain: &[u8], r: &[u8], op_hash: &[u8; 32]) -> [u8; 32] {
    Sha256::hash_slices(&[domain, b"\x00", r, op_hash])
}

/// End-to-end binding from canonical operation `o` and challenge `r`.
/// Returns `Err` if `op` contains float values (rejected by strict canonicalization).
pub fn binding_for_op(domain: &[u8], r: &[u8], op: &serde_json::Value) -> Result<[u8; 32]> {
    let canonical_o = canonical::canonicalize_body(op)?;
    let op_hash = Sha256::hash(&canonical_o);
    Ok(compute_binding(domain, r, &op_hash))
}

/// Legacy helper retained for tests: includes method+path in the binding.
/// Not used by the v1 grant pipeline; uses non-strict canonicalization so
/// test values with floats don't spuriously fail.
pub fn binding_for_request(
    domain: &[u8],
    r: &[u8],
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> [u8; 32] {
    let canonical_body = canonical::canonicalize(body);
    let req_hash = Sha256::hash_slices(&[
        method.to_ascii_uppercase().as_bytes(),
        b"\x00",
        path.as_bytes(),
        b"\x00",
        &canonical_body,
    ]);
    compute_binding(domain, r, &req_hash)
}

/// Constant-time byte comparison wrapper.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    sudp::beta::constant_time_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn op_binding_is_deterministic() {
        let op = json!({ "act": { "type": "reveal", "path": "x" } });
        let r = [0x11u8; 16];
        assert_eq!(
            binding_for_op(DOMAIN_STANDARD, &r, &op).unwrap(),
            binding_for_op(DOMAIN_STANDARD, &r, &op).unwrap()
        );
    }

    #[test]
    fn op_binding_changes_with_op() {
        let r = [0x11u8; 16];
        let a = binding_for_op(
            DOMAIN_STANDARD,
            &r,
            &json!({ "act": { "type": "reveal", "path": "x" } }),
        )
        .unwrap();
        let b = binding_for_op(
            DOMAIN_STANDARD,
            &r,
            &json!({ "act": { "type": "reveal", "path": "y" } }),
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn op_binding_changes_with_r() {
        let op = json!({ "act": { "type": "reveal", "path": "x" } });
        let a = binding_for_op(DOMAIN_STANDARD, &[0u8; 16], &op).unwrap();
        let b = binding_for_op(DOMAIN_STANDARD, &[1u8; 16], &op).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn op_binding_changes_with_domain() {
        let op = json!({ "x": 1 });
        let r = [0u8; 16];
        let a = binding_for_op(DOMAIN_STANDARD, &r, &op).unwrap();
        let b = binding_for_op(DOMAIN_SETUP, &r, &op).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn op_binding_rejects_float() {
        let op = json!({ "x": 1.5 });
        let r = [0u8; 16];
        assert!(binding_for_op(DOMAIN_STANDARD, &r, &op).is_err());
    }
}
