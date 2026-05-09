//! Channel binding hash for SafeClaw grants.
//!
//! Per SUDP §5: every grant carries a server-issued challenge `r` and binds
//! the WebAuthn assertion to the canonical operation `o` it authorizes.
//!
//! ```text
//! op_hash = SHA-256(canonical(o))
//! β       = SHA-256(domain_sep ‖ 0x00 ‖ r ‖ op_hash)
//! ```
//!
//! `β` is what the client uses as the WebAuthn challenge.

use sha2::{Digest, Sha256};

use crate::crypto::canonical;

/// Default domain separator for grants. Setup, identity, and offline flows
/// each have their own to prevent cross-context replay.
pub const DOMAIN_STANDARD: &[u8] = b"safeclaw/v1/binding";
pub const DOMAIN_SETUP: &[u8] = b"safeclaw/v1/binding-setup";
pub const DOMAIN_SETUP_OVERWRITE: &[u8] = b"safeclaw/v1/binding-setup-overwrite";
pub const DOMAIN_IDENTITY: &[u8] = b"safeclaw/v1/binding-identity";
pub const DOMAIN_OFFLINE: &[u8] = b"safeclaw/v1/binding-offline";

/// Compute SHA-256 over the canonicalized operation bytes.
pub fn compute_request_hash(_method: &str, _path: &str, body_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(body_bytes).into()
}

/// Compute β = SHA-256(domain ‖ 0x00 ‖ r ‖ op_hash).
pub fn compute_binding(domain: &[u8], r: &[u8], op_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(b"\x00");
    h.update(r);
    h.update(op_hash);
    h.finalize().into()
}

/// End-to-end binding from canonical operation `o` and challenge `r`.
pub fn binding_for_op(domain: &[u8], r: &[u8], op: &serde_json::Value) -> [u8; 32] {
    let canonical_o = canonical::canonicalize_body(op);
    let op_hash: [u8; 32] = Sha256::digest(&canonical_o).into();
    compute_binding(domain, r, &op_hash)
}

/// Legacy helper retained for tests: includes method+path in the binding.
/// Not used by the v1 grant pipeline.
pub fn binding_for_request(
    domain: &[u8],
    r: &[u8],
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> [u8; 32] {
    let canonical_body = canonical::canonicalize_body(body);
    let mut h = Sha256::new();
    h.update(method.to_ascii_uppercase().as_bytes());
    h.update(b"\x00");
    h.update(path.as_bytes());
    h.update(b"\x00");
    h.update(&canonical_body);
    let req_hash: [u8; 32] = h.finalize().into();
    compute_binding(domain, r, &req_hash)
}

/// Constant-time byte comparison wrapper.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
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
            binding_for_op(DOMAIN_STANDARD, &r, &op),
            binding_for_op(DOMAIN_STANDARD, &r, &op)
        );
    }

    #[test]
    fn op_binding_changes_with_op() {
        let r = [0x11u8; 16];
        let a = binding_for_op(DOMAIN_STANDARD, &r, &json!({ "act": { "type": "reveal", "path": "x" } }));
        let b = binding_for_op(DOMAIN_STANDARD, &r, &json!({ "act": { "type": "reveal", "path": "y" } }));
        assert_ne!(a, b);
    }

    #[test]
    fn op_binding_changes_with_r() {
        let op = json!({ "act": { "type": "reveal", "path": "x" } });
        let a = binding_for_op(DOMAIN_STANDARD, &[0u8; 16], &op);
        let b = binding_for_op(DOMAIN_STANDARD, &[1u8; 16], &op);
        assert_ne!(a, b);
    }

    #[test]
    fn op_binding_changes_with_domain() {
        let op = json!({ "x": 1 });
        let r = [0u8; 16];
        let a = binding_for_op(DOMAIN_STANDARD, &r, &op);
        let b = binding_for_op(DOMAIN_SETUP, &r, &op);
        assert_ne!(a, b);
    }
}
