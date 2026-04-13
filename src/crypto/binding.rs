//! Channel binding hash computation for v2 WebAuthn requests.
//!
//! Every v2 operation that carries a WebAuthn assertion binds the assertion to
//! the specific HTTP request being authorized. The binding is:
//!
//! ```text
//! request_hash = SHA-256( METHOD || 0x00 || PATH || 0x00 || canonical(body) )
//! binding      = SHA-256( domain_sep || 0x00 || server_random || request_hash )
//! ```
//!
//! The `domain_sep` string distinguishes normal vault operations from setup,
//! identity, and offline flows so an assertion from one context cannot be
//! replayed into another.

use sha2::{Digest, Sha256};

use crate::crypto::canonical;

/// Standard channel binding domain for normal vault operations.
pub const DOMAIN_STANDARD: &[u8] = b"safeclaw/v1/binding";
/// Setup-specific binding domain.
pub const DOMAIN_SETUP: &[u8] = b"safeclaw/v1/binding-setup";
/// Setup-overwrite binding domain (when overwriting an existing vault).
pub const DOMAIN_SETUP_OVERWRITE: &[u8] = b"safeclaw/v1/binding-setup-overwrite";
/// Identity operations (add/remove passkey).
pub const DOMAIN_IDENTITY: &[u8] = b"safeclaw/v1/binding-identity";
/// Offline unlock handshake.
pub const DOMAIN_OFFLINE: &[u8] = b"safeclaw/v1/binding-offline";

/// Compute the request hash: `SHA-256(method || 0x00 || path || 0x00 || canonical_body)`.
///
/// `body_bytes` should already be the canonicalized bytes (with excluded fields
/// stripped); see `crate::crypto::canonical::canonicalize_body`.
pub fn compute_request_hash(method: &str, path: &str, body_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(method.to_ascii_uppercase().as_bytes());
    h.update(b"\x00");
    h.update(path.as_bytes());
    h.update(b"\x00");
    h.update(body_bytes);
    h.finalize().into()
}

/// Compute the channel binding hash: `SHA-256(domain || 0x00 || server_random || request_hash)`.
///
/// `server_random` must be 16 bytes, `request_hash` must be 32 bytes.
pub fn compute_binding(domain: &[u8], server_random: &[u8], request_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(b"\x00");
    h.update(server_random);
    h.update(request_hash);
    h.finalize().into()
}

/// End-to-end binding computation from method, path, and the parsed request body.
pub fn binding_for_request(
    domain: &[u8],
    server_random: &[u8],
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> [u8; 32] {
    let canonical_body = canonical::canonicalize_body(body);
    let request_hash = compute_request_hash(method, path, &canonical_body);
    compute_binding(domain, server_random, &request_hash)
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
    fn binding_is_deterministic() {
        let body = json!({ "credential_id": "abc", "x": 1 });
        let server_random = [0x11u8; 16];
        let b1 = binding_for_request(DOMAIN_STANDARD, &server_random, "POST", "/vault/unlock", &body);
        let b2 = binding_for_request(DOMAIN_STANDARD, &server_random, "POST", "/vault/unlock", &body);
        assert_eq!(b1, b2);
    }

    #[test]
    fn binding_differs_on_method_change() {
        let body = json!({ "credential_id": "abc" });
        let sr = [0x11u8; 16];
        let b1 = binding_for_request(DOMAIN_STANDARD, &sr, "POST", "/vault/unlock", &body);
        let b2 = binding_for_request(DOMAIN_STANDARD, &sr, "GET", "/vault/unlock", &body);
        assert_ne!(b1, b2);
    }

    #[test]
    fn binding_differs_on_path_change() {
        let body = json!({ "credential_id": "abc" });
        let sr = [0x11u8; 16];
        let b1 = binding_for_request(DOMAIN_STANDARD, &sr, "POST", "/vault/unlock", &body);
        let b2 = binding_for_request(DOMAIN_STANDARD, &sr, "POST", "/vault/update", &body);
        assert_ne!(b1, b2);
    }

    #[test]
    fn binding_differs_on_body_change() {
        let b1 = binding_for_request(
            DOMAIN_STANDARD,
            &[0u8; 16],
            "POST",
            "/vault/update",
            &json!({ "new_vault": { "a": 1 } }),
        );
        let b2 = binding_for_request(
            DOMAIN_STANDARD,
            &[0u8; 16],
            "POST",
            "/vault/update",
            &json!({ "new_vault": { "a": 2 } }),
        );
        assert_ne!(b1, b2);
    }

    #[test]
    fn binding_ignores_excluded_fields() {
        // Changing only excluded fields should not change the binding.
        let b1 = binding_for_request(
            DOMAIN_STANDARD,
            &[0u8; 16],
            "POST",
            "/vault/unlock",
            &json!({ "credential_id": "abc", "assertion": { "x": 1 }, "user_key": "aaa" }),
        );
        let b2 = binding_for_request(
            DOMAIN_STANDARD,
            &[0u8; 16],
            "POST",
            "/vault/unlock",
            &json!({ "credential_id": "abc", "assertion": { "x": 999 }, "user_key": "zzz" }),
        );
        assert_eq!(b1, b2);
    }

    #[test]
    fn binding_differs_on_domain() {
        let sr = [0u8; 16];
        let body = json!({ "x": 1 });
        let b1 = binding_for_request(DOMAIN_STANDARD, &sr, "POST", "/x", &body);
        let b2 = binding_for_request(DOMAIN_SETUP, &sr, "POST", "/x", &body);
        assert_ne!(b1, b2);
    }

    #[test]
    fn binding_differs_on_server_random() {
        let body = json!({ "x": 1 });
        let b1 = binding_for_request(DOMAIN_STANDARD, &[0u8; 16], "POST", "/x", &body);
        let b2 = binding_for_request(DOMAIN_STANDARD, &[1u8; 16], "POST", "/x", &body);
        assert_ne!(b1, b2);
    }
}
