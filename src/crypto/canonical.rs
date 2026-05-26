//! JSON canonicalization for channel binding — thin adapter over
//! `sudp::canonical`.
//!
//! `canonicalize` and `canonicalize_body` are SafeClaw's call sites; the byte
//! encoding (JCS subset: sorted keys, no whitespace, standard JSON escapes) is
//! produced by sudp so client and server stay in lockstep. SafeClaw adds the
//! request-body field filter (`EXCLUDED_FIELDS`) — that's a deployment concern
//! about which fields are part of the bound operation `o`, not part of the
//! canonical-encoding contract.
//!
//! The matching client-side implementation lives in
//! `safeclaw-pro-frontend/lib/vault-crypto.ts` (see `canonicalize`).

use serde_json::Value;
use sudp::canonical as sudp_canonical;

use crate::error::{AppError, Result};

/// Fields excluded from canonicalization before channel binding.
/// These are the fields that are *produced using* the binding, or that are
/// cryptographic material transmitted alongside the request but not part of
/// the user's semantic intent.
pub const EXCLUDED_FIELDS: &[&str] = &[
    "assertion",
    "server_random",
    "wrapping_key",
    "wrapping_key_next",
    "setup_payload",
];

/// Produce a canonical byte representation of `value` with the excluded
/// top-level fields stripped. If `value` is not an object, this just
/// canonicalizes `value` unchanged.
pub fn canonicalize_body(value: &Value) -> Result<Vec<u8>> {
    let filtered = match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if !EXCLUDED_FIELDS.contains(&k.as_str()) {
                    out.insert(k.clone(), v.clone());
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    };
    sudp_canonical::canonicalize_strict(&filtered)
        .map_err(|_| AppError::BadRequest("op contains float values (not permitted in canonical form)".into()))
}

/// Produce a canonical byte representation of `value` without any field
/// filtering. Useful for hashing sub-objects.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    sudp_canonical::canonicalize(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        let out = canonicalize(&v);
        assert_eq!(std::str::from_utf8(&out).unwrap(), r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn strips_excluded_fields() {
        let v = json!({
            "credential_id": "abc",
            "server_random": "xxx",
            "wrapping_key": "yyy",
            "assertion": { "anything": 1 },
            "setup_payload": { "any": "blob" },
            "payload": 42
        });
        let out = canonicalize_body(&v).unwrap();
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            r#"{"credential_id":"abc","payload":42}"#
        );
    }

    #[test]
    fn rejects_float_in_body() {
        let v = json!({ "x": 1.5 });
        assert!(canonicalize_body(&v).is_err());
    }

    #[test]
    fn preserves_nested_order_but_sorts_object_keys() {
        let v = json!({
            "obj": { "z": 1, "a": 2 },
            "arr": [3, 2, 1]
        });
        let out = canonicalize(&v);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            r#"{"arr":[3,2,1],"obj":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn escapes_strings() {
        let v = json!({ "k": "hello \"world\"" });
        let out = canonicalize(&v);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            r#"{"k":"hello \"world\""}"#
        );
    }

    #[test]
    fn bool_and_null() {
        let v = json!({ "t": true, "f": false, "n": null });
        let out = canonicalize(&v);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            r#"{"f":false,"n":null,"t":true}"#
        );
    }
}
