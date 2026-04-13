//! JSON canonicalization for channel binding (RFC 8785 JCS subset).
//!
//! The server and client must agree byte-for-byte on the canonical form of the
//! request body so that `request_hash` can be recomputed independently. This
//! module implements the subset of JCS that SafeClaw's request bodies exercise:
//!
//! - Object keys sorted lexicographically by UTF-16 code unit order (which, for
//!   the ASCII keys SafeClaw uses, is equivalent to byte order).
//! - No insignificant whitespace.
//! - Array order preserved.
//! - Strings re-serialized through `serde_json::to_string` which produces the
//!   standard JSON escape forms.
//! - Numbers re-serialized through `serde_json::Number::to_string`. SafeClaw's
//!   request bodies never contain floats, so number edge cases do not apply.
//!
//! The matching client-side implementation lives in `public/safeclaw-client.js`
//! (see `canonicalizeJson`).

use serde_json::Value;

/// Fields excluded from canonicalization before channel binding.
/// These are the fields that are *produced using* the binding, or that are
/// cryptographic material transmitted alongside the request but not part of
/// the user's semantic intent.
pub const EXCLUDED_FIELDS: &[&str] = &[
    "assertion",
    "server_random",
    "user_key",
    "user_key_next",
];

/// Produce a canonical byte representation of `value` with the excluded
/// top-level fields stripped. If `value` is not an object, this just
/// canonicalizes `value` unchanged.
pub fn canonicalize_body(value: &Value) -> Vec<u8> {
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
    let mut buf = Vec::new();
    canonicalize_into(&filtered, &mut buf);
    buf
}

/// Produce a canonical byte representation of `value` without any field
/// filtering. Useful for hashing sub-objects.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    canonicalize_into(value, &mut buf);
    buf
}

fn canonicalize_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // serde_json's Number serialization is shortest-roundtrip for integers,
            // which is all SafeClaw request bodies contain.
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => {
            // Re-serialize via serde_json to get standard JSON escaping.
            let encoded = serde_json::to_string(s).unwrap_or_else(|_| String::new());
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonicalize_into(item, out);
            }
            out.push(b']');
        }
        Value::Object(obj) => {
            out.push(b'{');
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| {
                // RFC 8785: sort by UTF-16 code unit order. For ASCII strings
                // this is identical to byte order. Use a UTF-16-safe comparator
                // to be correct for non-ASCII keys as well.
                let a16: Vec<u16> = a.encode_utf16().collect();
                let b16: Vec<u16> = b.encode_utf16().collect();
                a16.cmp(&b16)
            });
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let key_encoded = serde_json::to_string(k).unwrap_or_else(|_| String::new());
                out.extend_from_slice(key_encoded.as_bytes());
                out.push(b':');
                canonicalize_into(&obj[*k], out);
            }
            out.push(b'}');
        }
    }
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
            "user_key": "yyy",
            "assertion": { "anything": 1 },
            "payload": 42
        });
        let out = canonicalize_body(&v);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            r#"{"credential_id":"abc","payload":42}"#
        );
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
