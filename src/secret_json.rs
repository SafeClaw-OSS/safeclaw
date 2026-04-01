use zeroize::Zeroize;

/// Best-effort recursive zeroize for sensitive JSON values before drop.
/// This cannot guarantee every serde_json allocation pattern is wiped,
/// but it clears owned string contents and walks nested arrays/objects.
pub fn zeroize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                zeroize_json(item);
            }
            items.clear();
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                zeroize_json(v);
            }
            // Keys are dropped when map is cleared; serde_json::Map doesn't
            // expose mutable key refs, but the sensitive data is in values.
            map.clear();
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

pub fn zeroize_json_option(value: &mut Option<serde_json::Value>) {
    if let Some(inner) = value.as_mut() {
        zeroize_json(inner);
    }
    *value = None;
}
