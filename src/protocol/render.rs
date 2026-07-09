//! Human-readable rendering of an `Operation` for the approve UI.

use super::operation::{as_enroll_credential, ActType, Operation};

/// Returns a short string describing what the operation will do.
/// Frontend can show this to the user before they confirm.
pub fn render_operation(op: &Operation) -> String {
    match &op.act.kind {
        ActType::Enroll if op.act.target == "passkeys" => {
            // Add-passkey to an already-set-up vault. New credential
            // material lives under scope.new (not the top-level fields
            // first-time Enroll uses), so don't route through
            // as_enroll_credential here.
            let device = op
                .act
                .scope
                .get("new")
                .and_then(|n| n.get("device_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("(new device)");
            format!("Add passkey \"{}\" to this vault.", device)
        }
        ActType::Enroll => {
            match as_enroll_credential(op) {
                Ok(cred) => format!(
                    "Set up vault with passkey \"{}\".",
                    if cred.device_name.is_empty() {
                        "(new device)"
                    } else {
                        cred.device_name.as_str()
                    }
                ),
                Err(_) => "Set up vault.".to_string(),
            }
        }
        ActType::Write => "Update vault contents.".to_string(),
        ActType::Export => {
            format!(
                "Reveal the value at \"{}\" to the requesting agent.",
                op.act.target
            )
        }
        ActType::Use => render_use(op),
        other => format!("Operation: {:?}", other),
    }
}

/// A brokered Use op. Surface the request line (method + host + path) and, for
/// a Phase-2 scope, the consent — so a HEADLESS / CLI approver (no console)
/// sees what the console's rich card shows, not just the target slot. A text
/// consent is rendered with its bound `scope_vars`; a rich `{ render }` consent
/// falls back to listing the bound fields (the decode lives in the console).
fn render_use(op: &Operation) -> String {
    let scope = &op.act.scope;
    let s = |k: &str| scope.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let (method, host, path) = (s("method"), s("host"), s("path"));

    let bound: Vec<(String, String)> = scope
        .get("scope_vars")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // The consent line: interpolate a text template over the bound fields, or
    // (rich form / none) list the bound fields.
    let consent_line = match scope.get("consent") {
        Some(serde_json::Value::String(t)) => Some(interpolate(t, &bound)),
        Some(serde_json::Value::Object(_)) | None if !bound.is_empty() => Some(
            bound
                .iter()
                .map(|(k, v)| format!("{}={}", k, truncate(v, 80)))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        _ => None,
    };

    let request = if !method.is_empty() || !host.is_empty() || !path.is_empty() {
        format!("{} {}{}", method, host, path).trim().to_string()
    } else {
        format!("the secret at \"{}\"", op.act.target)
    };
    match consent_line {
        Some(c) => format!("Brokered call: {}\n{}", request, c),
        None => format!("Use {} for a brokered call.", request),
    }
}

fn interpolate(template: &str, bound: &[(String, String)]) -> String {
    let mut out = template.to_string();
    for (k, v) in bound {
        out = out.replace(&format!("{{{}}}", k), &truncate(v, 80));
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
