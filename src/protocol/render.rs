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
        ActType::Enroll => match as_enroll_credential(op) {
            Ok(cred) => format!(
                "Set up vault with passkey \"{}\".",
                if cred.device_name.is_empty() {
                    "(new device)"
                } else {
                    cred.device_name.as_str()
                }
            ),
            Err(_) => "Set up vault.".to_string(),
        },
        ActType::Write => "Update vault contents.".to_string(),
        ActType::Export => {
            format!(
                "Reveal the value at \"{}\" to the requesting agent.",
                op.act.target
            )
        }
        ActType::Use => render_use(op),
        ActType::Custom(name) if name == "connection-add" => {
            let scope = &op.act.scope;
            let list = |k: &str| -> Vec<&str> {
                scope
                    .get(k)
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default()
            };
            let target = match scope.get("service").and_then(|v| v.as_str()) {
                Some(svc) => format!("service {}", svc),
                None => list("hosts").join(", "),
            };
            let keys = list("secrets");
            if keys.is_empty() {
                format!("Add connection \"{}\" → {}.", op.act.target, target)
            } else {
                format!(
                    "Add connection \"{}\" → {} (secrets: {}).",
                    op.act.target,
                    target,
                    keys.join(", ")
                )
            }
        }
        ActType::Custom(name) if name == "secret-set" => {
            let hosts: Vec<&str> = op
                .act
                .scope
                .get("hosts")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            if hosts.is_empty() {
                format!("Store secret {}.", op.act.target)
            } else {
                format!(
                    "Store secret {} for use at {}.",
                    op.act.target,
                    hosts.join(", ")
                )
            }
        }
        other => format!("Operation: {:?}", other),
    }
}

/// A brokered Use op. Surface the request line (method + host + path) and, for
/// a Phase-2 scope, the consent — so a HEADLESS / CLI approver (no console)
/// sees what the console's rich card shows, not just the target slot. The
/// `consent` template is interpolated over the bound `scope_vars`; with none,
/// the bound fields are listed. (A `render` hint is a console-only concern.)
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

    // The consent line: interpolate the template over the bound fields; with no
    // template but some bound fields, list them.
    let consent_line = match scope.get("consent").and_then(|v| v.as_str()) {
        Some(t) => Some(interpolate(t, &bound)),
        None if !bound.is_empty() => Some(
            bound
                .iter()
                .map(|(k, v)| format!("{}={}", k, truncate(v, 80)))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        None => None,
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

/// Render a `{{ vars.x | filter }}` consent template to plain text for the CLI:
/// interpolate each reference with its bound value (a filter is a
/// console-display concern, so here the value is shown as-is / truncated).
fn interpolate(template: &str, bound: &[(String, String)]) -> String {
    let vals: std::collections::HashMap<&str, &str> = bound
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str("{{");
            rest = after;
            continue;
        };
        let inner = after[..end].trim();
        let name = inner.splitn(2, '|').next().unwrap_or("").trim();
        if let Some(var) = name.strip_prefix("vars.").map(str::trim) {
            out.push_str(&truncate(vals.get(var).copied().unwrap_or(""), 80));
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
