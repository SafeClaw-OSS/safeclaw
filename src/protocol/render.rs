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
        // Control-plane acts: ONE source of copy — the acts.toml descriptor
        // (action line + non-empty fact rows), so the CLI prompt, audit row,
        // and grant page can't drift. Table-less acts get the humanized slug,
        // never a raw debug dump.
        ActType::Custom(name) => match crate::protocol::consent::consent_for(op) {
            Some(c) => {
                let facts = c
                    .facts
                    .iter()
                    .map(|(l, v)| format!("{}: {}", l, v))
                    .collect::<Vec<_>>()
                    .join(" · ");
                if facts.is_empty() {
                    format!("{}.", c.action)
                } else {
                    format!("{} ({}).", c.action, facts)
                }
            }
            None => crate::protocol::consent::fallback_line(name, &op.act.target),
        },
        other => format!("Operation: {:?}", other),
    }
}

/// A brokered Use op. Surface the request line (method + host + path), for a
/// Phase-2 scope the consent, and what approving grants (the signed `level`,
/// `reuse` and `window_s`), so a HEADLESS / CLI approver (no console) sees
/// what the console's card shows, not just the target slot. The `consent`
/// template is interpolated over the bound `scope_vars`; with none, the bound
/// fields are listed. (A `render` hint is a console-only concern.)
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
    let mut out = match consent_line {
        Some(c) => format!("Brokered call: {}\n{}", request, c),
        None => format!("Use {} for a brokered call.", request),
    };
    if let Some(g) = grant_line(scope) {
        out.push('\n');
        out.push_str(&g);
    }
    out
}

/// What approving a Use op grants, from its signed `level`, `reuse` (with the
/// rule's label or id, or the floor's class) and `window_s`. `None` when the
/// scope carries no signed level.
fn grant_line(scope: &serde_json::Value) -> Option<String> {
    let s = |k: &str| scope.get(k).and_then(|v| v.as_str());
    let level = s("level")?;
    let window = scope
        .get("window_s")
        .and_then(|v| v.as_u64())
        .map(|w| format!(" for {}", human_window(w)))
        .unwrap_or_default();
    let class = crate::approval::reuse::Class::of(s("method").unwrap_or("")).as_str();
    let reuse = match s("reuse") {
        Some("none") if level == "allow" => "none".to_string(),
        Some("none") => "none (this request only)".to_string(),
        Some("exact") => format!("exact (this identical request){}", window),
        Some("rule") => format!(
            "rule \"{}\" ({} requests it decides){}",
            truncate(s("reuse_label").or(s("reuse_rule")).unwrap_or(""), 80),
            class,
            window
        ),
        Some("floor") => format!(
            "floor ({} requests no rule matches){}",
            s("reuse_class").unwrap_or(""),
            window
        ),
        Some(other) => format!("{}{}", truncate(other, 40), window),
        None => "not stated".to_string(),
    };
    Some(format!(
        "Policy: {}; reuse: {}.",
        truncate(level, 20),
        reuse
    ))
}

/// `900` → "15 min", `90` → "90s".
fn human_window(secs: u64) -> String {
    if secs >= 60 && secs % 60 == 0 {
        format!("{} min", secs / 60)
    } else {
        format!("{}s", secs)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::operation::{Act, Bind, Valid};
    use serde_json::json;

    fn use_op(scope: serde_json::Value) -> Operation {
        Operation {
            act: Act {
                kind: ActType::Use,
                target: "GITHUB_TOKEN".into(),
                scope,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, Some(300)),
        }
    }

    /// A CLI / headless approver reads the level, the reuse (rule label or
    /// floor class, with the request's class for a rule) and the window.
    #[test]
    fn use_line_states_level_reuse_and_window() {
        let base = json!({ "method": "POST", "host": "api.github.com", "path": "/x" });
        let with = |extra: serde_json::Value| {
            let mut s = base.clone();
            for (k, v) in extra.as_object().unwrap() {
                s[k] = v.clone();
            }
            render_operation(&use_op(s))
        };
        let rule = with(json!({
            "level": "ask", "reuse": "rule", "reuse_rule": "send",
            "reuse_label": "Send email", "window_s": 900
        }));
        assert!(
            rule.starts_with("Use POST api.github.com/x for a brokered call."),
            "{rule}"
        );
        assert!(
            rule.ends_with(
                "Policy: ask; reuse: rule \"Send email\" (write requests it decides) for 15 min."
            ),
            "{rule}"
        );
        let floor = with(json!({
            "method": "GET", "level": "ask", "reuse": "floor", "reuse_class": "read", "window_s": 90
        }));
        assert!(
            floor.ends_with("Policy: ask; reuse: floor (read requests no rule matches) for 90s."),
            "{floor}"
        );
        let always = with(json!({ "level": "ask-always", "reuse": "none" }));
        assert!(
            always.ends_with("Policy: ask-always; reuse: none (this request only)."),
            "{always}"
        );
        let exact =
            with(json!({ "level": "ask", "reuse": "exact", "window_s": 120, "scoped": true }));
        assert!(
            exact.ends_with("reuse: exact (this identical request) for 2 min."),
            "{exact}"
        );
        // No signed level: no grant line is invented.
        let bare = render_operation(&use_op(base.clone()));
        assert_eq!(bare, "Use POST api.github.com/x for a brokered call.");
        assert!(!bare.contains('\u{2014}') && !rule.contains('\u{2014}'));
    }
}
