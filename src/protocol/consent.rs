//! Consent descriptors for control-plane acts — the acts.toml engine.
//!
//! WHY: every custom act needs human-readable approval copy on three surfaces
//! (grant page, CLI prompt, audit row). Hand-writing it per surface drifted
//! (acts shipped with raw-slug approval cards). This module is the single
//! source: a STATIC descriptor table (`acts.toml`, baked at compile time)
//! interpolated over the SIGNED op's own fields — never requester-authored
//! prose. Same philosophy (and template grammar) as a service.toml
//! `[requests].consent`: services declare what a REQUEST means; this table
//! declares what a VAULT OPERATION means. The console receives the raw table
//! through the registry SSoT pipeline (`sc registry --json` → registry.json)
//! and interpolates client-side from the op it verifies — display always
//! derives from signed bytes plus a reviewed static template (WYSIWYS; the
//! ERC-7730 / RFC 9396 shape).
//!
//! Grammar: `{{vars.target}}` and `{{vars.scope.<key>}}`, optional `|filter`
//! accepted-and-ignored (display filters are a console concern). P3 rule:
//! undefined/empty renders empty; `false` renders empty; `true` renders "yes";
//! arrays join with ", ". A fact row whose value renders empty is omitted.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::operation::{ActType, Operation};

/// One act's consent descriptor — raw templates, as authored in acts.toml.
/// Serialized verbatim into the registry catalog for client-side rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActConsent {
    /// Verb-object title template — doubles as the approve button label.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_zh: Option<String>,
    /// One-sentence consequence, ALWAYS shown inline (never hover-only).
    pub explain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explain_zh: Option<String>,
    /// "neutral" | "info" | "danger". Advisory upward-only: a client's
    /// built-in danger floor for an act kind can never be downgraded.
    #[serde(default = "default_tone")]
    pub tone: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<ActFact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActFact {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_zh: Option<String>,
    /// Value template over the op's signed fields.
    pub value: String,
}

fn default_tone() -> String {
    "neutral".into()
}

#[derive(Deserialize)]
struct ActsFile {
    acts: BTreeMap<String, ActConsent>,
}

/// The baked descriptor table. Parsed once; a parse failure is a build bug
/// (the `acts_toml_parses` test), so an empty table at runtime is the safe
/// degradation, not a panic.
pub fn act_catalog() -> &'static BTreeMap<String, ActConsent> {
    static TABLE: OnceLock<BTreeMap<String, ActConsent>> = OnceLock::new();
    TABLE.get_or_init(|| {
        toml::from_str::<ActsFile>(include_str!("acts.toml"))
            .map(|f| f.acts)
            .unwrap_or_default()
    })
}

/// A descriptor rendered against one concrete op (English; the console does
/// its own zh interpolation from the raw table).
#[derive(Debug, Clone, Serialize)]
pub struct RenderedConsent {
    pub action: String,
    pub explain: String,
    pub tone: String,
    /// `(label, value)` — rows whose value rendered empty are already omitted.
    pub facts: Vec<(String, String)>,
}

/// Render the consent view of a Custom op from the table. `None` when the op
/// isn't a Custom act or has no descriptor (callers fall back to a humanized
/// slug — see [`fallback_line`]).
pub fn consent_for(op: &Operation) -> Option<RenderedConsent> {
    let ActType::Custom(name) = &op.act.kind else {
        return None;
    };
    let desc = act_catalog().get(name.as_str())?;
    let facts = desc
        .facts
        .iter()
        .filter_map(|f| {
            let v = interpolate_op(&f.value, op);
            (!v.is_empty()).then(|| (f.label.clone(), v))
        })
        .collect();
    Some(RenderedConsent {
        action: interpolate_op(&desc.action, op),
        explain: desc.explain.clone(),
        tone: desc.tone.clone(),
        facts,
    })
}

/// The generic floor for a table-less custom act: humanized slug + target
/// ("connection-frobnicate x" → "connection frobnicate \"x\""). Every future
/// act gets at least this — never a raw debug dump.
pub fn fallback_line(kind: &str, target: &str) -> String {
    let words = kind.replace('-', " ");
    if target.is_empty() {
        capitalize(&words)
    } else {
        format!("{} \"{}\"", capitalize(&words), target)
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Interpolate a `{{vars.path|filter}}` template over the op's signed fields.
/// Paths: `target` → `op.act.target`; `scope.<key>` → `op.act.scope[key]`.
/// Filters are accepted and ignored (display-only concern). Values render per
/// the P3 rule in the module doc.
pub fn interpolate_op(template: &str, op: &Operation) -> String {
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
        if let Some(path) = name.strip_prefix("vars.").map(str::trim) {
            out.push_str(&truncate(&resolve_var(op, path), 120));
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out.trim().to_string()
}

fn resolve_var(op: &Operation, path: &str) -> String {
    if path == "target" {
        return op.act.target.clone();
    }
    let Some(key) = path.strip_prefix("scope.") else {
        return String::new();
    };
    render_value(op.act.scope.get(key))
}

fn render_value(v: Option<&serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Bool(true)) => "yes".into(),
        Some(serde_json::Value::Bool(false)) => String::new(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
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

    fn op(kind: &str, target: &str, scope: serde_json::Value) -> Operation {
        Operation {
            act: Act {
                kind: ActType::Custom(kind.into()),
                target: target.into(),
                scope,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, Some(300)),
        }
    }

    #[test]
    fn acts_toml_parses() {
        assert!(
            !act_catalog().is_empty(),
            "acts.toml failed to parse — the table degraded to empty"
        );
    }

    /// THE drift gate: every dispatched custom act has a descriptor, and every
    /// descriptor corresponds to a dispatched act. Adding an act without copy
    /// (or copy without an act) fails here, not in front of a user.
    #[test]
    fn dispatch_and_table_agree() {
        let table: Vec<&str> = act_catalog().keys().map(String::as_str).collect();
        let dispatched = crate::server::handlers::approve::DISPATCHED_CUSTOM_ACTS;
        for act in dispatched {
            assert!(
                table.contains(act),
                "custom act '{}' is dispatched but has no acts.toml descriptor",
                act
            );
        }
        for act in &table {
            assert!(
                dispatched.contains(act),
                "acts.toml describes '{}' but approve.rs never dispatches it",
                act
            );
        }
    }

    #[test]
    fn renders_action_facts_and_p3_rules() {
        let o = op(
            "connection-add",
            "mimo",
            json!({
                "hosts": ["api.xiaomimimo.com"],
                "secrets": ["MIMO_API_TOKEN"],
                "values_digest": "aa"
            }),
        );
        let c = consent_for(&o).expect("descriptor");
        assert_eq!(c.action, "Add connection mimo");
        assert_eq!(c.tone, "neutral");
        // Service is absent (raw connection) → row omitted (P3).
        assert!(c.facts.iter().all(|(l, _)| l != "Service"));
        assert!(c
            .facts
            .contains(&("Host".into(), "api.xiaomimimo.com".into())));
        assert!(c
            .facts
            .contains(&("Secret in use".into(), "MIMO_API_TOKEN".into())));
    }

    #[test]
    fn bool_and_missing_vars_render_per_p3() {
        let o = op("connection-rm", "x", json!({ "keep_secrets": false }));
        let c = consent_for(&o).unwrap();
        // false → empty → row omitted.
        assert!(c.facts.is_empty(), "{:?}", c.facts);
        let o = op("connection-rm", "x", json!({ "keep_secrets": true }));
        let c = consent_for(&o).unwrap();
        assert_eq!(c.facts, vec![("Secrets kept".into(), "yes".into())]);
    }

    #[test]
    fn unknown_act_falls_back_humanized() {
        let o = op("connection-frobnicate", "x", json!(null));
        assert!(consent_for(&o).is_none());
        assert_eq!(
            fallback_line("connection-frobnicate", "x"),
            "Connection frobnicate \"x\""
        );
    }

    #[test]
    fn filters_accepted_and_ignored() {
        let o = op("secret-set", "K", json!({ "hosts": ["h.com"] }));
        assert_eq!(
            interpolate_op(
                "Store {{ vars.target | upper }} at {{vars.scope.hosts}}",
                &o
            ),
            "Store K at h.com"
        );
    }
}
