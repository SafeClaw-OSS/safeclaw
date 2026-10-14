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
//! arrays join with ", "; an object renders its distinct string values (in
//! key order) joined with ", ". A fact row whose value renders empty is
//! omitted.

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
    /// The consequence tier: "neutral" (one-shot or reversible) | "warn"
    /// (persistent or irrevocable, amber, still batchable) | "danger"
    /// (destruction, red, confirmed alone, never batched). Styling AND the
    /// batch gate. Upward-only: a client's built-in danger floor for an act
    /// kind can never be downgraded.
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
    /// Long text (a definition's source) a client shows on request, never
    /// inline: left out of the one-line rendering ([`consent_for`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detail: bool,
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
    /// `(label, value)` — rows whose value rendered empty, and `detail`
    /// rows, are already omitted.
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
        .filter(|f| !f.detail)
        .filter_map(|f| {
            let v = interpolate_op(&f.value, op);
            (!v.is_empty()).then(|| (f.label.clone(), v))
        })
        .collect();
    Some(RenderedConsent {
        action: interpolate_op(&desc.action, op),
        // The explain carries {{vars}} templates too (widen-host names the
        // connection and host in its consequence sentence).
        explain: interpolate_op(&desc.explain, op),
        tone: desc.tone.clone(),
        facts,
    })
}

/// Stamp the op's consequence tier into the signed scope at op creation
/// (`scope.tone`), over anything the requester sent there: tone is the batch
/// gate (a danger act is confirmed alone, never batched), so the console must
/// read it from daemon-authored, signed material, never a requester field.
///
/// A Custom act carries its descriptor's tone. The built-ins: a `use` is
/// always "neutral" (windowed or one-shot, it is the agent's most routine
/// action; the window itself is on the card); an `export` with no recipient
/// binding is "warn" (a handover: the plaintext reaches the requester and
/// cannot be taken back) while one sealed to a recipient is "neutral".
/// Anything else gets none (a requester-supplied value is removed); clients
/// keep their own upward-only danger floor for the acts they know.
pub fn stamp_tone(op: &mut Operation) {
    let variant = |warn: bool| Some(if warn { "warn" } else { "neutral" }.to_string());
    let tone = match &op.act.kind {
        ActType::Custom(name) => act_catalog().get(name.as_str()).map(|d| d.tone.clone()),
        ActType::Use => variant(false),
        ActType::Export => variant(op.bind.recipient.is_none()),
        _ => None,
    };
    if op.act.scope.is_null() && tone.is_some() {
        op.act.scope = serde_json::json!({});
    }
    if let Some(o) = op.act.scope.as_object_mut() {
        match tone {
            Some(t) => {
                o.insert("tone".into(), serde_json::Value::String(t));
            }
            None => {
                o.remove("tone");
            }
        }
    }
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
        // A slot → KEY map (the connection-add card): the KEYs, each once.
        Some(serde_json::Value::Object(m)) => {
            let mut out: Vec<&str> = Vec::new();
            for v in m.values().filter_map(|x| x.as_str()) {
                if !out.contains(&v) {
                    out.push(v);
                }
            }
            out.join(", ")
        }
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

    /// A `detail` fact (the definition text of a `service-add`) is emitted
    /// with `"detail": true` in the catalog the registry serves; other facts
    /// carry no `detail`. The one-line rendering leaves it out.
    #[test]
    fn detail_facts_are_emitted_and_kept_out_of_one_line_renders() {
        let add = &act_catalog()["service-add"];
        let v = serde_json::to_value(add).unwrap();
        let facts = v["facts"].as_array().unwrap();
        let labels: Vec<&str> = facts.iter().map(|f| f["label"].as_str().unwrap()).collect();
        assert_eq!(
            labels,
            [
                "Services",
                "Sends credentials to",
                "Source",
                "OAuth",
                "New destinations",
                "Loosened or removed rules",
                "Rules applied",
                "Replaces",
                "Removes",
                "Definition"
            ]
        );
        assert_eq!(
            facts.last().unwrap(),
            &json!({
                "label": "Definition",
                "label_zh": "定义原文",
                "value": "{{vars.scope.definitions}}",
                "detail": true
            })
        );
        assert!(facts[..facts.len() - 1].iter().all(|f| f.get("detail").is_none()));
        assert_eq!(v["action"], json!("Install a third-party service"));
        assert_eq!(v["action_zh"], json!("安装第三方服务"));
        assert_eq!(
            v["explain"],
            json!("SafeClaw does not review third-party services. Connections that use one send credentials to the hosts it lists.")
        );
        assert_eq!(
            v["explain_zh"],
            json!("SafeClaw 不审查第三方服务。使用它的连接会把凭证发往它列出的主机。")
        );
        // The table round-trips with `detail` (a client parsing it back).
        let back: ActConsent = serde_json::from_value(v.clone()).unwrap();
        assert!(back.facts.last().unwrap().detail);
        let c = consent_for(&op(
            "service-add",
            "github:acme/tools",
            json!({ "ids": ["a1"], "from": "local folder mine", "definitions": "# a1 service.toml\n[service]\n" }),
        ))
        .unwrap();
        assert!(c.facts.iter().all(|(l, _)| l != "Definition"), "{:?}", c.facts);
        assert!(c.facts.iter().any(|(l, v)| l == "Source" && v == "local folder mine"));
    }

    /// Tone is the consequence tier: neutral (one-shot or reversible), warn
    /// (persistent or irrevocable, batchable) or danger (destruction,
    /// confirmed alone). Only vault-delete is danger, only widen-host is
    /// warn (its grant is forever), installs and removals are routine, and
    /// the rendered consent carries the tone so every surface reads the
    /// stamped material.
    #[test]
    fn only_vault_delete_is_danger() {
        let acts = act_catalog();
        for (name, a) in acts.iter() {
            assert!(
                ["neutral", "warn", "danger"].contains(&a.tone.as_str()),
                "{name}: {}",
                a.tone
            );
        }
        let of = |tone: &str| -> Vec<&str> {
            acts.iter()
                .filter(|(_, a)| a.tone == tone)
                .map(|(name, _)| name.as_str())
                .collect()
        };
        assert_eq!(of("danger"), ["vault-delete"]);
        assert_eq!(of("warn"), ["widen-host"]);
        for name in ["service-add", "service-rm", "secret-rm", "connection-rm"] {
            assert_eq!(acts[name].tone, "neutral", "{name}");
        }
        // The wire forms carry it: the catalog descriptor (registry `acts`)
        // and the rendered consent.
        let v = serde_json::to_value(&acts["vault-delete"]).unwrap();
        assert_eq!(v["tone"], json!("danger"));
        let v = serde_json::to_value(&acts["service-add"]).unwrap();
        assert_eq!(v["tone"], json!("neutral"));
        let c = consent_for(&op("vault-delete", "v1", json!({}))).unwrap();
        assert_eq!(c.tone, "danger");
        assert_eq!(serde_json::to_value(&c).unwrap()["tone"], json!("danger"));
        let c = consent_for(&op(
            "service-add",
            "github:acme/tools",
            json!({ "ids": ["a1"] }),
        ))
        .unwrap();
        assert_eq!(c.tone, "neutral");
    }

    /// The built-ins stamp their variant: a use is neutral whatever its
    /// window (the agent's most routine action); an export with no recipient
    /// binding (a handover) is warn, one sealed to a recipient neutral.
    #[test]
    fn use_and_export_stamp_their_variant_tone() {
        let built_in = |kind: ActType, scope: serde_json::Value, sealed: bool| {
            let mut o = Operation {
                act: Act {
                    kind,
                    target: "t".into(),
                    scope,
                },
                bind: Bind {
                    redeemer: "v1".into(),
                    recipient: sealed.then(|| crate::protocol::RecipientPk {
                        alg: "hpke-p256-sha256-aes128gcm".into(),
                        bytes: "cGs".into(),
                    }),
                },
                valid: Valid::single_use(0, Some(300)),
            };
            stamp_tone(&mut o);
            o.act.scope.get("tone").cloned()
        };
        let windowed = json!({ "level": "ask", "reuse": "floor", "window_s": 900 });
        assert_eq!(
            built_in(ActType::Use, windowed, false),
            Some(json!("neutral")),
            "a windowed use is still the routine action"
        );
        let once = json!({ "level": "ask-always", "reuse": "none", "tone": "warn" });
        assert_eq!(
            built_in(ActType::Use, once, false),
            Some(json!("neutral")),
            "one-shot, and a requester-supplied tone is overwritten"
        );
        assert_eq!(
            built_in(ActType::Export, json!({}), false),
            Some(json!("warn")),
            "a handover cannot be taken back"
        );
        assert_eq!(
            built_in(ActType::Export, json!({}), true),
            Some(json!("neutral")),
            "sealed to a recipient: no plaintext handover"
        );
    }

    /// Op creation stamps the descriptor's tone into the signed scope, over
    /// anything the requester sent; a table-less act carries none, whatever
    /// the requester claimed.
    #[test]
    fn op_creation_stamps_the_tone_into_the_signed_scope() {
        let mut del = op("vault-delete", "v1", serde_json::Value::Null);
        stamp_tone(&mut del);
        assert_eq!(del.act.scope["tone"], json!("danger"));
        let mut add = op(
            "service-add",
            "github:acme/tools",
            json!({ "ids": ["a1"], "tone": "danger" }),
        );
        stamp_tone(&mut add);
        assert_eq!(add.act.scope["tone"], json!("neutral"), "requester overwritten");
        assert_eq!(add.act.scope["ids"], json!(["a1"]), "other fields kept");
        let mut unknown = op("frobnicate", "x", json!({ "tone": "neutral" }));
        stamp_tone(&mut unknown);
        assert!(unknown.act.scope.get("tone").is_none(), "no descriptor, no tone");
        let mut widen = op("widen-host", "github", json!({ "host": "uploads.github.com" }));
        stamp_tone(&mut widen);
        assert_eq!(widen.act.scope["tone"], json!("warn"));
    }

    /// The consequence sentence interpolates over the signed op like the
    /// action line: a templated explain never shows literal braces.
    #[test]
    fn explain_interpolates_over_the_signed_op() {
        let c = consent_for(&op(
            "widen-host",
            "",
            json!({ "connection_id": "github", "host": "uploads.github.com" }),
        ))
        .unwrap();
        assert_eq!(
            c.explain,
            "github's credential can be sent to uploads.github.com from now on, without asking, until you remove it."
        );
        assert!(!c.explain.contains("{{"), "{}", c.explain);
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
                "values_digest": "aa",
                "destinations": ["api.xiaomimimo.com"],
                "written": { "MIMO_API_TOKEN": "MIMO_API_TOKEN" },
                "referenced": {},
                "overwrites": [],
                "shared_with": {},
                "replaces": false,
            }),
        );
        let c = consent_for(&o).expect("descriptor");
        assert_eq!(c.action, "Add connection mimo");
        assert_eq!(c.tone, "neutral");
        // Service is absent (raw connection) → row omitted (P3).
        assert!(c.facts.iter().all(|(l, _)| l != "Service"));
        assert!(c
            .facts
            .contains(&("Sends to".into(), "api.xiaomimimo.com".into())));
        assert!(c
            .facts
            .contains(&("Stores new value".into(), "MIMO_API_TOKEN".into())));
        // Empty card fields (and `replaces: false`) omit their rows.
        let labels: Vec<&str> = c.facts.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels, vec!["Sends to", "Stores new value"]);
    }

    /// The connection-add facts come from the daemon-stamped card, never
    /// from the requester's `secrets` list.
    #[test]
    fn connection_add_facts_come_from_the_card() {
        let o = op(
            "connection-add",
            "codex_x",
            json!({
                "service": "openai_codex",
                "secrets": ["REQUESTER_SAYS_THIS"],
                "destinations": ["chatgpt.com", "auth.openai.com"],
                "written": { "A": "NEW_A" },
                "referenced": { "R1": "OLD_KEY", "R2": "OLD_KEY" },
                "overwrites": ["NEW_A"],
                "shared_with": {},
                "replaces": true,
            }),
        );
        let c = consent_for(&o).unwrap();
        let get = |l: &str| {
            c.facts
                .iter()
                .find(|(k, _)| k == l)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("Uses existing secret"), Some("OLD_KEY"));
        assert_eq!(get("Stores new value"), Some("NEW_A"));
        assert_eq!(get("Overwrites"), Some("NEW_A"));
        assert_eq!(get("Replaces existing connection"), Some("yes"));
        assert!(c
            .facts
            .iter()
            .all(|(_, v)| !v.contains("REQUESTER_SAYS_THIS")));
        let line = crate::protocol::render::render_operation(&o);
        assert!(line.contains("Uses existing secret: OLD_KEY"), "{line}");
        assert!(line.contains("Overwrites: NEW_A"), "{line}");
        assert!(!line.contains("REQUESTER_SAYS_THIS"), "{line}");
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
