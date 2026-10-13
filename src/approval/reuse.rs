//! What an approved brokered `use` op lets the daemon serve again WITHOUT a new
//! approval — the signed `scope.reuse` (design/approvals-inbox.md D1).
//!
//! ONE classifier, three consumers: the proxy stamps it into the op scope at
//! mint (so the approver reads it), approve asserts the signed fields equal
//! what this classifier returns for the record's PolicyContext, and the Use
//! apply picks its grant from it. The three can't drift because none of them
//! re-derives the mapping.
//!
//! Authorization is separate from value residency. An approval that reuses
//! writes an entry into the vault's ask-grant ledger keyed by the policy unit
//! that produced the ask (`state::record_ask_grant`); a later ask-level
//! request is served without asking only when the policy, re-run on that
//! request, lands on the SAME unit with a live ledger entry
//! (`state::evaluate_request_decision`). Whether the credential value happens
//! to be resident in memory never authorizes an ask.
//!
//! The values (all bound to the approving agent, the connection, and the
//! destination host; the device is implicit, the ledger lives in this daemon):
//!
//! - `none`: nothing reusable. `ask-always` (and an `ask` from a rule with no
//!   id, which has no unit to key) mints a single-use grant for exactly the
//!   approved request; its replay spends it. An `allow`-level request whose
//!   value was not resident is also `none`: approving it holds the value for
//!   allow-level traffic for the policy window and never serves an ask. No
//!   `window_s` is stamped.
//! - `exact`: a scoped ask (the service declares a `[requests]` shape for the
//!   path): only this identical request, with the same bound values, is
//!   reused within `window_s`.
//! - `rule`: a rule-matched ask: later requests whose policy decision is the
//!   same rule (`reuse_rule`, its id; `reuse_label` when the rule has one)
//!   don't ask within `window_s`. Another rule, a floor ask, and ask-always
//!   requests still ask.
//! - `floor`: an ask from a default floor (no rule matched): later floor asks
//!   of the same class (`reuse_class`: `read` or `write`, by the method split
//!   the floors use) don't ask within `window_s`. A read approval never serves
//!   a write, and no rule-matched request rides it.
//!
//! Every window is an upper bound: any vault change (a write, a sync) or a
//! lock rebuilds the session cache and drops the ledger. A window can end
//! early; it never extends.

use crate::core::policy::{AccessLevel, DecidedBy};

/// Read vs write, by the same method split the default floors use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Read,
    Write,
}

impl Class {
    pub fn of(method: &str) -> Class {
        if crate::core::policy::is_write_method(method) {
            Class::Write
        } else {
            Class::Read
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Read => "read",
            Class::Write => "write",
        }
    }
}

/// The ledger unit a reusable ask approval authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrantUnit {
    /// A rule, by id.
    Rule(String),
    /// A default floor, by class.
    Floor(Class),
}

impl GrantUnit {
    /// The unit an unscoped `ask` decision belongs to. `None` for a rule with
    /// no id (nothing stable to key it by).
    pub fn of(decided_by: &DecidedBy, method: &str) -> Option<GrantUnit> {
        match decided_by {
            DecidedBy::Rule { id: Some(id), .. } => Some(GrantUnit::Rule(id.clone())),
            DecidedBy::Rule { id: None, .. } => None,
            DecidedBy::Floor => Some(GrantUnit::Floor(Class::of(method))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reuse {
    None,
    Exact,
    Rule { id: String, label: Option<String> },
    Floor(Class),
}

impl Reuse {
    /// The reuse an approval of a Use op minted under `level` grants.
    /// `decided_by` = what decided it; `scoped` = the service declares a
    /// `[requests]` shape for the path (the signed `scoped` marker); `method`
    /// = the request's method. `None` for `deny`, which never mints an op.
    pub fn of(
        level: AccessLevel,
        decided_by: &DecidedBy,
        scoped: bool,
        method: &str,
    ) -> Option<Reuse> {
        match level {
            AccessLevel::Deny => None,
            AccessLevel::AskAlways | AccessLevel::Allow => Some(Reuse::None),
            AccessLevel::Ask if scoped => Some(Reuse::Exact),
            AccessLevel::Ask => Some(match GrantUnit::of(decided_by, method) {
                Some(GrantUnit::Rule(id)) => Reuse::Rule {
                    id,
                    label: match decided_by {
                        DecidedBy::Rule { label, .. } => label.clone(),
                        DecidedBy::Floor => None,
                    },
                },
                Some(GrantUnit::Floor(class)) => Reuse::Floor(class),
                None => Reuse::None,
            }),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Reuse::None => "none",
            Reuse::Exact => "exact",
            Reuse::Rule { .. } => "rule",
            Reuse::Floor(_) => "floor",
        }
    }

    /// The ledger unit this reuse writes (`rule` / `floor` only).
    pub fn unit(&self) -> Option<GrantUnit> {
        match self {
            Reuse::Rule { id, .. } => Some(GrantUnit::Rule(id.clone())),
            Reuse::Floor(c) => Some(GrantUnit::Floor(*c)),
            Reuse::None | Reuse::Exact => None,
        }
    }

    /// The signed `window_s` that accompanies this reuse: the policy ttl,
    /// except `none`, which has no window.
    pub fn window(&self, ttl_seconds: u64) -> Option<u64> {
        match self {
            Reuse::None => None,
            Reuse::Exact | Reuse::Rule { .. } | Reuse::Floor(_) => Some(ttl_seconds),
        }
    }

    /// The signed fields, in the order the scope carries them: `reuse`, then
    /// `reuse_rule` + optional `reuse_label` (rule) or `reuse_class` (floor).
    fn fields(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("reuse", self.as_str().to_string())];
        match self {
            Reuse::Rule { id, label } => {
                out.push(("reuse_rule", id.clone()));
                if let Some(l) = label {
                    out.push(("reuse_label", l.clone()));
                }
            }
            Reuse::Floor(c) => out.push(("reuse_class", c.as_str().to_string())),
            Reuse::None | Reuse::Exact => {}
        }
        out
    }

    /// Stamp this reuse into an op scope: its fields plus `window_s` (integer
    /// seconds; JCS rejects floats) exactly when it has a window.
    pub fn stamp(&self, scope: &mut serde_json::Value, ttl_seconds: u64) {
        for (k, v) in self.fields() {
            scope[k] = serde_json::Value::String(v);
        }
        if let Some(w) = self.window(ttl_seconds) {
            scope["window_s"] = serde_json::Value::from(w);
        }
    }

    /// Apply-time: the signed reuse fields and `window_s` must be exactly the
    /// ones [`Self::stamp`] writes for this reuse. `Err` names the field.
    pub fn check_signed(&self, scope: &serde_json::Value, ttl_seconds: u64) -> Result<(), String> {
        let reuse = scope
            .get("reuse")
            .ok_or("signed level without signed reuse")?
            .as_str()
            .ok_or("signed reuse is not a string")?;
        if reuse != self.as_str() {
            return Err(format!(
                "signed reuse '{}' does not match what this approval grants ('{}')",
                reuse,
                self.as_str()
            ));
        }
        let want = self.fields();
        for k in ["reuse_rule", "reuse_label", "reuse_class"] {
            let signed = scope.get(k);
            let expected = want.iter().find(|(f, _)| *f == k).map(|(_, v)| v);
            let ok = match (signed, expected) {
                (None, None) => true,
                (Some(s), Some(e)) => s.as_str() == Some(e.as_str()),
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "signed {} does not match what this approval grants",
                    k
                ));
            }
        }
        match (self.window(ttl_seconds), scope.get("window_s")) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(format!(
                "signed window_s on a '{}' approval, which has no window",
                self.as_str()
            )),
            (Some(want), None) => Err(format!(
                "signed window_s missing (this approval holds for {}s)",
                want
            )),
            (Some(want), Some(w)) => {
                let w = w.as_u64().ok_or("signed window_s is not an integer")?;
                if w == want {
                    Ok(())
                } else {
                    Err(format!(
                        "signed window_s {} does not match the policy window ({}s)",
                        w, want
                    ))
                }
            }
        }
    }
}

/// The signed `scoped` marker: the service declares a `[requests]` shape for
/// this request's path.
pub fn is_scoped(scope: &serde_json::Value) -> bool {
    scope
        .get("scoped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The `[requests]` values a Use op's signed scope binds (`scope.scope_vars`),
/// as sorted `(name, value)` pairs — the exact input of
/// [`crate::service::scope_digest`]. Non-string entries are ignored (the proxy
/// only ever stamps strings). Empty when the scope binds nothing.
pub fn bound_values(scope: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = scope
        .get("scope_vars")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(id: Option<&str>, label: Option<&str>) -> DecidedBy {
        DecidedBy::Rule {
            id: id.map(str::to_string),
            label: label.map(str::to_string),
        }
    }

    #[test]
    fn classification_table() {
        use AccessLevel::*;
        let send = rule(Some("send"), Some("Send email"));
        assert_eq!(
            Reuse::of(AskAlways, &send, false, "POST"),
            Some(Reuse::None)
        );
        assert_eq!(Reuse::of(AskAlways, &send, true, "POST"), Some(Reuse::None));
        assert_eq!(Reuse::of(Ask, &send, true, "POST"), Some(Reuse::Exact));
        assert_eq!(
            Reuse::of(Ask, &DecidedBy::Floor, true, "GET"),
            Some(Reuse::Exact)
        );
        assert_eq!(
            Reuse::of(Ask, &send, false, "POST"),
            Some(Reuse::Rule {
                id: "send".into(),
                label: Some("Send email".into())
            })
        );
        assert_eq!(
            Reuse::of(Ask, &DecidedBy::Floor, false, "GET"),
            Some(Reuse::Floor(Class::Read))
        );
        assert_eq!(
            Reuse::of(Ask, &DecidedBy::Floor, false, "DELETE"),
            Some(Reuse::Floor(Class::Write))
        );
        // A rule with no id has no unit: single-use.
        assert_eq!(
            Reuse::of(Ask, &rule(None, Some("x")), false, "GET"),
            Some(Reuse::None)
        );
        // An allow-level miss never reuses for asks.
        assert_eq!(
            Reuse::of(Allow, &DecidedBy::Floor, false, "GET"),
            Some(Reuse::None)
        );
        assert_eq!(Reuse::of(Deny, &send, false, "GET"), None);
        assert_eq!(Reuse::None.window(900), None);
        assert_eq!(Reuse::Exact.window(60), Some(60));
        assert_eq!(Reuse::Floor(Class::Read).window(300), Some(300));
    }

    #[test]
    fn stamp_and_check_round_trip_and_refuse_any_difference() {
        let cases = [
            Reuse::None,
            Reuse::Exact,
            Reuse::Rule {
                id: "send".into(),
                label: Some("Send email".into()),
            },
            Reuse::Rule {
                id: "send".into(),
                label: None,
            },
            Reuse::Floor(Class::Write),
        ];
        for r in &cases {
            let mut s = json!({ "level": "ask" });
            r.stamp(&mut s, 900);
            assert!(r.check_signed(&s, 900).is_ok(), "{r:?} {s}");
            assert!(r.check_signed(&s, 60).is_err() || r.window(900).is_none());
        }
        let floor_read = Reuse::Floor(Class::Read);
        let mut s = json!({});
        floor_read.stamp(&mut s, 300);
        assert_eq!(
            s,
            json!({ "reuse": "floor", "reuse_class": "read", "window_s": 300 })
        );
        assert!(Reuse::Floor(Class::Write).check_signed(&s, 300).is_err());
        let rule_a = Reuse::Rule {
            id: "a".into(),
            label: None,
        };
        let mut s = json!({});
        rule_a.stamp(&mut s, 60);
        let rule_b = Reuse::Rule {
            id: "b".into(),
            label: None,
        };
        assert!(rule_b.check_signed(&s, 60).is_err());
        // An extra field the reuse does not carry is refused too.
        s["reuse_class"] = json!("read");
        assert!(rule_a.check_signed(&s, 60).is_err());
        assert!(Reuse::Exact
            .check_signed(&json!({ "reuse": "exact" }), 60)
            .is_err());
    }

    #[test]
    fn bound_values_sorted_strings_only() {
        let s = json!({ "scope_vars": { "b": "2", "a": "1", "n": 3 } });
        assert_eq!(
            bound_values(&s),
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
        assert!(bound_values(&json!({ "method": "GET" })).is_empty());
    }
}
