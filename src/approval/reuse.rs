//! What an approved brokered `use` op lets the daemon serve again WITHOUT a new
//! approval — the signed `scope.reuse` (design/approvals-inbox.md D1).
//!
//! ONE classifier, three consumers: the proxy stamps it into the op scope at
//! mint (so the approver reads it), approve asserts the signed value equals
//! what this function returns for the record's PolicyContext, and the Use
//! apply picks its grant store from it. The three can't drift because none of
//! them re-derives the mapping.
//!
//! The values, stated as what the grant store and the proxy's lookup actually
//! do (`proxy::handler::grant_lookup`):
//!
//! - `none`: nothing reusable. The approval mints a single-use grant bound to
//!   the approved request (agent, connection, method, host, path, bound
//!   values); the proxy spends it on that request's replay and the next
//!   identical request asks again. No `window_s` is stamped.
//! - `exact`: only this identical request is reused within `window_s`: the
//!   same agent, connection, method, host, path, and the same bound
//!   `[requests]` values. Any other request misses and asks.
//! - `connection`: the connection's credential is held for the approving
//!   agent for `window_s`. Within it, that agent's requests through this
//!   connection do not ask when their level is `ask` and they bind no request
//!   values, whatever their method, path, host, or matched rule (writes
//!   included). Requests the policy already allows on this connection (from
//!   any agent) are served from the same held value instead of asking for it.
//!   `ask-always` requests and value-bound (`exact`) requests keep their own
//!   approvals.
//!
//! Every window is an upper bound: a later approval on the same connection
//! replaces the held value, and any vault change (a write, a sync) or a lock
//! rebuilds the session cache and drops held approvals. A window can end
//! early; it never extends.
//!
//! A per-(rule, method) window is NOT a value here: the rule-approval record
//! (`state::record_ask_approval`) narrows the policy decision, but the held
//! value it reads is connection-wide, so stamping it would understate the
//! grant.

use crate::core::policy::AccessLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reuse {
    None,
    Exact,
    Connection,
}

impl Reuse {
    /// The reuse an approval of a Use op minted under `level` grants.
    /// `binds_values` = the op's signed scope binds at least one `[requests]`
    /// value (its scope digest is non-empty). `None` for `deny`, which never
    /// mints an op.
    pub fn of(level: AccessLevel, binds_values: bool) -> Option<Reuse> {
        match level {
            AccessLevel::AskAlways => Some(Reuse::None),
            AccessLevel::Ask if binds_values => Some(Reuse::Exact),
            // An unscoped ask, a scoped path whose request bound no values,
            // and an allow-level cache miss all hold the connection's value
            // for the approving agent (`state::cache_insert`).
            AccessLevel::Ask | AccessLevel::Allow => Some(Reuse::Connection),
            AccessLevel::Deny => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Reuse::None => "none",
            Reuse::Exact => "exact",
            Reuse::Connection => "connection",
        }
    }

    /// The signed `window_s` that accompanies this reuse: the policy ttl,
    /// except `none`, which has no window.
    pub fn window(self, ttl_seconds: u64) -> Option<u64> {
        match self {
            Reuse::None => None,
            Reuse::Exact | Reuse::Connection => Some(ttl_seconds),
        }
    }
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

    #[test]
    fn classification_table() {
        use AccessLevel::*;
        assert_eq!(Reuse::of(AskAlways, false), Some(Reuse::None));
        assert_eq!(Reuse::of(AskAlways, true), Some(Reuse::None));
        assert_eq!(Reuse::of(Ask, true), Some(Reuse::Exact));
        assert_eq!(Reuse::of(Ask, false), Some(Reuse::Connection));
        assert_eq!(Reuse::of(Allow, false), Some(Reuse::Connection));
        assert_eq!(Reuse::of(Allow, true), Some(Reuse::Connection));
        assert_eq!(Reuse::of(Deny, false), None);
        assert_eq!(Reuse::None.window(900), None);
        assert_eq!(Reuse::Exact.window(60), Some(60));
        assert_eq!(Reuse::Connection.window(900), Some(900));
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
