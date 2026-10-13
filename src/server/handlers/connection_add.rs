//! The `connection-add` approval card: the facts the owner approves, signed
//! into the op scope at mint and re-derived at apply (refused on any
//! difference), so what the approval shows is what the write does.
//!
//! An agent may PROPOSE a connection (`sc connection add`), including one that
//! binds secrets already in the vault; it takes effect only after the owner's
//! passkey approval, and the card lists every bound key and every destination
//! host. The daemon computes the card itself at op creation from its unlocked
//! session state (`stamp_at_mint`), overwriting whatever the requester put in
//! those fields; apply recomputes it from the opened vault (`card`) and
//! compares (`assert_card`).
//!
//! Card fields (all present, possibly empty):
//! - `written`: slot → KEY whose value this approval writes (from the local
//!   value deposit committed by `values_digest`).
//! - `referenced`: slot → KEY already in the vault, bound without writing.
//!   KEY is canonical: a native key in its stored casing, an external key as
//!   named.
//! - `overwrites`: written KEYs that already hold a value in the vault.
//! - `destinations`: every host the bound credentials, or tokens minted from
//!   them, are sent to: the hosts the proxy anchors the stored record to
//!   (`core::host::resolved_hosts`: a raw connection's anchors, or a
//!   service's exact hosts plus any pins) plus a minted mechanism's token
//!   endpoint.
//! - `shared_with`: KEY → other connections that can already use it,
//!   including a service's default connection that has no record of its own.
//! - `replaces`: a connection with this id already exists and is replaced.
//!
//! A slot is a service's declared secret role, or for a raw connection the
//! KEY itself. Every KEY the op names (`secrets`) must fill a slot.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::service::ServiceDef;
use crate::storage::plaintext::Connection;

/// The signed card. See the module docs for each field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Card {
    pub written: BTreeMap<String, String>,
    pub referenced: BTreeMap<String, String>,
    pub overwrites: Vec<String>,
    pub destinations: Vec<String>,
    pub shared_with: BTreeMap<String, Vec<String>>,
    pub replaces: bool,
}

impl Card {
    /// Write the card into an op scope (overwrites any requester-supplied
    /// values of these fields). A null scope becomes an object; any other
    /// non-object scope is refused.
    pub fn stamp(&self, scope: &mut Value) -> Result<(), String> {
        if scope.is_null() {
            *scope = json!({});
        }
        let Some(o) = scope.as_object_mut() else {
            return Err("op.act.scope must be a JSON object".into());
        };
        o.insert("written".into(), json!(self.written));
        o.insert("referenced".into(), json!(self.referenced));
        o.insert("overwrites".into(), json!(self.overwrites));
        o.insert("destinations".into(), json!(self.destinations));
        o.insert("shared_with".into(), json!(self.shared_with));
        o.insert("replaces".into(), json!(self.replaces));
        Ok(())
    }

    /// Read the signed card back out of an op scope. Every field is required.
    pub fn from_scope(scope: &Value) -> Result<Card, String> {
        fn map(scope: &Value, k: &str) -> Result<BTreeMap<String, String>, String> {
            let o = scope
                .get(k)
                .and_then(|v| v.as_object())
                .ok_or_else(|| format!("signed `{}` missing", k))?;
            o.iter()
                .map(|(s, v)| {
                    v.as_str()
                        .map(|v| (s.clone(), v.to_string()))
                        .ok_or_else(|| format!("signed `{}` is malformed", k))
                })
                .collect()
        }
        fn list(v: Option<&Value>, k: &str) -> Result<Vec<String>, String> {
            v.and_then(|v| v.as_array())
                .ok_or_else(|| format!("signed `{}` missing", k))?
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("signed `{}` is malformed", k))
                })
                .collect()
        }
        let shared_with = scope
            .get("shared_with")
            .and_then(|v| v.as_object())
            .ok_or("signed `shared_with` missing")?
            .iter()
            .map(|(key, by)| Ok((key.clone(), list(Some(by), "shared_with")?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        Ok(Card {
            written: map(scope, "written")?,
            referenced: map(scope, "referenced")?,
            overwrites: list(scope.get("overwrites"), "overwrites")?,
            destinations: list(scope.get("destinations"), "destinations")?,
            shared_with,
            replaces: scope
                .get("replaces")
                .and_then(|v| v.as_bool())
                .ok_or("signed `replaces` missing")?,
        })
    }
}

/// The record's `written` list (`Connection::written`): every KEY this
/// approval writes (deposited), plus any KEY the same-id record it replaces had
/// written and the new one still binds, so re-adding a connection over its own
/// secret keeps that secret's provenance. A KEY the new record only references
/// and the old one did not write (or a legacy record with no `written`) stays
/// off the list: removal then keeps it.
pub(crate) fn written_keys(
    slots: &[(String, String, bool)],
    replaced: Option<&Connection>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |k: &str| {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(k)) {
            out.push(k.to_string());
        }
    };
    for (_, key, written) in slots {
        if *written {
            push(key);
        }
    }
    let prev = replaced.and_then(|c| c.written.as_ref());
    for k in prev.into_iter().flatten() {
        if slots.iter().any(|(_, key, _)| key.eq_ignore_ascii_case(k)) {
            push(k);
        }
    }
    out.sort();
    out
}

/// Apply-time: the record a `connection-add` stores for resolved `slots` =
/// `(slot, canonical KEY, written?)`. RAW (`service: None`): the slot KEYs as
/// its `secrets` list (exact dedup only: native case-folding already collapsed
/// duplicates, and two external keys differing by case are distinct secrets).
/// SERVICE: the requested `keys` map with each KEY in its canonical form;
/// roles the request left on the identity binding stay off the map. Either
/// way `written` comes from [`written_keys`] against the record replaced.
pub(crate) fn record(
    service: Option<&str>,
    hosts: &[String],
    keys: Option<&BTreeMap<String, String>>,
    slots: &[(String, String, bool)],
    replaced: Option<&Connection>,
) -> Connection {
    let written = Some(written_keys(slots, replaced));
    match service {
        None => {
            let mut seen = std::collections::HashSet::new();
            let canonical: Vec<String> = slots
                .iter()
                .map(|(_, k, _)| k.clone())
                .filter(|k| seen.insert(k.clone()))
                .collect();
            Connection {
                name: None,
                service: None,
                hosts: Some(hosts.to_vec()),
                secrets: Some(canonical),
                keys: None,
                written,
            }
        }
        Some(service) => {
            let keys: Option<BTreeMap<String, String>> = keys.map(|m| {
                m.iter()
                    .map(|(role, key)| {
                        let canon = slots
                            .iter()
                            .find(|(slot, _, _)| slot.eq_ignore_ascii_case(role))
                            .map(|(_, k, _)| k.clone())
                            .unwrap_or_else(|| key.clone());
                        (role.clone(), canon)
                    })
                    .collect()
            });
            Connection {
                name: None,
                service: Some(service.to_string()),
                hosts: Some(hosts.to_vec()).filter(|h| !h.is_empty()),
                secrets: None,
                keys: keys.filter(|m| !m.is_empty()),
                written,
            }
        }
    }
}

/// One slot as the op REQUESTS it (before native case-folding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Requested {
    pub slot: String,
    pub key: String,
    /// A service role the op does not name (no `keys` entry, its KEY not in
    /// `secrets`): it falls back to the identity binding. Optional: it binds
    /// that KEY only when the vault already holds it natively (and the card
    /// then shows it), else it stays unfilled. Never set for a raw slot.
    pub implicit: bool,
}

/// The connection's slots and the KEY each binds, as the op REQUESTS them
/// (before native case-folding). A raw connection's slots are its `secrets`
/// list (slot = KEY). A service connection has a slot per declared role,
/// through the op's `keys` map (role matched case-insensitively) or, absent
/// an entry, the role's own name (the identity binding `secret_key_for`
/// applies); a role is NAMED when it has a `keys` entry or its KEY is in the
/// op's `secrets`, and implicit otherwise. A `secrets` entry that fills no
/// slot is refused: the op names only keys the connection binds.
pub(crate) fn requested_slots(
    scope: &Value,
    def: Option<&ServiceDef>,
) -> Result<Vec<Requested>, String> {
    let str_list = |k: &str| -> Vec<String> {
        scope
            .get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    match def {
        None => {
            let mut seen = BTreeSet::new();
            Ok(str_list("secrets")
                .into_iter()
                .filter(|k| seen.insert(k.clone()))
                .map(|k| Requested {
                    slot: k.clone(),
                    key: k,
                    implicit: false,
                })
                .collect())
        }
        Some(def) => {
            let keys: BTreeMap<String, String> = scope
                .get("keys")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(r, k)| k.as_str().map(|k| (r.clone(), k.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let named = str_list("secrets");
            let roles = &def.service.secrets;
            for r in keys.keys() {
                if !roles.iter().any(|d| d.eq_ignore_ascii_case(r)) {
                    return Err(format!(
                        "'{}' is not a secret declared by service '{}' (its secrets: {})",
                        r,
                        def.service.id,
                        roles.join(", ")
                    ));
                }
            }
            let slots: Vec<Requested> = roles
                .iter()
                .map(
                    |role| match keys.iter().find(|(r, _)| r.eq_ignore_ascii_case(role)) {
                        Some((_, k)) => Requested {
                            slot: role.clone(),
                            key: k.clone(),
                            implicit: false,
                        },
                        None => Requested {
                            slot: role.clone(),
                            key: role.clone(),
                            implicit: !named.iter().any(|n| n.eq_ignore_ascii_case(role)),
                        },
                    },
                )
                .collect();
            for n in &named {
                if !slots.iter().any(|s| s.key.eq_ignore_ascii_case(n)) {
                    return Err(format!(
                        "'{}' is not bound to any secret of service '{}' (bind it with `--from-secret <ROLE>={}`; its secrets: {})",
                        n,
                        def.service.id,
                        n,
                        roles.join(", ")
                    ));
                }
            }
            Ok(slots)
        }
    }
}

/// Fold a referenced KEY to its stored native casing when a native key matches
/// it case-insensitively; otherwise keep it as named (an external key, or one
/// apply will refuse as missing).
pub(crate) fn canonical_key(key: &str, native: &BTreeSet<String>) -> String {
    if native.contains(key) {
        return key.to_string();
    }
    native
        .iter()
        .find(|n| n.eq_ignore_ascii_case(key))
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

/// Every host the bound credentials (or tokens minted from them) reach: the
/// hosts the proxy anchors `rec` to ([`crate::core::host::resolved_hosts`],
/// the same function the proxy enforces with) plus a minted mechanism's
/// token endpoint. `rec` carries the record's `service` and `hosts` as
/// [`record`] stores them.
pub(crate) fn destinations(rec: &Connection, def: Option<&ServiceDef>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: &str| {
        let h = h.trim();
        if !h.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(h)) {
            out.push(h.to_string());
        }
    };
    for h in crate::core::host::resolved_hosts(rec, def) {
        push(&h);
    }
    let token_url = match def.and_then(|d| d.auth.as_ref()) {
        Some(crate::service::AuthDef::Oauth2(o)) => o.token_url.clone(),
        Some(crate::service::AuthDef::Snaplii(_)) => {
            Some(crate::auth::snaplii::TOKEN_URL.to_string())
        }
        None => None,
    };
    if let Some(host) = token_url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
    {
        push(&host);
    }
    out
}

/// Apply-time: resolve each requested slot against the opened vault into
/// `(slot, canonical KEY, written?)`. A KEY is WRITTEN when the op's deposit
/// holds it; otherwise a NAMED slot's KEY must already exist, native
/// (case-folded to its stored casing) or in an external store, walking the
/// full store_order (a network probe on this ceremony path; an outage fails
/// the approve loudly). An IMPLICIT slot (an optional service role the op
/// left on its identity binding) binds its KEY only when it exists natively
/// and is otherwise left out; one that exists only in an external store is
/// refused, since it would bind without the card (computed at mint from
/// native names only) showing it. Every deposited KEY must be bound to some
/// slot.
pub(crate) async fn resolve_slots(
    view: &crate::storage::plaintext::VaultPlaintextView,
    requested: Vec<Requested>,
    deposited: &BTreeSet<String>,
) -> crate::error::Result<Vec<(String, String, bool)>> {
    use crate::error::AppError;
    for k in deposited {
        if !requested.iter().any(|r| r.key == *k) {
            return Err(AppError::BadRequest(format!(
                "deposited key '{}' is not bound to any slot of this connection",
                k
            )));
        }
    }
    let native: BTreeSet<String> = view.native_secrets.keys().cloned().collect();
    let mut slots = Vec::with_capacity(requested.len());
    for Requested {
        slot,
        key,
        implicit,
    } in requested
    {
        if deposited.contains(&key) {
            slots.push((slot, key, true));
            continue;
        }
        let canon = canonical_key(&key, &native);
        if native.contains(&canon) {
            slots.push((slot, canon, false));
            continue;
        }
        let external = view.resolve_value_async(&canon).await?.is_some();
        match (implicit, external) {
            (false, true) => slots.push((slot, canon, false)),
            (false, false) => {
                return Err(AppError::BadRequest(format!(
                    "no such secret '{}' in the vault (checked native + external stores)",
                    key
                )))
            }
            (true, true) => {
                return Err(AppError::BadRequest(format!(
                    "slot '{}' was left unfilled, but an external store holds '{}', which this connection would then use; name it explicitly (`--from-secret {}={}`) so the approval shows it",
                    slot, canon, slot, canon
                )))
            }
            (true, false) => {} // optional role, unfilled
        }
    }
    Ok(slots)
}

/// The card for connection `id` (`service`, `hosts` as requested) binding
/// `slots` = `(slot, canonical KEY, written?)`, against the vault's current
/// `connections`, native key names, and service definitions (`defs`,
/// custom-first).
#[allow(clippy::too_many_arguments)]
pub(crate) fn card(
    id: &str,
    service: Option<&str>,
    def: Option<&ServiceDef>,
    hosts: &[String],
    slots: &[(String, String, bool)],
    connections: &BTreeMap<String, Connection>,
    native: &BTreeSet<String>,
    defs: &crate::service::ServiceDefs,
) -> Card {
    // The record as stored: its service and hosts are what the proxy anchors.
    let anchors = record(service, hosts, None, &[], None);
    let mut c = Card {
        destinations: destinations(&anchors, def),
        replaces: connections.contains_key(id),
        ..Default::default()
    };
    for (slot, key, written) in slots {
        if *written {
            c.written.insert(slot.clone(), key.clone());
            if native.contains(key) && !c.overwrites.contains(key) {
                c.overwrites.push(key.clone());
            }
        } else {
            c.referenced.insert(slot.clone(), key.clone());
        }
    }
    c.overwrites.sort();
    let claims = crate::storage::plaintext::connection_claims_in(connections, defs, id);
    let bound: BTreeSet<&String> = c.written.values().chain(c.referenced.values()).collect();
    for key in bound {
        let mut by: Vec<String> = claims
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .flat_map(|(_, ids)| ids.iter().cloned())
            .collect();
        by.sort();
        by.dedup();
        if !by.is_empty() {
            c.shared_with.insert(key.clone(), by);
        }
    }
    c
}

/// The service def a connection-add binds, custom-first (a per-vault
/// `aux.services` def wins, as at apply), else the compiled registry.
fn resolve_def(
    svc: &str,
    custom: Option<&ServiceDef>,
    reg: &crate::service::ServiceRegistry,
) -> Result<ServiceDef, String> {
    custom
        .cloned()
        .or_else(|| reg.get(svc).cloned())
        .ok_or_else(|| format!("unknown service '{}'", svc))
}

/// Mint-time: compute the card from the daemon's unlocked session state (the
/// connection snapshot and native key names, both rebuilt on every vault
/// change) and the value deposit's key names, and stamp it into the op scope.
pub(crate) fn stamp_at_mint(
    state: &crate::state::AppState,
    vault_id: &str,
    op: &mut crate::protocol::operation::Operation,
) -> Result<(), String> {
    let id = op.act.target.trim().to_string();
    if !crate::cli::conn::valid_conn_id(&id) {
        return Err(format!("'{}' is not a valid connection id", id));
    }
    if !(op.act.scope.is_object() || op.act.scope.is_null()) {
        return Err("op.act.scope must be a JSON object".into());
    }
    let scope = &op.act.scope;
    let service = scope
        .get("service")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let hosts: Vec<String> = scope
        .get("hosts")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let deposited: BTreeSet<String> = match scope.get("values_digest").and_then(|v| v.as_str()) {
        Some(d) => state
            .op_payload_keys(d)
            .ok_or("deposited values not found or expired; re-run the command")?
            .into_iter()
            .collect(),
        None => BTreeSet::new(),
    };
    let (connections, native, custom_defs, has_external) = {
        let states = state.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(crate::state::VaultState::Unlocked { cache, .. }) => (
                cache
                    .connections
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<_, _>>(),
                cache.native_keys.iter().cloned().collect::<BTreeSet<_>>(),
                cache.custom_services.clone(),
                !cache.external_store_order.is_empty(),
            ),
            _ => return Err(crate::error::VAULT_LOCKED_MSG.to_string()),
        }
    };
    let custom = service.as_deref().and_then(|s| custom_defs.get(s));
    let def = match &service {
        Some(svc) => Some(resolve_def(svc, custom, &state.services)?),
        None => None,
    };
    let requested = requested_slots(scope, def.as_ref())?;
    // Same rule as apply (`resolve_slots`): every deposited KEY fills a slot.
    for k in &deposited {
        if !requested.iter().any(|r| r.key == *k) {
            return Err(format!(
                "deposited key '{}' is not bound to any slot of this connection",
                k
            ));
        }
    }
    let mut slots: Vec<(String, String, bool)> = Vec::new();
    for r in requested {
        if deposited.contains(&r.key) {
            slots.push((r.slot, r.key, true));
            continue;
        }
        let canon = canonical_key(&r.key, &native);
        if native.contains(&canon) {
            slots.push((r.slot, canon, false));
        } else if r.implicit {
            // An optional role left unfilled (apply refuses if an external
            // store turns out to hold its identity KEY).
        } else if !has_external {
            // Refuse before anyone is asked to approve when a named key can't
            // exist: no native match and no external store that could hold
            // it. With an external store configured, apply checks it
            // (network) instead.
            return Err(format!("no such secret '{}' in the vault", r.key));
        } else {
            slots.push((r.slot, canon, false));
        }
    }
    let c = card(
        &id,
        service.as_deref(),
        def.as_ref(),
        &hosts,
        &slots,
        &connections,
        &native,
        &crate::service::ServiceDefs {
            reg: &state.services,
            custom: &custom_defs,
        },
    );
    c.stamp(&mut op.act.scope)
}

/// Apply-time: the signed card must equal the card recomputed from the opened
/// vault. `Err` names the first field that differs.
pub(crate) fn assert_card(scope: &Value, actual: &Card) -> Result<(), String> {
    let signed = Card::from_scope(scope)?;
    let field = if signed.written != actual.written {
        "written"
    } else if signed.referenced != actual.referenced {
        "referenced"
    } else if signed.overwrites != actual.overwrites {
        "overwrites"
    } else if signed.destinations != actual.destinations {
        "destinations"
    } else if signed.shared_with != actual.shared_with {
        "shared_with"
    } else if signed.replaces != actual.replaces {
        "replaces"
    } else {
        return Ok(());
    };
    Err(format!(
        "the vault changed since this connection request was made (`{}` differs from what was approved); re-run the command",
        field
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> crate::service::ServiceRegistry {
        crate::service::ServiceRegistry::load()
    }

    fn conn_raw(keys: &[&str]) -> Connection {
        Connection {
            name: None,
            service: None,
            hosts: Some(vec!["api.example.com".into()]),
            secrets: Some(keys.iter().map(|k| k.to_string()).collect()),
            keys: None,
            written: None,
        }
    }

    fn conn_svc(service: &str, keys: &[(&str, &str)]) -> Connection {
        Connection {
            name: None,
            service: Some(service.into()),
            hosts: None,
            secrets: None,
            keys: if keys.is_empty() {
                None
            } else {
                Some(
                    keys.iter()
                        .map(|(r, k)| (r.to_string(), k.to_string()))
                        .collect(),
                )
            },
            written: None,
        }
    }

    #[test]
    fn service_slots_cover_every_declared_role() {
        let r = reg();
        let cf = r.get("cloudflare").unwrap();
        let scope = json!({
            "service": "cloudflare",
            "keys": { "cloudflare_api_token": "CF_TOKEN_WORK" },
        });
        let slots = requested_slots(&scope, Some(cf)).unwrap();
        assert_eq!(
            slots,
            vec![
                req("CLOUDFLARE_API_TOKEN", "CF_TOKEN_WORK", false),
                // Not named by the op: optional, on its identity binding.
                req("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID", true),
            ]
        );
        // A role whose identity KEY the op lists in `secrets` is named.
        let scope = json!({
            "service": "cloudflare",
            "secrets": ["cloudflare_account_id"],
        });
        let slots = requested_slots(&scope, Some(cf)).unwrap();
        assert!(slots[0].implicit && !slots[1].implicit, "{slots:?}");
        // An undeclared role in `keys` is refused with the service's roles.
        let bad = json!({ "service": "cloudflare", "keys": { "NOPE": "X" } });
        let e = requested_slots(&bad, Some(cf)).unwrap_err();
        assert!(
            e.contains("not a secret declared by service 'cloudflare'"),
            "{e}"
        );
        assert!(e.contains("CLOUDFLARE_API_TOKEN"), "{e}");
        // A `secrets` entry that fills no slot is refused: the op names only
        // keys the connection binds.
        let stray = json!({
            "service": "cloudflare",
            "secrets": ["CF_TOKEN_WORK", "SOMETHING_ELSE"],
            "keys": { "CLOUDFLARE_API_TOKEN": "CF_TOKEN_WORK" },
        });
        let e = requested_slots(&stray, Some(cf)).unwrap_err();
        assert!(
            e.contains("'SOMETHING_ELSE' is not bound to any secret of service 'cloudflare'"),
            "{e}"
        );
        // Bound through `keys` (any case) or the identity binding: fine.
        let ok = json!({
            "service": "cloudflare",
            "secrets": ["cf_token_work", "CLOUDFLARE_ACCOUNT_ID"],
            "keys": { "CLOUDFLARE_API_TOKEN": "CF_TOKEN_WORK" },
        });
        assert!(requested_slots(&ok, Some(cf)).is_ok());
    }

    fn req(slot: &str, key: &str, implicit: bool) -> Requested {
        Requested {
            slot: slot.into(),
            key: key.into(),
            implicit,
        }
    }

    #[test]
    fn raw_slots_are_the_keys() {
        let scope = json!({ "secrets": ["A_KEY", "B_KEY", "A_KEY"] });
        assert_eq!(
            requested_slots(&scope, None).unwrap(),
            vec![req("A_KEY", "A_KEY", false), req("B_KEY", "B_KEY", false)]
        );
    }

    fn no_custom() -> std::collections::HashMap<String, ServiceDef> {
        std::collections::HashMap::new()
    }

    /// The destinations are exactly the hosts the proxy anchors the stored
    /// record to (`resolved_hosts`), plus a minted mechanism's token host.
    #[test]
    fn destinations_are_the_anchored_hosts_and_the_token_endpoint() {
        let r = reg();
        let at = |service: Option<&str>, def: Option<&ServiceDef>, hosts: &[&str]| {
            let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
            let rec = record(service, &hosts, None, &[], None);
            let d = destinations(&rec, def);
            let lower = |v: Vec<String>| -> BTreeSet<String> {
                v.into_iter().map(|h| h.to_ascii_lowercase()).collect()
            };
            assert_eq!(
                lower(
                    d.iter()
                        .filter(|h| !h.eq_ignore_ascii_case("auth.openai.com"))
                        .cloned()
                        .collect()
                ),
                lower(crate::core::host::resolved_hosts(&rec, def)),
                "the card lists what the proxy anchors"
            );
            d
        };
        let codex = r.get("openai_codex").unwrap();
        assert_eq!(
            at(Some("openai_codex"), Some(codex), &[]),
            vec!["chatgpt.com", "api.openai.com", "auth.openai.com"]
        );
        // A pin adds to the service's exact hosts; it never replaces them,
        // because the proxy anchors both.
        assert_eq!(
            at(Some("openai_codex"), Some(codex), &["chatgpt.com"]),
            vec!["chatgpt.com", "api.openai.com", "auth.openai.com"]
        );
        let mixed: ServiceDef = crate::service::gate::admit_toml(
            r#"
[service]
id = "mixed"
name = "Mixed"
hosts = ["api.x.example", "*.x.example"]
secrets = ["MIXED_KEY"]
"#,
        )
        .unwrap();
        assert_eq!(
            at(Some("mixed"), Some(&mixed), &["eu.x.example"]),
            vec!["api.x.example", "eu.x.example"]
        );
        // A wildcard is never anchored, so it is never listed: with no pin,
        // a wildcard-only service sends nowhere.
        let alchemy = r.get("alchemy").unwrap();
        assert!(at(Some("alchemy"), Some(alchemy), &[]).is_empty());
        assert_eq!(
            at(
                Some("alchemy"),
                Some(alchemy),
                &["eth-mainnet.g.alchemy.com"]
            ),
            vec!["eth-mainnet.g.alchemy.com"]
        );
        // Static service: its hosts only. Raw: its anchors.
        let gh = r.get("github").unwrap();
        assert_eq!(at(Some("github"), Some(gh), &[]), gh.service.hosts);
        assert_eq!(
            at(None, None, &["a.example.com", "A.example.com"]),
            vec!["a.example.com"]
        );
    }

    #[test]
    fn card_splits_written_referenced_and_finds_sharing() {
        let r = reg();
        let codex = r.get("openai_codex").unwrap();
        let mut conns = BTreeMap::new();
        conns.insert(
            "acct_a".to_string(),
            conn_raw(&["HEJIA_OAI_REFRESH_TOKEN_X"]),
        );
        conns.insert(
            "codex_y".to_string(),
            conn_svc(
                "openai_codex",
                &[("OPENAI_CODEX_REFRESH_TOKEN", "HEJIA_OAI_REFRESH_TOKEN_X")],
            ),
        );
        conns.insert("codex_x".to_string(), conn_svc("openai_codex", &[]));
        let native: BTreeSet<String> = ["HEJIA_OAI_REFRESH_TOKEN_X".to_string()].into();
        let slots = vec![(
            "OPENAI_CODEX_REFRESH_TOKEN".to_string(),
            "HEJIA_OAI_REFRESH_TOKEN_X".to_string(),
            false,
        )];
        let custom = no_custom();
        let defs = crate::service::ServiceDefs {
            reg: &r,
            custom: &custom,
        };
        let c = card(
            "codex_x",
            Some("openai_codex"),
            Some(codex),
            &[],
            &slots,
            &conns,
            &native,
            &defs,
        );
        assert!(c.written.is_empty());
        assert_eq!(
            c.referenced
                .get("OPENAI_CODEX_REFRESH_TOKEN")
                .map(String::as_str),
            Some("HEJIA_OAI_REFRESH_TOKEN_X")
        );
        assert_eq!(
            c.shared_with.get("HEJIA_OAI_REFRESH_TOKEN_X"),
            Some(&vec!["acct_a".to_string(), "codex_y".to_string()]),
            "every other connection bound to the key, never the target itself"
        );
        assert!(c.replaces, "codex_x already exists");
        assert!(c.overwrites.is_empty());

        // A written key that already holds a value is an overwrite.
        let slots = vec![("GITHUB_TOKEN".to_string(), "GITHUB_TOKEN".to_string(), true)];
        let native: BTreeSet<String> = ["GITHUB_TOKEN".to_string()].into();
        let c = card(
            "github",
            Some("github"),
            r.get("github"),
            &[],
            &slots,
            &BTreeMap::new(),
            &native,
            &defs,
        );
        assert_eq!(c.written.len(), 1);
        assert_eq!(c.overwrites, vec!["GITHUB_TOKEN".to_string()]);
        assert!(!c.replaces);
        assert!(
            c.shared_with.is_empty(),
            "the default connection being written is not shared with itself"
        );

        // Binding the same key from another connection: github's default
        // connection (no record of its own) can use it, so it is shared.
        let c = card(
            "github_work",
            Some("github"),
            r.get("github"),
            &[],
            &slots,
            &BTreeMap::new(),
            &native,
            &defs,
        );
        assert_eq!(
            c.shared_with.get("GITHUB_TOKEN"),
            Some(&vec!["github".to_string()])
        );
    }

    #[test]
    fn card_round_trips_and_assert_names_the_field() {
        let mut c = Card::default();
        c.written.insert("A".into(), "A".into());
        c.referenced.insert("B".into(), "OLD_B".into());
        c.destinations = vec!["h.example.com".into()];
        c.shared_with.insert("OLD_B".into(), vec!["other".into()]);
        let mut scope = json!({ "service": null, "written": { "forged": "X" } });
        c.stamp(&mut scope).unwrap();
        // A null scope becomes the card; any other non-object is refused,
        // never a panic.
        let mut null = Value::Null;
        c.stamp(&mut null).unwrap();
        assert_eq!(Card::from_scope(&null).unwrap(), c);
        for mut bad in [json!([1]), json!("s"), json!(3)] {
            assert!(c.stamp(&mut bad).is_err());
        }
        assert_eq!(
            Card::from_scope(&scope).unwrap(),
            c,
            "stamp overwrites requester fields"
        );
        assert!(assert_card(&scope, &c).is_ok());
        let mut changed = c.clone();
        changed
            .shared_with
            .insert("OLD_B".into(), vec!["other".into(), "new".into()]);
        let e = assert_card(&scope, &changed).unwrap_err();
        assert!(e.contains("shared_with"), "{e}");
        // A scope without the card (requester skipped mint) is refused.
        assert!(assert_card(&json!({}), &c).is_err());
    }

    fn test_state() -> crate::state::AppState {
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-connadd-{}",
                std::process::id()
            )),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            relying_party: crate::passkey::webauthn::RelyingParty::exact(
                "http://localhost",
                "localhost",
            ),
            admin_key: None,
            relay_url: None,
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        crate::state::AppState::new(cfg)
    }

    fn unlock(state: &crate::state::AppState, conns: &[(&str, Connection)], native: &[&str]) {
        let mut cache = crate::state::SecretsCache::default();
        for (id, c) in conns {
            cache.connections.insert(id.to_string(), c.clone());
        }
        for k in native {
            cache.native_keys.insert(k.to_string());
        }
        state.unlock_vault("v1".into(), cache, zeroize::Zeroizing::new(Vec::new()));
    }

    fn add_op(target: &str, scope: Value) -> crate::protocol::operation::Operation {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        Operation {
            act: Act {
                kind: ActType::Custom("connection-add".into()),
                target: target.into(),
                scope,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    /// The agent-proposed reference: the daemon stamps the card from its own
    /// session state (canonical key, every destination, sharing), replacing
    /// whatever the requester put in those fields.
    #[test]
    fn mint_stamps_reference_card_over_requester_fields() {
        let state = test_state();
        unlock(
            &state,
            &[("acct_a", conn_raw(&["HEJIA_OAI_REFRESH_TOKEN_X"]))],
            &["HEJIA_OAI_REFRESH_TOKEN_X"],
        );
        let mut op = add_op(
            "codex_x",
            json!({
                "service": "openai_codex",
                "secrets": ["hejia_oai_refresh_token_x"],
                "keys": { "OPENAI_CODEX_REFRESH_TOKEN": "hejia_oai_refresh_token_x" },
                "written": { "X": "Y" },
                "destinations": ["example.org"],
                "shared_with": {},
                "replaces": true,
            }),
        );
        stamp_at_mint(&state, "v1", &mut op).unwrap();
        let c = Card::from_scope(&op.act.scope).unwrap();
        assert!(c.written.is_empty());
        assert_eq!(
            c.referenced,
            BTreeMap::from([(
                "OPENAI_CODEX_REFRESH_TOKEN".to_string(),
                "HEJIA_OAI_REFRESH_TOKEN_X".to_string()
            )])
        );
        assert_eq!(
            c.destinations,
            vec!["chatgpt.com", "api.openai.com", "auth.openai.com"]
        );
        assert_eq!(
            c.shared_with.get("HEJIA_OAI_REFRESH_TOKEN_X"),
            Some(&vec!["acct_a".to_string()])
        );
        assert!(!c.replaces);
    }

    /// New values are read from the deposit's KEY names without consuming it
    /// (apply still takes it), and an existing key is flagged as overwritten.
    #[test]
    fn mint_reads_deposit_keys_without_consuming() {
        let state = test_state();
        unlock(&state, &[], &["GITHUB_TOKEN_WORK"]);
        let values =
            std::collections::BTreeMap::from([("GITHUB_TOKEN_WORK".to_string(), "v".to_string())]);
        let d = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(60))
            .unwrap();
        let mut op = add_op(
            "github_work",
            json!({
                "service": "github",
                "secrets": ["GITHUB_TOKEN_WORK"],
                "keys": { "GITHUB_TOKEN": "GITHUB_TOKEN_WORK" },
                "values_digest": d,
            }),
        );
        stamp_at_mint(&state, "v1", &mut op).unwrap();
        let c = Card::from_scope(&op.act.scope).unwrap();
        assert_eq!(
            c.written,
            BTreeMap::from([("GITHUB_TOKEN".to_string(), "GITHUB_TOKEN_WORK".to_string())])
        );
        assert_eq!(c.overwrites, vec!["GITHUB_TOKEN_WORK".to_string()]);
        assert_eq!(
            state.op_payload_take(&d),
            Some(values),
            "deposit still there"
        );
    }

    #[test]
    fn mint_refuses_a_reference_that_cannot_exist() {
        let state = test_state();
        unlock(&state, &[], &["SOMETHING_ELSE"]);
        let mut op = add_op(
            "myapi",
            json!({ "hosts": ["api.example.com"], "secrets": ["MISSING_KEY"] }),
        );
        let e = stamp_at_mint(&state, "v1", &mut op).unwrap_err();
        assert!(e.contains("no such secret 'MISSING_KEY'"), "{e}");
        // Unknown service and a locked vault are refused before any approval.
        let mut op = add_op("x", json!({ "service": "nope_svc" }));
        assert!(stamp_at_mint(&state, "v1", &mut op)
            .unwrap_err()
            .contains("unknown service"));
        let mut op = add_op("x", json!({ "hosts": ["h.example.com"], "secrets": ["K"] }));
        assert!(stamp_at_mint(&state, "v-locked", &mut op).is_err());
    }

    /// A scope that is not an object (or null) is refused, never indexed.
    #[test]
    fn mint_refuses_a_non_object_scope() {
        let state = test_state();
        unlock(&state, &[], &["K"]);
        for scope in [json!(["K"]), json!("K"), json!(1)] {
            let mut op = add_op("myapi", scope);
            let e = stamp_at_mint(&state, "v1", &mut op).unwrap_err();
            assert!(e.contains("must be a JSON object"), "{e}");
        }
    }

    /// The op names only keys the connection binds: a stray `secrets` entry
    /// or a deposited value no slot takes is refused before anyone is asked.
    #[test]
    fn mint_refuses_keys_no_slot_binds() {
        let state = test_state();
        unlock(&state, &[], &["CF_TOKEN_WORK", "OTHER_KEY"]);
        let mut op = add_op(
            "cloudflare_work",
            json!({
                "service": "cloudflare",
                "secrets": ["CF_TOKEN_WORK", "OTHER_KEY"],
                "keys": { "CLOUDFLARE_API_TOKEN": "CF_TOKEN_WORK" },
            }),
        );
        let e = stamp_at_mint(&state, "v1", &mut op).unwrap_err();
        assert!(e.contains("'OTHER_KEY' is not bound"), "{e}");

        let d = state
            .op_payload_insert(
                std::collections::BTreeMap::from([("LOOSE_KEY".to_string(), "v".to_string())]),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        let mut op = add_op(
            "cloudflare_work",
            json!({
                "service": "cloudflare",
                "keys": { "CLOUDFLARE_API_TOKEN": "CF_TOKEN_WORK" },
                "values_digest": d,
            }),
        );
        let e = stamp_at_mint(&state, "v1", &mut op).unwrap_err();
        assert!(e.contains("'LOOSE_KEY' is not bound to any slot"), "{e}");
    }

    fn view_with(native: &[&str]) -> crate::storage::plaintext::VaultPlaintextView {
        let mut m = sudp::state::ProtectedState::new();
        m.aux = serde_json::to_value(crate::storage::plaintext::VaultAux::initial()).unwrap();
        let mut v =
            crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m).unwrap();
        for k in native {
            v.native_secrets.insert(k.to_string(), b"x".to_vec());
        }
        v
    }

    /// Apply resolves raw and service slots alike: deposited → written, an
    /// existing key → referenced in its stored casing, a missing key → the
    /// loud "no such secret" refusal, an unbound deposit → refused.
    #[tokio::test]
    async fn apply_resolves_slots_against_the_vault() {
        let view = view_with(&["GITHUB_TOKEN", "OLD_REFRESH"]);
        let deposited: BTreeSet<String> = ["NEW_KEY".to_string()].into();
        let slots = resolve_slots(
            &view,
            vec![
                req("R1", "old_refresh", false),
                req("R2", "NEW_KEY", false),
                req("R3", "GITHUB_TOKEN", false),
            ],
            &deposited,
        )
        .await
        .unwrap();
        assert_eq!(
            slots,
            vec![
                ("R1".to_string(), "OLD_REFRESH".to_string(), false),
                ("R2".to_string(), "NEW_KEY".to_string(), true),
                ("R3".to_string(), "GITHUB_TOKEN".to_string(), false),
            ]
        );
        let e = resolve_slots(&view, vec![req("R", "TYPO_KEY", false)], &BTreeSet::new())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no such secret 'TYPO_KEY'"), "{e}");
        let e = resolve_slots(&view, vec![req("R", "GITHUB_TOKEN", false)], &deposited)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not bound to any slot"), "{e}");
    }

    /// An optional role the op left unnamed binds its identity KEY only when
    /// the vault holds it natively; otherwise it is simply left out.
    #[tokio::test]
    async fn apply_leaves_an_absent_optional_role_unfilled() {
        let view = view_with(&["CF_TOKEN"]);
        let slots = resolve_slots(
            &view,
            vec![
                req("CLOUDFLARE_API_TOKEN", "CF_TOKEN", false),
                req("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID", true),
            ],
            &BTreeSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            slots,
            vec![(
                "CLOUDFLARE_API_TOKEN".to_string(),
                "CF_TOKEN".to_string(),
                false
            )]
        );
        let view = view_with(&["CF_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]);
        let slots = resolve_slots(
            &view,
            vec![req("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", true)],
            &BTreeSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            slots,
            vec![(
                "CLOUDFLARE_ACCOUNT_ID".to_string(),
                "CLOUDFLARE_ACCOUNT_ID".to_string(),
                false
            )],
            "present natively: bound, and so on the card"
        );
    }

    /// Mint: a service connection that fills only its primary role is
    /// accepted (no "no such secret" for the optional role), and the card
    /// shows only what binds.
    #[test]
    fn mint_accepts_an_unfilled_optional_role() {
        let state = test_state();
        unlock(&state, &[], &["CF_TOKEN_WORK"]);
        let mut op = add_op(
            "cloudflare_work",
            json!({
                "service": "cloudflare",
                "secrets": ["CF_TOKEN_WORK"],
                "keys": { "CLOUDFLARE_API_TOKEN": "CF_TOKEN_WORK" },
            }),
        );
        stamp_at_mint(&state, "v1", &mut op).unwrap();
        let c = Card::from_scope(&op.act.scope).unwrap();
        assert_eq!(
            c.referenced,
            BTreeMap::from([(
                "CLOUDFLARE_API_TOKEN".to_string(),
                "CF_TOKEN_WORK".to_string()
            )])
        );
        assert!(c.written.is_empty());
        // A NAMED key that cannot exist is still refused.
        let mut op = add_op(
            "cloudflare_work",
            json!({
                "service": "cloudflare",
                "secrets": ["CF_TOKEN_WORK", "CF_ACCT_TYPO"],
                "keys": {
                    "CLOUDFLARE_API_TOKEN": "CF_TOKEN_WORK",
                    "CLOUDFLARE_ACCOUNT_ID": "CF_ACCT_TYPO",
                },
            }),
        );
        let e = stamp_at_mint(&state, "v1", &mut op).unwrap_err();
        assert!(e.contains("no such secret 'CF_ACCT_TYPO'"), "{e}");
    }

    /// Provenance: a deposited KEY is written, a referenced one is not, and a
    /// same-id record being replaced hands over only keys it wrote that the
    /// new record still binds.
    #[test]
    fn written_keys_track_what_this_connection_wrote() {
        let slots = vec![
            ("A".to_string(), "NEW_A".to_string(), true),
            ("B".to_string(), "OLD_B".to_string(), false),
            ("C".to_string(), "OWN_C".to_string(), false),
        ];
        assert_eq!(written_keys(&slots, None), vec!["NEW_A".to_string()]);
        let prev = Connection {
            written: Some(vec!["OWN_C".into(), "GONE".into()]),
            ..Connection::default()
        };
        assert_eq!(
            written_keys(&slots, Some(&prev)),
            vec!["NEW_A".to_string(), "OWN_C".to_string()]
        );
        let legacy = Connection::default();
        assert_eq!(
            written_keys(&slots, Some(&legacy)),
            vec!["NEW_A".to_string()]
        );
    }

    /// The design's acceptance (4) end to end over the apply code: a service
    /// connection BOUND to an existing refresh token, then removed, leaves
    /// that token in the vault; a connection that WROTE its key takes it with
    /// it; a pre-tracking record keeps everything.
    #[tokio::test]
    async fn rm_keeps_a_bound_key_and_deletes_a_written_one() {
        let r = reg();
        let mut view = view_with(&["HEJIA_OAI_REFRESH_TOKEN_X"]);
        // Add codex_x bound to the existing token (no deposit).
        let codex = r.get("openai_codex").unwrap();
        let scope = json!({
            "service": "openai_codex",
            "secrets": ["HEJIA_OAI_REFRESH_TOKEN_X"],
            "keys": { "OPENAI_CODEX_REFRESH_TOKEN": "HEJIA_OAI_REFRESH_TOKEN_X" },
        });
        let slots = resolve_slots(
            &view,
            requested_slots(&scope, Some(codex)).unwrap(),
            &BTreeSet::new(),
        )
        .await
        .unwrap();
        let keys: BTreeMap<String, String> = BTreeMap::from([(
            "OPENAI_CODEX_REFRESH_TOKEN".to_string(),
            "HEJIA_OAI_REFRESH_TOKEN_X".to_string(),
        )]);
        let rec = record(Some("openai_codex"), &[], Some(&keys), &slots, None);
        assert_eq!(rec.written, Some(vec![]));
        view.aux.connections.insert("codex_x".into(), rec);

        // Add github_work writing a new value.
        let gh = r.get("github").unwrap();
        let scope = json!({
            "service": "github",
            "secrets": ["GITHUB_TOKEN_WORK"],
            "keys": { "GITHUB_TOKEN": "GITHUB_TOKEN_WORK" },
        });
        let deposited: BTreeSet<String> = ["GITHUB_TOKEN_WORK".to_string()].into();
        let slots = resolve_slots(
            &view,
            requested_slots(&scope, Some(gh)).unwrap(),
            &deposited,
        )
        .await
        .unwrap();
        let keys = BTreeMap::from([("GITHUB_TOKEN".to_string(), "GITHUB_TOKEN_WORK".to_string())]);
        let rec = record(Some("github"), &[], Some(&keys), &slots, None);
        assert_eq!(rec.written, Some(vec!["GITHUB_TOKEN_WORK".to_string()]));
        view.native_secrets
            .insert("GITHUB_TOKEN_WORK".into(), b"ghp".to_vec());
        view.aux.connections.insert("github_work".into(), rec);

        // A record from before write tracking, bound to its own key.
        view.native_secrets
            .insert("LEGACY_KEY".into(), b"l".to_vec());
        view.aux
            .connections
            .insert("legacy".into(), conn_raw(&["LEGACY_KEY"]));

        let rm = crate::server::handlers::approve::apply_connection_rm_to_view;
        let (removed, plan) = rm(&mut view, "codex_x", false, &r).unwrap();
        assert!(removed.is_empty());
        assert_eq!(
            plan.referenced,
            vec!["HEJIA_OAI_REFRESH_TOKEN_X".to_string()]
        );
        assert!(view
            .native_secrets
            .contains_key("HEJIA_OAI_REFRESH_TOKEN_X"));
        assert!(!view.aux.connections.contains_key("codex_x"));

        let (removed, _) = rm(&mut view, "github_work", false, &r).unwrap();
        assert_eq!(removed, vec!["GITHUB_TOKEN_WORK".to_string()]);
        assert!(!view.native_secrets.contains_key("GITHUB_TOKEN_WORK"));

        let (removed, plan) = rm(&mut view, "legacy", false, &r).unwrap();
        assert!(removed.is_empty());
        assert_eq!(plan.untracked, vec!["LEGACY_KEY".to_string()]);
        assert!(view.native_secrets.contains_key("LEGACY_KEY"));
    }

    #[test]
    fn canonical_key_folds_native_case_only() {
        let native: BTreeSet<String> = ["GITHUB_TOKEN".to_string()].into();
        assert_eq!(canonical_key("github_token", &native), "GITHUB_TOKEN");
        assert_eq!(canonical_key("xh-gcp-test", &native), "xh-gcp-test");
    }
}
