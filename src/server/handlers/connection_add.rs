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
//!   them, are sent to: the connection's hosts (raw anchors, service pins, or
//!   the service's declared hosts) plus a minted mechanism's token endpoint.
//! - `shared_with`: KEY → other existing connections already bound to it.
//! - `replaces`: a connection with this id already exists and is replaced.
//!
//! A slot is a service's declared secret role, or for a raw connection the
//! KEY itself.

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
    /// values of these fields).
    pub fn stamp(&self, scope: &mut Value) {
        scope["written"] = json!(self.written);
        scope["referenced"] = json!(self.referenced);
        scope["overwrites"] = json!(self.overwrites);
        scope["destinations"] = json!(self.destinations);
        scope["shared_with"] = json!(self.shared_with);
        scope["replaces"] = json!(self.replaces);
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

/// The connection's slots and the KEY each binds, as the op REQUESTS them
/// (before native case-folding). A raw connection's slots are its `secrets`
/// list (slot = KEY); a service connection binds EVERY declared role, through
/// the op's `keys` map (role matched case-insensitively) or, absent an entry,
/// the role's own name (the identity binding `secret_key_for` applies).
pub(crate) fn requested_slots(
    scope: &Value,
    def: Option<&ServiceDef>,
) -> Result<Vec<(String, String)>, String> {
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
                .map(|k| (k.clone(), k))
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
            Ok(roles
                .iter()
                .map(|role| {
                    let key = keys
                        .iter()
                        .find(|(r, _)| r.eq_ignore_ascii_case(role))
                        .map(|(_, k)| k.clone())
                        .unwrap_or_else(|| role.clone());
                    (role.clone(), key)
                })
                .collect())
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

/// Every host the bound credentials (or tokens minted from them) reach.
pub(crate) fn destinations(def: Option<&ServiceDef>, hosts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: &str| {
        let h = h.trim();
        if !h.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(h)) {
            out.push(h.to_string());
        }
    };
    match def {
        None => hosts.iter().for_each(|h| push(h)),
        Some(def) => {
            if hosts.is_empty() {
                def.service.hosts.iter().for_each(|h| push(h));
            } else {
                hosts.iter().for_each(|h| push(h));
            }
            let token_url = match def.auth.as_ref() {
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
                let covered = out
                    .iter()
                    .any(|o| crate::core::host::wildcard_matches(o, &host));
                if !covered {
                    out.push(host);
                }
            }
        }
    }
    out
}

/// Apply-time: resolve each requested `(slot, KEY)` against the opened vault
/// into `(slot, canonical KEY, written?)`. A KEY is WRITTEN when the op's
/// deposit holds it; otherwise it must already exist, native (case-folded to
/// its stored casing) or in an external store, walking the full store_order
/// (a network probe on this ceremony path; an outage fails the approve
/// loudly). Every deposited KEY must be bound to some slot.
pub(crate) async fn resolve_slots(
    view: &crate::storage::plaintext::VaultPlaintextView,
    requested: Vec<(String, String)>,
    deposited: &BTreeSet<String>,
) -> crate::error::Result<Vec<(String, String, bool)>> {
    use crate::error::AppError;
    for k in deposited {
        if !requested.iter().any(|(_, key)| key == k) {
            return Err(AppError::BadRequest(format!(
                "deposited key '{}' is not bound to any slot of this connection",
                k
            )));
        }
    }
    let native: BTreeSet<String> = view.native_secrets.keys().cloned().collect();
    let mut slots = Vec::with_capacity(requested.len());
    for (slot, key) in requested {
        if deposited.contains(&key) {
            slots.push((slot, key, true));
            continue;
        }
        let canon = canonical_key(&key, &native);
        if !native.contains(&canon) && view.resolve_value_async(&canon).await?.is_none() {
            return Err(AppError::BadRequest(format!(
                "no such secret '{}' in the vault (checked native + external stores)",
                key
            )));
        }
        slots.push((slot, canon, false));
    }
    Ok(slots)
}

/// The card for connection `id` binding `slots` = `(slot, canonical KEY,
/// written?)`, against the vault's current `connections` and native key names.
pub(crate) fn card(
    id: &str,
    def: Option<&ServiceDef>,
    hosts: &[String],
    slots: &[(String, String, bool)],
    connections: &BTreeMap<String, Connection>,
    native: &BTreeSet<String>,
    reg: &crate::service::ServiceRegistry,
) -> Card {
    let mut c = Card {
        destinations: destinations(def, hosts),
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
    let claims = crate::storage::plaintext::connection_claims_in(connections, reg, id);
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
    let (connections, native, custom, has_external) = {
        let states = state.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(crate::state::VaultState::Unlocked { cache, .. }) => (
                cache
                    .connections
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<_, _>>(),
                cache.native_keys.iter().cloned().collect::<BTreeSet<_>>(),
                service
                    .as_deref()
                    .and_then(|s| cache.custom_services.get(s).cloned()),
                !cache.external_store_order.is_empty(),
            ),
            _ => return Err(crate::error::VAULT_LOCKED_MSG.to_string()),
        }
    };
    let def = match &service {
        Some(svc) => Some(resolve_def(svc, custom.as_ref(), &state.services)?),
        None => None,
    };
    let slots: Vec<(String, String, bool)> = requested_slots(scope, def.as_ref())?
        .into_iter()
        .map(|(slot, key)| {
            if deposited.contains(&key) {
                (slot, key, true)
            } else {
                (slot, canonical_key(&key, &native), false)
            }
        })
        .collect();
    // Refuse before anyone is asked to approve when a referenced key can't
    // exist: no native match and no external store that could hold it. With
    // an external store configured, apply checks it (network) instead.
    if !has_external {
        if let Some((_, key, _)) = slots
            .iter()
            .find(|(_, k, written)| !written && !native.contains(k))
        {
            return Err(format!("no such secret '{}' in the vault", key));
        }
    }
    let c = card(
        &id,
        def.as_ref(),
        &hosts,
        &slots,
        &connections,
        &native,
        &state.services,
    );
    c.stamp(&mut op.act.scope);
    Ok(())
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
                ("CLOUDFLARE_API_TOKEN".into(), "CF_TOKEN_WORK".into()),
                (
                    "CLOUDFLARE_ACCOUNT_ID".into(),
                    "CLOUDFLARE_ACCOUNT_ID".into()
                ),
            ]
        );
        // An undeclared role in `keys` is refused with the service's roles.
        let bad = json!({ "service": "cloudflare", "keys": { "NOPE": "X" } });
        let e = requested_slots(&bad, Some(cf)).unwrap_err();
        assert!(
            e.contains("not a secret declared by service 'cloudflare'"),
            "{e}"
        );
        assert!(e.contains("CLOUDFLARE_API_TOKEN"), "{e}");
    }

    #[test]
    fn raw_slots_are_the_keys() {
        let scope = json!({ "secrets": ["A_KEY", "B_KEY", "A_KEY"] });
        assert_eq!(
            requested_slots(&scope, None).unwrap(),
            vec![
                ("A_KEY".into(), "A_KEY".into()),
                ("B_KEY".into(), "B_KEY".into())
            ]
        );
    }

    #[test]
    fn destinations_include_the_token_endpoint() {
        let r = reg();
        let codex = r.get("openai_codex").unwrap();
        assert_eq!(
            destinations(Some(codex), &[]),
            vec!["chatgpt.com", "api.openai.com", "auth.openai.com"]
        );
        // Pins replace the API hosts; the token endpoint still applies.
        assert_eq!(
            destinations(Some(codex), &["chatgpt.com".into()]),
            vec!["chatgpt.com", "auth.openai.com"]
        );
        // Static service: its hosts only. Raw: its anchors.
        let gh = r.get("github").unwrap();
        assert_eq!(destinations(Some(gh), &[]), gh.service.hosts);
        assert_eq!(
            destinations(None, &["a.example.com".into(), "A.example.com".into()]),
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
        let c = card("codex_x", Some(codex), &[], &slots, &conns, &native, &r);
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
            r.get("github"),
            &[],
            &slots,
            &BTreeMap::new(),
            &native,
            &r,
        );
        assert_eq!(c.written.len(), 1);
        assert_eq!(c.overwrites, vec!["GITHUB_TOKEN".to_string()]);
        assert!(!c.replaces);
        assert!(c.shared_with.is_empty());
    }

    #[test]
    fn card_round_trips_and_assert_names_the_field() {
        let mut c = Card::default();
        c.written.insert("A".into(), "A".into());
        c.referenced.insert("B".into(), "OLD_B".into());
        c.destinations = vec!["h.example.com".into()];
        c.shared_with.insert("OLD_B".into(), vec!["other".into()]);
        let mut scope = json!({ "service": null, "written": { "forged": "X" } });
        c.stamp(&mut scope);
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
            rp_id: "localhost".into(),
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
                ("R1".into(), "old_refresh".into()),
                ("R2".into(), "NEW_KEY".into()),
                ("R3".into(), "GITHUB_TOKEN".into()),
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
        let e = resolve_slots(
            &view,
            vec![("R".into(), "TYPO_KEY".into())],
            &BTreeSet::new(),
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("no such secret 'TYPO_KEY'"), "{e}");
        let e = resolve_slots(&view, vec![("R".into(), "GITHUB_TOKEN".into())], &deposited)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not bound to any slot"), "{e}");
    }

    #[test]
    fn canonical_key_folds_native_case_only() {
        let native: BTreeSet<String> = ["GITHUB_TOKEN".to_string()].into();
        assert_eq!(canonical_key("github_token", &native), "GITHUB_TOKEN");
        assert_eq!(canonical_key("xh-gcp-test", &native), "xh-gcp-test");
    }
}
