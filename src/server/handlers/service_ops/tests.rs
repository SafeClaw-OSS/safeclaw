use super::*;
use crate::crypto::vault_key::UikRoot;
use crate::service::source::tests::tar_gz;
use crate::storage::plaintext::{MemberRole, VaultAux, VaultPlaintextView};
use crate::storage::sealed_vault::PerItemVault;

/// GitHub as the tests see it: serves `tarball`, or is out of reach.
struct Gh(Option<Vec<u8>>);

impl GitHubApi for Gh {
    async fn default_branch(&self, _o: &str, _r: &str) -> std::result::Result<String, String> {
        Err("offline".into())
    }
    async fn commit_of(&self, _o: &str, _r: &str, _g: &str) -> std::result::Result<String, String> {
        Err("offline".into())
    }
    async fn tarball(&self, _o: &str, _r: &str, _c: &str) -> std::result::Result<Vec<u8>, String> {
        self.0.clone().ok_or_else(|| "offline".to_string())
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn svc(id: &str, host: &str) -> String {
    format!(
        "[service]\nid = \"{}\"\nname = \"{}\"\nhosts = [\"{}\"]\nsecrets = [\"TOKEN\"]\n",
        id, id, host
    )
}

fn gh(commit: char) -> ServiceSource {
    ServiceSource::Github {
        repo: "acme/tools".into(),
        path: None,
        git_ref: None,
        commit: commit.to_string().repeat(40),
    }
}

fn scope(defs: &[(&str, &str)], source: &ServiceSource, update: bool) -> Value {
    let definitions: serde_json::Map<String, Value> = defs
        .iter()
        .map(|(id, host)| ((*id).to_string(), json!({ "service": svc(id, host) })))
        .collect();
    json!({ "definitions": definitions, "source": source, "update": update })
}

fn empty_view() -> VaultPlaintextView {
    let mut m = sudp::state::ProtectedState::new();
    m.aux = serde_json::to_value(VaultAux::initial()).unwrap();
    VaultPlaintextView::from_protected_state(&m).unwrap()
}

fn copy(v: &VaultPlaintextView) -> VaultPlaintextView {
    let mut n = empty_view();
    n.aux = v.aux.clone();
    n
}

fn test_state() -> AppState {
    let cfg = crate::config::Config {
        state_dir: std::path::PathBuf::from(format!(
            "/tmp/safeclaw-test-service-ops-{}",
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
    AppState::new(cfg)
}

/// Mint (stamp) then apply, the way an approved op flows. GitHub is out of
/// reach here unless `gh` serves a tarball.
fn mint_with(state: &AppState, scope: Value, gh: &Gh) -> std::result::Result<Value, String> {
    let mut op: crate::protocol::operation::Operation = serde_json::from_value(json!({
        "act": { "type": { "custom": "service-add" }, "target": "github:acme/tools", "scope": scope },
        "bind": { "redeemer": "v1" },
        "valid": { "iat": 0, "multiplicity": 1 }
    }))
    .unwrap();
    block_on(mint_add(state, "v1", &mut op, gh))?;
    Ok(op.act.scope)
}

fn mint(state: &AppState, scope: Value) -> std::result::Result<Value, String> {
    mint_with(state, scope, &Gh(None))
}

fn unlock_with(state: &AppState, view: &VaultPlaintextView) {
    let cache = crate::state::SecretsCache {
        service_entries: view.aux.services.clone(),
        connections: view
            .aux
            .connections
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        ..Default::default()
    };
    state.unlock_vault("v1".into(), cache, zeroize::Zeroizing::new(Vec::new()));
}

#[test]
fn parse_add_checks_every_field() {
    let ok = scope(&[("a1", "a.dev")], &gh('a'), false);
    let req = parse_add(&ok).unwrap();
    assert_eq!(req.defs.len(), 1);
    assert!(!req.update);
    for bad in [
        json!({}),
        json!({ "definitions": {}, "source": gh('a') }),
        json!({ "definitions": { "a1": { "service": "x", "extra": 1 } }, "source": gh('a') }),
        json!({ "definitions": { "a1": { "service": "x" } } }),
        json!({ "definitions": { "a1": { "service": "x" } }, "source": { "kind": "github", "repo": "../x", "commit": "a".repeat(40) } }),
        json!({ "definitions": { "a1": { "service": "x" } }, "source": gh('a'), "update": "yes" }),
    ] {
        assert!(parse_add(&bad).is_err(), "{bad}");
    }
    let too_big = "#".repeat(MAX_SOURCE_DEFINITION_BYTES + 1);
    let big = json!({ "definitions": { "a1": { "service": too_big } }, "source": gh('a') });
    assert!(parse_add(&big).unwrap_err().contains("limit"));
    // Admission is all or nothing, under each definition's key.
    let mixed = parse_add(&scope(
        &[("a1", "a.dev"), ("b2", "10.0.0.1")],
        &gh('a'),
        false,
    ))
    .unwrap();
    assert!(admit_add(&mixed).unwrap_err().contains("b2"));
}

#[test]
fn add_then_update_then_rm_through_the_signed_card() {
    let state = test_state();
    let mut view = empty_view();
    // A definition written before sources stays as it is.
    view.aux
        .services
        .insert("old".into(), StoredService::from(svc("old", "o.dev")));
    unlock_with(&state, &view);

    // Add: stamped at mint, applied against the same vault.
    let signed = mint(
        &state,
        scope(&[("a1", "a.dev"), ("b2", "b.dev")], &gh('a'), false),
    )
    .unwrap();
    assert_eq!(signed["ids"], json!(["a1", "b2"]));
    assert_eq!(signed["destinations"], json!(["a.dev", "b.dev"]));
    let req = parse_add(&signed).unwrap();
    let snap = admit_add(&req).unwrap();
    apply_add(&mut view, req, &snap, &signed, &state.services).unwrap();
    let stored = serde_json::to_value(&view.aux.services).unwrap();
    assert_eq!(stored["a1"]["source"]["commit"], json!("a".repeat(40)));
    assert!(
        stored["old"].is_string(),
        "an unchanged entry is not rewritten"
    );
    let (defs, skipped) =
        crate::service::vault_custom_services(&view.aux.services, &state.services);
    assert!(skipped.is_empty() && defs.len() == 3);

    // Adding the same source again is refused at mint.
    unlock_with(&state, &view);
    assert!(mint(&state, scope(&[("a1", "a.dev")], &gh('b'), false))
        .unwrap_err()
        .contains("already added"));

    // Update: b2 vanished upstream, a1 now also sends to a new host.
    let mut up = scope(&[("a1", "a.dev")], &gh('b'), true);
    up["definitions"]["a1"]["service"] = json!(
        "[service]\nid = \"a1\"\nname = \"a1\"\nhosts = [\"a.dev\", \"new.dev\"]\nsecrets = [\"TOKEN\"]\n"
    );
    let signed = mint(&state, up).unwrap();
    assert_eq!(signed["removes"], json!(["b2"]));
    assert_eq!(signed["new_destinations"], json!(["new.dev"]));

    // The vault changed between mint and apply: refused, nothing written.
    let mut raced = copy(&view);
    raced.aux.services.remove("b2");
    let req = parse_add(&signed).unwrap();
    let snap = admit_add(&req).unwrap();
    let e = apply_add(&mut raced, req.clone(), &snap, &signed, &state.services).unwrap_err();
    assert!(e.contains("`removes` differs"), "{e}");
    // The source check stamped at mint is part of the card.
    let mut unchecked = signed.clone();
    unchecked.as_object_mut().unwrap().remove("source_check");
    let e = apply_add(
        &mut copy(&view),
        req.clone(),
        &snap,
        &unchecked,
        &state.services,
    )
    .unwrap_err();
    assert!(e.contains("source_check"), "{e}");
    // A requester cannot pre-fill the card: mint overwrites it.
    let mut forged = signed.clone();
    forged["new_destinations"] = json!([]);
    let e = apply_add(
        &mut copy(&view),
        req.clone(),
        &snap,
        &forged,
        &state.services,
    )
    .unwrap_err();
    assert!(e.contains("new_destinations"), "{e}");
    apply_add(&mut view, req, &snap, &signed, &state.services).unwrap();
    assert!(!view.aux.services.contains_key("b2"));
    assert_eq!(view.aux.services["a1"].source(), Some(gh('b')));

    // Remove the whole source: the card lists the connections still naming it.
    view.aux.connections.insert(
        "work".into(),
        Connection {
            service: Some("a1".into()),
            ..Connection::default()
        },
    );
    unlock_with(&state, &view);
    let mut op: crate::protocol::operation::Operation = serde_json::from_value(json!({
        "act": { "type": { "custom": "service-rm" }, "target": "github:acme/tools", "scope": null },
        "bind": { "redeemer": "v1" },
        "valid": { "iat": 0, "multiplicity": 1 }
    }))
    .unwrap();
    stamp_rm_at_mint(&state, "v1", &mut op).unwrap();
    assert_eq!(op.act.scope["connections"], json!(["work"]));
    let c = apply_rm(&mut view, "github:acme/tools", &op.act.scope).unwrap();
    assert_eq!(c.ids, ["a1"]);
    assert_eq!(view.aux.services.keys().collect::<Vec<_>>(), ["old"]);
    // By id, for an entry from before sources.
    let mut rm_old = json!({});
    card::rm_card("old", &view.aux.services, |_| vec![])
        .unwrap()
        .stamp(&mut rm_old)
        .unwrap();
    apply_rm(&mut view, "old", &rm_old).unwrap();
    assert!(view.aux.services.is_empty());
}

#[test]
fn collisions_are_refused_at_mint() {
    let state = test_state();
    let mut view = empty_view();
    view.aux.services.insert(
        "a1".into(),
        StoredService::new(
            svc("a1", "a.dev"),
            None,
            Some(ServiceSource::Local {
                name: "mine".into(),
            }),
        ),
    );
    unlock_with(&state, &view);
    let e = mint(&state, scope(&[("a1", "a.dev")], &gh('a'), false)).unwrap_err();
    assert!(
        e.contains("already in this vault from local folder mine"),
        "{e}"
    );
    let e = mint(
        &state,
        scope(&[("github", "api.github.com")], &gh('a'), false),
    )
    .unwrap_err();
    assert!(e.contains("built-in"), "{e}");
    // A locked vault: nothing to compare against, refused.
    state.lock_vault("v1");
    assert!(mint(&state, scope(&[("z9", "z.dev")], &gh('a'), false)).is_err());
}

#[test]
fn listing_shows_source_status_and_reason() {
    let state = test_state();
    let mut entries = BTreeMap::new();
    entries.insert("old".to_string(), StoredService::from(svc("old", "o.dev")));
    entries.insert(
        "a1".to_string(),
        StoredService::new(svc("a1", "a.dev"), None, Some(gh('a'))),
    );
    entries.insert(
        "bad".to_string(),
        StoredService::from(svc("bad", "10.0.0.1")),
    );
    entries.insert(
        "github".to_string(),
        StoredService::from(svc("github", "api.github.com")),
    );
    let mut conns = HashMap::new();
    conns.insert(
        "w".to_string(),
        Connection {
            service: Some("a1".into()),
            ..Connection::default()
        },
    );
    let rows = listing(&entries, &conns, &state.services);
    let row = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap().clone();
    assert_eq!(row("a1")["valid"], json!(true));
    assert_eq!(row("a1")["source"]["kind"], json!("github"));
    assert_eq!(row("a1")["connections"], json!(["w"]));
    assert_eq!(row("a1")["summary"]["destinations"], json!(["a.dev"]));
    assert_eq!(row("old")["source"], Value::Null);
    assert_eq!(row("old")["valid"], json!(true));
    assert_eq!(row("bad")["valid"], json!(false));
    assert!(!row("bad")["problems"].as_array().unwrap().is_empty());
    assert_eq!(row("github")["problems"], json!(["shadows a built-in id"]));
    assert_eq!(
        row("a1")["digest"],
        json!(crate::service::source::definition_digest(
            &svc("a1", "a.dev"),
            None
        ))
    );
}

/// A v2 keyset (members): a creator (owner) and a member, roles signed by the
/// creator, the anchor pinned.
fn v2_vault(vault: &str) -> PerItemVault {
    let creator = UikRoot::from_root([0x11u8; 32]);
    let member = UikRoot::from_root([0x22u8; 32]);
    let mut pv = PerItemVault::build_initial(
        b"c".to_vec(),
        "x".into(),
        "y".into(),
        "Dev".into(),
        vec![0u8; 32],
        vec![0u8; 48],
    )
    .unwrap();
    for (cid, who, role, role_str) in [
        ("cid-creator", &creator, MemberRole::Owner, "owner"),
        ("cid-member", &member, MemberRole::Member, "member"),
    ] {
        let grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault,
            &who.user_id(),
            role_str,
            0,
        ));
        pv.set_uik_cred(
            cid.into(),
            who.user_id(),
            who.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            role,
            grant.to_vec(),
        );
    }
    pv.keyset.uik.as_mut().unwrap().creator_sig_pub = creator.signing().public_bytes().to_vec();
    pv
}

/// Owner-config on a vault with members must be owner-signed, and this
/// process never signs it: `sc service add|update|rm` are refused at op
/// creation, and a write reaching apply anyway is refused with nothing
/// written. A vault with no members (v1 keyset, or no store yet) is not.
#[test]
fn a_vault_needing_owner_signatures_refuses_service_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state();
    state.config.state_dir = dir.path().to_path_buf();
    state.vaults = crate::storage::vault_dir::VaultDir::new(dir.path());
    let state = Arc::new(state);
    let team = "vault-team";
    let path = state.vaults.per_item_path(team).unwrap();
    crate::storage::sealed_vault::write_per_item_atomic(&path, &v2_vault(team)).unwrap();
    let before = std::fs::read(&path).unwrap();

    let e = refuse_if_owner_signed(&state, team).unwrap_err();
    assert!(
        matches!(&e, AppError::Forbidden(m) if m == OWNER_SIGNATURE_NEEDED),
        "{e:?}"
    );
    assert!(OWNER_SIGNATURE_NEEDED.contains("console"));
    let e = persist(
        &state,
        team,
        &crate::storage::sealed_vault::ViewBase::default(),
        &empty_view(),
        &[0u8; 32],
    )
    .unwrap_err();
    assert!(matches!(e, AppError::Forbidden(_)), "{e:?}");
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");

    // One person, no members: not refused.
    let personal = "vault-personal";
    let v1 = PerItemVault::build_initial(
        b"c".to_vec(),
        "x".into(),
        "y".into(),
        "Dev".into(),
        vec![0u8; 32],
        vec![0u8; 48],
    )
    .unwrap();
    crate::storage::sealed_vault::write_per_item_atomic(
        &state.vaults.per_item_path(personal).unwrap(),
        &v1,
    )
    .unwrap();
    assert!(refuse_if_owner_signed(&state, personal).is_ok());
    assert!(refuse_if_owner_signed(&state, "vault-none").is_ok());
}

/// The card's source is a fact only when this device fetched the pinned
/// commit again and found the same definitions; other definitions refuse
/// the op; when it cannot be checked the card says the requester stated it.
#[test]
fn mint_checks_a_github_source_at_its_pinned_commit() {
    let state = test_state();
    unlock_with(&state, &empty_view());
    let at_commit = tar_gz(&[(
        "acme-tools-x/services/a1/service.toml",
        b'0',
        svc("a1", "a.dev").as_bytes(),
    )]);
    let signed = mint_with(
        &state,
        scope(&[("a1", "a.dev")], &gh('a'), false),
        &Gh(Some(at_commit.clone())),
    )
    .unwrap();
    assert_eq!(signed["source_check"], json!("fetched"));
    let from = signed["from"].as_str().unwrap();
    assert!(from.contains("fetched again on your device"), "{from}");
    // The requester's definitions differ from the commit's: refused.
    let e = mint_with(
        &state,
        scope(&[("a1", "evil.example")], &gh('a'), false),
        &Gh(Some(at_commit)),
    )
    .unwrap_err();
    assert!(e.contains("not what github:acme/tools"), "{e}");
    // GitHub out of reach: stated, not checked.
    let signed = mint(&state, scope(&[("a1", "a.dev")], &gh('a'), false)).unwrap();
    assert_eq!(signed["source_check"], json!("not-reached"));
    assert!(signed["from"]
        .as_str()
        .unwrap()
        .contains("as stated by the requester"));
    // A local folder cannot be checked here.
    let local = ServiceSource::Local {
        name: "mine".into(),
    };
    let signed = mint(&state, scope(&[("a1", "a.dev")], &local, false)).unwrap();
    assert_eq!(signed["source_check"], json!("local"));
    assert!(signed["from"]
        .as_str()
        .unwrap()
        .starts_with("local folder mine, as stated by the requester"));
}
