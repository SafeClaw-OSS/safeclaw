use super::*;
use crate::crypto::vault_key::UikRoot;
use crate::service::source::tests::tar_gz;
use crate::storage::plaintext::{MemberRole, VaultAux, VaultPlaintextView};
use crate::storage::sealed_vault::PerItemVault;

use crate::service::source::github::{FetchError, GitObject};

/// GitHub as the tests see it: serves `tarball` (or answers its read with an
/// error) at the commit `main`, the default branch, is at (`head`), or is
/// out of reach.
struct Gh {
    tarball: std::result::Result<Vec<u8>, FetchError>,
    head: String,
}

impl Gh {
    fn serving(tarball: Vec<u8>) -> Self {
        Gh {
            tarball: Ok(tarball),
            head: "a".repeat(40),
        }
    }
    fn answering(e: FetchError) -> Self {
        Gh {
            tarball: Err(e),
            head: "a".repeat(40),
        }
    }
    fn offline() -> Self {
        Gh::answering(FetchError::Unreachable("offline".into()))
    }
    /// GitHub holding exactly the definitions `scope` requests, at the head
    /// of the default branch, which is at the source's pinned commit.
    fn holding(scope: &Value) -> Self {
        let mut files: Vec<(String, String)> = Vec::new();
        for (id, d) in scope["defs"].as_object().into_iter().flatten() {
            let dir = format!("acme-tools-x/services/{}", id);
            files.push((format!("{}/service.toml", dir), d["service"].as_str().unwrap().into()));
            if let Some(p) = d.get("policy").and_then(|p| p.as_str()) {
                files.push((format!("{}/policy.toml", dir), p.into()));
            }
        }
        let entries: Vec<(&str, u8, &[u8])> = files
            .iter()
            .map(|(p, t)| (p.as_str(), b'0', t.as_bytes()))
            .collect();
        Gh {
            tarball: Ok(tar_gz(&entries)),
            head: scope["source"]["commit"].as_str().unwrap_or("").to_string(),
        }
    }
}

impl Gh {
    fn reached(&self) -> std::result::Result<(), FetchError> {
        match &self.tarball {
            Err(e @ FetchError::Unreachable(_)) => Err(e.clone()),
            _ => Ok(()),
        }
    }
}

impl GitHubApi for Gh {
    async fn default_branch(&self, _o: &str, _r: &str) -> std::result::Result<String, FetchError> {
        self.reached().map(|_| "main".to_string())
    }
    async fn git_ref(
        &self,
        _o: &str,
        _r: &str,
        path: &str,
    ) -> std::result::Result<Option<GitObject>, FetchError> {
        self.reached()?;
        Ok((path == "heads/main").then(|| GitObject::Commit(self.head.clone())))
    }
    async fn tag_target(
        &self,
        _o: &str,
        _r: &str,
        sha: &str,
    ) -> std::result::Result<GitObject, FetchError> {
        Err(FetchError::Answered(format!("tag {} not found", sha)))
    }
    async fn tarball(
        &self,
        _o: &str,
        _r: &str,
        _c: &str,
    ) -> std::result::Result<Vec<u8>, FetchError> {
        self.tarball.clone()
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
    let defs: serde_json::Map<String, Value> = defs
        .iter()
        .map(|(id, host)| ((*id).to_string(), json!({ "service": svc(id, host) })))
        .collect();
    json!({ "defs": defs, "source": source, "update": update })
}

/// A vault whose owner switch for installed services is `on`.
fn view_with_switch(on: bool) -> VaultPlaintextView {
    let mut m = sudp::state::ProtectedState::new();
    let mut aux = VaultAux::initial();
    aux.policy = Some(crate::core::policy::Policy {
        timeout: None,
        default: None,
        categories: HashMap::new(),
        connections: HashMap::new(),
        allow_installed_services: on,
    });
    m.aux = serde_json::to_value(aux).unwrap();
    VaultPlaintextView::from_protected_state(&m).unwrap()
}

/// A vault that allows installed services.
fn empty_view() -> VaultPlaintextView {
    view_with_switch(true)
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

/// Mint with GitHub holding exactly what is requested.
fn mint(state: &AppState, scope: Value) -> std::result::Result<Value, String> {
    let upstream = Gh::holding(&scope);
    mint_with(state, scope, &upstream)
}

fn unlock_with(state: &AppState, view: &VaultPlaintextView) {
    let cache = crate::state::SecretsCache {
        policy: crate::core::policy::Policy::effective(view.aux.policy.as_ref()),
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
        json!({ "defs": {}, "source": gh('a') }),
        json!({ "defs": { "a1": { "service": "x", "extra": 1 } }, "source": gh('a') }),
        json!({ "defs": { "a1": { "service": "x" } } }),
        json!({ "defs": { "a1": { "service": "x" } }, "source": { "kind": "github", "repo": "../x", "commit": "a".repeat(40) } }),
        json!({ "defs": { "a1": { "service": "x" } }, "source": gh('a'), "update": "yes" }),
    ] {
        assert!(parse_add(&bad).is_err(), "{bad}");
    }
    let too_big = "#".repeat(MAX_SOURCE_DEFINITION_BYTES + 1);
    let big = json!({ "defs": { "a1": { "service": too_big } }, "source": gh('a') });
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
    // Each installed entry carries the summary of its admitted definition.
    assert_eq!(
        stored["a1"]["summary"],
        json!({ "name": "a1", "hosts": ["a.dev"], "secrets": ["TOKEN"], "oauth": false })
    );
    let (defs, skipped) =
        crate::service::vault_custom_services(&view.aux.services, true, &state.services);
    assert!(skipped.is_empty() && defs.len() == 3);

    // Adding the same source again is refused at mint.
    unlock_with(&state, &view);
    assert!(mint(&state, scope(&[("a1", "a.dev")], &gh('b'), false))
        .unwrap_err()
        .contains("already added"));

    // Update: b2 vanished upstream, a1 now also sends to a new host.
    let mut up = scope(&[("a1", "a.dev")], &gh('b'), true);
    up["defs"]["a1"]["service"] = json!(
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
    // The definition text stamped at mint is part of the card.
    let mut retexted = signed.clone();
    retexted["definitions"] = json!("# a1 service.toml\n[service]\n");
    let e = apply_add(
        &mut copy(&view),
        req.clone(),
        &snap,
        &retexted,
        &state.services,
    )
    .unwrap_err();
    assert!(e.contains("`definitions` differs"), "{e}");
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
    let rows = listing(&entries, &conns, &state.services, true);
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

/// A tempdir-backed state holding `pv` for `vault`, unlocked under `k`
/// (session entries = the store's fold, as an unlock leaves them).
fn state_with_store(
    vault: &str,
    pv: &PerItemVault,
    k: &[u8; 32],
) -> (tempfile::TempDir, Arc<AppState>) {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state();
    state.config.state_dir = dir.path().to_path_buf();
    state.vaults = crate::storage::vault_dir::VaultDir::new(dir.path());
    let state = Arc::new(state);
    let path = state.vaults.per_item_path(vault).unwrap();
    crate::storage::sealed_vault::write_per_item_atomic(&path, pv).unwrap();
    let view = crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(k, pv, vault)
        .unwrap();
    let cache = crate::state::SecretsCache {
        policy: crate::core::policy::Policy::effective(view.aux.policy.as_ref()),
        service_entries: view.aux.services.clone(),
        ..Default::default()
    };
    state.unlock_vault(vault.into(), cache, zeroize::Zeroizing::new(k.to_vec()));
    (dir, state)
}

fn stored(state: &AppState, vault: &str) -> PerItemVault {
    crate::storage::sealed_vault::read_per_item(&state.vaults.per_item_path(vault).unwrap())
        .unwrap()
        .unwrap()
}

/// The approved flow end to end on a vault with members (v2), whose
/// owner-config needs owner signatures: service definitions are data records,
/// so `service-add` and `service-rm` are minted, applied and written by this
/// process (unsigned native `service` items, as any member's daemon writes a
/// connection), and the fold honors them. The source is stamped in its stored
/// form.
#[test]
fn services_are_data_records_on_a_vault_with_members() {
    type S = sudp::primitives::StdPrimitives;
    let vault = "vault-team";
    let k = [0x5au8; 32];
    let keys = crate::storage::item::VaultKeys::single(&k);
    // The owner's switch, signed by the owner: honored on a v2 keyset.
    let mut pv = v2_vault(vault);
    crate::storage::sealed_vault::tests::plant_signed(
        &mut pv,
        keys,
        vault,
        &UikRoot::from_root([0x11u8; 32]),
        "policy",
        &crate::storage::item::ItemPayload::live(
            crate::storage::item::ItemNs::Policy,
            "",
            json!({ "allow_installed_services": true }),
        ),
    );
    let (_dir, state) = state_with_store(vault, &pv, &k);

    // Mint: `path: null` is not kept.
    let mut sc = scope(&[("a1", "a.dev")], &gh('a'), false);
    sc["source"]["path"] = Value::Null;
    let mut op: crate::protocol::operation::Operation = serde_json::from_value(json!({
        "act": { "type": { "custom": "service-add" }, "target": "github:acme/tools", "scope": sc },
        "bind": { "redeemer": vault },
        "valid": { "iat": 0, "multiplicity": 1 }
    }))
    .unwrap();
    let upstream = Gh::holding(&op.act.scope);
    block_on(mint_add(&state, vault, &mut op, &upstream)).unwrap();
    let signed = op.act.scope.clone();
    assert_eq!(signed["source"], serde_json::to_value(gh('a')).unwrap());
    assert!(signed["source"].get("path").is_none());

    // Apply the approved card: the daemon writes a native item, unsigned.
    let open = |state: &AppState| {
        crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(
            &k,
            &stored(state, vault),
            vault,
        )
        .unwrap()
    };
    let mut view = open(&state);
    let base = crate::storage::sealed_vault::ViewBase::of(&view).unwrap();
    let req = parse_add(&signed).unwrap();
    let snap = admit_add(&req).unwrap();
    apply_add(&mut view, req, &snap, &signed, &state.services).unwrap();
    persist(&state, vault, &base, &view, &k).unwrap();
    let pv = stored(&state, vault);
    let a1 = crate::storage::item::wire_id_for::<S>(
        keys.id_seed,
        crate::storage::item::ItemNs::Service,
        "a1",
    )
    .unwrap();
    assert!(pv.items[&a1].sig.is_none(), "no signature");
    assert!(
        open(&state).aux.services.contains_key("a1"),
        "honored on a v2 keyset"
    );
    assert!(
        session(&state, vault).unwrap().0.contains_key("a1"),
        "the session sees it"
    );

    // Remove it the same way: a native tombstone.
    let mut rm: crate::protocol::operation::Operation = serde_json::from_value(json!({
        "act": { "type": { "custom": "service-rm" }, "target": "a1", "scope": {} },
        "bind": { "redeemer": vault },
        "valid": { "iat": 0, "multiplicity": 1 }
    }))
    .unwrap();
    stamp_rm_at_mint(&state, vault, &mut rm).unwrap();
    let mut view = open(&state);
    let base = crate::storage::sealed_vault::ViewBase::of(&view).unwrap();
    apply_rm(&mut view, "a1", &rm.act.scope).unwrap();
    persist(&state, vault, &base, &view, &k).unwrap();
    assert!(stored(&state, vault).items[&a1].tombstone);
    assert!(open(&state).aux.services.is_empty());
}

/// LEGACY(services row): after an unlock, and only after a pull, a vault
/// without a keyset copies the legacy record to native items (object form);
/// the retirement tombstones it once the copies are held (locally here: no
/// cloud). A failed pull moves nothing. A vault with a keyset is left to the
/// owner's console: nothing is written.
#[test]
fn legacy_services_move_only_after_a_pull() {
    use crate::storage::item::ItemPayload;
    use crate::storage::item::{ItemNs, VaultKeys};
    type S = sudp::primitives::StdPrimitives;
    let k = [0x5au8; 32];
    let keys = VaultKeys::single(&k);
    // One entry written before sources (plain text), one in the object form.
    let legacy = || {
        ItemPayload::live(
            ItemNs::Aux,
            "services",
            json!({ "old": svc("old", "o.dev"), "new": { "service": svc("new", "n.dev") } }),
        )
    };
    let pulled = || async { std::result::Result::<(), String>::Ok(()) };
    let offline = || async { std::result::Result::<(), String>::Err("offline".into()) };

    // v1: a failed pull moves nothing; after a pull both move, the legacy
    // record is tombstoned.
    let vault = "vault-personal";
    let mut v1 = PerItemVault::build_initial(
        b"c".to_vec(),
        "x".into(),
        "y".into(),
        "Dev".into(),
        vec![0u8; 32],
        vec![0u8; 48],
    )
    .unwrap();
    v1.plant::<S>(keys, vault, ItemNs::Aux, "services", 1, &legacy())
        .unwrap();
    let (_d1, state) = state_with_store(vault, &v1, &k);
    let path = state.vaults.per_item_path(vault).unwrap();
    let before = std::fs::read(&path).unwrap();
    let copies = LegacyStep::Copies;
    let retire = LegacyStep::Retire { on_cloud: false };
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, offline(), copies)),
        None
    );
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, offline(), retire)),
        None
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), copies)),
        Some(2)
    );
    assert!(
        !stored(&state, vault)
            .open_item::<S>(keys, vault, ItemNs::Aux, "services")
            .unwrap()
            .unwrap()
            .is_tombstone(),
        "the copies first; the legacy record stays"
    );
    // Held on the cloud: not yet (the copies are not pushed), nothing retired.
    let on_cloud = LegacyStep::Retire { on_cloud: true };
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), on_cloud)),
        Some(0)
    );
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), retire)),
        Some(1)
    );
    let pv = stored(&state, vault);
    assert!(pv
        .open_item::<S>(keys, vault, ItemNs::Aux, "services")
        .unwrap()
        .unwrap()
        .is_tombstone());
    assert_eq!(
        pv.open_item::<S>(keys, vault, ItemNs::Service, "old")
            .unwrap()
            .unwrap()
            .body,
        json!({ "service": svc("old", "o.dev") }),
        "written in the object form"
    );
    let services =
        crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(&k, &pv, vault)
            .unwrap()
            .aux
            .services;
    assert_eq!(services.keys().collect::<Vec<_>>(), ["new", "old"]);
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), copies)),
        Some(0)
    );
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), retire)),
        Some(0)
    );

    // v2: the console's job; nothing is written, signed or not.
    let vault = "vault-team";
    let mut v2 = v2_vault(vault);
    v2.plant::<S>(keys, vault, ItemNs::Aux, "services", 1, &legacy())
        .unwrap();
    let (_d2, state) = state_with_store(vault, &v2, &k);
    let before = std::fs::read(state.vaults.per_item_path(vault).unwrap()).unwrap();
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), copies)),
        Some(0)
    );
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), retire)),
        Some(0)
    );
    assert_eq!(
        std::fs::read(state.vaults.per_item_path(vault).unwrap()).unwrap(),
        before
    );

    // A locked vault: nothing.
    state.lock_vault(vault);
    assert_eq!(
        block_on(migrate_legacy_after(&state, vault, pulled(), copies)),
        Some(0)
    );
}

/// A GitHub source is fetched by the daemon at the head of its branch or
/// tag: only the same definitions at the pinned commit mint an op. A commit
/// the ref is not at, other definitions, a ref that is no branch or tag, an
/// answer without the data and no answer at all refuse it. The card's source
/// line is the source's display, nothing appended.
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
        &Gh::serving(at_commit.clone()),
    )
    .unwrap();
    assert_eq!(signed["from"], json!(gh('a').display()));
    assert!(signed.get("source_check").is_none());
    // A commit the default branch is not at (say, one pushed only to a fork,
    // which GitHub serves through the parent repository's URLs): refused.
    let e = mint_with(
        &state,
        scope(&[("a1", "a.dev")], &gh('b'), false),
        &Gh::serving(at_commit.clone()),
    )
    .unwrap_err();
    assert!(
        e.contains(&format!("the default branch is at {}", "a".repeat(40))),
        "{e}"
    );
    // The requester's definitions differ from the commit's: refused.
    let e = mint_with(
        &state,
        scope(&[("a1", "evil.example")], &gh('a'), false),
        &Gh::serving(at_commit.clone()),
    )
    .unwrap_err();
    assert!(e.contains("not what github:acme/tools"), "{e}");
    // A commit id or another refs/ name as the ref: no branch or tag, refused.
    for r in ["a".repeat(40), "refs/pull/1/head".to_string(), "v9".to_string()] {
        let src = ServiceSource::Github {
            repo: "acme/tools".into(),
            path: None,
            git_ref: Some(r.clone()),
            commit: "a".repeat(40),
        };
        let e = mint_with(
            &state,
            scope(&[("a1", "a.dev")], &src, false),
            &Gh::serving(at_commit.clone()),
        )
        .unwrap_err();
        assert!(e.contains("is not a branch or tag"), "{r}: {e}");
        assert!(e.contains("nothing was stored"), "{r}: {e}");
    }
    // GitHub not answering (a transport error, no answer in time): refused.
    let e = mint_with(
        &state,
        scope(&[("a1", "a.dev")], &gh('a'), false),
        &Gh::offline(),
    )
    .unwrap_err();
    assert!(e.contains("GitHub did not respond"), "{e}");
    assert!(e.contains("nothing was stored"), "{e}");
    // An answer from GitHub without the data (not found, refused, a server
    // error, too large or too slow) refuses the op.
    for answer in [404u16, 422, 403, 502] {
        let gh_answer = Gh::answering(crate::service::source::github::status_problem(
            answer,
            "github:acme/tools",
        ));
        let e = mint_with(
            &state,
            scope(&[("a1", "a.dev")], &gh('a'), false),
            &gh_answer,
        )
        .unwrap_err();
        assert!(e.contains("nothing was stored"), "{answer}: {e}");
    }
    let oversize = Gh::answering(FetchError::Answered(
        "the download is larger than 16 bytes".into(),
    ));
    assert!(mint_with(
        &state,
        scope(&[("a1", "a.dev")], &gh('a'), false),
        &oversize
    )
    .is_err());
    // A local folder is read by the requester only; its line is its display.
    let local = ServiceSource::Local {
        name: "mine".into(),
    };
    let signed = mint_with(
        &state,
        scope(&[("a1", "a.dev")], &local, false),
        &Gh::offline(),
    )
    .unwrap();
    assert_eq!(signed["from"], json!("local folder mine"));
}

/// The owner switch: off (or no policy at all), `service-add` is refused at
/// op creation and at apply with the one message, installed entries are not
/// loaded and are listed skipped with the reason, and a connection using one
/// is refused by name. On, they load. Entries without a source are not
/// installed and load either way.
#[test]
fn the_owner_switch_decides_whether_installed_services_exist() {
    let state = test_state();
    let off = view_with_switch(false);
    unlock_with(&state, &off);
    let e = mint(&state, scope(&[("a1", "a.dev")], &gh('a'), false)).unwrap_err();
    assert_eq!(e, crate::service::INSTALLED_OFF_MSG);
    assert_eq!(
        e,
        "Installed services are off for this vault. A vault owner can turn them on in the console: Settings → Services."
    );
    let mut no_policy = copy(&off);
    no_policy.aux.policy = None;
    unlock_with(&state, &no_policy);
    assert_eq!(
        mint(&state, scope(&[("a1", "a.dev")], &gh('a'), false)).unwrap_err(),
        crate::service::INSTALLED_OFF_MSG
    );

    // Minted while on, applied after the owner turned it off: refused.
    let on = empty_view();
    unlock_with(&state, &on);
    let signed = mint(&state, scope(&[("a1", "a.dev")], &gh('a'), false)).unwrap();
    let req = parse_add(&signed).unwrap();
    let snap = admit_add(&req).unwrap();
    let mut turned_off = view_with_switch(false);
    let e = apply_add(&mut turned_off, req.clone(), &snap, &signed, &state.services).unwrap_err();
    assert_eq!(e, crate::service::INSTALLED_OFF_MSG);
    assert!(turned_off.aux.services.is_empty());
    let mut view = copy(&on);
    apply_add(&mut view, req, &snap, &signed, &state.services).unwrap();
    view.aux
        .services
        .insert("old".into(), StoredService::from(svc("old", "o.dev")));
    view.aux.services.insert(
        "console".into(),
        StoredService::new(svc("console", "c.dev"), None, None),
    );

    // Loading: on, all three; off, the installed one is skipped by name.
    let (defs, skipped) = crate::service::vault_custom_services(&view.aux.services, true, &state.services);
    assert_eq!(defs.len(), 3, "{skipped:?}");
    let (defs, skipped) = crate::service::vault_custom_services(&view.aux.services, false, &state.services);
    assert!(defs.contains_key("old") && defs.contains_key("console"));
    assert!(!defs.contains_key("a1"));
    assert_eq!(
        skipped,
        vec![("a1".to_string(), "installed services are off for this vault".to_string())]
    );
    let mut off_view = copy(&view);
    off_view.aux.policy = view_with_switch(false).aux.policy;
    assert!(!off_view.aux.allows_installed_services());
    assert!(view.aux.allows_installed_services());

    // Listing: skipped with the reason while off.
    let rows = listing(&view.aux.services, &HashMap::new(), &state.services, false);
    let a1 = rows.iter().find(|r| r["id"] == "a1").unwrap();
    assert_eq!(a1["valid"], json!(false));
    assert_eq!(a1["problems"], json!(["installed services are off for this vault"]));
    assert_eq!(a1["source"], json!(gh('a')));
    for id in ["old", "console"] {
        assert_eq!(rows.iter().find(|r| r["id"] == id).unwrap()["valid"], json!(true));
    }
    let rows = listing(&view.aux.services, &HashMap::new(), &state.services, true);
    assert!(rows.iter().all(|r| r["valid"] == json!(true)), "{rows:?}");

    // A connection naming it: refused by name while off, not while on.
    unlock_with(&state, &off_view);
    assert!(state.installed_service_off("v1", "a1"));
    assert!(!state.installed_service_off("v1", "old"));
    assert!(!state.installed_service_off("v1", "console"));
    unlock_with(&state, &view);
    assert!(!state.installed_service_off("v1", "a1"));
}

/// The stored record carries no claim about its source: one an older client
/// wrote (`checked: true`) is read and ignored, and the summary beside an
/// installed definition is display data the daemon never reads (an entry
/// without one, or with any other content in it, reads the same).
#[test]
fn stored_records_carry_no_check_and_a_summary_that_is_not_read() {
    let state = test_state();
    let view = empty_view();
    unlock_with(&state, &view);
    let mut sc = scope(&[("a1", "a.dev")], &gh('a'), false);
    sc["source"]["checked"] = json!(true);
    let signed = mint(&state, sc).unwrap();
    assert!(signed["source"].get("checked").is_none());
    let a = "a".repeat(40);
    let claimed: StoredService = serde_json::from_value(json!({
        "service": svc("b2", "b.dev"),
        "source": { "kind": "github", "repo": "acme/tools", "commit": a, "checked": true },
        "summary": { "name": "anything", "hosts": ["elsewhere.example"], "secrets": [], "oauth": true },
    }))
    .unwrap();
    assert_eq!(claimed.source(), Some(gh('a')));
    assert!(claimed.is_installed());
    let def = claimed.admit("b2").unwrap();
    assert_eq!(def.service.hosts, ["b.dev"], "the summary is never read");
    let plain: StoredService = serde_json::from_value(json!({ "service": svc("b2", "b.dev") })).unwrap();
    assert!(!plain.is_installed());
    assert!(!StoredService::from(svc("b2", "b.dev")).is_installed());
}

/// A conflict copy (`"<id> (conflict copy)"`, kept by the sync beside the
/// service) is listed as skipped with the reason, is never part of its
/// source (an update or a source-wide removal leaves it), and `sc service rm`
/// refuses it: it is resolved in the console.
#[test]
fn a_conflict_copy_is_listed_skipped_and_never_used() {
    let state = test_state();
    let copy = "a1 (conflict copy)".to_string();
    let mut entries = BTreeMap::new();
    entries.insert(
        "a1".to_string(),
        StoredService::new(svc("a1", "a.dev"), None, Some(gh('a'))),
    );
    entries.insert(
        copy.clone(),
        StoredService::new(svc("a1", "evil.dev"), None, Some(gh('a'))),
    );
    let rows = listing(&entries, &HashMap::new(), &state.services, true);
    let row = rows.iter().find(|r| r["id"] == copy.as_str()).unwrap();
    assert_eq!(row["valid"], json!(false));
    assert_eq!(
        row["problems"],
        json!([crate::service::CONFLICT_COPY_REASON])
    );
    assert!(crate::service::CONFLICT_COPY_REASON.contains("console"));
    let (defs, skipped) = crate::service::vault_custom_services(&entries, true, &state.services);
    assert!(defs.contains_key("a1") && !defs.contains_key(&copy));
    assert!(skipped.iter().any(|(id, _)| id == &copy));
    // Not part of its source.
    let c = card::rm_card("github:acme/tools", &entries, |_| vec![]).unwrap();
    assert_eq!(c.ids, ["a1"]);
    assert!(card::rm_card(&copy, &entries, |_| vec![])
        .unwrap_err()
        .contains("conflict copy"));
}
