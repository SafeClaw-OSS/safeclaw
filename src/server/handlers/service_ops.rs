//! The vault side of `sc service`: the `service-add` / `service-rm` acts and
//! the `GET /v/{vid}/services` listing.
//!
//! `service-add` stores one source's definitions with one approval. The op
//! carries `definitions` (`id → { service, policy? }`), the `source` record
//! (with its pinned commit) and `update`; the daemon admits every definition
//! through the gate, fetches a GitHub source again at its commit to check the
//! definitions are what it holds, and stamps the card ([`card::AddCard`]:
//! services, destinations, the rules that tighten, the source as checked or
//! as stated, what an update replaces, removes, newly sends to or loosens)
//! into the signed scope at op creation, and at apply re-admits, recomputes
//! the card against the opened vault and refuses any difference.
//! `service-rm` removes one service or a whole source the same way
//! ([`card::RmCard`]).
//!
//! Each definition is its own native `service` item (`ns = "service"`,
//! `name` = the id, body `{ service, policy?, source? }`): a data record like
//! a connection, sealed under `K`, unsigned, written by this process after the
//! approved card on every vault ([`persist`]). The old single `services`
//! record is owner-config, read only here; the fold takes
//! the union, a native item or tombstone winning for its id, and after an
//! unlock and a pull the daemon moves it to native items on a vault without a
//! keyset ([`migrate_legacy_after_unlock`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
use crate::service::source::card::SourceCheck;
use crate::service::source::github::{self, GitHubApi};
use crate::service::source::{
    card, ServiceSource, StoredService, MAX_SOURCE_DEFINITION_BYTES, MAX_SOURCE_SERVICES,
};
use crate::service::{gate, ServiceDef, ServiceRegistry};
use crate::state::{AppState, VaultState};
use crate::storage::plaintext::Connection;

/// A `service-add` op's request fields.
#[derive(Debug, Clone)]
pub(crate) struct AddRequest {
    /// Service id → (service.toml, policy.toml).
    pub defs: BTreeMap<String, (String, Option<String>)>,
    pub source: ServiceSource,
    /// True for `sc service update` (the source must already be stored),
    /// false for `sc service add` (it must not be).
    pub update: bool,
}

/// Read a `service-add` scope. Every field is checked: the definitions are
/// untrusted text and the source names a repository.
pub(crate) fn parse_add(scope: &Value) -> std::result::Result<AddRequest, String> {
    let defs_in = scope
        .get("definitions")
        .and_then(|v| v.as_object())
        .ok_or("service-add scope.definitions (object) required")?;
    if defs_in.is_empty() || defs_in.len() > MAX_SOURCE_SERVICES {
        return Err(format!(
            "service-add carries 1 to {} definitions",
            MAX_SOURCE_SERVICES
        ));
    }
    let mut defs = BTreeMap::new();
    let mut total = 0usize;
    for (id, v) in defs_in {
        let o = v
            .as_object()
            .ok_or("each definition is { service, policy? }")?;
        if o.keys().any(|k| k != "service" && k != "policy") {
            return Err("each definition is { service, policy? }".into());
        }
        let service = o
            .get("service")
            .and_then(|s| s.as_str())
            .ok_or("each definition needs its service text")?
            .to_string();
        let policy = match o.get("policy") {
            None | Some(Value::Null) => None,
            Some(Value::String(p)) => Some(p.clone()),
            Some(_) => return Err("a definition's policy must be text".into()),
        };
        total += service.len() + policy.as_ref().map_or(0, |p| p.len());
        defs.insert(id.clone(), (service, policy));
    }
    if total > MAX_SOURCE_DEFINITION_BYTES {
        return Err(format!(
            "the definitions total {} bytes; the limit is {}",
            total, MAX_SOURCE_DEFINITION_BYTES
        ));
    }
    let mut source: ServiceSource = serde_json::from_value(
        scope
            .get("source")
            .cloned()
            .ok_or("service-add scope.source required")?,
    )
    .map_err(|_| "service-add scope.source is not a source record".to_string())?;
    source.check()?;
    // Whether the source was checked is the daemon's finding (the card's
    // `source_check`), never the requester's claim.
    source.set_checked(false);
    let update = match scope.get("update") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("service-add scope.update must be true or false".into()),
    };
    Ok(AddRequest {
        defs,
        source,
        update,
    })
}

/// Admit every requested definition through the gate under its id, all or
/// nothing.
pub(crate) fn admit_add(
    req: &AddRequest,
) -> std::result::Result<BTreeMap<String, ServiceDef>, String> {
    let mut out = BTreeMap::new();
    let mut problems = Vec::new();
    for (id, (svc, pol)) in &req.defs {
        match gate::admit(Some(id), svc, pol.as_deref()) {
            Ok(d) => {
                out.insert(id.clone(), d);
            }
            Err(ps) => problems.extend(
                ps.into_iter()
                    .map(|p| format!("{}: {}", crate::util::terminal_safe(id), p)),
            ),
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(format!(
            "invalid service definition: {}",
            problems.join("; ")
        ))
    }
}

/// The connection records that name `id` as their service.
pub(crate) fn connections_using<'a>(
    conns: impl IntoIterator<Item = (&'a String, &'a Connection)>,
    id: &str,
) -> Vec<String> {
    let mut out: Vec<String> = conns
        .into_iter()
        .filter(|(_, c)| c.service.as_deref() == Some(id))
        .map(|(cid, _)| cid.clone())
        .collect();
    out.sort();
    out
}

/// The unlocked session's stored entries and connection records.
fn session(
    state: &AppState,
    vault_id: &str,
) -> std::result::Result<(BTreeMap<String, StoredService>, HashMap<String, Connection>), String> {
    let states = state.vault_states.lock().unwrap();
    match states.get(vault_id) {
        Some(VaultState::Unlocked { cache, .. }) => {
            Ok((cache.service_entries.clone(), cache.connections.clone()))
        }
        _ => Err(crate::error::VAULT_LOCKED_MSG.to_string()),
    }
}

/// LEGACY(aux addressing, services row): one step of the migration on a
/// vault without a keyset, under the vault write lock the caller holds:
/// `Copies` writes the native copies of the legacy rows
/// ([`crate::storage::sealed_vault::PerItemVault::migrate_legacy_copies`]);
/// `Retire { on_cloud }` tombstones each legacy row whose copies are all
/// confirmed ([`crate::storage::sealed_vault::PerItemVault::retire_legacy_rows`]).
/// Needs the vault unlocked. Best-effort: a failure is logged and the next
/// unlock tries again. Returns the number of items written (the caller
/// pushes them).
pub(crate) fn migrate_legacy_now(state: &Arc<AppState>, vault_id: &str, step: LegacyStep) -> usize {
    use crate::storage::sealed_vault::{read_per_item, write_per_item_atomic};
    type S = sudp::primitives::StdPrimitives;
    let run = || -> Result<usize> {
        let Some(k) = state.cloned_state_key(vault_id) else {
            return Ok(0);
        };
        let path = state.vaults.per_item_path(vault_id)?;
        let Some(mut pv) = read_per_item(&path)? else {
            return Ok(0);
        };
        let keys = crate::storage::item::VaultKeys::from_material(&k);
        let changed = match step {
            LegacyStep::Copies => pv.migrate_legacy_copies::<S>(keys, vault_id),
            LegacyStep::Retire { on_cloud } => pv.retire_legacy_rows::<S>(keys, vault_id, on_cloud),
        };
        if !changed.is_empty() {
            write_per_item_atomic(&path, &pv)?;
        }
        Ok(changed.len())
    };
    match run() {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "legacy rows migration deferred: {}", e);
            0
        }
    }
}

/// LEGACY: a step of the migration ([`migrate_legacy_now`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyStep {
    /// Write the native copies.
    Copies,
    /// Retire the legacy rows whose copies are held: on the cloud
    /// (`on_cloud`), or locally on a device without a cloud.
    Retire { on_cloud: bool },
}

/// LEGACY(aux addressing, services row): after `pull` (the device's pull of
/// the vault's items), run `step` under the vault write lock
/// ([`migrate_legacy_now`]). A failed pull migrates nothing: a device that is
/// behind must not write copies of rows that changed elsewhere. `None`: the
/// pull failed; else the number of items written.
pub(crate) async fn migrate_legacy_after<F>(
    state: &Arc<AppState>,
    vault_id: &str,
    pull: F,
    step: LegacyStep,
) -> Option<usize>
where
    F: std::future::Future<Output = std::result::Result<(), String>>,
{
    if let Err(e) = pull.await {
        tracing::info!(vault = %vault_id, "legacy rows migration waits for a pull: {}", e);
        return None;
    }
    let lock = state.vault_write_lock(vault_id);
    let _guard = lock.lock().await;
    Some(migrate_legacy_now(state, vault_id, step))
}

/// LEGACY(aux addressing, services row): at unlock (run detached, after the
/// unlock handler released the vault write lock): pull this vault's items,
/// write the native copies and push them; then, after another pull, retire
/// the legacy rows whose copies the cloud now holds and push those
/// tombstones. A copy that did not land (an error, a refusal, a conflict
/// left for later) keeps its legacy row live for a later unlock, so no
/// reader ever sees a setting gone. A retirement that conflicts (the legacy
/// row changed meanwhile) keeps theirs and is reported by the push.
pub(crate) async fn migrate_legacy_after_unlock(state: Arc<AppState>, vault_id: String) {
    let pull = || crate::sync::pull_items_now(&state, &vault_id);
    let Some(n) = migrate_legacy_after(&state, &vault_id, pull(), LegacyStep::Copies).await else {
        return;
    };
    if n > 0 {
        crate::sync::refresh_after_item_pull(&state, &vault_id);
        crate::sync::push_items_best_effort(&state, &vault_id).await;
    }
    let on_cloud = crate::sync::cloud_configured();
    let step = LegacyStep::Retire { on_cloud };
    if let Some(m) = migrate_legacy_after(&state, &vault_id, pull(), step).await {
        if m > 0 {
            crate::sync::refresh_after_item_pull(&state, &vault_id);
            crate::sync::push_items_best_effort(&state, &vault_id).await;
        }
    }
}

/// How long op creation waits for GitHub to check a source before the card
/// says it could not be checked (the requester's own request times out at
/// 15 s).
const SOURCE_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Op creation: admit the definitions, check where they come from (a GitHub
/// source is fetched again through `api` at its pinned commit; definitions it
/// does not hold refuse the op), compute the `service-add` card from the
/// unlocked session and stamp it into the scope (over anything the requester
/// sent in its fields).
pub(crate) async fn mint_add<A: GitHubApi>(
    state: &AppState,
    vault_id: &str,
    op: &mut crate::protocol::operation::Operation,
    api: &A,
) -> std::result::Result<(), String> {
    let req = parse_add(&op.act.scope)?;
    let snapshot = admit_add(&req)?;
    // Collisions and the add/update rule first: nothing is fetched for a
    // request the vault refuses anyway.
    let (entries, _) = session(state, vault_id)?;
    card::add_card(
        &snapshot,
        &req.source,
        SourceCheck::NotReached,
        req.update,
        &entries,
        &state.services,
    )?;
    let check = match tokio::time::timeout(
        SOURCE_CHECK_TIMEOUT,
        github::verify(api, &req.source, &req.defs),
    )
    .await
    {
        Ok(checked) => checked?,
        Err(_) => SourceCheck::NotReached,
    };
    let (entries, _) = session(state, vault_id)?;
    let c = card::add_card(
        &snapshot,
        &req.source,
        check,
        req.update,
        &entries,
        &state.services,
    )?;
    c.stamp(&mut op.act.scope)?;
    // The source as stored (with whether this device checked it), so every
    // reader of the signed scope reads one spelling.
    let mut source = req.source;
    source.set_checked(check == SourceCheck::Fetched);
    op.act.scope["source"] = serde_json::to_value(&source).map_err(|e| e.to_string())?;
    Ok(())
}

/// Op creation: compute the `service-rm` card (`op.act.target` = a service
/// id or a source identity) and stamp it.
pub(crate) fn stamp_rm_at_mint(
    state: &AppState,
    vault_id: &str,
    op: &mut crate::protocol::operation::Operation,
) -> std::result::Result<(), String> {
    let target = op.act.target.trim().to_string();
    if target.is_empty() {
        return Err("service-rm target (a service id or a source) required".into());
    }
    let (entries, conns) = session(state, vault_id)?;
    let c = card::rm_card(&target, &entries, |id| connections_using(conns.iter(), id))?;
    c.stamp(&mut op.act.scope)?;
    Ok(())
}

/// Write the changed definitions and refresh the session: the usual reseal +
/// reconcile + cache refresh ([`crate::auth::connect::persist_mutated_view`]),
/// which writes each changed service as its own native `service` item and a
/// removed one as a native tombstone, on every vault (data records, like
/// connections). The legacy `services` record is never rewritten here.
pub(crate) fn persist(
    state: &Arc<AppState>,
    vault_id: &str,
    base: &crate::storage::sealed_vault::ViewBase,
    view: &crate::storage::plaintext::VaultPlaintextView,
    k: &[u8],
) -> Result<()> {
    crate::auth::connect::persist_mutated_view(state, vault_id, base, view, k)
        .map_err(AppError::Internal)
}

/// Apply a `service-add`: the stored definitions of the source become exactly
/// `snapshot` (its other services are removed), each stored in the object
/// form with the source. `Err` when the signed card differs from the card the
/// opened vault gives now. The source check is the one stamped at op creation
/// (made by this process over these exact definitions; an op is immutable once
/// created, and approval compares the grant's op with the stored one).
pub(crate) fn apply_add(
    view: &mut crate::storage::plaintext::VaultPlaintextView,
    req: AddRequest,
    snapshot: &BTreeMap<String, ServiceDef>,
    signed_scope: &Value,
    reg: &ServiceRegistry,
) -> std::result::Result<card::AddCard, String> {
    let check = signed_scope
        .get("source_check")
        .and_then(|v| v.as_str())
        .and_then(SourceCheck::parse)
        .ok_or_else(|| changed_since("source_check"))?;
    let c = card::add_card(
        snapshot,
        &req.source,
        check,
        req.update,
        &view.aux.services,
        reg,
    )?;
    if let Some(f) = c.first_difference(signed_scope) {
        return Err(changed_since(f));
    }
    for id in &c.removes {
        view.aux.services.remove(id);
    }
    // Stored with the check the approved card states.
    let mut source = req.source;
    source.set_checked(check == SourceCheck::Fetched);
    for (id, (svc, pol)) in req.defs {
        view.aux
            .services
            .insert(id, StoredService::new(svc, pol, Some(source.clone())));
    }
    Ok(c)
}

/// Apply a `service-rm` of `target`; same card discipline as [`apply_add`].
pub(crate) fn apply_rm(
    view: &mut crate::storage::plaintext::VaultPlaintextView,
    target: &str,
    signed_scope: &Value,
) -> std::result::Result<card::RmCard, String> {
    let conns = view.aux.connections.clone();
    let c = card::rm_card(target, &view.aux.services, |id| {
        connections_using(conns.iter(), id)
    })?;
    if let Some(f) = c.first_difference(signed_scope) {
        return Err(changed_since(f));
    }
    for id in &c.ids {
        view.aux.services.remove(id);
    }
    Ok(c)
}

fn changed_since(field: &str) -> String {
    format!(
        "the vault changed since this request was made (`{}` differs from what was approved); re-run the command",
        field
    )
}

/// One `aux.services` entry as `sc service ls` shows it: its source, whether
/// the daemon loads it (and if not, why), the connections that name it, and
/// what it applies (destinations, rules) when it loads.
pub(crate) fn listing(
    entries: &BTreeMap<String, StoredService>,
    conns: &HashMap<String, Connection>,
    reg: &ServiceRegistry,
) -> Vec<Value> {
    entries
        .iter()
        .map(|(id, e)| {
            let parts = e.parts().ok();
            let digest = parts.as_ref().map(|p| {
                crate::service::source::definition_digest(&p.service, p.policy.as_deref())
            });
            let source = parts.and_then(|p| p.source);
            let (summary, problems) = if crate::storage::item::is_conflict_copy_name(id) {
                (None, vec![crate::service::CONFLICT_COPY_REASON.to_string()])
            } else if reg.get(id).is_some() {
                (None, vec!["shadows a built-in id".to_string()])
            } else {
                match e.admit(id) {
                    Ok(d) => (Some(card::summarize(&d)), Vec::new()),
                    Err(ps) => (None, ps),
                }
            };
            json!({
                "id": id,
                "source": source,
                "valid": problems.is_empty(),
                "problems": problems,
                "connections": connections_using(conns.iter(), id),
                "summary": summary,
                "digest": digest,
            })
        })
        .collect()
}

/// `GET /v/{vid}/services`: the vault's own definitions from the unlocked
/// session (no network, no passkey; the same exposure as `/v/{vid}/registry`,
/// which already serves these definitions). A locked vault answers 423.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<Value>> {
    crate::server::handlers::op::validate_vault_id(&vault_id)?;
    let (entries, conns) = session(&state, &vault_id).map_err(|_| AppError::VaultLocked)?;
    Ok(Json(json!({
        "services": listing(&entries, &conns, &state.services),
    })))
}

#[cfg(test)]
mod tests;
