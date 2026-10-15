//! Console install requests: a `service_request:<id>` item asks this vault's
//! daemons to install a service from a source, through the same path as
//! `sc service add` (the daemon fetches the source, the gate admits it, op
//! creation checks it again and stamps the card). A source the vault already
//! holds is updated to the source's current head, as `sc service update`
//! does: the console's Update is the same request.
//!
//! The console writes `{ source, ref?, requested_at }`. On an unlocked sync
//! one daemon claims a request (`claimed_by`, a compare-and-swap write at the
//! row's version: another device's claim wins and this one leaves it), then
//! writes `op_id` (the pending `service-add` op), `up_to_date: true` (an
//! update whose definitions match what the vault holds: nothing to approve)
//! or `error` (what `sc service add` would print). The request is removed
//! once its op is resolved; a request claimed here whose op this process does
//! not hold (it restarted) gets [`EXPIRED`]. A request with `up_to_date` or
//! `error` stays for the console to show and clear.
//!
//! One source has at most one open request (not failed, not up to date): a
//! request for a source an older open request already names is removed
//! unclaimed, so two tabs or devices asking at once get one approval.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::approval::store::ApprovalStatus;
use crate::error::AppError;
use crate::service::source::github::{self, GitHubApi};
use crate::service::source::{self, SourceSpec};
use crate::state::AppState;
use crate::storage::item::{wire_id_for, ItemNs, ItemPayload, VaultKeys};
use crate::sync::PushOutcome;

/// The error a request claimed here gets when its op is gone.
pub(crate) const EXPIRED: &str = "the approval request expired; install again";

/// Where a request's op stands in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpState {
    Pending,
    /// Applied, rejected, expired or withdrawn.
    Resolved,
    /// Not held here (this process restarted since it was created).
    Gone,
}

/// The ops this process created for requests (a resolved op may be dropped
/// from the approval store; one created before a restart is not here).
fn created() -> &'static Mutex<BTreeSet<String>> {
    static CREATED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    CREATED.get_or_init(Default::default)
}

pub(crate) fn op_state(state: &AppState, op_id: &str) -> OpState {
    let store = state.approvals.lock().unwrap();
    match store.get_any(op_id) {
        Some(r) if matches!(r.status, ApprovalStatus::Pending) && !r.is_expired() => {
            OpState::Pending
        }
        Some(_) => OpState::Resolved,
        None if created().lock().unwrap().contains(op_id) => OpState::Resolved,
        None => OpState::Gone,
    }
}

/// What this device does with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Claim,
    /// Claimed here, and its op is gone: [`EXPIRED`].
    Expire,
    /// Its op is resolved: remove it.
    Remove,
    Leave,
}

/// The step for request `body` on the device `me`.
pub(crate) fn step(body: &Value, me: &str, op: impl Fn(&str) -> OpState) -> Step {
    let text = |k: &str| body.get(k).and_then(|v| v.as_str());
    if body.get("error").is_some_and(|v| !v.is_null())
        || body.get("up_to_date") == Some(&json!(true))
    {
        return Step::Leave;
    }
    match text("claimed_by") {
        None => Step::Claim,
        Some(c) if c != me => Step::Leave,
        Some(_) => match text("op_id") {
            None => Step::Expire,
            Some(id) => match op(id) {
                OpState::Pending => Step::Leave,
                OpState::Resolved => Step::Remove,
                OpState::Gone => Step::Expire,
            },
        },
    }
}

/// Pushes one sealed row to the cloud with compare-and-swap.
#[allow(async_fn_in_trait)]
pub(crate) trait ItemPush {
    /// `None`: no cloud is configured (the write stays local).
    async fn push(
        &self,
        vault: &str,
        item_id: &str,
        base: Option<u64>,
        version: u64,
        ct_b64: &str,
        generation: Option<u64>,
    ) -> Option<Result<PushOutcome, String>>;
}

/// The cloud this device syncs with.
pub(crate) struct Cloud;

impl ItemPush for Cloud {
    async fn push(
        &self,
        vault: &str,
        item_id: &str,
        base: Option<u64>,
        version: u64,
        ct_b64: &str,
        generation: Option<u64>,
    ) -> Option<Result<PushOutcome, String>> {
        let cfg = crate::cli::active::load().ok()?;
        let cloud = cfg.cloud_backend.filter(|s| !s.is_empty())?;
        let dk = crate::sync::device_key()?;
        Some(
            crate::sync::push_item(&cloud, vault, &dk, item_id, base, version, ct_b64, generation)
                .await,
        )
    }
}

/// How a request write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    Done,
    /// Another writer changed the row first; nothing was written here.
    Taken,
}

/// Write request `name` as `body` (`None`: remove it) over the row this
/// device holds, compare-and-swap at the version the cloud is known to hold.
pub(crate) async fn write<P: ItemPush>(
    state: &Arc<AppState>,
    vault: &str,
    name: &str,
    body: Option<Value>,
    push: &P,
) -> Result<Written, String> {
    type S = sudp::primitives::StdPrimitives;
    let lock = state.vault_write_lock(vault);
    let _guard = lock.lock().await;
    let k = state
        .cloned_state_key(vault)
        .ok_or_else(|| crate::error::VAULT_LOCKED_MSG.to_string())?;
    let keys = VaultKeys::from_material(&k);
    let path = state.vaults.per_item_path(vault).map_err(|e| e.to_string())?;
    let mut pv = crate::storage::sealed_vault::read_per_item(&path)
        .map_err(|e| e.to_string())?
        .ok_or("this vault has no item store")?;
    let id = wire_id_for::<S>(keys.id_seed, ItemNs::ServiceRequest, name).map_err(|e| e.to_string())?;
    let (version, synced) = pv
        .items
        .get(&id)
        .map(|r| (r.version, r.synced_version))
        .ok_or("the request is gone")?;
    let payload = match body {
        Some(b) => ItemPayload::live(ItemNs::ServiceRequest, name, b),
        None => ItemPayload::tombstone(ItemNs::ServiceRequest, name),
    };
    pv.seal_and_upsert::<S>(keys, vault, ItemNs::ServiceRequest, name, version + 1, &payload)
        .map_err(|e| e.to_string())?;
    let row = pv.items[&id].clone();
    let ct = URL_SAFE_NO_PAD.encode(&row.ct);
    let base = (synced > 0).then_some(synced);
    match push
        .push(vault, &id, base, row.version, &ct, row.generation)
        .await
    {
        None | Some(Ok(PushOutcome::EndpointMissing)) => {}
        Some(Ok(PushOutcome::Ok { .. })) => {
            if let Some(r) = pv.items.get_mut(&id) {
                r.synced_version = r.version;
                r.base = None;
            }
        }
        Some(Ok(PushOutcome::Conflict { .. })) => return Ok(Written::Taken),
        Some(Ok(PushOutcome::Rejected { status, error })) => {
            return Err(format!("the cloud refused the write ({}: {})", status, error))
        }
        Some(Ok(PushOutcome::KeysetChanged)) => {
            return Err("the vault key changed; the request waits for the next sync".into())
        }
        Some(Err(e)) => return Err(e),
    }
    crate::storage::sealed_vault::write_per_item_atomic(&path, &pv).map_err(|e| e.to_string())?;
    Ok(Written::Done)
}

fn app_error_text(e: AppError) -> String {
    match e {
        AppError::BadRequest(m) => m,
        other => other.to_string(),
    }
}

/// Install what request `name` (`body`) asks for, as `sc service add
/// <source> [--ref <ref>]` does: the owner switch, the source read from
/// GitHub through `fetch_api` and admitted by the gate, then the op created
/// through [`crate::server::handlers::op::create_op`] (`mint_api`: `None` =
/// GitHub itself), naming the request in its scope (`service_request`) and
/// no agent. `Ok(Some(op_id))`, `Ok(None)` when the vault already holds
/// exactly these definitions from the source (nothing to approve), or the
/// message `sc service add` would print.
pub(crate) async fn install<A: GitHubApi>(
    state: &Arc<AppState>,
    vault: &str,
    name: &str,
    body: &Value,
    fetch_api: &A,
    mint_api: Option<&A>,
) -> Result<Option<String>, String> {
    let (entries, _, allowed) = super::session(state, vault)?;
    if !allowed {
        return Err(crate::service::INSTALLED_OFF_MSG.to_string());
    }
    let src = body.get("source").and_then(|v| v.as_str()).unwrap_or("");
    let git_ref = body.get("ref").and_then(|v| v.as_str());
    let spec = match source::parse_source(src)? {
        SourceSpec::GitHub(g) => g,
        _ => {
            return Err(format!(
                "'{}' is not a GitHub source; write github:owner/repo[:path]",
                crate::util::terminal_safe(src)
            ))
        }
    };
    let (files, stated) = github::fetch(fetch_api, &spec, git_ref)
        .await
        .map_err(|p| source::problems_text(src, &p))?;
    // Installing a source the vault holds updates it; a single-service
    // source keeps the id it is stored under, as `sc service update` does.
    let mine = source::card::stored_from(&entries, &stated.identity());
    let keep = match mine.keys().collect::<Vec<_>>().as_slice() {
        [id] if files.single => Some(id.as_str()),
        _ => None,
    };
    let admitted =
        source::admit_files(&files, keep).map_err(|p| source::problems_text(src, &p))?;
    let digest = |svc: &str, pol: Option<&str>| source::definition_digest(svc, pol);
    let unchanged = !mine.is_empty()
        && mine.len() == admitted.len()
        && admitted.iter().all(|a| {
            mine.iter().any(|(id, e)| {
                **id == a.id
                    && e.parts().is_ok_and(|p| {
                        digest(&p.service, p.policy.as_deref())
                            == digest(&a.service, a.policy.as_deref())
                    })
            })
        });
    if unchanged {
        return Ok(None);
    }
    let built_in: Vec<String> = admitted
        .iter()
        .filter(|a| state.services.get(&a.id).is_some())
        .map(|a| {
            format!(
                "'{}' is a built-in service id; store it under another id with --id",
                crate::util::terminal_safe(&a.id)
            )
        })
        .collect();
    if !built_in.is_empty() {
        return Err(source::problems_text(src, &built_in));
    }
    let mut op: crate::protocol::operation::Operation = serde_json::from_value(source::add_op(
        vault,
        &stated,
        &admitted,
        crate::util::now_unix(),
    ))
    .map_err(|e| e.to_string())?;
    op.act.scope["service_request"] = json!(name);
    let resp = crate::server::handlers::op::create_op(
        state,
        vault.to_string(),
        op,
        None,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        mint_api,
    )
    .await
    .map_err(app_error_text)?;
    let op_id = resp
        .get("op_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "the op was not created".to_string())?;
    created().lock().unwrap().insert(op_id.clone());
    Ok(Some(op_id))
}

/// Request `name` as this device's store holds it now (`None`: removed or
/// absent).
fn current(state: &AppState, vault: &str, name: &str) -> Option<Value> {
    type S = sudp::primitives::StdPrimitives;
    let k = state.cloned_state_key(vault)?;
    let path = state.vaults.per_item_path(vault).ok()?;
    let pv = crate::storage::sealed_vault::read_per_item(&path).ok()??;
    let payload = pv
        .open_item::<S>(VaultKeys::from_material(&k), vault, ItemNs::ServiceRequest, name)
        .ok()??;
    (!payload.is_tombstone()).then_some(payload.body)
}

/// The source identity a request names (`None`: not a GitHub source).
fn request_identity(body: &Value) -> Option<String> {
    match source::parse_source(body.get("source")?.as_str()?).ok()? {
        SourceSpec::GitHub(g) => Some(g.identity()),
        _ => None,
    }
}

/// Whether request `body` (on the device `me`) is still open: not failed,
/// not up to date, and its op (when this device holds it) not resolved. One
/// another device claimed counts as open: that device resolves it.
fn is_open(body: &Value, me: &str, op: impl Fn(&str) -> OpState) -> bool {
    if body.get("error").is_some_and(|v| !v.is_null())
        || body.get("up_to_date") == Some(&json!(true))
    {
        return false;
    }
    let mine = body.get("claimed_by").and_then(|v| v.as_str()) == Some(me);
    match body.get("op_id").and_then(|v| v.as_str()) {
        Some(id) if mine => op(id) == OpState::Pending,
        _ => true,
    }
}

/// Whether an older open request in `others` (name, body) names the same
/// source as request `name` (`body`): then `name` is a duplicate.
pub(crate) fn duplicate_of_older(
    name: &str,
    body: &Value,
    others: &[(String, Value)],
    me: &str,
    op: impl Fn(&str) -> OpState + Copy,
) -> bool {
    let Some(want) = request_identity(body) else {
        return false;
    };
    let at = |b: &Value| b.get("requested_at").and_then(|v| v.as_u64()).unwrap_or(0);
    others.iter().any(|(n, b)| {
        n != name
            && (at(b), n.as_str()) < (at(body), name)
            && request_identity(b).as_deref() == Some(want.as_str())
            && is_open(b, me, op)
    })
}

/// Handle the requests `names` of `vault` on the device `me`, one at a time,
/// each as the store holds it now.
pub(crate) async fn process<A: GitHubApi, P: ItemPush>(
    state: &Arc<AppState>,
    vault: &str,
    names: Vec<String>,
    me: &str,
    fetch_api: &A,
    mint_api: Option<&A>,
    push: &P,
) {
    let log = |name: &str, e: String| {
        tracing::warn!(vault = %vault, request = %name, "service request: {}", e);
    };
    for name in names {
        let Some(body) = current(state, vault, &name) else {
            continue;
        };
        let next = match step(&body, me, |id| op_state(state, id)) {
            Step::Leave => continue,
            Step::Remove => None,
            Step::Expire => {
                let mut b = body.clone();
                b["error"] = json!(EXPIRED);
                Some(b)
            }
            Step::Claim => {
                let others: Vec<(String, Value)> = state
                    .service_request_names(vault)
                    .into_iter()
                    .filter_map(|n| current(state, vault, &n).map(|b| (n, b)))
                    .collect();
                if duplicate_of_older(&name, &body, &others, me, |id| op_state(state, id)) {
                    if let Err(e) = write(state, vault, &name, None, push).await {
                        log(&name, e);
                    }
                    continue;
                }
                let mut claimed = body.clone();
                claimed["claimed_by"] = json!(me);
                match write(state, vault, &name, Some(claimed.clone()), push).await {
                    Ok(Written::Done) => {}
                    Ok(Written::Taken) => continue,
                    Err(e) => {
                        log(&name, e);
                        continue;
                    }
                }
                match install(state, vault, &name, &claimed, fetch_api, mint_api).await {
                    Ok(Some(op_id)) => claimed["op_id"] = json!(op_id),
                    Ok(None) => claimed["up_to_date"] = json!(true),
                    Err(e) => claimed["error"] = json!(e),
                }
                Some(claimed)
            }
        };
        if let Err(e) = write(state, vault, &name, next, push).await {
            log(&name, e);
        }
    }
}

/// Vaults whose requests are being handled now (one pass per vault at a time).
fn running() -> &'static Mutex<BTreeSet<String>> {
    static RUNNING: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    RUNNING.get_or_init(Default::default)
}

/// After a sync of an unlocked vault: handle its requests in the background
/// (nothing while locked, or without requests, a runtime or a device
/// identity).
pub(crate) fn after_sync(state: &Arc<AppState>, vault: &str) {
    let names = state.service_request_names(vault);
    if names.is_empty() {
        return;
    }
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(me) = crate::device_auth::device_signer().map(|s| s.device_id().to_string()) else {
        return;
    };
    if !running().lock().unwrap().insert(vault.to_string()) {
        return;
    }
    let state = state.clone();
    let vault = vault.to_string();
    rt.spawn(async move {
        // One request at a time, each with GitHub's own deadline.
        for one in names {
            match super::source_check_api() {
                Ok(api) => {
                    process::<github::GitHubHttp, Cloud>(
                        &state,
                        &vault,
                        vec![one],
                        &me,
                        &api,
                        None,
                        &Cloud,
                    )
                    .await
                }
                Err(e) => tracing::warn!(vault = %vault, "service requests wait: {}", e),
            }
        }
        running().lock().unwrap().remove(&vault);
    });
}
