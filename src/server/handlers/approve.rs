//! `/op/{op_id}` family — op lifecycle (poll, approve, reject).
//!
//! - `GET  /op/{op_id}`            — poll: status + cached value + render(o)
//! - `POST /op/{op_id}/approve`    — U submits grant G; T validates, dispatches act
//! - `POST /op/{op_id}/reject`     — U denies
//!
//! All act kinds (Enroll, Write, Export, Use) flow through `approve_op`; the
//! act-specific dispatch is inlined per the SUDP protocol.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroize as _;

use axum::{
    extract::{Path, State},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

use serde_json::{json, Value};

use crate::approval::ApprovalStatus;
use crate::audit::{STATUS_APPROVED, STATUS_REJECTED};
use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::grant::{delivery_form, DeliveredVaultKey, DeliveryForm};
use crate::protocol::operation::{as_export_path, decode_credential_id, discriminator, ActType};
use crate::protocol::{render_operation, validate_batch_grant, validate_grant, Grant};
use crate::state::{AppState, ApprovalEvent, SecretsCache};
use crate::storage::plaintext::{Category, VaultPlaintextView};
use crate::storage::sealed_vault::{
    find_pubkey, find_pubkey_in_registry, read as read_vault, read_per_item, write_atomic,
    ApprovalAuthority, PerItemVault,
};
use std::collections::BTreeSet;

/// `GET /op/{op_id}` — JSON poll: status + cached value + render(o).
///
/// The agent (and the CLI's browser-callback flow) polls this for the op's
/// state. There is no HTML branch: the human approves on safeclaw.pro (the
/// op-relay carries the sealed grant back to the daemon), so the daemon serves
/// no approval page of its own (2026-06-23 zero-inbound pivot).
pub async fn get_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let waiter = headers
        .get(WAITER_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    match get_op_json(state, op_id, waiter.as_deref()).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

/// Request header carrying an Export's waiter secret (E1,
/// design/approvals-inbox.md D2). Never logged.
pub const WAITER_HEADER: &str = "x-safeclaw-waiter";

async fn get_op_json(
    state: Arc<AppState>,
    op_id: String,
    waiter: Option<&str>,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let body = op_poll_value(&state, &op_id, waiter)?;
    let pending = body.get("status").and_then(|s| s.as_str()) == Some("pending");
    let mut resp = Json(body).into_response();
    // Pending → advertise the poll pacing (Retry-After, matching the 202's
    // `approval.interval`) so agents keep a standard cadence.
    if pending {
        if let Ok(v) = axum::http::HeaderValue::from_str(
            &crate::approval::store::POLL_INTERVAL_HINT_SECS.to_string(),
        ) {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
    }
    Ok(resp)
}

/// The `/op/{id}` poll body as a plain `Value`. Shared by the axum handler
/// (above) and the 23294 API face (`proxy::api_face`), so the agent's poll loop
/// sees identical JSON whether it hit the control plane or the proxy port. Pure
/// read — briefly locks `approvals`, no I/O.
///
/// `waiter` = the `x-safeclaw-waiter` header, if any. An Export's plaintext is
/// released (and consumed) ONLY to a poll presenting the op's waiter secret
/// (E1): every other poll sees status but no `value`, and consumes nothing.
pub fn op_poll_value(state: &AppState, op_id: &str, waiter: Option<&str>) -> Result<Value> {
    let mut store = state.approvals.lock().unwrap();
    let rec = store.get(op_id).ok_or(AppError::NotFound)?;
    let waiter_ok = rec.waiter_matches(waiter);
    // Consumed ops: the approve window is closed. Return a minimal tombstone
    // — no op content — to limit the exposure window for the agent request
    // body and upstream URL that live in op.act.scope. The op_id's 122-bit
    // entropy is the access-control mechanism for in-flight ops; once the
    // op is consumed, that window should close.
    if matches!(rec.status, ApprovalStatus::Consumed) {
        return Ok(json!({
            "op_id": rec.id,
            "status": "consumed",
        }));
    }

    let act_kind = discriminator(&rec.op.act);
    let display = render_operation(&rec.op);
    let path = match &rec.op.act.kind {
        ActType::Export => Some(rec.op.act.target.clone()),
        _ => None,
    };
    let op_json = serde_json::to_value(&rec.op)?;
    // Whether this op reveals a raw secret (Export). Its plaintext must be
    // SINGLE-USE: handed to the one poll that delivers it, then tombstoned —
    // `sc secret get`'s remote arm reads `value` from exactly this poll, and the
    // op was minted `multiplicity: one`. Leaving it re-readable let a co-resident
    // process re-fetch the secret for the op's whole TTL.
    let is_export = matches!(rec.op.act.kind, ActType::Export);
    let id = rec.id.clone();
    let r = rec.r.clone();
    let expires_at_unix = rec.expires_at_unix;
    let superseded_by = rec.superseded_by.clone();
    let satisfied_by = rec.satisfied_by.clone();
    let retry_count = rec.retry_count.max(1);
    let (status, value) = match &rec.status {
        ApprovalStatus::Pending => ("pending", None),
        // "ok" is the skill-documented terminal (done — result in `value`). The
        // internal enum stays `Approved`; only the wire status is normalized so
        // the agent's poll loop (`ok`/`pending`/`rejected`) recognizes completion.
        //
        // `value` shape by act: a Use caches the upstream envelope as a JSON
        // string — emit it as the OBJECT the skill documents ({status, headers,
        // body}), matching the allow fast-path, instead of a double-encoded
        // string agents must re-parse. Export stays a raw string (the plaintext
        // secret is opaque — never parse it, even when it happens to be JSON).
        ApprovalStatus::Approved => {
            let v = rec.cached_value.clone().map(|s| match &rec.op.act.kind {
                ActType::Use => serde_json::from_str::<Value>(&s).unwrap_or(Value::String(s)),
                _ => Value::String(s),
            });
            ("ok", v)
        }
        ApprovalStatus::Rejected { .. } => ("rejected", None),
        ApprovalStatus::Consumed => unreachable!("handled above"),
    };
    // E1: an Export's value reaches only its creating process. Without the
    // waiter secret the poll reports status alone and the plaintext stays
    // put (not consumed) for the creator.
    let value = if is_export && !waiter_ok { None } else { value };
    // A rejected op's reason distinguishes a USER rejection from a mechanical
    // withdrawal ("superseded by a newer request") — the waiter renders them
    // differently, so a superseded `sc up`/`sc lock` never reads as "the user
    // said no" (it confused exactly that way before this field existed).
    let reason = match &rec.status {
        ApprovalStatus::Rejected { reason } if !reason.is_empty() => Some(reason.clone()),
        _ => None,
    };
    // Consume an Export's plaintext on delivery (single-use). Only Export —
    // a Use result is the agent's own upstream reply, which its poll loop may
    // legitimately re-read; consuming it would break an interrupted retry. The
    // `rec` borrow ends above (everything below is owned), so the &mut is clean.
    if is_export && value.is_some() {
        store.consume(&id);
    }
    // Liveness: a poll carrying the valid waiter secret proves the creator
    // is still waiting (the abandoned-Export reaper keys off this).
    if waiter_ok {
        store.touch_waiter(&id);
    }
    Ok(json!({
        "op_id": id,
        "r": r,
        "status": status,
        "reason": reason,
        "act": act_kind,
        "path": path,
        "display": display,
        "op": op_json,
        "value": value,
        "expires_at": expires_at_unix,
        // Intent chain (design/approvals-inbox.md D1). Display only: a
        // superseded op is still `pending` and still approvable; a satisfied
        // one mirrors the applied op's body plus the pointer.
        "superseded_by": superseded_by,
        "satisfied_by": satisfied_by,
        "retry_count": retry_count,
    }))
}

/// Apply-time assertion (design/approvals-inbox.md D1): what the approver was
/// shown is exactly what apply grants. The SIGNED Use scope's `level` must
/// equal the record's PolicyContext level, and its reuse fields (`reuse`,
/// `reuse_rule` / `reuse_label` / `reuse_class`) and `window_s` must be exactly
/// what [`crate::approval::Reuse::of`] yields for that context (what decided
/// the request, the scope's own `scoped` marker and `method`): the same
/// classifier the proxy stamped with and [`plan_use_grant`] writes from. A Use
/// op must carry both: a scope with no signed `level`, or a `level` with no
/// `reuse`, is refused (every mint stamps both, and the approval store is
/// in-memory, so no live op predates them). `Err` carries the human reason;
/// the caller picks the arm's error variant.
fn assert_signed_level(
    scope: &Value,
    pc: Option<&crate::approval::PolicyContext>,
) -> std::result::Result<(), String> {
    let Some(signed) = scope.get("level") else {
        return Err(
            "this use request carries no signed policy level, so what approving it grants is not stated; re-run the request".into(),
        );
    };
    let pc = pc.ok_or("signed level on an op with no policy context")?;
    let signed = signed.as_str().ok_or("signed level is not a string")?;
    if signed != pc.level.to_string() {
        return Err(format!(
            "signed level '{}' does not match the policy this op was minted under ('{}')",
            signed, pc.level
        ));
    }
    let method = scope.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let expected = crate::approval::Reuse::of(
        pc.level,
        &pc.decided_by,
        crate::approval::reuse::is_scoped(scope),
        method,
    )
    .ok_or("a deny-level op has nothing to approve")?;
    expected.check_signed(scope, pc.ttl_seconds)
}

/// The per-op Export checks — run on EVERY Export apply, plain or batch arm
/// (design/approvals-inbox.md D2: batching changes the gesture, never these).
/// Returns the export path.
fn export_precheck(op: &crate::protocol::operation::Operation) -> Result<&str> {
    // F-15: reject KEM-sealed Export until it is implemented.
    // If a client submits a grant with bind.recipient set, the raw-reveal
    // path would silently ignore it and return the secret in plain TLS.
    // Block this until a proper HPKE-sealed Export path is available.
    if op.bind.recipient.is_some() {
        return Err(AppError::BadRequest(
            "KEM-sealed Export not yet implemented; omit bind.recipient".into(),
        ));
    }
    let path = as_export_path(op)?;
    // RETIRED: whole-vault reveal-all (`target = "env"` / "").
    // An Export must name ONE secret so its plaintext egress stays
    // scope-constrained (and single-use). The console editor no longer
    // uses a daemon reveal-all — it derives its `{kv, aux}` view
    // client-side (`revealAllVault = unlockVault`), and `sc secret get`
    // always names a specific key. Refuse the unbounded form outright so
    // no path can dump the whole vault's plaintext through one op.
    if path == "env" || path.is_empty() {
        return Err(AppError::BadRequest(
            "reveal-all export is retired — export a specific secret by name".into(),
        ));
    }
    Ok(path)
}

/// Best-effort: if the acting credential's stored keyset row carries no KCV yet,
/// compute it from the `W_c` that just unlocked the vault and persist it (then
/// push the keyset row cloud-side so it survives pulls and reaches other
/// devices).
///
/// The KCV is a check value over `W_c` (the browser compares a re-derived `W_c`
/// against it), so it is computed from `W_c` ONLY: never from a delivered vault
/// key, and never on a v2 (UIK) keyset, where the secret behind a passkey is the
/// identity root and custody slots carry their own check values. Under grant v3
/// no grant delivers `W_c` to the daemon, so this only runs for a caller that
/// genuinely holds a v1 credential's `W_c`. Idempotent; never fatal to the
/// unlock (failures are logged and swallowed).
fn maybe_backfill_wc_check(state: &Arc<AppState>, vault_id: &str, cid: &[u8], w_c: &[u8]) {
    let Ok(per_item_path) = state.vaults.per_item_path(vault_id) else {
        return;
    };
    let mut pv = match crate::storage::sealed_vault::read_per_item(&per_item_path) {
        Ok(Some(pv)) => pv,
        _ => return, // no per-item keyset (legacy or unreadable) — skip
    };
    if pv.keyset.uik.is_some() {
        return; // v2: the passkey secret is the identity root, not W_c
    }
    let Some(cred) = pv
        .keyset
        .credentials
        .iter_mut()
        .find(|c| c.credential_id == cid)
    else {
        return;
    };
    if cred.wc_check.is_some() {
        return; // already present (freshly enrolled with a KCV, or backfilled)
    }
    let wc = match sudp::primitives::wc_check_value::<sudp::primitives::HkdfSha256>(
        w_c,
        &cred.prf_salt,
        cid,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "wc_check backfill KDF failed: {}", e);
            return;
        }
    };
    cred.wc_check = Some(wc.to_vec());
    if let Err(e) = crate::storage::sealed_vault::write_per_item_atomic(&per_item_path, &pv) {
        tracing::warn!(vault = %vault_id, "wc_check backfill write failed: {}", e);
        return;
    }
    tracing::info!(vault = %vault_id, "backfilled wc_check for the acting credential");
    let state = state.clone();
    let vid = vault_id.to_string();
    tokio::spawn(async move {
        crate::sync::push_keys_best_effort(&state, &vid).await;
    });
}

/// Every custom act the dispatch below handles. Keep in lockstep with the
/// `ActType::Custom` match arms — `consent::tests::dispatch_and_table_agree`
/// fails when this list and acts.toml drift in either direction, so an act
/// can't ship without approval copy (and dead copy can't linger).
pub(crate) const DISPATCHED_CUSTOM_ACTS: &[&str] = &[
    "vault-unlock",
    "vault-lock",
    "vault-delete",
    "rename-passkey",
    "widen-host",
    "narrow-host",
    "service-rm",
    "service-add",
    "secret-rm",
    "connection-rm",
    "connection-add",
    "secret-set",
];

/// Validate a `secret-set`'s KEY + host binding and return the normalized
/// (uppercase KEY, hosts). Shared by the grant-approve path and the unlocked
/// local write path so the two can't diverge on what a valid set is.
pub(crate) fn validate_secret_set(
    key_raw: &str,
    hosts: &[String],
    no_broker: bool,
) -> Result<(String, Vec<String>)> {
    let key = key_raw.trim().to_ascii_uppercase();
    if !crate::cli::conn::valid_role(&key) {
        return Err(AppError::BadRequest(format!(
            "'{}' is not a valid secret key",
            key_raw.trim()
        )));
    }
    if no_broker && !hosts.is_empty() {
        return Err(AppError::BadRequest(
            "secret-set: no_broker and hosts are mutually exclusive".into(),
        ));
    }
    if !hosts.is_empty() {
        let conn = key.to_ascii_lowercase();
        if !crate::cli::conn::valid_conn_id(&conn) {
            return Err(AppError::BadRequest(format!(
                "can't derive a connection id from '{}'",
                key
            )));
        }
        for h in hosts {
            crate::cli::conn::validate_raw_host(h).map_err(AppError::BadRequest)?;
        }
    }
    Ok((key, hosts.to_vec()))
}

/// Apply a `secret-set` to an open vault view: write the value at its bare KEY
/// and (un)anchor its raw connection. Returns whether a prior host anchor was
/// removed. The KEY/hosts must already be [`validate_secret_set`]-normalized.
/// Shared by the grant-approve path and the unlocked local write path.
pub(crate) fn apply_secret_set_to_view(
    view: &mut crate::storage::plaintext::VaultPlaintextView,
    key: &str,
    value: Vec<u8>,
    hosts: &[String],
    no_broker: bool,
) -> bool {
    let conn = key.to_ascii_lowercase();
    view.native_secrets.insert(key.to_string(), value);
    if no_broker {
        // Opting out must actually un-broker: drop the raw connection a prior
        // `sc set <key> --host …` created.
        view.aux.connections.remove(&conn).is_some()
    } else if !hosts.is_empty() {
        view.aux.connections.insert(
            conn,
            crate::storage::plaintext::Connection {
                name: None,
                service: None,
                hosts: Some(hosts.to_vec()),
                secrets: Some(vec![key.to_string()]),
                keys: None,
                // This op wrote the key's value above.
                written: Some(vec![key.to_string()]),
            },
        );
        false
    } else {
        false
    }
}

/// Apply a `connection-rm` to an open vault view: drop the record and, unless
/// `keep_secrets`, delete the native keys `connection_removal` plans (written
/// by this connection, bound by no other). Its rule (`policy:connection:<id>`)
/// goes too where this process may write owner-config
/// ([`crate::storage::item::device_may_write`]: a vault without a keyset,
/// `has_keyset` false), so a later connection of the same id does not take it
/// over. On a vault with a keyset the rule is owner-signed config and stays:
/// the owner's console removes it. Returns the deleted keys and the plan (its
/// kept lists carry the reasons). The SSOT for the mutation, so tests drive
/// the code the approve path runs.
pub(crate) fn apply_connection_rm_to_view(
    view: &mut crate::storage::plaintext::VaultPlaintextView,
    id: &str,
    keep_secrets: bool,
    has_keyset: bool,
    reg: &crate::service::ServiceRegistry,
) -> std::result::Result<(Vec<String>, crate::storage::plaintext::ConnectionRemoval), String> {
    let rec = view
        .aux
        .connections
        .get(id)
        .cloned()
        .ok_or_else(|| format!("no connection '{}' in this vault", id))?;
    let plan = if keep_secrets {
        crate::storage::plaintext::ConnectionRemoval::default()
    } else {
        let (custom, _) = crate::service::vault_custom_services(
            &view.aux.services,
            view.aux.allows_installed_services(),
            reg,
        );
        crate::storage::plaintext::connection_removal(
            id,
            &rec,
            &view.aux.connections,
            &view.native_secrets,
            &crate::service::ServiceDefs {
                reg,
                custom: &custom,
            },
        )
    };
    let mut removed = Vec::new();
    for key in &plan.delete {
        if view.native_secrets.remove(key).is_some() {
            removed.push(key.clone());
        }
    }
    view.aux.connections.remove(id);
    let rule = format!("{}{}", crate::storage::item::POLICY_CONNECTION, id);
    if crate::storage::item::device_may_write(
        crate::storage::item::ItemNs::Policy,
        &rule,
        has_keyset,
        true,
    ) {
        if let Some(policy) = view.aux.policy.as_mut() {
            policy.connections.remove(id);
        }
    }
    Ok((removed, plan))
}

/// Whether `vault_id` has a keyset with members, as its per-item store says
/// (`keyset.uik`): the rule table's `has_keyset` for what this process may
/// write. A vault with no store (a whole-blob vault) has none; a store that
/// cannot be read counts as having one, so owner-config is never written on
/// a guess.
fn vault_has_keyset(state: &AppState, vault_id: &str) -> bool {
    let Ok(path) = state.vaults.per_item_path(vault_id) else {
        return true;
    };
    match crate::storage::sealed_vault::read_per_item(&path) {
        Ok(Some(pv)) => pv.keyset.uik.is_some(),
        Ok(None) => false,
        Err(_) => true,
    }
}

/// `POST /op/{op_id}/approve` — U submits the signed grant. T validates and
/// dispatches the act (Enroll / Write / Export / Use).
/// Batch-arm pre-verification (design/batch-approve.md §Daemon verify 1-5):
/// bounds BEFORE any record load, then rebuild the Merkle root from the
/// daemon's OWN stored (o, r) pairs in `op_ids` order and derive the tagged
/// challenge. Sibling lookup is status- and expiry-agnostic (`get_any`) —
/// rows apply at independent times, so earlier siblings are legitimately
/// Approved/Consumed/expired by the time later rows arrive; only a genuinely
/// absent record fails the rebuild. The root memo in `state.batch_roots`
/// makes later rows of an honest batch O(1) here; the WebAuthn verify and
/// every per-row check still run in the shared validation core.
fn batch_expected_challenge(
    state: &AppState,
    op_id: &str,
    vault_id: &str,
    grant: &Grant,
) -> Result<[u8; 32]> {
    use crate::crypto::batch::{batch_challenge, batch_root, BATCH_MAX, BATCH_MIN};
    use crate::crypto::binding::{binding_for_op, DOMAIN_STANDARD};

    let batch = grant
        .batch
        .as_ref()
        .ok_or_else(|| AppError::BatchVerify("grant carries no batch proof".into()))?;
    let n = batch.op_ids.len();
    if !(BATCH_MIN..=BATCH_MAX).contains(&n) {
        return Err(AppError::BatchVerify(format!(
            "batch size {} outside {}..={}",
            n, BATCH_MIN, BATCH_MAX
        )));
    }
    {
        let mut seen = std::collections::HashSet::with_capacity(n);
        for id in &batch.op_ids {
            if !seen.insert(id.as_str()) {
                return Err(AppError::BatchVerify("duplicate op id in batch".into()));
            }
        }
    }
    if !batch.op_ids.iter().any(|i| i == op_id) {
        return Err(AppError::BatchVerify(
            "op is not a member of its own batch".into(),
        ));
    }

    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cache_key = format!("{}|{}", grant.credential_id, batch.op_ids.join(","));
    if let Some((root, exp)) = state.batch_roots.lock().unwrap().get(&cache_key).copied() {
        if exp >= now_s {
            return Ok(batch_challenge(&root));
        }
    }

    let (root, max_exp) = {
        let store = state.approvals.lock().unwrap();
        let mut betas: Vec<[u8; 32]> = Vec::with_capacity(n);
        let mut max_exp = 0u64;
        for id in &batch.op_ids {
            let rec = store
                .get_any(id)
                .ok_or_else(|| AppError::BatchVerify(format!("unknown batch member op {}", id)))?;
            if rec.vault_id != vault_id {
                return Err(AppError::BatchVerify("batch spans vaults".into()));
            }
            // The consent boundary, not an optimization: lifecycle and
            // high-consequence kinds keep the per-op ceremony. Export joins
            // behind E1 (design/approvals-inbox.md D2) — its value reaches
            // only the creating waiter — and every per-op Export check still
            // runs at this row's own apply (`export_precheck`).
            if !matches!(rec.op.act.kind, ActType::Use | ActType::Export) {
                return Err(AppError::BatchVerify(
                    "batch may contain only `use` and `export` ops".into(),
                ));
            }
            let r_bytes = STANDARD
                .decode(&rec.r)
                .map_err(|_| AppError::BatchVerify("stored r not base64".into()))?;
            let op_value = serde_json::to_value(&rec.op)?;
            betas.push(binding_for_op(DOMAIN_STANDARD, &r_bytes, &op_value)?);
            max_exp = max_exp.max(rec.expires_at_unix);
        }
        let root = batch_root(&betas).ok_or_else(|| AppError::BatchVerify("empty batch".into()))?;
        (root, max_exp)
    };

    {
        let mut cache = state.batch_roots.lock().unwrap();
        cache.retain(|_, (_, exp)| *exp >= now_s);
        if cache.len() >= 64 {
            if let Some(k) = cache
                .iter()
                .min_by_key(|(_, (_, e))| *e)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&k);
            }
        }
        cache.insert(cache_key, (root, max_exp));
    }
    Ok(batch_challenge(&root))
}

/// Who raised the ops this daemon holds: the account it is paired to, its
/// pinned account UIK (`account`, from [`crate::cli::active::account_uik`]). The
/// daemon acts for that one account, so that is the requester, whatever else
/// the keyset seats. Membership data is not consulted when the pin exists: it
/// is server-served, and since an admin's passkeys now ride the membership
/// (`approver: true`, adopted into the registry, which is never pruned) a
/// registry-derived set could name an admin, or a demoted one, as a requester.
///
/// Fallback for a daemon paired without an account UIK (an older backend):
/// the identities the vault seats under this device's own passkeys
/// ([`PerItemVault::own_identities`]), which excludes every credential the
/// membership served as another member's approval material.
fn requester_identities(pv: &PerItemVault, account: Option<String>) -> BTreeSet<String> {
    match account {
        Some(us) => [us].into(),
        None => pv.own_identities(),
    }
}

/// The paired account's UIK (`us_…`) this daemon acts for.
fn paired_account() -> Option<String> {
    #[cfg(test)]
    if let Some(account) = tests::PAIRED_ACCOUNT.with(|a| a.borrow().clone()) {
        return account;
    }
    crate::cli::active::account_uik()
}

/// The paired account's UIK signing key, pinned at pairing from the verified
/// admit signer (`sc login`). Self-certifying against [`paired_account`].
fn paired_account_pub() -> Option<[u8; 32]> {
    #[cfg(test)]
    if let Some(pk) = tests::PAIRED_ACCOUNT_PUB.with(|a| *a.borrow()) {
        return pk;
    }
    crate::cli::active::account_uik_pub()
}

/// Decode base64url-no-pad (the grant v3 wire form), standard base64 tolerated.
fn decode_b64_wire(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| STANDARD.decode(s))
        .ok()
}

/// Grant v3 (contract C3, design approval-key-delivery §1 I4): a grant delivers
/// the vault key (`k_enc`/`k_ct`) and nothing else. An unlock secret (`wk_*`,
/// or the plaintext `wrapping_key`) is the approver's `W_c` or UIK root, which
/// never leaves their browser: refused outright on every vault, before
/// anything is opened. Both or neither form stays a malformed grant.
fn require_vault_key_delivery(grant: &Grant, pv: Option<&PerItemVault>) -> Result<()> {
    match delivery_form(grant)? {
        DeliveryForm::SealedVaultKey => Ok(()),
        DeliveryForm::Plain | DeliveryForm::SealedSecret => {
            let shared = pv.is_some_and(|pv| pv.keyset.uik.is_some());
            Err(AppError::WkRefused(format!(
                "this approval delivered an unlock secret{}; SafeClaw takes only the vault key \
                 and the approver's signature. Reload the approval page and approve again",
                if shared { " on a shared vault" } else { "" }
            )))
        }
    }
}

/// Verify a grant's identity signature (contract C3) and return the approver it
/// proves (`us_…`). Runs FIRST among the crypto checks (design §2 order):
/// decode → `id_sig` over this op's own stored `(o, r)` β, the raw passkey id,
/// the K seal hash and THIS daemon's `sc_pk`, under `id`'s key (the pinned
/// account key, or a self-certifying key the vault holds for `id`) → on a v2
/// vault the approving passkey's identity label must be `id` (a server can't
/// pass one person's passkey off as another's). Nothing is consumed on a
/// failure: [`AppError::GrantIdInvalid`] leaves the op pending.
fn verify_grant_identity(
    state: &AppState,
    pv: Option<&PerItemVault>,
    vault_id: &str,
    op_id: &str,
    grant: &Grant,
    stored_op: &crate::protocol::operation::Operation,
    stored_r: &str,
) -> Result<String> {
    let invalid = |m: &str| AppError::GrantIdInvalid(m.to_string());
    let id = grant
        .id
        .as_deref()
        .filter(|s| s.starts_with("us_"))
        .ok_or_else(|| invalid("the approval carries no approver id"))?;
    let sig: [u8; 64] = grant
        .id_sig
        .as_deref()
        .and_then(decode_b64_wire)
        .and_then(|v| <[u8; 64]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| invalid("the approval carries no valid identity signature"))?;
    let (Some(k_enc), Some(k_ct)) = (
        grant
            .k_enc
            .as_deref()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok()),
        grant
            .k_ct
            .as_deref()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok()),
    ) else {
        return Err(AppError::BadRequest(
            "a sealed grant needs both k_enc and k_ct (base64url)".into(),
        ));
    };
    let cid = decode_credential_id(&grant.credential_id)?;
    let r_bytes = STANDARD
        .decode(stored_r)
        .map_err(|_| AppError::Internal("stored r not base64".into()))?;
    let beta = crate::crypto::binding::binding_for_op(
        crate::crypto::binding::DOMAIN_STANDARD,
        &r_bytes,
        &serde_json::to_value(stored_op)?,
    )?;
    let sc_pk = state.sc.pk_bytes();
    let input =
        crate::identity::grant_id_input(vault_id, op_id, &beta, &cid, &k_enc, &k_ct, &sc_pk, id);
    let certifies =
        |pk: &[u8; 32]| crate::identity::derive_id(crate::identity::IdKind::User, pk) == id;
    let sig_pub = paired_account_pub()
        .filter(|pk| paired_account().as_deref() == Some(id) && certifies(pk))
        .or_else(|| pv.and_then(|pv| pv.identity_sig_pub(vault_id, id)))
        .ok_or_else(|| {
            invalid(&format!(
                "{id} is not an identity this device knows (not the account it is paired to, \
                 nor a member of this vault)"
            ))
        })?;
    if !crate::identity::verify(&sig_pub, &input, &sig) {
        return Err(invalid("the approver's identity signature does not verify"));
    }
    // The passkey that asserted must be the signer's own (v2 keysets label
    // every passkey with its person). A v1 keyset is a personal vault: its
    // passkeys are the paired account's, which the authority gate requires.
    if let Some(pv) = pv.filter(|pv| pv.keyset.uik.is_some()) {
        let cid_b64 = URL_SAFE_NO_PAD.encode(&cid);
        match pv.credential_identity(&cid_b64) {
            Some(owner) if owner == id => {}
            Some(owner) => {
                return Err(invalid(&format!(
                    "the approving passkey belongs to {owner}, not to the signer {id}"
                )))
            }
            None => {
                return Err(invalid(
                    "the approving passkey belongs to no identity in this vault",
                ))
            }
        }
    }
    Ok(id.to_string())
}

/// The approval-authority gate of [`approve_op`]: the VERIFIED signer
/// ([`verify_grant_identity`]) must be the requester (the paired account) or
/// an admin of the vault per its verified role fold.
fn check_approval_authority(pv: Option<&PerItemVault>, vault_id: &str, signer: &str) -> Result<()> {
    let requester = match pv {
        Some(pv) => requester_identities(pv, paired_account()),
        None => paired_account().into_iter().collect(),
    };
    authorize_approver(pv, vault_id, &requester, signer)
}

/// [`check_approval_authority`] with the requester given (unit-testable).
fn authorize_approver(
    pv: Option<&PerItemVault>,
    vault_id: &str,
    requester: &BTreeSet<String>,
    signer: &str,
) -> Result<()> {
    if requester.contains(signer) {
        return Ok(());
    }
    let Some(pv) = pv else {
        return Err(AppError::ApproverNotAuthorized(format!(
            "{signer} is not the account this device is paired to"
        )));
    };
    match pv.approval_authority(vault_id, requester, signer) {
        ApprovalAuthority::Refused(reason) => Err(AppError::ApproverNotAuthorized(reason)),
        ApprovalAuthority::Requester | ApprovalAuthority::Admin => Ok(()),
    }
}

/// Open one HPKE grant seal (`enc`/`ct`, base64url-no-pad) addressed to this
/// daemon's `sc_pk` under `info`. `name` is the wire pair's prefix (`k`) for
/// the error text. A half pair is malformed.
fn open_grant_seal(
    state: &AppState,
    enc: Option<&str>,
    ct: Option<&str>,
    name: &str,
    info: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let (Some(enc_b64), Some(ct_b64)) = (enc, ct) else {
        return Err(AppError::BadRequest(format!(
            "a sealed grant needs both {name}_enc and {name}_ct"
        )));
    };
    let enc = URL_SAFE_NO_PAD
        .decode(enc_b64)
        .map_err(|_| AppError::BadRequest(format!("{name}_enc not base64url")))?;
    let ct = URL_SAFE_NO_PAD
        .decode(ct_b64)
        .map_err(|_| AppError::BadRequest(format!("{name}_ct not base64url")))?;
    Ok(zeroize::Zeroizing::new(
        state.sc.open(&enc, &ct, info, b"")?,
    ))
}

/// Open the vault key a grant delivers (`k_*`, sealed to this daemon's `sc_pk`
/// under `grant_k_seal_info(op_id)`) into `grant.vault_key`. Nothing is
/// consumed: a malformed or mis-sealed delivery leaves the op pending with its
/// challenge live.
fn open_grant_delivery(state: &AppState, op_id: &str, grant: &mut Grant) -> Result<()> {
    let info = crate::crypto::envelope::grant_k_seal_info(op_id);
    let mut k = open_grant_seal(
        state,
        grant.k_enc.as_deref(),
        grant.k_ct.as_deref(),
        "k",
        &info,
    )?;
    grant.vault_key = Some(DeliveredVaultKey::new(std::mem::take(&mut *k))?);
    Ok(())
}

pub async fn approve_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    Json(mut grant): Json<Grant>,
) -> Result<Json<Value>> {
    // 0. §15: a device that is not admitted, past its lease, or revoked applies
    // no grant (K was evicted; nothing may re-open it). The op stays pending.
    if let Some(e) = state.ledger_refusal() {
        return Err(e);
    }

    // 1. Look up the pending op. A SUPERSEDED op is still `Pending` and still
    // approvable (design/approvals-inbox.md D1): supersede is display state,
    // and the grant verifies against this op's OWN stored (o, r).
    let (vault_id, approval_op, stored_r, stored_pc) = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
        if !matches!(rec.status, ApprovalStatus::Pending) {
            return Err(AppError::Conflict("op not pending".into()));
        }
        if rec.fail_count >= crate::approval::store::MAX_APPROVE_ATTEMPTS {
            return Err(AppError::TooManyRequests);
        }
        (
            rec.vault_id.clone(),
            rec.op.clone(),
            rec.r.clone(),
            rec.policy_context.clone(),
        )
    };

    // 2. grant.o must equal the stored op (canonical equality). Batch arm:
    // recoverable, like its twin `grant.r` check below (design §7 lists the
    // o/r equalities under batch_verify_failed).
    let canonical_grant_op = serde_json::to_value(&grant.o)?;
    let canonical_stored_op = serde_json::to_value(&approval_op)?;
    if canonical_grant_op != canonical_stored_op {
        return Err(if grant.batch.is_some() {
            AppError::BatchVerify("grant.o does not match the stored op".into())
        } else {
            AppError::BadRequest("grant.o does not match the stored op".into())
        });
    }

    // 2b. grant.r must equal THIS op's stored challenge — REQUIRED in both
    // arms (design/batch-approve.md §Daemon verify 2). The batch assertion
    // covers STORED r's, not the wire r; and even in the plain arm the
    // challenge store is daemon-global, so a relay-swapped `r` would
    // otherwise still verify (β binds whatever wire r the console was fed)
    // while consuming a SIBLING op's live single-use challenge.
    if grant.r != stored_r {
        let auto_rejected = state.approvals.lock().unwrap().record_failure(&op_id);
        if auto_rejected {
            tracing::warn!(op = %op_id, "op auto-rejected after too many failed approve attempts");
        }
        return Err(if grant.batch.is_some() {
            AppError::BatchVerify("grant.r does not match this op's challenge".into())
        } else {
            AppError::BadRequest("grant.r does not match this op's challenge".into())
        });
    }

    // 2b'. A Use op's SIGNED level/window must match the policy it was minted
    // under (design/approvals-inbox.md D1), so the approver's rendered scope
    // ("this one request" / "N min") is exactly what apply grants.
    if approval_op.act.kind == ActType::Use {
        if let Err(msg) = assert_signed_level(&approval_op.act.scope, stored_pc.as_ref()) {
            return Err(if grant.batch.is_some() {
                AppError::BatchVerify(msg)
            } else {
                AppError::BadRequest(msg)
            });
        }
    }

    // 2c. Batch arm — rebuild the Merkle root from OUR OWN stored ops and
    // derive the expected challenge (design/batch-approve.md §Daemon verify).
    // Failures here are `batch_verify_failed`: RECOVERABLE (the relay client
    // re-registers the op instead of rejecting it), never terminal.
    let batch_challenge_bytes: Option<[u8; 32]> = if grant.batch.is_some() {
        match batch_expected_challenge(&state, &op_id, &vault_id, &grant) {
            Ok(c) => Some(c),
            Err(e) => {
                let auto_rejected = state.approvals.lock().unwrap().record_failure(&op_id);
                if auto_rejected {
                    tracing::warn!(op = %op_id, "op auto-rejected after too many failed approve attempts");
                }
                return Err(e);
            }
        }
    } else {
        None
    };

    // 3. Serialize vault reads/writes per vault (F-17).
    // Two concurrent approve calls on the same vault both read the same
    // on-disk state and race to write_atomic — the second rename wins
    // silently. This per-vault async mutex ensures the full read-validate-
    // write cycle is atomic per vault without blocking unrelated vaults.
    let _vault_write_guard = state
        .vault_write_guard(&vault_id)
        .await
        .map_err(|error| error.app_error())?;

    // 3a. Re-check UNDER the vault write lock (design/approvals-inbox.md D1,
    // atomic apply). One intent chain is always one vault (redeemer ==
    // vault_id), and a chain's resolution flips every live sibling in the same
    // `approvals` critical section as the applying op's own approve — so "still
    // pending here" is exactly "this chain has not been resolved". Two grants
    // for one chain arriving together: the second waits on this lock, finds
    // the chain resolved, and its relay poll ends quietly on the 409.
    {
        let store = state.approvals.lock().unwrap();
        match store.get(&op_id) {
            Some(rec) if matches!(rec.status, ApprovalStatus::Pending) => {}
            Some(_) => return Err(AppError::Conflict("op not pending".into())),
            None => return Err(AppError::NotFound),
        }
    }

    // 3b. Resolve credential pubkey lookup.
    //
    // For Enroll, the credential is brand-new (not in vault yet) — pubkey is
    // taken from the op's scope. For Write/Export/Use, the credential must be
    // already enrolled — look it up in the existing vault.
    let vault_path = state.vaults.vault_path(&vault_id)?;
    let existing_vault = read_vault(&vault_path)?;
    // A web-enrolled vault synced down as per-item rows (vault.per-item.json)
    // has NO vault.dat — its keyset (credential pubkeys) lives in the per-item
    // store. Read it once so credential lookup + the read grants (Unlock / Use /
    // Export) below work for those vaults too.
    let mut existing_per_item = state
        .vaults
        .per_item_path(&vault_id)
        .ok()
        .and_then(|p| read_per_item(&p).ok().flatten());
    // SELF-HEAL a stale keyset registry before validating. If the credential this
    // grant is signed with isn't resolvable yet, force a FULL membership re-pull
    // and re-read. An out-of-band x/y backfill (a credential's WebAuthn pubkey
    // added to an already-synced membership) does NOT bump the membership seq, so
    // the daemon never re-pulled and `credential_lookup` misses it even though the
    // cloud offers it ("unknown credential"). Best-effort: a failed re-pull just
    // leaves the original miss to surface (now as a clear rejection, not a hang).
    // On a team (v2) keyset the passkey must also resolve to an identity (the
    // device's own entry or an admin's approver credential), else an admin's
    // passkey adopted before its label would never re-pull.
    let cred_resolvable = existing_vault
        .as_ref()
        .and_then(|v| find_pubkey(v, &grant.credential_id))
        .or_else(|| {
            existing_per_item
                .as_ref()
                .and_then(|pv| find_pubkey_in_registry(&pv.keyset.registry, &grant.credential_id))
        })
        .is_some()
        && existing_per_item.as_ref().is_none_or(|pv| {
            pv.keyset.uik.is_none()
                || decode_credential_id(&grant.credential_id)
                    .map(|b| URL_SAFE_NO_PAD.encode(b))
                    .is_ok_and(|cid| pv.credential_identity(&cid).is_some())
        });
    if !cred_resolvable {
        match crate::sync::resync_membership_now(&state, &vault_id).await {
            Ok(n) => {
                tracing::info!(op = %op_id, vault = %vault_id, adopted = n, "approve self-heal: re-pulled membership for unresolved credential");
                existing_per_item = state
                    .vaults
                    .per_item_path(&vault_id)
                    .ok()
                    .and_then(|p| read_per_item(&p).ok().flatten());
            }
            Err(e) => tracing::debug!(op = %op_id, "approve self-heal re-pull failed: {}", e),
        }
    }
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        existing_vault
            .as_ref()
            .and_then(|v| find_pubkey(v, cred_id_b64))
            .or_else(|| {
                existing_per_item
                    .as_ref()
                    .and_then(|pv| find_pubkey_in_registry(&pv.keyset.registry, cred_id_b64))
            })
    };
    // 3c. Grant v3 (design approval-key-delivery §2, contract C3), in order:
    // the delivery form (the vault key, never an unlock secret) → the
    // approver's identity signature over THIS op → authority on that verified
    // identity → open the vault key → (below) the WebAuthn assertion. Nothing
    // before apply consumes the op: every refusal here leaves it pending with
    // its challenge live and never counts toward auto-reject. A batch grant
    // lands here once per op row, each row judged on its own signature.
    let refuse = |e: AppError| {
        tracing::warn!(op = %op_id, vault = %vault_id, "approval refused: {}", e);
        e
    };
    if grant.o.act.kind == ActType::Enroll {
        return Err(AppError::BadRequest(ENROLL_RETIRED.into()));
    }
    require_vault_key_delivery(&grant, existing_per_item.as_ref()).map_err(refuse)?;
    let signer = verify_grant_identity(
        &state,
        existing_per_item.as_ref(),
        &vault_id,
        &op_id,
        &grant,
        &approval_op,
        &stored_r,
    )
    .map_err(refuse)?;
    check_approval_authority(existing_per_item.as_ref(), &vault_id, &signer).map_err(refuse)?;
    // The K seal is sealed to our `sc_pk` and bound to this op id, so a cloud
    // intermediary carrying the grant never saw K. A batch row's malformed
    // seal is recoverable (batch_verify_failed), like every other bad row.
    if let Err(e) = open_grant_delivery(&state, &op_id, &mut grant) {
        return Err(match e {
            AppError::BadRequest(msg) if grant.batch.is_some() => AppError::BatchVerify(msg),
            other => other,
        });
    }

    let validated = {
        let result = {
            let mut chs = state.challenges.lock().unwrap();
            match &batch_challenge_bytes {
                // Batch arm: same shared validation core, challenge = the
                // domain-tagged root rebuilt above from our own op store.
                Some(chal) => validate_batch_grant(
                    &grant,
                    chal,
                    &mut chs,
                    &state.config.relying_party,
                    lookup_credential,
                ),
                None => validate_grant(
                    &grant,
                    &mut chs,
                    &state.config.relying_party,
                    lookup_credential,
                ),
            }
        };
        match result {
            Ok(v) => v,
            Err(e) => {
                // Track failure; auto-reject op if limit reached.
                let auto_rejected = state.approvals.lock().unwrap().record_failure(&op_id);
                if auto_rejected {
                    tracing::warn!(op = %op_id, "op auto-rejected after too many failed approve attempts");
                }
                return Err(e);
            }
        }
    };

    // 3b. Verify bind.redeemer matches the vault this op was created for.
    // SUDP §4 binds an op to a specific custodian/vault via bind.redeemer;
    // failing to check this would let a grant authorized for vault A be
    // submitted against vault B's approve endpoint.
    if validated.op.bind.redeemer != vault_id {
        return Err(AppError::Unauthorized(
            "grant.o.bind.redeemer does not match vault".into(),
        ));
    }

    // 4. Act dispatch — same logic that previously lived in grant.rs.
    // Captured here for the audit row finalize at the bottom (Use's upstream
    // status code; None for all other act kinds).
    let audit_upstream_status: Option<i64> = None;
    // A Use apply's grant/cache write is DEFERRED until the op is actually
    // marked approved (step 5): any status flip that bypasses the vault write
    // lock (a user reject, a requester withdrawal, the reaper, an auto-reject)
    // can land between dispatch and approve, and must never leave a live
    // grant behind an op that reads rejected.
    let mut deferred_grant: Option<DeferredGrant> = None;
    let (response, cached_value) = match &validated.op.act.kind {
        // Retired (refused at op creation and before validation above): a vault
        // and its passkeys are created in the console, where the identity key
        // already lives (design approval-key-delivery §4).
        ActType::Enroll => {
            return Err(AppError::BadRequest(ENROLL_RETIRED.into()));
        }
        // Retired (also refused at op creation): see WHOLE_BLOB_WRITE_RETIRED.
        ActType::Write => {
            return Err(AppError::BadRequest(WHOLE_BLOB_WRITE_RETIRED.into()));
        }
        ActType::Revoke => {
            // Remove-passkey. `target = "passkeys.<cid_b64>"`. K stays
            // the same — we only drop the named credential's SealedCredential
            // entry and Registry record. At-least-one safeguard prevents
            // locking the user out of their own vault.
            //
            // Acting credential CAN revoke itself (matches per-VM and 1P
            // behavior — user might want to remove a compromised device).
            // The at-least-one safeguard still catches "revoking the only
            // remaining credential".
            let target = validated.op.act.target.as_str();
            let cid_b64 = target.strip_prefix("passkeys.").ok_or_else(|| {
                AppError::BadRequest("revoke target must be 'passkeys.<credential_id>'".into())
            })?;
            let mut vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            if vault.credentials.len() <= 1 {
                return Err(AppError::BadRequest(
                    "cannot remove the last passkey — add another one first".into(),
                ));
            }
            let cid_bytes = decode_credential_id(cid_b64)?;
            if vault.find_credential(&cid_bytes).is_none() {
                return Err(AppError::BadRequest(
                    "target credential not enrolled on this vault".into(),
                ));
            }
            vault.credentials.retain(|c| c.credential_id != cid_bytes);
            vault.registry.remove(&cid_bytes);
            write_atomic(&vault_path, &vault)?;
            tracing::info!(
                vault = %vault_id,
                cred_count = vault.credentials.len(),
                "vault revoke-passkey applied"
            );
            (
                json!({ "ok": true, "act": "revoke", "target": target }),
                None,
            )
        }
        ActType::Export => {
            let path = export_precheck(&validated.op)?;
            // Read seam: per-item store first, whole-blob vault.dat as fallback
            // (Option — a web-enrolled per-item vault has no vault.dat).
            let view = crate::server::handlers::metadata::open_view_for_grant(
                &state,
                &vault_id,
                &validated.op,
                validated.key(),
                &validated.credential_id_bytes,
                existing_vault.as_ref(),
            )?;
            {
                let raw = view
                    .resolve_value_async(path)
                    .await?
                    .ok_or(AppError::NotFound)?;
                let value = String::from_utf8(raw)
                    .map_err(|_| AppError::Internal("resolved item not utf8".into()))?;
                (
                    json!({ "ok": true, "act": "export", "path": path, "value": value.clone() }),
                    Some(value),
                )
            }
        }
        ActType::Use => {
            // Read seam (per-item first, whole-blob Option fallback) lives inside
            // the broker resolve call — so a web-enrolled per-item vault
            // (no vault.dat) resolves without the old "vault not initialized" bail.
            // Phantom-only: an approved Use op is ALWAYS authorize_only — the
            // resident proxy serves live traffic and retries the real request
            // after approval. Resolve the connection's primary secret with the
            // verified grant and stash it so the retry fast-paths; never forward
            // here (there is no buffered request on the op plane).
            let s_o = crate::server::broker::resolve_use_primary(
                &validated.op,
                validated.key(),
                &validated.credential_id_bytes,
                existing_vault.as_ref(),
                &state,
                &vault_id,
            )
            .await?;
            let scope = &validated.op.act.scope;
            let (pc, grant_agent) = {
                let store = state.approvals.lock().unwrap();
                let rec = store.get(&op_id);
                (
                    rec.and_then(|r| r.policy_context.clone()),
                    rec.and_then(|r| r.agent_prefix.clone()).unwrap_or_default(),
                )
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            deferred_grant = plan_use_grant(pc.as_ref(), scope, &vault_id, &grant_agent, s_o, now);
            if deferred_grant.is_none() {
                tracing::warn!(
                    vault = %vault_id, op = %op_id,
                    "use approve without a full binding — grant not stored (replay will re-prompt)"
                );
            }
            (
                json!({ "ok": true, "act": "use", "authorized": true, "stream": true }),
                None,
            )
        }
        ActType::Custom(name) => match name.as_str() {
            // Lifecycle op (H3 / PROTOCOL.md §6.3): decrypt vault, bootstrap
            // secrets_cache for allow-policy services, transition to Unlocked,
            // and return all target plaintexts to the requester (the same
            // shape Export-with-target="env" returned, so /try's editor
            // doesn't need a separate reveal call).
            "vault-unlock" => {
                // Read seam: per-item store first (a web-enrolled vault has only
                // vault.per-item.json, no vault.dat), whole-blob as Option fallback.
                let (mut view, unlock_key) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                // The general read seam can return a partial per-item view so
                // existing rows remain usable. Unlock is stricter: the new key
                // must open every current row before this flag is cleared.
                let has_per_item = state
                    .vaults
                    .per_item_path(&vault_id)
                    .ok()
                    .is_some_and(|p| p.exists());
                if has_per_item {
                    view = crate::sync::fold_with_key(&state, &vault_id, &unlock_key)
                        .ok_or_else(|| {
                            AppError::Unauthorized(
                                "the approved key does not open the vault's current rows".into(),
                            )
                        })?;
                } else {
                    state.clear_vault_key_changed(&vault_id);
                }
                // Before the vault serves: every held row is offered again under
                // the key, then the cloud is pulled. A failed pull keeps
                // retrying in the background and is reported (`sc status`).
                let (adopted, pull_error) =
                    crate::sync::catch_up_at_unlock(&state, &vault_id, &unlock_key).await;
                if adopted {
                    if let Some(v) = crate::sync::fold_with_key(&state, &vault_id, &unlock_key) {
                        view = v;
                    }
                }
                // vault-unlock is a pure STATE TRANSITION: it uses the grant's
                // W_c to open the vault, bootstrap the daemon's in-memory
                // secrets cache, and flip the vault unlocked. It deliberately
                // returns NO secret material. The console editor derives its
                // `{kv, aux}` view entirely client-side (it pulls the sealed
                // per-item rows and unseals them under its own passkey PRF —
                // `unlockVault` in the frontend), the CLI reads only the ok
                // status, and the grant page discards the response body. A
                // cached plaintext here served no consumer and was readable via
                // the (capability-gated) op-poll — so a routine unlock left the
                // whole vault's plaintext retrievable. Plaintext leaves the
                // daemon ONLY through a scope-constrained, single-use `Export`
                // op (the passkey-gated `sc secret get` / reveal path), never
                // here. Bootstrap the cache from `view` (every allow-policy
                // service's auth value via the v3 store_order; native-only at
                // unlock — external adapters fetch lazily at /use); never
                // materialize kv.
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    "vault unlocked"
                );
                state.unlock_vault(vault_id.clone(), cache, unlock_key);
                match pull_error {
                    Some(e) => {
                        crate::sync::retry_pull_after_unlock(state.clone(), vault_id.clone(), e)
                    }
                    None => state.clear_catch_up(&vault_id),
                }
                // LEGACY(aux addressing, services row): now that K is held,
                // pull, then move the legacy rows to their native records (a
                // vault without a keyset), then push. Detached: it takes the
                // vault write lock after this handler releases it. The fold
                // reads the same configuration before and after.
                tokio::spawn(
                    crate::server::handlers::service_ops::migrate_legacy_after_unlock(
                        state.clone(),
                        vault_id.clone(),
                    ),
                );
                // Backfill the acting credential's key-check value if the stored
                // keyset predates it (best-effort; we hold the write guard). This
                // lets a later cross-device approval fail FAST in the browser
                // (the KCV won't match a divergent W_c) instead of silently
                // hanging on an unseal the daemon can't complete.
                // A delivered vault key is not the passkey's secret: nothing to backfill.
                if let Ok(secret) = validated.custody_secret() {
                    maybe_backfill_wc_check(
                        &state,
                        &vault_id,
                        &validated.credential_id_bytes,
                        secret,
                    );
                }
                // On unlock, complete any pending OAuth connect: a
                // browser "Connect" may have sealed `<conn>_oauth_pending`
                // into the vault while it was locked (or before this device
                // synced). Run it detached — it acquires the per-vault write
                // lock itself, so it must start AFTER this handler's
                // `_vault_write_guard` drops (the lock is not reentrant).
                // Best-effort + never fatal (CONNECTIONS_AND_AUTH.md §4a).
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::auth::connect::process_vault_connects(&state, &vid, None).await;
                    });
                }
                let resp = json!({ "ok": true, "act": "vault-unlock" });
                // No cached value: unlock returns no secret, so nothing is
                // stashed for the op-poll to hand back.
                (resp, None)
            }
            // Lifecycle op: drop the cache and flip Locked. No vault read
            // needed — pure state transition. Requires a fresh grant so an
            // attacker with the user's session token can't DOS-lock without
            // a passkey gesture.
            "vault-lock" => {
                state.lock_vault(&vault_id);
                tracing::info!(vault = %vault_id, "vault locked");
                (json!({ "ok": true, "act": "vault-lock" }), None)
            }
            // Lifecycle op: wipe the vault's on-disk state (vault.dat +
            // any sibling blob files) and clear the in-memory locked/
            // unlocked entry. Passkey-gated through the standard grant
            // machinery so a stolen session token can't destroy data. Once
            // approved, this is irreversible — the user must re-enroll to
            // get a new vault.
            "vault-delete" => {
                if existing_vault.is_none() {
                    return Err(AppError::Conflict("vault not initialized".into()));
                }
                drop(_vault_write_guard);
                state
                    .close_vault(
                        &vault_id,
                        crate::vault_runtime::TombstoneReason::Deleted,
                        true,
                    )
                    .await;
                tracing::info!(vault = %vault_id, "vault deleted");
                (json!({ "ok": true, "act": "vault-delete" }), None)
            }
            // Rename a passkey's `device_name`. Pure registry update — K,
            // M, and credentials list stay untouched. Modeled as Custom
            // (not Write/Rotate) because it doesn't mutate the protected
            // state, just an opaque public-info field.
            //
            // Wire shape: `target = "passkeys.<cid_b64>"`,
            // `scope = { device_name: "<new name>" }`.
            // Acting credential authenticates via the standard grant
            // pipeline. Self-rename allowed (matches per-VM UX).
            "rename-passkey" => {
                let target = validated.op.act.target.as_str();
                let cid_b64 = target.strip_prefix("passkeys.").ok_or_else(|| {
                    AppError::BadRequest(
                        "rename-passkey target must be 'passkeys.<credential_id>'".into(),
                    )
                })?;
                let new_name = validated
                    .op
                    .act
                    .scope
                    .get("device_name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::BadRequest("rename-passkey scope.device_name required".into())
                    })?
                    .trim()
                    .to_string();
                if new_name.is_empty() {
                    return Err(AppError::BadRequest("device_name cannot be empty".into()));
                }
                if new_name.len() > 120 {
                    return Err(AppError::BadRequest(
                        "device_name too long (max 120 chars)".into(),
                    ));
                }
                let mut vault = existing_vault
                    .clone()
                    .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
                let cid_bytes = decode_credential_id(cid_b64)?;
                let mut pk = vault
                    .registry
                    .get::<sudp::passkey::WebAuthn>(&cid_bytes)
                    .map_err(|e| AppError::Internal(format!("registry get: {}", e)))?
                    .ok_or_else(|| {
                        AppError::BadRequest("target credential not enrolled on this vault".into())
                    })?;
                pk.device_name = new_name.clone();
                vault
                    .registry
                    .insert::<sudp::passkey::WebAuthn>(&cid_bytes, &pk)
                    .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
                write_atomic(&vault_path, &vault)?;
                tracing::info!(
                    vault = %vault_id,
                    cred = %cid_b64,
                    "passkey rename applied"
                );
                (
                    json!({ "ok": true, "act": "rename-passkey", "target": target, "device_name": new_name }),
                    None,
                )
            }
            // Component C — one-tap host widen. The agent hit a destination the
            // connection doesn't anchor; the user approves adding that exact
            // FQDN as a permanent grant. Session-level today (the in-memory
            // routing snapshot is widened so the agent's retry passes the
            // anchor); durable persistence into `aux.connections[conn].hosts`
            // is the documented follow-up (see BUILD_NOTES: widen durable write).
            "widen-host" => {
                let conn = validated
                    .op
                    .act
                    .scope
                    .get("connection_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let host = validated
                    .op
                    .act
                    .scope
                    .get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if conn.is_empty() || host.is_empty() {
                    return Err(AppError::BadRequest(
                        "widen-host scope needs connection_id + host".into(),
                    ));
                }
                // Session snapshot first, so the agent's immediate retry passes
                // the anchor, then persist DURABLY into `aux.connections[conn]`
                // so the grant survives a restart / re-unlock — the same
                // open -> mutate -> reseal -> push path connection-add/secret-set
                // use. The grant already carries W_c (every approve path attaches
                // it, act-agnostic: cli/approve.rs + fe vault-grant.ts), so this
                // opens + reseals the vault like any other mutating custom act.
                state.widen_connection_host(&vault_id, &conn, &host);
                crate::cli::conn::validate_raw_host(&host).map_err(AppError::BadRequest)?;
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                match view.aux.connections.get_mut(&conn) {
                    Some(rec) => {
                        let hosts = rec.hosts.get_or_insert_with(Vec::new);
                        if !hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
                            hosts.push(host.clone());
                        }
                    }
                    // No explicit record = a synthesized default connection
                    // (`conn` names a catalog/custom service, brokered off its
                    // declared hosts). Materialise a record that keeps the
                    // service binding and pins the just-approved host.
                    None => {
                        let bound_service = (state.services.get(&conn).is_some()
                            || crate::service::vault_custom_services(
                                &view.aux.services,
                                view.aux.allows_installed_services(),
                                &state.services,
                            )
                            .0
                            .contains_key(&conn))
                        .then(|| conn.clone());
                        view.aux.connections.insert(
                            conn.clone(),
                            crate::storage::plaintext::Connection {
                                name: None,
                                service: bound_service,
                                hosts: Some(vec![host.clone()]),
                                secrets: None,
                                keys: None,
                                // Materialising the record writes no secret:
                                // the keys it binds were stored by others.
                                written: Some(Vec::new()),
                            },
                        );
                    }
                }
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, conn = %conn, host = %host, "host widened (durable)");
                (
                    json!({ "ok": true, "act": "widen-host", "connection_id": conn, "host": host }),
                    None,
                )
            }
            // Inverse of widen-host — remove a host from a connection's anchor
            // (tighten access). Minted by `sc connection rm-host`; passkey-gated
            // like every vault mutation. Durable: open under the grant, drop the
            // host from aux.connections[conn].hosts, reseal + push (the re-bootstrap
            // in persist refreshes the routing snapshot, so no session call).
            // Idempotent — a host not on the anchor is a no-op (removed = false).
            "narrow-host" => {
                let conn = validated
                    .op
                    .act
                    .scope
                    .get("connection_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let host = validated
                    .op
                    .act
                    .scope
                    .get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if conn.is_empty() || host.is_empty() {
                    return Err(AppError::BadRequest(
                        "narrow-host scope needs connection_id + host".into(),
                    ));
                }
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                let mut removed = false;
                if let Some(rec) = view.aux.connections.get_mut(&conn) {
                    if let Some(hosts) = rec.hosts.as_mut() {
                        let before = hosts.len();
                        hosts.retain(|h| !h.eq_ignore_ascii_case(&host));
                        removed = hosts.len() != before;
                    }
                }
                if removed {
                    crate::auth::connect::persist_mutated_view(
                        &state, &vault_id, &base, &view, &k,
                    )?;
                    {
                        let state = state.clone();
                        let vid = vault_id.clone();
                        tokio::spawn(async move {
                            crate::sync::push_keys_best_effort(&state, &vid).await;
                            crate::sync::push_items_best_effort(&state, &vid).await;
                        });
                    }
                }
                tracing::info!(vault = %vault_id, conn = %conn, host = %host, removed, "host narrowed");
                (
                    json!({ "ok": true, "act": "narrow-host", "connection_id": conn, "host": host, "removed": removed }),
                    None,
                )
            }
            // Remove one vault service definition, or every definition of one
            // source (`target` = a service id, or a source identity such as
            // `github:owner/repo`). Connections naming them are kept (their
            // secrets stay) and listed on the signed card; the card is
            // recomputed and compared at apply. Each removed service becomes a
            // native `service` tombstone (a data record, like a connection).
            "service-rm" => {
                let target = validated.op.act.target.trim().to_string();
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                let card = crate::server::handlers::service_ops::apply_rm(
                    &mut view,
                    &target,
                    &validated.op.act.scope,
                )
                .map_err(AppError::BadRequest)?;
                crate::server::handlers::service_ops::persist(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, removed = card.ids.len(), "service definitions removed");
                let resp = json!({
                    "ok": true, "act": "service-rm",
                    "removed": card.ids, "referencing_connections": card.connections,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Install one source's service definitions (`aux.services`), only
            // while the vault's owner allows installed services. The op
            // carries the definitions and the source; the daemon re-admits each
            // through the gate (the one the unlock load uses), refuses a built-in
            // id or one another source holds, recomputes the signed card against
            // the opened vault (refused on any difference), and on an update
            // drops the source's services it no longer has. Each service is
            // its own native `service` item (a data record, like a
            // connection): daemon-side reseal + reconcile + push.
            "service-add" => {
                let req = crate::server::handlers::service_ops::parse_add(&validated.op.act.scope)
                    .map_err(AppError::BadRequest)?;
                let snapshot = crate::server::handlers::service_ops::admit_add(&req)
                    .map_err(AppError::BadRequest)?;
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                let card = crate::server::handlers::service_ops::apply_add(
                    &mut view,
                    req,
                    &snapshot,
                    &validated.op.act.scope,
                    &state.services,
                )
                .map_err(AppError::BadRequest)?;
                crate::server::handlers::service_ops::persist(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, stored = card.ids.len(), removed = card.removes.len(), "service definitions stored");
                let resp = json!({
                    "ok": true, "act": "service-add",
                    "ids": card.ids, "removed": card.removes,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Delete a native secret KEY. Shared-pool semantics
            // (CONNECTION_SCHEMA.md §3): never cascades into a connection — the
            // referencing connections just turn unconfigured until the key is
            // re-added. Returns who referenced it so the CLI can say so. The
            // KEY name is public (rides the op), the value never does.
            "secret-rm" => {
                let key = validated.op.act.target.trim().to_ascii_uppercase();
                if key.is_empty() {
                    return Err(AppError::BadRequest(
                        "secret-rm target (key) required".into(),
                    ));
                }
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                if !view.native_secrets.contains_key(&key) {
                    // One flat namespace, two authorities: SafeClaw OWNS
                    // native items but only READS external stores — so an
                    // external-hosted key gets a precise refusal, not a
                    // misleading "not found".
                    if view.resolve_value_async(&key).await?.is_some() {
                        return Err(AppError::BadRequest(format!(
                            "key '{}' is hosted by an external store — SafeClaw reads it pass-through and cannot delete it; remove it in the provider's console",
                            key
                        )));
                    }
                    return Err(AppError::BadRequest(format!(
                        "key '{}' not found in vault",
                        key
                    )));
                }
                let referenced_by = view
                    .aux
                    .connection_claims(&state.services, "")
                    .remove(&key)
                    .unwrap_or_default();
                view.native_secrets.remove(&key);
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, key = %key, "secret removed");
                let resp = json!({
                    "ok": true, "act": "secret-rm",
                    "removed": key, "referenced_by": referenced_by,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Delete a connection record. Unless `scope.keep_secrets`, also
            // deletes the secret(s) this connection WROTE that no other
            // connection binds (`connection_removal`): a key it only bound
            // (`--from-secret`), a key another connection still claims, and
            // every key of a record that predates write tracking are kept.
            // Returns the removed list and each kept key with its reason so
            // the CLI can report them.
            "connection-rm" => {
                let id = validated.op.act.target.trim().to_string();
                if id.is_empty() {
                    return Err(AppError::BadRequest(
                        "connection-rm target (connection id) required".into(),
                    ));
                }
                let keep_secrets = validated
                    .op
                    .act
                    .scope
                    .get("keep_secrets")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                let has_keyset = vault_has_keyset(&state, &vault_id);
                let (removed_secrets, plan) = apply_connection_rm_to_view(
                    &mut view,
                    &id,
                    keep_secrets,
                    has_keyset,
                    &state.services,
                )
                .map_err(AppError::BadRequest)?;
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, connection = %id, "connection removed");
                // `kept_secrets` keeps its original shape ([key, [conn, …]]:
                // still bound elsewhere) for older CLIs; the two newer reasons
                // ride their own fields.
                let resp = json!({
                    "ok": true, "act": "connection-rm",
                    "removed": id,
                    "removed_secrets": removed_secrets,
                    "kept_secrets": plan.shared,
                    "kept_referenced": plan.referenced,
                    "kept_untracked": plan.untracked,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Create (or replace) a connection — the CLI's `sc connect`, ONE
            // approval. `scope` carries the public shape only: hosts / service /
            // referenced KEY names / an optional `values_digest` committing to
            // the new secret VALUES the CLI deposited at `/v/{vid}/op-payload`
            // (the full op rides to the cloud relay, so plaintext never can —
            // see `AppState::op_payloads`). Daemon-side reseal + push, so this
            // works over SSH via the grant link like the other write acts.
            "connection-add" => {
                let id = validated.op.act.target.trim().to_string();
                if !crate::cli::conn::valid_conn_id(&id) {
                    return Err(AppError::BadRequest(format!(
                        "'{}' is not a valid connection id",
                        id
                    )));
                }
                let scope = &validated.op.act.scope;
                let service = scope
                    .get("service")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let hosts: Option<Vec<String>> =
                    scope.get("hosts").and_then(|v| v.as_array()).map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    });
                let referenced: Vec<String> = scope
                    .get("secrets")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                // Referenced keys may name EXTERNAL-store secrets, whose
                // casing/hyphens are not ours to fold — the relaxed
                // phantom-safe charset applies here. NEW keys (deposited
                // values) keep the strict uppercase gate below: they write
                // into native-secrets, whose canonical form is UPPERCASE.
                for k in &referenced {
                    if !crate::cli::conn::valid_secret_ref(k) {
                        return Err(AppError::BadRequest(format!(
                            "'{}' is not a valid secret key reference",
                            k
                        )));
                    }
                }
                let keys: Option<std::collections::BTreeMap<String, String>> =
                    scope.get("keys").and_then(|v| v.as_object()).map(|m| {
                        m.iter()
                            .filter_map(|(r, k)| k.as_str().map(|k| (r.clone(), k.to_string())))
                            .collect()
                    });
                // A service slot may bind an existing key by name: same
                // reference charset as `secrets`.
                for k in keys.iter().flat_map(|m| m.values()) {
                    if !crate::cli::conn::valid_secret_ref(k) {
                        return Err(AppError::BadRequest(format!(
                            "'{}' is not a valid secret key reference",
                            k
                        )));
                    }
                }
                // The committed value deposit (absent = no new values, e.g. a
                // pure `--from-secret` connection). Single-use; expiry or a
                // daemon restart between create and approve fails closed.
                let values = match scope.get("values_digest").and_then(|v| v.as_str()) {
                    Some(d) => Some(state.op_payload_take(d).ok_or_else(|| {
                        AppError::BadRequest(
                            "deposited values not found or expired — re-run the command".into(),
                        )
                    })?),
                    None => None,
                };
                if let Some(vals) = &values {
                    for k in vals.keys() {
                        if !referenced.contains(k) {
                            return Err(AppError::BadRequest(format!(
                                "deposited key '{}' is not in the approved scope.secrets",
                                k
                            )));
                        }
                        // Deposits WRITE into native-secrets — enforce the
                        // native canonical form (strict uppercase role).
                        if !crate::cli::conn::valid_role(k) || k.to_ascii_uppercase() != *k {
                            return Err(AppError::BadRequest(format!(
                                "'{}' is not a valid UPPERCASE secret key",
                                k
                            )));
                        }
                    }
                }

                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;

                // The service def, resolved as mint and the proxy resolve it:
                // the vault's valid custom defs (never shadowing a built-in
                // id), else the compiled registry.
                let (custom_defs, _) = crate::service::vault_custom_services(
                    &view.aux.services,
                    view.aux.allows_installed_services(),
                    &state.services,
                );
                let def: Option<crate::service::ServiceDef> = match &service {
                    None => None,
                    Some(svc) => Some(
                        custom_defs
                            .get(svc)
                            .or_else(|| state.services.get(svc))
                            .cloned()
                            .ok_or_else(|| {
                                AppError::BadRequest(format!("unknown service '{}'", svc))
                            })?,
                    ),
                };
                let hosts: Vec<String> = hosts.unwrap_or_default();
                if def.is_none() {
                    // RAW: anchors its own exact FQDNs; explicit `secrets` list.
                    if hosts.is_empty() {
                        return Err(AppError::BadRequest(
                            "a raw connection needs at least one host".into(),
                        ));
                    }
                    if referenced.is_empty() {
                        return Err(AppError::BadRequest(
                            "a raw connection needs at least one secret key".into(),
                        ));
                    }
                }
                for h in &hosts {
                    crate::cli::conn::validate_raw_host(h).map_err(AppError::BadRequest)?;
                }
                if let Some(def) = &def {
                    // SERVICE-backed: `hosts` here only PINS exact FQDNs inside
                    // the service's `*.suffix` wildcards.
                    for h in &hosts {
                        let ok = def
                            .service
                            .hosts
                            .iter()
                            .any(|e| crate::core::host::wildcard_matches(e, h));
                        if !ok {
                            return Err(AppError::BadRequest(format!(
                                "pinned host '{}' is not within service '{}' hosts",
                                h, def.service.id
                            )));
                        }
                    }
                }

                // Every NAMED slot's KEY is either WRITTEN here (deposited) or
                // must already be in the vault, raw and service alike; an
                // optional service role the request left unnamed binds its
                // identity KEY only if the vault holds it natively. The vault
                // is ONE flat namespace across every store: a key hosted in an
                // external store (GCP etc.) binds exactly like a native one, so
                // walk the full store_order, not just native-secrets.
                // Canonicalisation: native keys are canonically UPPERCASE (a
                // lowercase-typed reference rewrites to the stored casing);
                // external keys are accepted exactly as named. The external
                // probe is a network call, but this is a ceremony (approve)
                // path; a store outage surfaces as the approve failing loudly,
                // never as a silent "no such secret".
                let requested =
                    crate::server::handlers::connection_add::requested_slots(scope, def.as_ref())
                        .map_err(AppError::BadRequest)?;
                let deposited: std::collections::BTreeSet<String> = values
                    .as_ref()
                    .map(|v| v.keys().cloned().collect())
                    .unwrap_or_default();
                let slots = crate::server::handlers::connection_add::resolve_slots(
                    &view, requested, &deposited,
                )
                .await?;
                let native: std::collections::BTreeSet<String> =
                    view.native_secrets.keys().cloned().collect();

                // What the owner approved must be what this write does.
                let card = crate::server::handlers::connection_add::card(
                    &id,
                    service.as_deref(),
                    def.as_ref(),
                    &hosts,
                    &slots,
                    &view.aux.connections,
                    &native,
                    &crate::service::ServiceDefs {
                        reg: &state.services,
                        custom: &custom_defs,
                    },
                );
                crate::server::handlers::connection_add::assert_card(scope, &card)
                    .map_err(AppError::BadRequest)?;

                let record = crate::server::handlers::connection_add::record(
                    service.as_deref(),
                    &hosts,
                    keys.as_ref(),
                    &slots,
                    view.aux.connections.get(&id),
                );

                let written: Vec<String> = values
                    .as_ref()
                    .map(|v| v.keys().cloned().collect())
                    .unwrap_or_default();
                if let Some(vals) = values {
                    for (key, val) in vals {
                        view.native_secrets.insert(key, val.into_bytes());
                    }
                }
                view.aux.connections.insert(id.clone(), record);
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, connection = %id, "connection added");
                let resp = json!({
                    "ok": true, "act": "connection-add",
                    "id": id, "service": service,
                    "written": written, "referenced": referenced,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Store one native secret — the CLI's `sc set`, ONE approval. The
            // value rides the local `op-payload` deposit (committed by
            // `scope.values_digest`); `scope.hosts` optionally anchors a raw
            // single-secret connection at the lowercased KEY (the `sc set
            // --host` sugar), `scope.no_broker` explicitly un-brokers instead.
            "secret-set" => {
                let scope = &validated.op.act.scope;
                let no_broker = scope
                    .get("no_broker")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let hosts_in: Vec<String> = scope
                    .get("hosts")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let (key, hosts) =
                    validate_secret_set(&validated.op.act.target, &hosts_in, no_broker)?;
                let conn = key.to_ascii_lowercase();
                let digest = scope
                    .get("values_digest")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::BadRequest("secret-set: scope.values_digest required".into())
                    })?;
                let mut values = state.op_payload_take(digest).ok_or_else(|| {
                    AppError::BadRequest(
                        "deposited value not found or expired — re-run the command".into(),
                    )
                })?;
                let value = values.remove(&key).ok_or_else(|| {
                    AppError::BadRequest("deposited values don't match the op's key".into())
                })?;
                if !values.is_empty() {
                    return Err(AppError::BadRequest(
                        "secret-set deposit must carry exactly the op's key".into(),
                    ));
                }

                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        validated.key(),
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let base = crate::storage::sealed_vault::ViewBase::of(&view)?;
                let removed_prior_anchor = apply_secret_set_to_view(
                    &mut view,
                    &key,
                    value.into_bytes(),
                    &hosts,
                    no_broker,
                );
                // A value-only write (no hosts, no opt-out) echoes the
                // connection's CURRENT (untouched) anchors, same as the
                // unlocked fast-path response.
                let echo_hosts: Vec<String> = if hosts.is_empty() && !no_broker {
                    view.aux
                        .connections
                        .get(&conn)
                        .and_then(|c| c.hosts.clone())
                        .unwrap_or_default()
                } else {
                    hosts.clone()
                };
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &base, &view, &k)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, key = %key, "secret set");
                let resp = json!({
                    "ok": true, "act": "secret-set", "key": key,
                    "conn": if hosts.is_empty() { Value::Null } else { json!(conn) },
                    "hosts": echo_hosts,
                    "removed_prior_anchor": removed_prior_anchor,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "unsupported Custom act: {}",
                    other
                )));
            }
        },
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported act kind: {:?}",
                other
            )));
        }
    };

    // 5. Mark approved + emit event. A Use op's grant (request-bound grant,
    // ask-grant ledger entry, or held value) is written inside
    // `approve_and_commit`, only once the op is approved.
    //
    // Intent chain (design/approvals-inbox.md D1): the applying op's approve
    // and the resolution of every other live op of its chain (approved,
    // `satisfied_by` = this op, no value of its own) happen in this ONE
    // `approvals` acquisition. Their relay withdrawals are spawned below,
    // after it is released. One applied op = one grant, exactly as before.
    let (rec_id, rec_vault_id, response_preview, satisfied_siblings) = {
        let (rec, siblings) =
            approve_and_commit(&state, &op_id, cached_value.clone(), deferred_grant)?;
        let preview = match &validated.op.act.kind {
            ActType::Use => cached_value
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok()),
            _ => None,
        };
        (rec.id.clone(), rec.vault_id.clone(), preview, siblings)
    };

    // Audit: pending → approved. Best-effort; daemon UX must not depend on
    // audit being healthy.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audit_for_vault(&rec_vault_id) {
        if let Err(e) = store.finalize(
            &op_id,
            STATUS_APPROVED,
            now,
            Some(&grant.credential_id),
            None,
            audit_upstream_status,
        ) {
            tracing::warn!(vault = %rec_vault_id, op = %op_id, "audit finalize approved failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: rec_vault_id,
        approval_id: rec_id.clone(),
        kind: "approved".into(),
        op_summary: None,
        response_preview,
        reason: None,
    });

    finish_chain_siblings(
        &state,
        &satisfied_siblings,
        &ChainOutcome::Satisfied { by: &rec_id },
    );

    Ok(Json(response))
}

/// The grant a Use apply writes, chosen by [`crate::approval::Reuse`]: the
/// same classifier the proxy stamped the reuse fields with and
/// [`assert_signed_level`] checked, so what is written is the reuse the
/// approver was shown:
///   - `none` from `ask-always` (or an `ask` with no unit): a single-use
///     `op_grants` entry bound to the approved request and its tier,
///     redeemable for [`crate::state::ASK_ALWAYS_REPLAY_WINDOW_SECS`] (the
///     replay deadline, not a reuse window).
///   - `none` from an `allow`-level miss: the value is held for allow-level
///     traffic for the policy window. No ledger entry, so it never serves an
///     ask.
///   - `exact` (scoped ask): an `op_grants` entry bound to the request, value
///     digest and unit, peeked (reused) for the policy window.
///   - `rule` / `floor`: an ask-grant ledger entry for the approving agent,
///     connection, host and unit, plus the held value, for the policy window.
///
/// Each request-bound entry carries the tier
/// ([`crate::approval::reuse::BoundTier`]) the proxy's redeem derives from the
/// same decision, so it is redeemable only by a request of that tier.
///
/// `None` (nothing stored, the replay asks again) when the op has no
/// PolicyContext (none is minted without one, and approve refuses such an
/// op) or the scope lacks the binding the grant needs (no connection, or a
/// request-bound grant missing method/host/path).
pub(crate) fn plan_use_grant(
    pc: Option<&crate::approval::PolicyContext>,
    scope: &Value,
    vault_id: &str,
    agent: &str,
    value: Vec<u8>,
    now: u64,
) -> Option<DeferredGrant> {
    use crate::approval::Reuse;
    use crate::core::policy::AccessLevel;
    // Every path that stores nothing wipes the resolved secret first.
    let drop_value = |mut v: Vec<u8>| -> Option<DeferredGrant> {
        v.zeroize();
        None
    };
    let conn = scope
        .get("connection_id")
        .or_else(|| scope.get("service"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if conn.is_empty() {
        return drop_value(value);
    }
    let method = scope.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let path = scope.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let host = pc
        .and_then(|p| p.host.clone())
        .or_else(|| scope.get("host").and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_default();
    // Phase 2: the bound `[requests]` values the proxy stamped into
    // `scope.scope_vars` (and the passkey signed) fold into the grant identity,
    // rebuilt as the SAME sorted pairs the redeem path re-extracts from the
    // live request. Empty (no requests shape, or none resolved) ⇒ `""`.
    let scope_digest = crate::service::scope_digest(&crate::approval::reuse::bound_values(scope));
    let Some(p) = pc else {
        return drop_value(value);
    };
    let scoped = crate::approval::reuse::is_scoped(scope);
    let (reuse, level, ttl) = match Reuse::of(p.level, &p.decided_by, scoped, method) {
        Some(r) => (r, p.level, p.ttl_seconds),
        None => return drop_value(value),
    };
    if reuse == Reuse::None && level == AccessLevel::Allow {
        return Some(DeferredGrant::Value {
            vault_id: vault_id.to_string(),
            conn,
            value,
            expires_at: now + ttl,
            agent: agent.to_string(),
        });
    }
    if let Some(unit) = reuse.unit() {
        if host.is_empty() {
            return drop_value(value);
        }
        return Some(DeferredGrant::Ledger {
            vault_id: vault_id.to_string(),
            agent: agent.to_string(),
            conn,
            host,
            unit,
            value,
            ttl,
            expires_at: now + ttl,
        });
    }
    // `none` / `exact`: request-BOUND, keyed by the exact request the user
    // saw. Never the connection value: that would let a different request on
    // this connection use the approval.
    if method.is_empty() || host.is_empty() || path.is_empty() {
        return drop_value(value);
    }
    let Some(tier) = crate::approval::reuse::BoundTier::of(level, &p.decided_by, scoped, method)
    else {
        return drop_value(value);
    };
    let window = if tier.single_use() {
        crate::state::ASK_ALWAYS_REPLAY_WINDOW_SECS
    } else {
        ttl
    };
    Some(DeferredGrant::OpGrant {
        vault_id: vault_id.to_string(),
        agent: agent.to_string(),
        conn,
        method: method.to_string(),
        host,
        path: path.to_string(),
        scope_digest,
        tier,
        value,
        expires_at: now + window,
    })
}

/// A Use apply's grant write, captured during dispatch and executed only once
/// the op is marked approved ([`approve_and_commit`]).
pub(crate) enum DeferredGrant {
    /// Request-bound grant (`op_grants`): ask-always, a scoped ask, or an ask
    /// a rule with no id decided, keyed with the tier that minted it.
    OpGrant {
        vault_id: String,
        agent: String,
        conn: String,
        method: String,
        host: String,
        path: String,
        scope_digest: String,
        tier: crate::approval::reuse::BoundTier,
        value: Vec<u8>,
        expires_at: u64,
    },
    /// A rule / floor ask: the ask-grant ledger entry for `unit`, plus the
    /// held value its downgraded requests read.
    Ledger {
        vault_id: String,
        agent: String,
        conn: String,
        host: String,
        unit: crate::approval::reuse::GrantUnit,
        value: Vec<u8>,
        ttl: u64,
        expires_at: u64,
    },
    /// An allow-level miss: the held value only (residency, no ledger).
    Value {
        vault_id: String,
        conn: String,
        value: Vec<u8>,
        expires_at: u64,
        agent: String,
    },
}

impl DeferredGrant {
    fn write(self, state: &AppState) {
        match self {
            DeferredGrant::OpGrant {
                vault_id,
                agent,
                conn,
                method,
                host,
                path,
                scope_digest,
                tier,
                value,
                expires_at,
            } => state.op_grant_insert(
                &vault_id,
                &agent,
                &conn,
                &method,
                &host,
                &path,
                &scope_digest,
                &tier,
                value,
                expires_at,
            ),
            DeferredGrant::Ledger {
                vault_id,
                agent,
                conn,
                host,
                unit,
                value,
                ttl,
                expires_at,
            } => {
                state.record_ask_grant(&vault_id, &agent, &conn, &host, unit, ttl);
                state.cache_insert(&vault_id, &conn, value, Some(expires_at), Some(agent));
            }
            DeferredGrant::Value {
                vault_id,
                conn,
                value,
                expires_at,
                agent,
            } => state.cache_insert(&vault_id, &conn, value, Some(expires_at), Some(agent)),
        }
    }

    /// Wipe the captured secret when the grant is never written.
    fn discard(self) {
        match self {
            DeferredGrant::OpGrant { mut value, .. }
            | DeferredGrant::Ledger { mut value, .. }
            | DeferredGrant::Value { mut value, .. } => value.zeroize(),
        }
    }
}

/// Step 5 core: mark `op_id` approved and resolve its intent chain in ONE
/// `approvals` acquisition, THEN write the deferred Use grant. If the op is no
/// longer pending (a reject / withdrawal / auto-reject landed after dispatch),
/// nothing is written and the secret is wiped: an op that reads rejected never
/// has a live grant. Once approved, its status can no longer flip, so writing
/// after the mutex is released is race-free.
fn approve_and_commit(
    state: &AppState,
    op_id: &str,
    value: Option<String>,
    deferred: Option<DeferredGrant>,
) -> Result<(
    crate::approval::ApprovalRecord,
    Vec<crate::approval::ChainSibling>,
)> {
    let approved = state.approvals.lock().unwrap().approve_chain(op_id, value);
    match approved {
        Some(done) => {
            if let Some(g) = deferred {
                g.write(state);
            }
            Ok(done)
        }
        None => {
            if let Some(g) = deferred {
                g.discard();
            }
            Err(AppError::Conflict(
                "op no longer pending after validation".into(),
            ))
        }
    }
}

/// How an intent chain resolved its siblings.
pub(crate) enum ChainOutcome<'a> {
    /// `by` applied; the siblings resolved approved with `satisfied_by = by`.
    Satisfied { by: &'a str },
    /// The user rejected `by`; the siblings resolved rejected.
    Rejected { by: &'a str },
}

/// Bookkeeping for intent-chain siblings ALREADY resolved in the store
/// (`approve_chain` / `reject_chain`): audit row, SSE event, and the relay
/// withdrawal with its reason. Called after the `approvals` mutex is
/// released. The audit row is `cancelled` (a non-access outcome: the sibling
/// itself touched no credential — the applied op is the one approval of
/// record) with the pointer in its reason, matching the relay row's cancel;
/// the SSE event says the same (`cancelled` + reason).
pub(crate) fn finish_chain_siblings(
    state: &Arc<AppState>,
    siblings: &[crate::approval::ChainSibling],
    outcome: &ChainOutcome<'_>,
) {
    if siblings.is_empty() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for sib in siblings {
        let (audit_reason, relay_reason) = match outcome {
            ChainOutcome::Satisfied { by } => (
                format!("satisfied by {}", by),
                crate::relay::client::CancelReason::Satisfied { by: by.to_string() },
            ),
            ChainOutcome::Rejected { by } => (
                format!("rejected with {}", by),
                crate::relay::client::CancelReason::Rejected,
            ),
        };
        if let Ok(store) = state.audit_for_vault(&sib.vault_id) {
            if let Err(e) = store.finalize(
                &sib.id,
                crate::audit::STATUS_CANCELLED,
                now,
                None,
                Some(&audit_reason),
                None,
            ) {
                tracing::warn!(vault = %sib.vault_id, op = %sib.id, "audit finalize chain sibling failed: {}", e);
            }
        }
        state.emit_event(ApprovalEvent {
            vault_id: sib.vault_id.clone(),
            approval_id: sib.id.clone(),
            // SSE agrees with the audit row: `cancelled`, the reason carries
            // the pointer. Pollers still read `ok` / `rejected` from GET /op.
            kind: "cancelled".into(),
            op_summary: None,
            response_preview: None,
            reason: Some(audit_reason),
        });
        crate::relay::client::spawn_cancel(
            state.clone(),
            sib.vault_id.clone(),
            sib.id.clone(),
            Some(relay_reason),
        );
    }
}

pub async fn reject_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>> {
    // Default = a human said no. A caller may carry the REAL cause instead
    // (the relay client's apply-failure path does): recording an apply
    // failure as a human "no" misled every reader — the approver saw their
    // own approval come back as a denial, and the agent was told not to
    // retry a request the user in fact allowed.
    let explicit: Option<String> = body
        .as_ref()
        .and_then(|b| b.get("reason"))
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(300).collect::<String>())
        .filter(|s| !s.trim().is_empty());
    // Only a USER rejection (no carried cause) resolves the whole intent chain
    // (design/approvals-inbox.md D1): an apply failure is about THIS grant,
    // never the human's answer to the request.
    let user_rejection = explicit.is_none();
    let reason = explicit.unwrap_or_else(|| "user rejected".to_string());
    let (rec_id, rec_vault_id, rejected_siblings) = {
        let mut store = state.approvals.lock().unwrap();
        let (rec, siblings) = store
            .reject_chain(&op_id, &reason, user_rejection)
            .ok_or(AppError::NotFound)?;
        (rec.id.clone(), rec.vault_id.clone(), siblings)
    };

    // Audit: pending → rejected.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audit_for_vault(&rec_vault_id) {
        if let Err(e) = store.finalize(
            &op_id,
            STATUS_REJECTED,
            now,
            None,
            Some(reason.as_str()),
            None,
        ) {
            tracing::warn!(vault = %rec_vault_id, op = %op_id, "audit finalize rejected failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: rec_vault_id,
        approval_id: rec_id.clone(),
        kind: "rejected".into(),
        op_summary: None,
        response_preview: None,
        reason: Some(reason),
    });

    finish_chain_siblings(
        &state,
        &rejected_siblings,
        &ChainOutcome::Rejected { by: &rec_id },
    );

    Ok(Json(
        json!({ "ok": true, "op_id": rec_id, "status": "rejected" }),
    ))
}

/// The refusal for a daemon-side `ActType::Enroll` (vault create, add passkey).
/// Both need the approver's own unlock secret on the daemon, which grant v3
/// never delivers: the console creates the vault and enrolls passkeys in the
/// browser, where the identity key already lives.
pub(crate) const ENROLL_RETIRED: &str = "creating a vault and adding a passkey happen in the \
     SafeClaw console now: open it in your browser (`sc vault create` prints the link)";

/// The refusal for a whole-blob `ActType::Write`. No current client sends one
/// (console writes are per-item; the CLI writes through grant-approved
/// mutations), and applying a base-less full replacement would revert or drop
/// items another device changed since.
pub(crate) const WHOLE_BLOB_WRITE_RETIRED: &str = "whole-vault write ops are no longer supported: \
     this client is out of date. Upgrade the SafeClaw console/CLI (`sc upgrade`) and retry.";

/// The role KEYs cached for a service's connections: the declared `secrets`
/// plus any oauth `[auth].exposes` roles (derived at connect, stored UPPERCASED —
/// the phantom's lowercase segment matches case-insensitively at resolve).
fn cacheable_roles(svc: &crate::service::ServiceDef) -> Vec<String> {
    let mut roles: Vec<String> = svc.service.secrets.clone();
    if let Some(o) = svc.oauth2() {
        roles.extend(o.exposes.iter().map(|r| r.to_ascii_uppercase()));
    }
    roles
}

/// Build the per-service `secrets_cache` from a decrypted v3 view. The cache
/// carries three things per session:
///   1. `entries` — resolved auth bytes for every service whose required
///      item is currently available (any store). Per-rule evaluation at /use
///      time decides whether to USE them (Allow), prompt (Ask / AskAlways),
///      or block (Deny) — so we don't pre-filter to allow-default services
///      anymore: a rule-level Allow on a service whose default was Ask still
///      needs the bytes ready for fast-path forwarding.
///   2. `policy` — the effective policy tree (`aux.policy` overlaid on
///      compiled defaults). Holds default floors, per-tag, and
///      per-connection user policy. Built-in per-service rules are read
///      live from the service at eval, not cached here.
pub(crate) fn bootstrap_cache_from_view(
    view: &VaultPlaintextView,
    state: &AppState,
) -> SecretsCache {
    let mut cache = SecretsCache::default();
    // Effective policy = the vault's sparse `aux.policy` overlaid on compiled
    // defaults. Rebuilt here on every unlock/refresh, so a per-connection edit
    // is live on the next request (PROTOCOL.md §6.2/§6.4).
    let effective_policy = crate::core::policy::Policy::effective(view.aux.policy.as_ref());
    cache.policy = effective_policy.clone();
    cache.audit_retention_days = view.aux.audit_retention_days;
    // Residency mirrors the DECISION floor (`AppState::evaluate_request_policy`):
    // a connection's credential is pre-loaded at unlock iff its effective READ
    // floor resolves to `allow` — recipe `[default]` ⊕ the user's `aux.policy`
    // connection override, then tag, then the global `allow` floor. This
    // replaces the old `default_read_level(service) == Allow` gate, whose
    // no-`[policy]` fallback was `ask-always` (contradicting the decision layer's
    // global-`allow` floor, so the first use of a policy-less recipe always
    // prompted) and which never consulted `aux.policy` (a user tightening a
    // service to ask-always still got it resident — PROTOCOL.md §6.2). Reusing
    // `evaluate` with a GET and no rules resolves exactly that read floor, so
    // residency can't drift from the decision. `service = None` ⇒ raw connection.
    let read_floor_allows = |service: Option<&str>, conn: &str| -> bool {
        residency_read_floor_allows(&effective_policy, &state.services, service, conn)
    };
    // Routing snapshot (CONNECTION_SCHEMA.md §6): `connection_id → {service,
    // config}`. The per-service loop below bootstraps every *default* connection
    // (conn == service); a second pass after it covers *named* connections.
    cache.connections = view
        .aux
        .connections
        .iter()
        .map(|(c, conn)| (c.clone(), conn.clone()))
        .collect();
    cache.agents = view.aux.agents.clone();
    // Snapshot native-store item names (names only, never values). Surface
    // for GET /v/{vid}/secret-keys so the frontend can compute "which
    // services are reachable" without re-walking the kv map.
    for name in view.native_secrets.keys() {
        cache.native_keys.insert(name.clone());
    }
    // Snapshot external stores' adapter inputs so GET /v/{vid}/secret-keys
    // can list() them later without re-decrypting the vault. Only kinds
    // we have an adapter for today — others are skipped (they live in
    // store_order but never resolve).
    for (store_id, store) in view.aux.stores.iter() {
        if store.kind != "gcp-secret-manager" {
            continue;
        }
        // ONE adapter instance per store for the whole unlocked session:
        // this is what makes the adapter's OAuth-token cache effective
        // (F-19: the adapter zeroizes the SA private key on drop, i.e. on
        // lock). A store that fails to materialise is skipped, same as the
        // old missing-credential cases — its keys just aren't resident and
        // `secret-keys` won't list it.
        match crate::store::build_adapter(store_id, store, view) {
            Ok(adapter) => {
                cache.external_stores.insert(
                    store_id.clone(),
                    (store.clone(), std::sync::Arc::new(adapter)),
                );
            }
            Err(e) => {
                // F-20: full error in the log only; the cache carries a
                // sanitised reason for `secret-keys` to surface.
                tracing::warn!(store = %store_id, "unlock: external store adapter init failed: {}", e);
                cache.external_store_errors.push((
                    store_id.clone(),
                    format!("store '{}' unavailable", store_id),
                ));
            }
        }
    }
    // Resolution order for the lazy fill — aux.store_order restricted to the
    // adapters that actually materialised, so first-match-wins agrees with
    // `resolve_value_async`.
    cache.external_store_order = view
        .aux
        .store_order
        .iter()
        .filter(|id| {
            cache
                .external_stores
                .get(*id)
                .is_some_and(|(s, _)| s.category == Category::Value)
        })
        .cloned()
        .collect();
    for (service_id, _) in state.services.iter_sorted() {
        // PROTOCOL.md §6.2: only connections whose effective READ floor is
        // `allow` get their auth value loaded at unlock. ask / ask-always
        // connections don't sit in cache pre-approval — they're filled lazily
        // by `approve_op` after the user passkey gesture (ask) or never
        // (ask-always — fresh-decrypted-per-request via the grant's W_c and
        // immediately zeroized). Marked `from_bootstrap` so a per-path
        // ask/ask-always RULE on this (read-allow) connection still forces a
        // fresh passkey instead of riding this residency.
        if read_floor_allows(Some(service_id), service_id) {
            // The default connection's record (usually absent) may rebind a role
            // to an existing key (`keys` map); identity otherwise. Cache maps
            // stay ROLE-keyed — only the storage lookup goes through the record.
            let rec = view.aux.connections.get(service_id);
            if let Some(role) = state.services.service_env_key(service_id) {
                let key = crate::storage::plaintext::secret_key_for(rec, &role);
                if let Some(val) = view.resolve_value_native(&key) {
                    cache.entries.insert(
                        service_id.to_string(),
                        crate::state::CacheEntry {
                            value: val.to_vec(),
                            expires_at: None, // allow = lives whole unlocked session
                            from_bootstrap: true,
                            agent_prefix: None,
                        },
                    );
                }
            }

            // v4 multi-secret: resolve each declared `secrets` role so the
            // allow fast-path can inject multi-secret services without a vault
            // view. oauth services declare no injectable direct secret here
            // (their access token is minted from the refresh_token at forward),
            // but their `exposes` roles — derived at connect and stored
            // UPPERCASED — ARE injectable, so they load alongside.
            if let Some(svc) = state.services.get(service_id) {
                let mut map: std::collections::HashMap<String, Vec<u8>> =
                    std::collections::HashMap::new();
                for name in cacheable_roles(svc) {
                    let key = crate::storage::plaintext::secret_key_for(rec, &name);
                    if let Some(val) = view.resolve_value_native(&key) {
                        map.insert(name, val.to_vec());
                    }
                }
                if !map.is_empty() {
                    cache.allow_secrets.insert(service_id.to_string(), map);
                }
            }
        }

        // Built-in policy rules are NOT cached: they're read live from the
        // service registry at eval and merged with the connection's user rules
        // (`aux.policy.connections.<id>.rules`). See
        // `AppState::evaluate_request_policy`.
    }

    // Named connections (`conn_id != service_id`) bind each ROLE to its own
    // BARE key via the record's `keys` map (CONNECTION_SCHEMA.md §3; identity
    // when unmapped). The per-service loop above already covered every default
    // connection; here we add the named ones, keyed by connection_id, resolving
    // each role through its binding but storing the multi-secret map under the
    // ROLE name so the proxy's phantom resolution finds each role's bytes.
    // (Allow-level only — ask-level connections resolve lazily from the op's
    // bound `target` key.)
    for (conn, c) in view.aux.connections.iter() {
        // Raw connections (service: None) have no service to bootstrap from; their
        // bytes resolve lazily at approve. Only service-backed named connections
        // are pre-bootstrapped here.
        let Some(service) = c.service.as_deref() else {
            continue;
        };
        if conn == service {
            continue; // default — already bootstrapped above
        }
        if !read_floor_allows(Some(service), conn) {
            continue;
        }
        if let Some(role) = state.services.service_env_key(service) {
            let key = crate::storage::plaintext::secret_key_for(Some(c), &role);
            if let Some(val) = view.resolve_value_native(&key) {
                cache.entries.insert(
                    conn.clone(),
                    crate::state::CacheEntry {
                        value: val.to_vec(),
                        expires_at: None,
                        from_bootstrap: true,
                        agent_prefix: None,
                    },
                );
            }
        }
        if let Some(svc) = state.services.get(service) {
            let mut map: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            for name in cacheable_roles(svc) {
                let key = crate::storage::plaintext::secret_key_for(Some(c), &name);
                if let Some(val) = view.resolve_value_native(&key) {
                    map.insert(name, val.to_vec());
                }
            }
            if !map.is_empty() {
                cache.allow_secrets.insert(conn.clone(), map);
            }
        }
    }

    // Raw connections (`service: None`, created by `sc set K --host h` or
    // `sc connect`) have no service definition, so the per-service loops above
    // skip them. Their policy floor is the global default (`allow`), and the
    // resident proxy resolves an allow request straight from the session cache
    // (no grant to open the vault), so their secret bytes MUST be resident. §2:
    // read the connection's EXPLICIT `secrets` (uppercase KEY names, stored bare)
    // — no reverse-index-by-casing. Each KEY is resolved case-insensitively
    // (canonical uppercase storage, but a legacy key may differ).
    for (conn, c) in view.aux.connections.iter() {
        if c.service.is_some() {
            continue; // service-backed — handled above
        }
        let Some(keys) = &c.secrets else { continue };
        // Same read-floor gate as service connections: a raw connection the user
        // tightened to ask/ask-always must NOT be resident (PROTOCOL.md §6.2); an
        // untouched raw connection floors to the global `allow` and stays resident.
        if !read_floor_allows(None, conn) {
            continue;
        }
        let mut map: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        for key in keys {
            if let Some((_, bytes)) = view
                .native_secrets
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
            {
                map.insert(key.clone(), bytes.clone());
            }
        }
        // Sole secret → also the short-phantom `primary`; a multi-secret raw
        // connection resolves each role from the map (role phantoms).
        if map.len() == 1 {
            let primary = map.values().next().cloned().unwrap();
            cache.entries.insert(
                conn.clone(),
                crate::state::CacheEntry {
                    value: primary,
                    expires_at: None,
                    from_bootstrap: true,
                    agent_prefix: None,
                },
            );
        }
        if !map.is_empty() {
            cache.allow_secrets.insert(conn.clone(), map);
        }
    }

    // Custom (per-vault `aux.services`) definitions: validate before they can
    // broker (defense in depth — never trust the stored blob), never shadow a
    // built-in id, load only if valid. Wiped on lock with the rest of the cache.
    let (custom, skipped) = crate::service::vault_custom_services(
        &view.aux.services,
        view.aux.allows_installed_services(),
        &state.services,
    );
    for (service_id, reason) in skipped {
        tracing::warn!(service = %service_id, "custom service {} — skipped", reason);
    }
    cache.custom_services = custom;
    cache.service_entries = view.aux.services.clone();
    cache.service_requests = view.aux.service_requests.keys().cloned().collect();
    cache
}

/// Residency gate shared by the unlock bootstrap and the allow-path lazy
/// fill: a connection's bytes may sit in the session cache iff its effective
/// READ floor resolves to `allow` (PROTOCOL.md §6.2 — residency mirrors the
/// decision layer, see the block comment in `bootstrap_cache_from_view`).
/// `service = None` ⇒ raw connection.
pub(crate) fn residency_read_floor_allows(
    effective_policy: &crate::core::policy::Policy,
    services: &crate::service::ServiceRegistry,
    service: Option<&str>,
    conn: &str,
) -> bool {
    let recipe = service.and_then(|s| services.default_policy_levels(s));
    let user = effective_policy
        .connections
        .get(conn)
        .and_then(|c| c.default.as_ref());
    let conn_levels = crate::core::policy::merge_levels(user, recipe.as_ref());
    let tags = service.map(|s| services.service_tags(s)).unwrap_or(&[]);
    crate::core::policy::evaluate(
        "GET",
        "/",
        None,
        &crate::core::policy::VarMap::new(),
        None,
        conn_levels.as_ref(),
        effective_policy,
        tags,
    ) == crate::core::policy::AccessLevel::Allow
}

/// Allow-path lazy residency for EXTERNAL stores (the store-agnostic half of
/// the unlock bootstrap above). The secret model is one abstraction: a
/// connection binds KEYS and policy gates CONNECTIONS — neither knows which
/// store hosts the bytes. native-secrets values are resident from unlock
/// because they're already in hand; external values are network I/O we
/// refuse to put on the unlock path, so they load on FIRST TOUCH instead:
/// same read-floor gate, same `from_bootstrap` marking, same
/// whole-session lifetime — only the load moment differs.
///
/// Returns:
///   - `Ok(true)`  — the cache now holds bytes for `conn`; retry the lookup.
///   - `Ok(false)` — nothing external to load (no stores, floor not allow,
///     or no store has the keys); fall through to the portal as before.
///   - `Err(store_id)` — a CONFIGURED store failed (auth/network). Fail
///     loudly (P2): the caller surfaces an explicit error, never a portal
///     that would misread an outage as "needs approval".
pub(crate) async fn lazy_fill_external(
    state: &AppState,
    vault_id: &str,
    conn: &str,
) -> std::result::Result<bool, String> {
    // Single-flight: a burst of first requests fills once. Waiters re-check
    // the cache under the lock and ride the winner's insert.
    let _fill = state.external_fill_lock.lock().await;

    let (policy, rec, adapters) = {
        let Some(runtime) = state.runtime_if_present(vault_id) else {
            return Ok(false);
        };
        let runtime_state = runtime.state.lock().unwrap();
        let crate::state::VaultState::Unlocked { cache, .. } = &*runtime_state else {
            return Ok(false);
        };
        if cache.entries.contains_key(conn) || cache.allow_secrets.contains_key(conn) {
            return Ok(true); // another request filled while we waited
        }
        if cache.external_store_order.is_empty() {
            return Ok(false);
        }
        let adapters: Vec<(String, Arc<crate::store::Adapter>)> = cache
            .external_store_order
            .iter()
            .filter_map(|id| {
                cache
                    .external_stores
                    .get(id)
                    .map(|(_, a)| (id.clone(), a.clone()))
            })
            .collect();
        (
            cache.policy.clone(),
            cache.connections.get(conn).cloned(),
            adapters,
        )
    };

    // Service resolution: explicit record binding, else the connection id
    // names a REGISTRY service (default connection), else raw. Custom
    // (per-vault) services deliberately follow the bootstrap's behavior —
    // registry-blind residency, first use goes through the portal — so the
    // two residency paths can never disagree.
    let service = rec
        .as_ref()
        .and_then(|c| c.service.clone())
        .or_else(|| state.services.get(conn).map(|_| conn.to_string()));

    if !residency_read_floor_allows(&policy, &state.services, service.as_deref(), conn) {
        return Ok(false);
    }

    // Walk stores in vault order for one key; external keys resolve EXACT
    // (external naming is accepted as-is — no case folding). `Err(store_id)`
    // aborts the whole fill: a configured store outage must surface, not
    // degrade into "not found".
    let resolve_key = |key: String| {
        let adapters = &adapters;
        let conn = conn.to_string();
        async move {
            for (store_id, adapter) in adapters {
                match adapter.resolve(&key).await {
                    Ok(Some(bytes)) => return Ok(Some(bytes)),
                    Ok(None) => continue,
                    Err(e) => {
                        // F-20: full error server-side only; the caller
                        // returns a sanitised message.
                        tracing::warn!(store = %store_id, conn = %conn, "lazy external fill failed: {}", e);
                        return Err(store_id.clone());
                    }
                }
            }
            Ok(None)
        }
    };

    // Same shapes as the bootstrap's passes: `entries` primary from the
    // service's env-key role; `allow_secrets` map from `cacheable_roles`
    // (NOT the primary role — an oauth refresh token is resident for the
    // mint path only, never in the injectable role map); raw connections
    // map their explicit keys, sole key doubling as primary.
    let mut primary: Option<Vec<u8>> = None;
    let mut map: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    // Names that actually resolved from an external store — fed back into
    // the cache's external_keys slot so registry/entries surfaces learn
    // them even when the store's SA can't list().
    let mut fetched_keys: Vec<String> = Vec::new();
    match service.as_deref() {
        Some(svc_id) => {
            if let Some(role) = state.services.service_env_key(svc_id) {
                let key = crate::storage::plaintext::secret_key_for(rec.as_ref(), &role);
                primary = resolve_key(key.clone()).await?;
                if primary.is_some() {
                    fetched_keys.push(key);
                }
            }
            if let Some(svc) = state.services.get(svc_id) {
                for name in cacheable_roles(svc) {
                    let key = crate::storage::plaintext::secret_key_for(rec.as_ref(), &name);
                    if let Some(bytes) = resolve_key(key.clone()).await? {
                        map.insert(name, bytes);
                        fetched_keys.push(key);
                    }
                }
            }
        }
        None => {
            let Some(keys) = rec.as_ref().and_then(|c| c.secrets.clone()) else {
                return Ok(false); // raw connection with no explicit keys
            };
            for key in keys {
                if let Some(bytes) = resolve_key(key.clone()).await? {
                    map.insert(key.clone(), bytes);
                    fetched_keys.push(key);
                }
            }
            if map.len() == 1 {
                primary = map.values().next().cloned();
            }
        }
    }
    if primary.is_none() && map.is_empty() {
        return Ok(false);
    }
    {
        let Some(runtime) = state.runtime_if_present(vault_id) else {
            return Ok(false);
        };
        let crate::state::VaultState::Unlocked { cache, .. } = &mut *runtime.state.lock().unwrap()
        else {
            return Ok(false); // locked while we were fetching — drop the bytes
        };
        if let Some(val) = primary {
            cache
                .entries
                .entry(conn.to_string())
                .or_insert(crate::state::CacheEntry {
                    value: val,
                    expires_at: None,
                    from_bootstrap: true,
                    agent_prefix: None,
                });
        }
        if !map.is_empty() {
            cache.allow_secrets.entry(conn.to_string()).or_insert(map);
        }
        cache
            .external_keys
            .lock()
            .unwrap()
            .extend(fetched_keys.iter().cloned());
    }
    tracing::info!(conn = %conn, "external store secrets resident after lazy fill");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::plaintext::{Store, VaultAux};
    use std::collections::BTreeMap;

    thread_local! {
        /// The paired account a test pins for [`paired_account`] (`Some(None)`:
        /// a daemon paired without one). Unset reads the machine's own pairing.
        pub(super) static PAIRED_ACCOUNT: std::cell::RefCell<Option<Option<String>>> =
            const { std::cell::RefCell::new(None) };
        /// The pinned account UIK key a test sets for [`paired_account_pub`].
        pub(super) static PAIRED_ACCOUNT_PUB: std::cell::RefCell<Option<Option<[u8; 32]>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Pin the paired account (no pinned account key).
    fn pin_account(account: Option<&str>) {
        PAIRED_ACCOUNT.with(|a| *a.borrow_mut() = Some(account.map(str::to_string)));
        PAIRED_ACCOUNT_PUB.with(|a| *a.borrow_mut() = Some(None));
    }

    /// Pin the paired account by its UIK key, as `sc login` does.
    fn pin_account_key(pk: [u8; 32]) {
        let id = crate::identity::derive_id(crate::identity::IdKind::User, &pk);
        PAIRED_ACCOUNT.with(|a| *a.borrow_mut() = Some(Some(id)));
        PAIRED_ACCOUNT_PUB.with(|a| *a.borrow_mut() = Some(Some(pk)));
    }

    fn test_state() -> AppState {
        test_state_in("")
    }

    /// [`test_state`] under its own state dir (`tag`), for a test that writes a
    /// vault another test also uses.
    fn test_state_in(tag: &str) -> AppState {
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-approve-{}{}",
                std::process::id(),
                tag
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
        {
            let s = AppState::new(cfg);
            s.open_ledger_for_tests(&[]);
            s
        }
    }

    fn empty_view() -> crate::storage::plaintext::VaultPlaintextView {
        let mut m = sudp::state::ProtectedState::new();
        m.aux = serde_json::to_value(VaultAux::initial()).unwrap();
        crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m).unwrap()
    }

    /// Removing a connection from a vault without a keyset removes its rule
    /// (`policy:connection:<id>`) too, as a native tombstone: a later
    /// connection of the same id does not take the rule over. On a vault with
    /// a keyset the rule is owner-signed config and stays (the owner's console
    /// removes it).
    #[test]
    fn connection_rm_takes_its_rule_along_only_without_a_keyset() {
        use crate::storage::item::{wire_id_for, ItemNs, VaultKeys, POLICY_CONNECTION};
        use crate::storage::sealed_vault::{PerItemVault, ReconcileBase, ViewBase};
        type S = sudp::primitives::StdPrimitives;
        let reg = crate::service::ServiceRegistry::load();
        let k = [0x42u8; 32];
        let keys = VaultKeys::single(&k);
        let vid = "v-conn-rm";
        let conn = || crate::storage::plaintext::Connection {
            name: None,
            service: None,
            hosts: Some(vec!["api.example.com".into()]),
            secrets: None,
            keys: None,
            written: Some(Vec::new()),
        };
        let mut view = empty_view();
        view.aux.connections.insert("gh".into(), conn());
        view.aux.policy = Some(
            serde_json::from_value(serde_json::json!({
                "connections": { "gh": { "default": { "read": "deny", "write": "deny" } } }
            }))
            .unwrap(),
        );
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        pv.seed_items_from_view::<S>(keys, vid, &view).unwrap();
        let rule =
            wire_id_for::<S>(&k, ItemNs::Policy, &format!("{}gh", POLICY_CONNECTION)).unwrap();
        assert!(pv.items.contains_key(&rule), "the rule is its own record");

        // A keyset: the rule stays in the view (and the device writes no
        // owner-config there).
        let mut kept = pv.fold_view::<S>(keys, vid).unwrap();
        apply_connection_rm_to_view(&mut kept, "gh", true, true, &reg).unwrap();
        assert!(!kept.aux.connections.contains_key("gh"));
        assert!(kept
            .aux
            .policy
            .as_ref()
            .unwrap()
            .connections
            .contains_key("gh"));

        // No keyset: the rule goes with the connection, as a tombstone.
        let mut gone = pv.fold_view::<S>(keys, vid).unwrap();
        let base = ViewBase::of(&gone).unwrap();
        apply_connection_rm_to_view(&mut gone, "gh", true, false, &reg).unwrap();
        let r = pv
            .reconcile_from_view::<S>(keys, vid, &gone, ReconcileBase::Since(&base))
            .unwrap();
        assert!(r.changed.contains(&rule), "{:?}", r.changed);
        assert!(pv.items[&rule].tombstone);
        let after = pv.fold_view::<S>(keys, vid).unwrap();
        assert!(!after
            .aux
            .policy
            .as_ref()
            .is_some_and(|p| p.connections.contains_key("gh")));

        // A later connection of the same id starts without it.
        let base = ViewBase::of(&after).unwrap();
        let mut again = pv.fold_view::<S>(keys, vid).unwrap();
        again.aux.connections.insert("gh".into(), conn());
        pv.reconcile_from_view::<S>(keys, vid, &again, ReconcileBase::Since(&base))
            .unwrap();
        let now = pv.fold_view::<S>(keys, vid).unwrap();
        assert!(now.aux.connections.contains_key("gh"));
        assert!(!now
            .aux
            .policy
            .as_ref()
            .is_some_and(|p| p.connections.contains_key("gh")));
    }

    // The shared secret-set mutation is the SSOT for BOTH write paths (grant
    // approve + unlocked local write); assert new/overwrite/anchor/no-broker.
    #[test]
    fn secret_set_apply_new_overwrite_anchor_and_no_broker() {
        let mut view = empty_view();

        // New key + host anchor → value written, raw connection created.
        let removed = apply_secret_set_to_view(
            &mut view,
            "FOO_KEY",
            b"v1".to_vec(),
            &["api.foo.com".into()],
            false,
        );
        assert!(!removed);
        assert_eq!(
            view.native_secrets.get("FOO_KEY").map(Vec::as_slice),
            Some(&b"v1"[..])
        );
        let conn = view.aux.connections.get("foo_key").expect("anchor created");
        assert_eq!(
            conn.hosts.as_deref(),
            Some(&["api.foo.com".to_string()][..])
        );
        assert_eq!(conn.secrets.as_deref(), Some(&["FOO_KEY".to_string()][..]));

        // Overwrite: value + host list both replaced.
        apply_secret_set_to_view(
            &mut view,
            "FOO_KEY",
            b"v2".to_vec(),
            &["api2.foo.com".into()],
            false,
        );
        assert_eq!(
            view.native_secrets.get("FOO_KEY").map(Vec::as_slice),
            Some(&b"v2"[..])
        );
        assert_eq!(
            view.aux.connections["foo_key"].hosts.as_deref(),
            Some(&["api2.foo.com".to_string()][..])
        );

        // no_broker → drop the raw connection (removed=true), keep the value.
        let removed = apply_secret_set_to_view(&mut view, "FOO_KEY", b"v3".to_vec(), &[], true);
        assert!(removed);
        assert!(!view.aux.connections.contains_key("foo_key"));
        assert_eq!(
            view.native_secrets.get("FOO_KEY").map(Vec::as_slice),
            Some(&b"v3"[..])
        );
    }

    #[test]
    fn secret_set_validate_key_and_hosts() {
        let (k, h) = validate_secret_set("foo_key", &[], false).unwrap();
        assert_eq!(k, "FOO_KEY"); // uppercased
        assert!(h.is_empty());
        assert!(validate_secret_set("bad key!", &[], false).is_err()); // bad key
        assert!(validate_secret_set("FOO", &["api.x.com".into()], true).is_err()); // no_broker+hosts
        assert!(validate_secret_set("FOO", &["api.x.com".into()], false).is_ok());
    }

    fn gcp_store(creds_item: &str) -> Store {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "project_id".into(),
            serde_json::Value::String("proj".into()),
        );
        extra.insert(
            "credentials_item".into(),
            serde_json::Value::String(creds_item.into()),
        );
        Store {
            kind: "gcp-secret-manager".into(),
            category: Category::Value,
            items: BTreeMap::new(),
            extra,
        }
    }

    /// The unlock bootstrap materialises ONE shared adapter per external
    /// store (a store whose credential is missing is skipped, not fatal)
    /// and snapshots store_order restricted to what materialised — the
    /// exact walk order `lazy_fill_external` uses.
    #[test]
    fn bootstrap_snapshots_external_adapters_and_order() {
        let state = test_state();
        let mut aux = VaultAux::initial();
        aux.stores.insert("gcpa".into(), gcp_store("GCPA_SA_JSON"));
        aux.stores.insert("gcpb".into(), gcp_store("MISSING_ITEM"));
        aux.store_order = vec!["native-secrets".into(), "gcpa".into(), "gcpb".into()];
        let mut native_secrets = BTreeMap::new();
        native_secrets.insert(
            "GCPA_SA_JSON".to_string(),
            br#"{"client_email":"sa@proj.iam.gserviceaccount.com","private_key":"not-a-real-pem"}"#
                .to_vec(),
        );
        let view = VaultPlaintextView {
            aux,
            native_secrets,
            native_secret_notes: BTreeMap::new(),
        };

        let cache = bootstrap_cache_from_view(&view, &state);

        assert!(cache.external_stores.contains_key("gcpa"));
        assert!(
            !cache.external_stores.contains_key("gcpb"),
            "store with a missing credential item must be skipped"
        );
        assert_eq!(cache.external_store_order, vec!["gcpa".to_string()]);
        let (store, adapter) = &cache.external_stores["gcpa"];
        assert_eq!(store.kind, "gcp-secret-manager");
        assert_eq!(adapter.kind(), "gcp-secret-manager");
    }

    fn export_op(target: &str) -> crate::protocol::operation::Operation {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        Operation {
            act: Act {
                kind: ActType::Export,
                target: target.into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    // An Export reveals a raw secret; its plaintext must be handed to exactly
    // ONE poll and then tombstoned, so a co-resident process can't re-fetch it
    // for the op's remaining TTL.
    #[test]
    fn export_plaintext_is_single_use_via_poll() {
        let state = test_state();
        let op_id = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), export_op("GITHUB_TOKEN"), "r".into());
            s.set_waiter(&id, "w-secret");
            s.approve(&id, Some("ghp_SECRET".into()));
            id
        };

        let first = op_poll_value(&state, &op_id, Some("w-secret")).unwrap();
        assert_eq!(first["status"], "ok");
        assert_eq!(first["value"], "ghp_SECRET");

        // Second read: consumed tombstone, the plaintext is gone.
        let second = op_poll_value(&state, &op_id, Some("w-secret")).unwrap();
        assert_eq!(second["status"], "consumed");
        assert!(second.get("value").and_then(|v| v.as_str()).is_none());
    }

    // E1: whoever polls first no longer gets the plaintext. Without (or with a
    // wrong) waiter secret the poll sees status only and consumes NOTHING;
    // the creator's poll still gets the value afterwards.
    #[test]
    fn export_value_released_only_with_waiter_secret() {
        let state = test_state();
        let op_id = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), export_op("GITHUB_TOKEN"), "r".into());
            s.set_waiter(&id, "w-secret");
            s.approve(&id, Some("ghp_SECRET".into()));
            id
        };
        for bad in [None, Some("wrong"), Some("")] {
            let body = op_poll_value(&state, &op_id, bad).unwrap();
            assert_eq!(body["status"], "ok", "status is still visible");
            assert!(
                body["value"].is_null(),
                "no value without the secret: {body}"
            );
        }
        let good = op_poll_value(&state, &op_id, Some("w-secret")).unwrap();
        assert_eq!(
            good["value"], "ghp_SECRET",
            "not consumed by the status-only polls"
        );

        // An Export with NO waiter secret on record never releases its value.
        let bare = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), export_op("X"), "r".into());
            s.approve(&id, Some("plain".into()));
            id
        };
        let body = op_poll_value(&state, &bare, Some("anything")).unwrap();
        assert!(body["value"].is_null());
    }

    // Liveness: only a poll carrying the valid secret refreshes the clock.
    #[test]
    fn waiter_poll_refreshes_liveness() {
        let state = test_state();
        let op_id = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), export_op("K"), "r".into());
            s.set_waiter(&id, "w");
            s.get_mut_for_test(&id).unwrap().last_waiter_poll =
                std::time::Instant::now() - std::time::Duration::from_secs(90);
            id
        };
        let idle = std::time::Duration::from_secs(60);
        op_poll_value(&state, &op_id, None).unwrap();
        op_poll_value(&state, &op_id, Some("nope")).unwrap();
        assert_eq!(
            state
                .approvals
                .lock()
                .unwrap()
                .abandoned_exports(idle)
                .len(),
            1
        );
        op_poll_value(&state, &op_id, Some("w")).unwrap();
        assert!(state
            .approvals
            .lock()
            .unwrap()
            .abandoned_exports(idle)
            .is_empty());
    }

    // A Use result is the agent's own upstream reply, which its poll loop may
    // legitimately re-read after an interrupted retry — it must NOT be consumed.
    #[test]
    fn use_result_survives_repeat_poll() {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let state = test_state();
        let op = Operation {
            act: Act {
                kind: ActType::Use,
                target: "github".into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        };
        let op_id = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), op, "r".into());
            s.approve(&id, Some("{\"status\":200}".into()));
            id
        };

        for _ in 0..2 {
            let body = op_poll_value(&state, &op_id, None).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["value"]["status"], 200);
        }
    }

    // ── batch-approve pre-verification (design/batch-approve.md) ────────────

    fn use_op(vault: &str, path: &str) -> crate::protocol::operation::Operation {
        use crate::protocol::operation::{Act, Bind, Valid};
        crate::protocol::operation::Operation {
            act: Act {
                kind: ActType::Use,
                target: "github".into(),
                scope: json!({ "method": "GET", "host": "api.github.com", "path": path }),
            },
            bind: Bind {
                redeemer: vault.into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    fn batch_grant(
        op: crate::protocol::operation::Operation,
        r: &str,
        op_ids: Vec<String>,
    ) -> Grant {
        Grant {
            o: op,
            r: r.into(),
            credential_id: "cred1".into(),
            wrapping_key: None,
            wk_enc: None,
            wk_ct: None,
            k_enc: None,
            k_ct: None,
            id: None,
            id_sig: None,
            vault_key: None,
            assertion: None,
            batch: Some(crate::protocol::grant::BatchProof {
                op_ids,
                assertion: crate::passkey::webauthn::AssertionData {
                    credential_id: None,
                    authenticator_data: String::new(),
                    client_data_json: String::new(),
                    signature: String::new(),
                },
            }),
            setup_payload: None,
            opt: None,
        }
    }

    fn b64r(seed: u8) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        B64.encode([seed; 16])
    }

    #[test]
    fn batch_challenge_bounds_membership_and_kind() {
        let state = test_state();
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let mut s = state.approvals.lock().unwrap();
            ids.push(s.create("v1".into(), use_op("v1", &format!("/r/{}", i)), b64r(i)));
        }

        // Too small.
        let g = batch_grant(use_op("v1", "/r/0"), &b64r(0), vec![ids[0].clone()]);
        let e = batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap_err();
        assert!(matches!(e, AppError::BatchVerify(_)), "size floor: {}", e);

        // Duplicate member.
        let g = batch_grant(
            use_op("v1", "/r/0"),
            &b64r(0),
            vec![ids[0].clone(), ids[0].clone()],
        );
        assert!(matches!(
            batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap_err(),
            AppError::BatchVerify(_)
        ));

        // Target not a member of its own batch.
        let g = batch_grant(
            use_op("v1", "/r/0"),
            &b64r(0),
            vec![ids[1].clone(), ids[2].clone()],
        );
        assert!(matches!(
            batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap_err(),
            AppError::BatchVerify(_)
        ));

        // Unknown sibling.
        let g = batch_grant(
            use_op("v1", "/r/0"),
            &b64r(0),
            vec![ids[0].clone(), "nope".into()],
        );
        assert!(matches!(
            batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap_err(),
            AppError::BatchVerify(_)
        ));

        // Lifecycle / high-consequence siblings — the consent boundary. Every
        // Custom act keeps the per-op ceremony: a batch carries only `use`
        // and `export`, so the console must never plan these kinds into an
        // envelope at ANY daemon version (there is no version with the arm).
        for kind in ["vault-delete", "vault-unlock", "widen-host", "secret-rm"] {
            let custom_id = {
                let mut s = state.approvals.lock().unwrap();
                let mut op = use_op("v1", "/x");
                op.act.kind = ActType::Custom(kind.into());
                s.create("v1".into(), op, b64r(9))
            };
            let g = batch_grant(
                use_op("v1", "/r/0"),
                &b64r(0),
                vec![ids[0].clone(), custom_id],
            );
            match batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap_err() {
                AppError::BatchVerify(m) => {
                    assert!(m.contains("only `use` and `export`"), "{kind}: {m}")
                }
                other => panic!("{kind}: {other}"),
            }
        }

        // Export joins the batch arm (design/approvals-inbox.md D2, behind E1).
        let export_id = {
            let mut s = state.approvals.lock().unwrap();
            s.create("v1".into(), export_op("GITHUB_TOKEN"), b64r(7))
        };
        let g = batch_grant(
            use_op("v1", "/r/0"),
            &b64r(0),
            vec![ids[0].clone(), export_id],
        );
        assert!(
            batch_expected_challenge(&state, &ids[0], "v1", &g).is_ok(),
            "a use+export batch must rebuild its root"
        );

        // Cross-vault sibling.
        let other_vault_id = {
            let mut s = state.approvals.lock().unwrap();
            s.create("v2".into(), use_op("v2", "/y"), b64r(8))
        };
        let g = batch_grant(
            use_op("v1", "/r/0"),
            &b64r(0),
            vec![ids[0].clone(), other_vault_id],
        );
        assert!(matches!(
            batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap_err(),
            AppError::BatchVerify(_)
        ));
    }

    #[test]
    fn batch_challenge_matches_manual_rebuild_and_survives_sibling_status() {
        use crate::crypto::batch::{batch_challenge, batch_root};
        use crate::crypto::binding::{binding_for_op, DOMAIN_STANDARD};
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let state = test_state();
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let mut s = state.approvals.lock().unwrap();
            ids.push(s.create("v1".into(), use_op("v1", &format!("/p/{}", i)), b64r(i)));
        }

        // Manual root over the STORED (o, r) pairs in op_ids order.
        let manual = {
            let s = state.approvals.lock().unwrap();
            let betas: Vec<[u8; 32]> = ids
                .iter()
                .map(|id| {
                    let rec = s.get_any(id).unwrap();
                    let r = B64.decode(&rec.r).unwrap();
                    binding_for_op(DOMAIN_STANDARD, &r, &serde_json::to_value(&rec.op).unwrap())
                        .unwrap()
                })
                .collect();
            batch_challenge(&batch_root(&betas).unwrap())
        };

        let g = batch_grant(use_op("v1", "/p/0"), &b64r(0), ids.clone());
        let got = batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap();
        assert_eq!(got, manual);

        // Order is part of the commitment: permuted op_ids → different root.
        let mut rev = ids.clone();
        rev.reverse();
        let g_rev = batch_grant(use_op("v1", "/p/0"), &b64r(0), rev);
        assert_ne!(
            batch_expected_challenge(&state, &ids[0], "v1", &g_rev).unwrap(),
            manual
        );

        // Sibling status must not matter: approve one, reject another —
        // later rows still rebuild the same root (get_any is status-blind).
        {
            let mut s = state.approvals.lock().unwrap();
            s.approve(&ids[1], None);
            s.reject(&ids[2], "user rejected");
        }
        let got_after = batch_expected_challenge(&state, &ids[0], "v1", &g).unwrap();
        assert_eq!(got_after, manual, "status-agnostic sibling rebuild");

        // Batch grant must not carry a top-level assertion (checked in the
        // validation arm, not the challenge rebuild — see validate_batch_grant).
    }

    // ── approvals inbox (design/approvals-inbox.md) ─────────────────────────

    /// Batching never relaxes an Export's own checks: every one still runs
    /// at the row's apply (the same `export_precheck` both arms reach).
    #[test]
    fn export_precheck_enforced_regardless_of_arm() {
        assert_eq!(
            export_precheck(&export_op("GITHUB_TOKEN")).unwrap(),
            "GITHUB_TOKEN"
        );
        for bad in ["env", ""] {
            assert!(matches!(
                export_precheck(&export_op(bad)),
                Err(AppError::BadRequest(_))
            ));
        }
        let mut sealed = export_op("GITHUB_TOKEN");
        sealed.bind.recipient = Some(sudp::RecipientPk {
            alg: "x".into(),
            bytes: "y".into(),
        });
        assert!(matches!(
            export_precheck(&sealed),
            Err(AppError::BadRequest(_))
        ));
        let mut wrong_kind = export_op("GITHUB_TOKEN");
        wrong_kind.act.kind = ActType::Use;
        assert!(export_precheck(&wrong_kind).is_err());
    }

    fn pc(level: crate::core::policy::AccessLevel, ttl: u64) -> crate::approval::PolicyContext {
        crate::approval::PolicyContext {
            level,
            decided_by: crate::core::policy::DecidedBy::Floor,
            ttl_seconds: ttl,
            host: Some("api.github.com".into()),
        }
    }

    fn rule_pc(id: &str, label: Option<&str>, ttl: u64) -> crate::approval::PolicyContext {
        crate::approval::PolicyContext {
            decided_by: crate::core::policy::DecidedBy::Rule {
                id: Some(id.into()),
                label: label.map(str::to_string),
            },
            ..pc(crate::core::policy::AccessLevel::Ask, ttl)
        }
    }

    #[test]
    fn signed_level_assertion() {
        use crate::core::policy::AccessLevel;
        let floor = pc(AccessLevel::Ask, 900);
        let send = rule_pc("send", Some("Send email"), 900);
        let always = pc(AccessLevel::AskAlways, 900);
        let allow = pc(AccessLevel::Allow, 600);
        let ok = |scope: Value, pc: &crate::approval::PolicyContext| {
            assert_signed_level(&scope, Some(pc)).is_ok()
        };
        // Each row with its own reuse fields + window.
        assert!(ok(
            json!({"method":"GET","level":"ask","reuse":"floor","reuse_class":"read","window_s":900}),
            &floor
        ));
        assert!(ok(
            json!({"method":"DELETE","level":"ask","reuse":"floor","reuse_class":"write","window_s":900}),
            &floor
        ));
        assert!(ok(
            json!({"method":"POST","level":"ask","reuse":"rule","reuse_rule":"send","reuse_label":"Send email","window_s":900}),
            &send
        ));
        assert!(ok(
            json!({"method":"POST","level":"ask","scoped":true,"reuse":"exact","window_s":900,"scope_vars":{"amount":"80"}}),
            &send
        ));
        assert!(ok(
            json!({"method":"POST","level":"ask","scoped":true,"reuse":"exact","window_s":900}),
            &floor
        ));
        // ask-always: reuse none and NO window, while its record still carries a ttl.
        assert!(ok(json!({"level":"ask-always","reuse":"none"}), &always));
        // An allow-level miss is `none` too: it never serves an ask.
        assert!(ok(json!({"level":"allow","reuse":"none"}), &allow));

        // Level mismatch either way.
        assert!(!ok(
            json!({"method":"GET","level":"ask","reuse":"floor","reuse_class":"read","window_s":900}),
            &always
        ));
        assert!(!ok(json!({"level":"ask-always","reuse":"none"}), &floor));
        // The reuse must be exactly what apply grants.
        assert!(
            !ok(
                json!({"method":"GET","level":"ask","reuse":"floor","reuse_class":"write","window_s":900}),
                &floor
            ),
            "read floor signed as write"
        );
        assert!(
            !ok(
                json!({"method":"POST","level":"ask","reuse":"rule","reuse_rule":"other","reuse_label":"Send email","window_s":900}),
                &send
            ),
            "another rule"
        );
        assert!(
            !ok(
                json!({"method":"POST","level":"ask","reuse":"rule","reuse_rule":"send","window_s":900}),
                &send
            ),
            "label dropped"
        );
        assert!(
            !ok(
                json!({"method":"GET","level":"ask","reuse":"exact","window_s":900}),
                &floor
            ),
            "unscoped is not exact"
        );
        assert!(
            !ok(
                json!({"method":"GET","level":"ask","reuse":"connection","window_s":900}),
                &floor
            ),
            "the retired connection-wide value"
        );
        assert!(
            !ok(
                json!({"method":"GET","level":"ask","reuse":"floor","reuse_class":"read","window_s":900}),
                &send
            ),
            "a rule ask is not a floor ask"
        );
        assert!(!ok(
            json!({"level":"allow","reuse":"floor","reuse_class":"read","window_s":600}),
            &allow
        ));
        assert!(!ok(json!({"level":"ask","reuse":7,"window_s":900}), &floor));
        // A signed level without a signed reuse is refused (fail closed).
        assert!(!ok(
            json!({"method":"GET","level":"ask","window_s":900}),
            &floor
        ));
        assert!(!ok(json!({"level":"ask-always"}), &always));
        // Window: present exactly when the reuse has one, equal to the ttl.
        assert!(!ok(
            json!({"method":"GET","level":"ask","reuse":"floor","reuse_class":"read"}),
            &floor
        ));
        assert!(!ok(
            json!({"method":"GET","level":"ask","reuse":"floor","reuse_class":"read","window_s":60}),
            &floor
        ));
        assert!(!ok(
            json!({"level":"ask-always","reuse":"none","window_s":900}),
            &always
        ));
        assert!(!ok(
            json!({"level":"allow","reuse":"none","window_s":600}),
            &allow
        ));
        // A signed level with no policy context can't be honoured.
        assert!(assert_signed_level(&json!({"level":"ask","reuse":"floor"}), None).is_err());
        // A Use op with no signed level (or reuse) is refused: what approving
        // it grants is not stated.
        assert!(!ok(json!({"method":"GET"}), &floor));
        assert!(!ok(
            json!({"method":"GET","reuse":"floor","reuse_class":"read","window_s":900}),
            &floor
        ));
        assert!(assert_signed_level(&json!({"method":"GET"}), None).is_err());
        assert!(assert_signed_level(&Value::Null, None).is_err());
    }

    fn leveled_use_op(level: &str, window: Option<u64>) -> crate::protocol::operation::Operation {
        let mut op = use_op("v1", "/user");
        op.act.scope["level"] = json!(level);
        if level == "ask-always" {
            op.act.scope["reuse"] = json!("none");
        } else {
            // use_op is a GET: a floor ask of class read.
            op.act.scope["reuse"] = json!("floor");
            op.act.scope["reuse_class"] = json!("read");
        }
        if let Some(w) = window {
            op.act.scope["window_s"] = json!(w);
        }
        op
    }

    fn plain_grant(op: crate::protocol::operation::Operation, r: &str) -> Grant {
        let mut g = batch_grant(op, r, vec![]);
        g.batch = None;
        g.assertion = Some(crate::passkey::webauthn::AssertionData {
            credential_id: None,
            authenticator_data: String::new(),
            client_data_json: String::new(),
            signature: String::new(),
        });
        g
    }

    /// Apply-time: a stored op whose signed level disagrees with the policy it
    /// was minted under is refused before any crypto or vault access —
    /// BadRequest on the plain arm, recoverable BatchVerify on the batch arm.
    #[tokio::test]
    async fn approve_refuses_signed_level_mismatch() {
        use crate::core::policy::AccessLevel;
        let state = Arc::new(test_state());
        let op = leveled_use_op("ask-always", None);
        let id = {
            let mut s = state.approvals.lock().unwrap();
            s.create_with_policy(
                "v1".into(),
                op.clone(),
                b64r(1),
                Some(pc(AccessLevel::Ask, 900)),
            )
        };
        let err = approve_op(
            State(state.clone()),
            Path(id.clone()),
            Json(plain_grant(op.clone(), &b64r(1))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::BadRequest(m) if m.contains("level")),
            "{err}"
        );

        let err = approve_op(
            State(state.clone()),
            Path(id.clone()),
            Json(batch_grant(op, &b64r(1), vec![id.clone(), "other".into()])),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::BatchVerify(m) if m.contains("level")),
            "{err}"
        );

        // ask with a window that doesn't match pc.ttl_seconds.
        let op = leveled_use_op("ask", Some(60));
        let id = {
            let mut s = state.approvals.lock().unwrap();
            s.create_with_policy(
                "v1".into(),
                op.clone(),
                b64r(2),
                Some(pc(AccessLevel::Ask, 900)),
            )
        };
        let err = approve_op(
            State(state.clone()),
            Path(id),
            Json(plain_grant(op, &b64r(2))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::BadRequest(m) if m.contains("window_s")),
            "{err}"
        );
    }

    fn chained(state: &AppState, path: &str, r: &str) -> crate::approval::ChainedCreate {
        let mut op = use_op("v1", path);
        op.act.scope["level"] = json!("ask");
        op.act.scope["reuse"] = json!("connection");
        op.act.scope["window_s"] = json!(900);
        state.approvals.lock().unwrap().create_chained(
            "v1".into(),
            op,
            r.into(),
            Some(pc(crate::core::policy::AccessLevel::Ask, 900)),
            Some("ag_x".into()),
        )
    }

    /// GET /op/{id}: a superseded op stays `pending` with its pointer; once a
    /// sibling applies it mirrors the applied op's body (`ok`, no value) plus
    /// `satisfied_by`.
    #[test]
    fn chain_poll_bodies() {
        let state = test_state();
        let a = chained(&state, "/user", &b64r(1));
        let b = chained(&state, "/user", &b64r(2));

        let pa = op_poll_value(&state, &a.id, None).unwrap();
        assert_eq!(pa["status"], "pending");
        assert_eq!(pa["superseded_by"], json!(b.id));
        assert_eq!(pa["retry_count"], 1);
        assert!(pa["satisfied_by"].is_null());
        let pb = op_poll_value(&state, &b.id, None).unwrap();
        assert_eq!(pb["status"], "pending");
        assert!(pb["superseded_by"].is_null());
        assert_eq!(pb["retry_count"], 2);

        // Apply B (the head) the way approve_op's step 5 does.
        state
            .approvals
            .lock()
            .unwrap()
            .approve_chain(&b.id, None)
            .unwrap();
        let applied = op_poll_value(&state, &b.id, None).unwrap();
        let sat = op_poll_value(&state, &a.id, None).unwrap();
        for k in ["status", "value", "reason", "act"] {
            assert_eq!(sat[k], applied[k], "satisfied sibling mirrors `{k}`");
        }
        assert_eq!(sat["status"], "ok");
        assert!(sat["value"].is_null());
        assert_eq!(sat["satisfied_by"], json!(b.id));
        assert!(applied["satisfied_by"].is_null());
    }

    /// A second grant for an already-resolved chain is a 409 at the pre-lock
    /// check — no validation, no fail_count — and the relay client ends that
    /// poll quietly.
    #[tokio::test]
    async fn approve_on_resolved_chain_member_is_conflict() {
        let state = Arc::new(test_state());
        let a = chained(&state, "/user", &b64r(1));
        let b = chained(&state, "/user", &b64r(2));
        state
            .approvals
            .lock()
            .unwrap()
            .approve_chain(&b.id, None)
            .unwrap();
        let op = state
            .approvals
            .lock()
            .unwrap()
            .get(&a.id)
            .unwrap()
            .op
            .clone();
        let err = approve_op(
            State(state.clone()),
            Path(a.id.clone()),
            Json(plain_grant(op, &b64r(1))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err}");
        assert_eq!(
            state
                .approvals
                .lock()
                .unwrap()
                .get(&a.id)
                .unwrap()
                .fail_count,
            0
        );
    }

    /// reject_op: a USER rejection (no carried reason) resolves every live op
    /// of the chain; an apply-failure rejection touches only its own op.
    #[tokio::test]
    async fn reject_op_propagates_user_rejection_to_chain() {
        let state = Arc::new(test_state());
        let a = chained(&state, "/user", &b64r(1));
        let b = chained(&state, "/user", &b64r(2));
        let _ = reject_op(
            State(state.clone()),
            Path(b.id.clone()),
            Some(Json(
                json!({ "reason": "approved, but applying it failed: boom" }),
            )),
        )
        .await
        .unwrap();
        assert_eq!(
            op_poll_value(&state, &a.id, None).unwrap()["status"],
            "pending"
        );

        let c = chained(&state, "/user", &b64r(3));
        let _ = reject_op(State(state.clone()), Path(c.id.clone()), None)
            .await
            .unwrap();
        let pa = op_poll_value(&state, &a.id, None).unwrap();
        assert_eq!(pa["status"], "rejected");
        assert_eq!(pa["reason"], "user rejected");
        // Unrelated request untouched.
        let other = chained(&state, "/repos", &b64r(4));
        assert_eq!(
            op_poll_value(&state, &other.id, None).unwrap()["status"],
            "pending"
        );
    }

    // ── signed reuse vs apply, end to end per row ──────────────────────────
    //
    // Each test mints the op scope exactly as the proxy does (stamp_signed_level
    // + the scoped/scope_vars fields), asserts the stamped reuse fields, runs
    // apply's write (plan_use_grant, after the approve-time assertion), then
    // probes later requests through the SAME decision + lookup the proxy runs
    // (evaluate_request_decision + grant_lookup). `true` from `served` = served
    // without asking. One test per row of the reuse table
    // (approval/reuse.rs).

    const RV: &str = "v-reuse";
    const RC: &str = "gh";
    const RH: &str = "api.gh.com";

    fn reuse_policy() -> crate::core::policy::Policy {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Levels, Policy, RuleConfig};
        let rule = |pat: &str, level: AccessLevel, ttl: Option<u64>| RuleConfig {
            match_pattern: Some(pat.to_string()),
            level: Some(level),
            ttl,
            ..Default::default()
        };
        let mut rules = std::collections::HashMap::new();
        rules.insert(
            "read".to_string(),
            RuleConfig {
                label: Some("Read x".into()),
                ..rule("GET /x", AccessLevel::Ask, Some(60))
            },
        );
        rules.insert(
            "write".to_string(),
            rule("POST /x", AccessLevel::Ask, Some(60)),
        );
        rules.insert(
            "del".to_string(),
            rule("DELETE /x", AccessLevel::AskAlways, None),
        );
        rules.insert(
            "buy".to_string(),
            rule("POST /buy", AccessLevel::Ask, Some(120)),
        );
        rules.insert(
            "open".to_string(),
            rule("GET /open", AccessLevel::Allow, Some(900)),
        );
        // One rule over every method of a path.
        rules.insert("rw".to_string(), rule("/rw", AccessLevel::Ask, Some(60)));
        let mut p = Policy::default();
        p.connections.insert(
            RC.to_string(),
            ConnectionPolicy {
                // Floor: ask both ways with its own window, so the connection
                // is not resident and unmatched paths are floor asks.
                default: Some(Levels {
                    read: Some(AccessLevel::Ask),
                    write: Some(AccessLevel::Ask),
                    ttl: Some(300),
                }),
                rules,
            },
        );
        p
    }

    fn reuse_state() -> AppState {
        let state = test_state();
        let cache = crate::state::SecretsCache {
            policy: reuse_policy(),
            ..Default::default()
        };
        state.unlock_vault(RV.into(), cache, zeroize::Zeroizing::new(Vec::new()));
        state
    }

    fn now_s() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// The proxy's decision for a request: (level, decided by, ttl).
    fn decide_at(
        state: &AppState,
        agent: &str,
        method: &str,
        path: &str,
        host: &str,
        scoped: bool,
    ) -> (
        crate::core::policy::AccessLevel,
        crate::core::policy::DecidedBy,
        u64,
    ) {
        let (l, by, t) = state
            .evaluate_request_decision(
                RV,
                agent,
                RC,
                RC,
                method,
                path,
                host,
                None,
                &crate::core::policy::VarMap::new(),
                scoped,
            )
            .expect("unlocked");
        (l, by, t.unwrap_or(900))
    }

    /// Mint the op scope + PolicyContext for the request the way captive_portal
    /// does (agent `agA`), and check the approve-time assertion accepts it.
    fn mint(
        state: &AppState,
        method: &str,
        path: &str,
        scope_shape: bool,
        bound: &[(&str, &str)],
    ) -> (Value, crate::approval::PolicyContext) {
        let (level, decided_by, ttl) = decide_at(state, "agA", method, path, RH, scope_shape);
        let mut scope = json!({
            "connection_id": RC, "service": RC, "host": RH,
            "method": method, "path": path, "authorize_only": true, "agent": "agA",
        });
        crate::proxy::handler::stamp_signed_level(
            &mut scope,
            level,
            &decided_by,
            scope_shape,
            method,
            ttl,
        );
        if scope_shape {
            scope["scoped"] = json!(true);
            if !bound.is_empty() {
                let m: serde_json::Map<String, Value> = bound
                    .iter()
                    .map(|(k, v)| (k.to_string(), json!(v)))
                    .collect();
                scope["scope_vars"] = Value::Object(m);
            }
        }
        let pc = crate::approval::PolicyContext {
            level,
            decided_by,
            ttl_seconds: ttl,
            host: Some(RH.into()),
        };
        assert_signed_level(&scope, Some(&pc)).expect("stamp passes the apply assertion");
        (scope, pc)
    }

    /// Apply's grant write.
    fn apply(state: &AppState, scope: &Value, pc: &crate::approval::PolicyContext, now: u64) {
        plan_use_grant(Some(pc), scope, RV, "agA", b"tok".to_vec(), now)
            .expect("a grant is planned")
            .write(state);
    }

    /// Would the proxy serve this request without asking?
    fn served_at(
        state: &AppState,
        agent: &str,
        method: &str,
        path: &str,
        host: &str,
        bound: &[(&str, &str)],
    ) -> bool {
        let shape = path == "/buy";
        let (level, by, _) = decide_at(state, agent, method, path, host, shape);
        if level == crate::core::policy::AccessLevel::Deny {
            return false;
        }
        let pairs: Vec<(String, String)> = bound
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let digest = crate::service::scope_digest(&pairs);
        let (primary, _) = crate::proxy::handler::grant_lookup(
            state, RV, agent, RC, level, &by, method, host, path, &digest, shape,
        );
        primary.is_some()
    }

    fn served(
        state: &AppState,
        agent: &str,
        method: &str,
        path: &str,
        bound: &[(&str, &str)],
    ) -> bool {
        served_at(state, agent, method, path, RH, bound)
    }

    fn held_expiry(state: &AppState) -> Option<u64> {
        let runtime = state.runtime_if_present(RV)?;
        let runtime_state = runtime.state.lock().unwrap();
        match &*runtime_state {
            crate::state::VaultState::Unlocked { cache, .. } => {
                cache.entries.get(RC).and_then(|e| e.expires_at)
            }
            _ => None,
        }
    }

    fn ledger_len(state: &AppState) -> usize {
        let Some(runtime) = state.runtime_if_present(RV) else {
            return 0;
        };
        let runtime_state = runtime.state.lock().unwrap();
        match &*runtime_state {
            crate::state::VaultState::Unlocked { cache, .. } => cache.ask_grants.len(),
            _ => 0,
        }
    }

    fn bound_expiry(
        state: &AppState,
        method: &str,
        path: &str,
        bound: &[(&str, &str)],
    ) -> Option<u64> {
        let pairs: Vec<(String, String)> = bound
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let digest = crate::service::scope_digest(&pairs);
        let runtime = state.runtime_if_present(RV)?;
        let runtime_state = runtime.state.lock().unwrap();
        match &*runtime_state {
            // Whatever tier minted it: the request line + digest identify it.
            crate::state::VaultState::Unlocked { cache, .. } => cache
                .op_grants
                .iter()
                .find(|(k, _)| {
                    k.agent == "agA"
                        && k.conn == RC
                        && k.method == method
                        && k.host == RH
                        && k.path == path
                        && k.scope_digest == digest
                })
                .and_then(|(_, e)| e.expires_at),
            _ => None,
        }
    }

    /// ask-always → `none`, no window: the approved request replays once, the
    /// next identical one asks, and nothing else rides it.
    #[test]
    fn reuse_ask_always_is_none() {
        let state = reuse_state();
        assert!(
            !served(&state, "agA", "DELETE", "/x", &[]),
            "asks before approval"
        );
        let (scope, pc) = mint(&state, "DELETE", "/x", false, &[]);
        assert_eq!(scope["level"], "ask-always");
        assert_eq!(scope["reuse"], "none");
        assert!(scope.get("window_s").is_none());
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(
            bound_expiry(&state, "DELETE", "/x", &[]),
            Some(now + crate::state::ASK_ALWAYS_REPLAY_WINDOW_SECS),
            "replay deadline only"
        );
        assert!(
            served(&state, "agA", "DELETE", "/x", &[]),
            "the approved replay"
        );
        assert!(
            !served(&state, "agA", "DELETE", "/x", &[]),
            "the next identical request asks"
        );
        assert!(
            !served(&state, "agA", "GET", "/y", &[]),
            "nothing held for other requests"
        );
        assert_eq!(held_expiry(&state), None);
        assert_eq!(ledger_len(&state), 0);
    }

    /// A rule-matched ask → `rule` (id + label) for the rule's window: later
    /// requests that the policy decides by the SAME rule don't ask; approving
    /// rule A does not serve rule B, a floor ask, an ask-always request,
    /// another agent, or another host.
    #[test]
    fn reuse_rule_ask_serves_only_that_rule() {
        let state = reuse_state();
        let (scope, pc) = mint(&state, "GET", "/x", false, &[]);
        assert_eq!(scope["level"], "ask");
        assert_eq!(scope["reuse"], "rule");
        assert_eq!(scope["reuse_rule"], "read");
        assert_eq!(scope["reuse_label"], "Read x");
        assert_eq!(scope["window_s"], 60);
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(
            held_expiry(&state),
            Some(now + 60),
            "value held for the window"
        );
        assert!(served(&state, "agA", "GET", "/x", &[]));
        assert!(
            served(&state, "agA", "GET", "/x", &[]),
            "reused, not single-use"
        );
        assert!(
            !served(&state, "agA", "POST", "/x", &[]),
            "rule B (write) still asks"
        );
        assert!(
            !served(&state, "agA", "GET", "/y", &[]),
            "a floor ask still asks"
        );
        assert!(
            !served(&state, "agA", "DELETE", "/x", &[]),
            "ask-always keeps its own approval"
        );
        assert!(
            !served(&state, "agA", "POST", "/buy", &[("amount", "80")]),
            "value-bound asks keep their own approval"
        );
        assert!(!served(&state, "agB", "GET", "/x", &[]), "other agent");
        assert!(
            !served_at(&state, "agA", "GET", "/x", "other.gh.com", &[]),
            "other host"
        );
    }

    /// An owner-set floor ask → `floor` + class for the floor window: later
    /// floor asks of the same class don't ask; a read approval does not serve
    /// a write, nor any rule-matched request.
    #[test]
    fn reuse_floor_ask_serves_only_its_class() {
        let state = reuse_state();
        let (scope, pc) = mint(&state, "GET", "/y", false, &[]);
        assert_eq!(pc.decided_by, crate::core::policy::DecidedBy::Floor);
        assert_eq!(scope["reuse"], "floor");
        assert_eq!(scope["reuse_class"], "read");
        assert_eq!(scope["window_s"], 300);
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(held_expiry(&state), Some(now + 300));
        assert!(served(&state, "agA", "GET", "/y", &[]));
        assert!(
            served(&state, "agA", "GET", "/z", &[]),
            "another floor read, same agent"
        );
        assert!(
            !served(&state, "agA", "DELETE", "/z", &[]),
            "a floor write still asks"
        );
        assert!(
            !served(&state, "agA", "POST", "/z", &[]),
            "a floor write still asks"
        );
        assert!(
            !served(&state, "agA", "GET", "/x", &[]),
            "a rule-matched read still asks"
        );
        assert!(!served(&state, "agB", "GET", "/y", &[]), "other agent");

        // The write class is its own unit.
        let (scope, pc) = mint(&state, "POST", "/z", false, &[]);
        assert_eq!(scope["reuse_class"], "write");
        apply(&state, &scope, &pc, now_s());
        assert!(served(&state, "agA", "DELETE", "/z", &[]));
    }

    /// A scoped ask that bound values → `exact`: only the identical request
    /// (same values) is reused within window_s; nothing connection-wide.
    #[test]
    fn reuse_scoped_ask_with_values_is_exact() {
        let state = reuse_state();
        let v80 = [("amount", "80")];
        let (scope, pc) = mint(&state, "POST", "/buy", true, &v80);
        assert_eq!(scope["reuse"], "exact");
        assert_eq!(scope["window_s"], 120);
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(bound_expiry(&state, "POST", "/buy", &v80), Some(now + 120));
        assert_eq!(held_expiry(&state), None, "no connection value held");
        assert!(served(&state, "agA", "POST", "/buy", &v80));
        assert!(
            served(&state, "agA", "POST", "/buy", &v80),
            "identical request reused"
        );
        assert!(
            !served(&state, "agA", "POST", "/buy", &[("amount", "180")]),
            "other value"
        );
        assert!(
            !served(&state, "agA", "GET", "/y", &[]),
            "nothing else rides it"
        );
        assert!(!served(&state, "agB", "POST", "/buy", &v80), "other agent");
    }

    /// A scoped path whose request bound no values → `exact` too: the
    /// identical value-less request is reused; a request with values asks.
    #[test]
    fn reuse_scoped_path_without_values_is_exact() {
        let state = reuse_state();
        let (scope, pc) = mint(&state, "POST", "/buy", true, &[]);
        assert_eq!(scope["scoped"], true);
        assert!(scope.get("scope_vars").is_none());
        assert_eq!(scope["reuse"], "exact");
        assert_eq!(scope["window_s"], 120);
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(bound_expiry(&state, "POST", "/buy", &[]), Some(now + 120));
        assert_eq!(held_expiry(&state), None);
        assert!(served(&state, "agA", "POST", "/buy", &[]));
        assert!(
            served(&state, "agA", "POST", "/buy", &[]),
            "peeked, not spent"
        );
        assert!(!served(&state, "agA", "POST", "/buy", &[("amount", "80")]));
        assert!(!served(&state, "agA", "GET", "/y", &[]));
        assert!(!served(&state, "agB", "POST", "/buy", &[]));
    }

    /// An allow-level cache miss → `none`, no window: the value is held for
    /// allow-level traffic (any agent), and the approval serves no ask.
    #[test]
    fn reuse_allow_miss_serves_allow_traffic_only() {
        let state = reuse_state();
        assert!(
            !served(&state, "agA", "GET", "/open", &[]),
            "not resident: a miss asks"
        );
        let (scope, pc) = mint(&state, "GET", "/open", false, &[]);
        assert_eq!(scope["level"], "allow");
        assert_eq!(scope["reuse"], "none");
        assert!(scope.get("window_s").is_none());
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(held_expiry(&state), Some(now + 900));
        assert_eq!(ledger_len(&state), 0, "no ask is authorized");
        assert!(served(&state, "agA", "GET", "/open", &[]));
        assert!(
            served(&state, "agB", "GET", "/open", &[]),
            "allowed requests, any agent"
        );
        assert!(
            !served(&state, "agA", "GET", "/y", &[]),
            "the approving agent's floor ask still asks"
        );
        assert!(
            !served(&state, "agA", "GET", "/x", &[]),
            "the approving agent's rule ask still asks"
        );
        assert!(!served(&state, "agA", "DELETE", "/x", &[]));
    }

    /// A value held for one unit never authorizes another: after a rule
    /// approval holds the value, a floor ask by the same agent still asks
    /// (residency is not authorization), and a later, shorter approval never
    /// shortens the held value's window.
    #[test]
    fn residency_never_authorizes_and_never_shrinks() {
        let state = reuse_state();
        let (scope, pc) = mint(&state, "GET", "/y", false, &[]);
        let now = now_s();
        apply(&state, &scope, &pc, now);
        assert_eq!(held_expiry(&state), Some(now + 300));
        let (scope, pc) = mint(&state, "GET", "/x", false, &[]);
        apply(&state, &scope, &pc, now);
        assert_eq!(
            held_expiry(&state),
            Some(now + 300),
            "60s rule did not shorten it"
        );
        assert!(served(&state, "agA", "GET", "/x", &[]));
        assert!(
            !served(&state, "agA", "POST", "/z", &[]),
            "write floor never approved"
        );
    }

    /// Mint under an explicit decision, as when the policy (or a field the
    /// grant key does not carry) decided the approved request differently
    /// from the request that later replays it.
    fn mint_as(
        level: crate::core::policy::AccessLevel,
        by: crate::core::policy::DecidedBy,
        method: &str,
        path: &str,
        scoped: bool,
        bound: &[(&str, &str)],
    ) -> (Value, crate::approval::PolicyContext) {
        let mut scope = json!({
            "connection_id": RC, "service": RC, "host": RH,
            "method": method, "path": path, "authorize_only": true, "agent": "agA",
        });
        crate::proxy::handler::stamp_signed_level(&mut scope, level, &by, scoped, method, 120);
        if scoped {
            scope["scoped"] = json!(true);
            if !bound.is_empty() {
                let m: serde_json::Map<String, Value> = bound
                    .iter()
                    .map(|(k, v)| (k.to_string(), json!(v)))
                    .collect();
                scope["scope_vars"] = Value::Object(m);
            }
        }
        let pc = crate::approval::PolicyContext {
            level,
            decided_by: by,
            ttl_seconds: 120,
            host: Some(RH.into()),
        };
        assert_signed_level(&scope, Some(&pc)).expect("stamp passes the apply assertion");
        (scope, pc)
    }

    /// The proxy's lookup for a request the policy decides as `(level, by)`.
    fn served_as(
        state: &AppState,
        level: crate::core::policy::AccessLevel,
        by: &crate::core::policy::DecidedBy,
        method: &str,
        path: &str,
        scoped: bool,
        bound: &[(&str, &str)],
    ) -> bool {
        let pairs: Vec<(String, String)> = bound
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let digest = crate::service::scope_digest(&pairs);
        crate::proxy::handler::grant_lookup(
            state, RV, "agA", RC, level, by, method, RH, path, &digest, scoped,
        )
        .0
        .is_some()
    }

    fn by_rule(id: Option<&str>) -> crate::core::policy::DecidedBy {
        crate::core::policy::DecidedBy::Rule {
            id: id.map(str::to_string),
            label: None,
        }
    }

    /// An ask-always grant is spent only by an ask-always request: a scoped
    /// ask (which would only read it) and an id-less-rule ask on the same
    /// request line miss, without spending it.
    #[test]
    fn ask_always_grant_redeems_only_as_ask_always() {
        use crate::core::policy::AccessLevel::{Ask, AskAlways};
        let state = reuse_state();
        let v80 = [("amount", "80")];
        let (scope, pc) = mint_as(AskAlways, by_rule(Some("buy")), "POST", "/buy", true, &v80);
        assert_eq!(scope["reuse"], "none");
        apply(&state, &scope, &pc, now_s());
        assert!(
            !served_as(
                &state,
                Ask,
                &by_rule(Some("buy")),
                "POST",
                "/buy",
                true,
                &v80
            ),
            "a scoped ask does not read an ask-always grant"
        );
        assert!(!served_as(
            &state,
            Ask,
            &by_rule(None),
            "POST",
            "/buy",
            true,
            &v80
        ));
        assert!(served_as(
            &state,
            AskAlways,
            &by_rule(Some("buy")),
            "POST",
            "/buy",
            true,
            &v80
        ));
        assert!(
            !served_as(
                &state,
                AskAlways,
                &by_rule(Some("buy")),
                "POST",
                "/buy",
                true,
                &v80
            ),
            "single-use"
        );
    }

    /// A scoped ask's `exact` grant is read only by a scoped ask of the same
    /// unit: an ask-always request on the same line cannot spend it, and
    /// another unit (a floor ask, an id-less rule) cannot read it.
    #[test]
    fn exact_grant_redeems_only_for_its_unit() {
        use crate::core::policy::AccessLevel::{Ask, AskAlways};
        use crate::core::policy::DecidedBy;
        let state = reuse_state();
        let v80 = [("amount", "80")];
        let (scope, pc) = mint(&state, "POST", "/buy", true, &v80);
        assert_eq!(scope["reuse"], "exact");
        apply(&state, &scope, &pc, now_s());
        assert!(
            !served_as(
                &state,
                AskAlways,
                &by_rule(Some("buy")),
                "POST",
                "/buy",
                true,
                &v80
            ),
            "ask-always never spends an exact grant"
        );
        assert!(!served_as(
            &state,
            Ask,
            &DecidedBy::Floor,
            "POST",
            "/buy",
            true,
            &v80
        ));
        assert!(!served_as(
            &state,
            Ask,
            &by_rule(Some("other")),
            "POST",
            "/buy",
            true,
            &v80
        ));
        assert!(!served_as(
            &state,
            Ask,
            &by_rule(None),
            "POST",
            "/buy",
            true,
            &v80
        ));
        assert!(
            served(&state, "agA", "POST", "/buy", &v80),
            "still there for its own unit"
        );
    }

    /// An ask a rule with no id decided is single-use on a scoped path too
    /// (signed `none`), and only an id-less-rule ask redeems it.
    #[test]
    fn id_less_rule_ask_is_single_use_and_same_tier_only() {
        use crate::core::policy::AccessLevel::{Ask, AskAlways};
        use crate::core::policy::DecidedBy;
        let state = reuse_state();
        let (scope, pc) = mint_as(Ask, by_rule(None), "GET", "/y", false, &[]);
        assert_eq!(scope["reuse"], "none");
        assert!(scope.get("window_s").is_none());
        apply(&state, &scope, &pc, now_s());
        assert_eq!(ledger_len(&state), 0);
        assert!(!served_as(
            &state,
            AskAlways,
            &by_rule(None),
            "GET",
            "/y",
            false,
            &[]
        ));
        assert!(!served_as(
            &state,
            Ask,
            &DecidedBy::Floor,
            "GET",
            "/y",
            false,
            &[]
        ));
        assert!(served_as(
            &state,
            Ask,
            &by_rule(None),
            "GET",
            "/y",
            false,
            &[]
        ));
        assert!(!served_as(
            &state,
            Ask,
            &by_rule(None),
            "GET",
            "/y",
            false,
            &[]
        ));

        let v80 = [("amount", "80")];
        let (scope, pc) = mint_as(Ask, by_rule(None), "POST", "/buy", true, &v80);
        assert_eq!(scope["reuse"], "none", "no unit: not exact");
        apply(&state, &scope, &pc, now_s());
        assert!(
            !served(&state, "agA", "POST", "/buy", &v80),
            "not an exact grant"
        );
        assert!(served_as(
            &state,
            Ask,
            &by_rule(None),
            "POST",
            "/buy",
            true,
            &v80
        ));
        assert!(!served_as(
            &state,
            Ask,
            &by_rule(None),
            "POST",
            "/buy",
            true,
            &v80
        ));
    }

    /// A read approved under a rule never serves a write under the same rule
    /// (the ledger unit is the rule and the request's class). The signed
    /// fields stay the rule's id and label.
    #[test]
    fn rule_reuse_is_per_class() {
        let state = reuse_state();
        let (scope, pc) = mint(&state, "GET", "/rw", false, &[]);
        assert_eq!(scope["reuse"], "rule");
        assert_eq!(scope["reuse_rule"], "rw");
        assert!(scope.get("reuse_class").is_none());
        apply(&state, &scope, &pc, now_s());
        assert!(served(&state, "agA", "GET", "/rw", &[]));
        assert!(served(&state, "agA", "HEAD", "/rw", &[]), "another read");
        assert!(!served(&state, "agA", "POST", "/rw", &[]), "a write asks");
        assert!(!served(&state, "agA", "DELETE", "/rw", &[]), "a write asks");
        assert!(
            !served(&state, "agA", "MOVE", "/rw", &[]),
            "an extension method is a write"
        );

        let (scope, pc) = mint(&state, "post", "/rw", false, &[]);
        apply(&state, &scope, &pc, now_s());
        assert!(
            served(&state, "agA", "PUT", "/rw", &[]),
            "the write class, any case"
        );
    }

    /// A Use op that does not carry a signed level is refused at approve, and
    /// apply plans no grant without a policy context.
    #[tokio::test]
    async fn approve_refuses_a_use_op_without_a_signed_level() {
        use crate::core::policy::AccessLevel;
        let state = Arc::new(test_state());
        let op = use_op("v1", "/user");
        assert!(op.act.scope.get("level").is_none());
        let id = {
            let mut s = state.approvals.lock().unwrap();
            s.create_with_policy(
                "v1".into(),
                op.clone(),
                b64r(9),
                Some(pc(AccessLevel::Ask, 900)),
            )
        };
        let err = approve_op(
            State(state.clone()),
            Path(id),
            Json(plain_grant(op.clone(), &b64r(9))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::BadRequest(m) if m.contains("no signed policy level")),
            "{err}"
        );
        assert!(plan_use_grant(None, &op.act.scope, "v1", "agA", b"t".to_vec(), 0).is_none());
    }

    /// The whole approve_op path refuses a stored op whose signed reuse is not
    /// the reuse apply would grant (before any crypto or vault access).
    #[tokio::test]
    async fn approve_refuses_signed_reuse_mismatch() {
        use crate::core::policy::AccessLevel;
        let state = Arc::new(test_state());
        // use_op is a GET floor ask: anything but floor/read/900 is refused.
        let cases: [&[(&str, Value)]; 5] = [
            &[("reuse", json!("exact")), ("window_s", json!(900))],
            &[("reuse", json!("none"))],
            &[("reuse", json!("connection")), ("window_s", json!(900))],
            &[
                ("reuse", json!("floor")),
                ("reuse_class", json!("write")),
                ("window_s", json!(900)),
            ],
            &[
                ("reuse", json!("rule")),
                ("reuse_rule", json!("read")),
                ("window_s", json!(900)),
            ],
        ];
        for fields in cases {
            let mut op = use_op("v1", "/user");
            op.act.scope["level"] = json!("ask");
            for (k, v) in fields {
                op.act.scope[*k] = v.clone();
            }
            let id = {
                let mut s = state.approvals.lock().unwrap();
                s.create_with_policy(
                    "v1".into(),
                    op.clone(),
                    b64r(9),
                    Some(pc(AccessLevel::Ask, 900)),
                )
            };
            let err = approve_op(
                State(state.clone()),
                Path(id),
                Json(plain_grant(op, &b64r(9))),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&err, AppError::BadRequest(m) if m.contains("reuse") || m.contains("window_s")),
                "{fields:?}: {err}"
            );
        }
    }

    fn exact_read_tier() -> crate::approval::reuse::BoundTier {
        use crate::approval::reuse::{BoundTier, Class, GrantUnit};
        BoundTier::Exact(GrantUnit::Floor(Class::Read))
    }

    fn deferred_pair(agent: &str) -> (DeferredGrant, DeferredGrant) {
        use crate::approval::reuse::{Class, GrantUnit};
        (
            DeferredGrant::Ledger {
                vault_id: "v1".into(),
                agent: agent.into(),
                conn: "github".into(),
                host: "api.github.com".into(),
                unit: GrantUnit::Rule("read".into(), Class::Read),
                value: b"tok-conn".to_vec(),
                ttl: 600,
                expires_at: u64::MAX / 2,
            },
            DeferredGrant::OpGrant {
                vault_id: "v1".into(),
                agent: agent.into(),
                conn: "github".into(),
                method: "GET".into(),
                host: "api.github.com".into(),
                path: "/user".into(),
                scope_digest: String::new(),
                tier: exact_read_tier(),
                value: b"tok-bound".to_vec(),
                expires_at: u64::MAX / 2,
            },
        )
    }

    fn grants_present(state: &AppState, agent: &str) -> (bool, bool) {
        let ledger = {
            let runtime = state.runtime_if_present("v1").unwrap();
            let runtime_state = runtime.state.lock().unwrap();
            match &*runtime_state {
                crate::state::VaultState::Unlocked { cache, .. } => cache
                    .ask_grants
                    .keys()
                    .any(|(a, c, _, _)| a == agent && c == "github"),
                _ => false,
            }
        };
        (
            ledger,
            state
                .op_grant_take(
                    "v1",
                    agent,
                    "github",
                    "GET",
                    "api.github.com",
                    "/user",
                    "",
                    &exact_read_tier(),
                )
                .is_some(),
        )
    }

    /// The Use grant is written only once the op is marked approved. A status
    /// flip that bypasses the vault write lock (user reject, requester
    /// withdrawal / reaper, auto-reject) landing between dispatch and approve
    /// leaves NO grant behind an op that reads rejected.
    #[test]
    fn deferred_use_grant_not_written_when_op_flipped_before_approve() {
        let state = test_state();
        state.unlock_vault(
            "v1".into(),
            crate::state::SecretsCache::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );
        for flip in [
            "user rejected",
            crate::server::handlers::op::WITHDRAWN_REASON,
        ] {
            for which in 0..2 {
                let c = chained(&state, "/user", &b64r(1));
                let (conn, bound) = deferred_pair("ag_x");
                let g = if which == 0 { conn } else { bound };
                // Dispatch done; the flip lands before step 5.
                state.approvals.lock().unwrap().reject(&c.id, flip);
                let err = approve_and_commit(&state, &c.id, None, Some(g)).unwrap_err();
                assert!(matches!(err, AppError::Conflict(_)), "{err}");
                assert_eq!(
                    grants_present(&state, "ag_x"),
                    (false, false),
                    "flip={flip}"
                );
                assert!(matches!(
                    state.approvals.lock().unwrap().get(&c.id).unwrap().status,
                    ApprovalStatus::Rejected { .. }
                ));
            }
        }
        // Auto-reject (MAX_APPROVE_ATTEMPTS failures) is the same flip.
        let c = chained(&state, "/user", &b64r(2));
        for _ in 0..crate::approval::store::MAX_APPROVE_ATTEMPTS {
            state.approvals.lock().unwrap().record_failure(&c.id);
        }
        let (conn, _) = deferred_pair("ag_x");
        assert!(approve_and_commit(&state, &c.id, None, Some(conn)).is_err());
        assert_eq!(grants_present(&state, "ag_x"), (false, false));

        // Still pending at step 5: approved, then the grant is written.
        let c = chained(&state, "/user", &b64r(3));
        let (conn, bound) = deferred_pair("ag_x");
        approve_and_commit(&state, &c.id, None, Some(conn)).unwrap();
        let c2 = chained(&state, "/user", &b64r(4));
        approve_and_commit(&state, &c2.id, None, Some(bound)).unwrap();
        assert_eq!(grants_present(&state, "ag_x"), (true, true));
    }

    /// Satisfied / rejected chain siblings emit SSE `cancelled` with the
    /// pointer in the reason, agreeing with their audit row.
    #[tokio::test]
    async fn chain_sibling_sse_agrees_with_audit() {
        let state = Arc::new(test_state());
        let mut rx = state.events.subscribe();
        let a = chained(&state, "/user", &b64r(1));
        let b = chained(&state, "/user", &b64r(2));
        let (_, sibs) = state
            .approvals
            .lock()
            .unwrap()
            .approve_chain(&b.id, None)
            .unwrap();
        finish_chain_siblings(&state, &sibs, &ChainOutcome::Satisfied { by: &b.id });
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.approval_id, a.id);
        assert_eq!(ev.kind, "cancelled");
        assert_eq!(
            ev.reason.as_deref(),
            Some(format!("satisfied by {}", b.id).as_str())
        );
        // The poller still reads `ok`.
        assert_eq!(op_poll_value(&state, &a.id, None).unwrap()["status"], "ok");
    }

    // ── approval authority (requester or vault admin) ──────────────────────

    /// The shared-vault fixture of the role tests: the creator (root 0x11) is
    /// an admin; B (root 0x22, passkey "cid-b") and C (root 0x33, passkey
    /// "cid-c") are members.
    fn authority_vault() -> (&'static str, String, String, String, PerItemVault) {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, b, creator_id, b_id, mut pv) =
            crate::storage::sealed_vault::tests::role_fixture_creator_cred();
        let c = UikRoot::from_root([0x33u8; 32]);
        let c_id = c.user_id();
        for (cid, who) in [("cid-b", &b), ("cid-c", &c)] {
            let g = creator.signing().sign(&crate::identity::role_grant_input(
                vault,
                &who.user_id(),
                "member",
                0,
            ));
            pv.set_uik_cred(
                cid.into(),
                who.user_id(),
                who.signing().public_bytes().to_vec(),
                vec![9u8; 32],
                vec![1u8; 40],
                vec![2u8; 40],
                MemberRole::Member,
                g.to_vec(),
            );
        }
        (vault, creator_id, b_id, c_id, pv)
    }

    /// One gesture over several ops: every op row is judged on its own, so a
    /// member's batch applies to the op they raised and is refused for the op
    /// another member raised; an admin's batch applies to both.
    #[test]
    fn batch_refuses_only_the_foreign_op() {
        let (vault, admin_id, b_id, c_id, pv) = authority_vault();
        let requester = |who: &str| -> BTreeSet<String> { [who.to_string()].into() };
        // B's rows: B's own op applies; C's op is foreign to B.
        let verdicts: Vec<bool> = [&b_id, &c_id]
            .iter()
            .map(|who| authorize_approver(Some(&pv), vault, &requester(who), &b_id).is_ok())
            .collect();
        assert_eq!(verdicts, vec![true, false]);
        let err = authorize_approver(Some(&pv), vault, &requester(&c_id), &b_id).unwrap_err();
        assert!(matches!(err, AppError::ApproverNotAuthorized(_)), "{err}");
        assert_eq!(err.code().0.as_str(), "approver_not_authorized");
        // The admin's rows apply to every member's op.
        for who in [&b_id, &c_id] {
            authorize_approver(Some(&pv), vault, &requester(who), &admin_id).unwrap();
        }
        // No per-item keyset (a whole-blob personal vault): only the paired account.
        authorize_approver(None, vault, &requester(&b_id), &b_id).unwrap();
        assert!(authorize_approver(None, vault, &requester(&b_id), &admin_id).is_err());
    }

    // ── an admin approves another member's op with the vault key (k_*) ─────

    /// The admin's passkey id on B's daemon (url-safe base64 of `admin`).
    const ADMIN_CID: &str = "YWRtaW4";
    /// C's passkey id (url-safe base64 of `c-c`).
    const C_CID: &str = "Yy1j";
    /// The vault key (generation 0) the vault's items are sealed under.
    const VAULT_K: [u8; 32] = [0x42u8; 32];

    /// B's daemon on the shared vault, paired to B: B's own passkey ("Yw") is
    /// seated; the membership served the creator's (an admin) passkey and C's
    /// (a member) as approval material only. FOO and BAR are sealed under K.
    struct BDaemon {
        state: Arc<AppState>,
        vault: &'static str,
        admin: p256::ecdsa::SigningKey,
        c: p256::ecdsa::SigningKey,
        /// r → op id of every op [`BDaemon::raise`]d.
        ids: std::cell::RefCell<std::collections::HashMap<String, String>>,
    }

    impl Drop for BDaemon {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.state.config.state_dir);
        }
    }

    fn xy(key: &p256::ecdsa::SigningKey) -> (String, String) {
        let point = key.verifying_key().to_encoded_point(false);
        (
            STANDARD.encode(point.x().unwrap()),
            STANDARD.encode(point.y().unwrap()),
        )
    }

    fn b_daemon(tag: &str) -> BDaemon {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::item::{ItemNs, ItemPayload, VaultKeys};
        use crate::storage::plaintext::MemberRole;
        type S = sudp::primitives::StdPrimitives;
        let state = Arc::new(test_state_in(tag));
        let (vault, admin_id, b_id, c_id, mut pv) = authority_vault();
        let b = UikRoot::from_root([0x22u8; 32]);
        pv.set_uik_cred(
            "Yw".into(),
            b_id.clone(),
            b.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            Vec::new(),
        );
        let admin = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let c = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (ax, ay) = xy(&admin);
        let (cx, cy) = xy(&c);
        pv.set_approver_credential(ADMIN_CID, &admin_id, &ax, &ay)
            .unwrap();
        pv.set_approver_credential(C_CID, &c_id, &cx, &cy).unwrap();
        let keys = VaultKeys::single(&VAULT_K);
        for (name, value) in [("FOO", "foo-value"), ("BAR", "bar-value")] {
            pv.plant::<S>(
                keys,
                vault,
                ItemNs::Secret,
                name,
                1,
                &ItemPayload::secret_live(name, value),
            )
            .unwrap();
        }
        let path = state.vaults.per_item_path(vault).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::storage::sealed_vault::write_per_item_atomic(&path, &pv).unwrap();
        pin_account(Some(&b_id));
        BDaemon {
            state,
            vault,
            admin,
            c,
            ids: Default::default(),
        }
    }

    fn team_export_op(vault: &str, name: &str) -> crate::protocol::operation::Operation {
        use crate::protocol::operation::{Act, Bind, Operation, Valid};
        Operation {
            act: Act {
                kind: ActType::Export,
                target: name.into(),
                scope: json!({}),
            },
            bind: Bind {
                redeemer: vault.into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    impl BDaemon {
        /// An op B's agent raised: (op, r, op id).
        fn raise(&self, name: &str) -> (crate::protocol::operation::Operation, String, String) {
            let op = team_export_op(self.vault, name);
            let r = self
                .state
                .challenges
                .lock()
                .unwrap()
                .issue("127.0.0.1".parse().unwrap())
                .unwrap();
            let id = self.state.approvals.lock().unwrap().create(
                self.vault.into(),
                op.clone(),
                r.clone(),
            );
            self.ids.borrow_mut().insert(r.clone(), id.clone());
            (op, r, id)
        }

        /// Seal `material` to this daemon's `sc_pk` under `info`.
        fn seal(&self, material: &[u8], info: &[u8]) -> (String, String) {
            let (enc, ct) =
                crate::crypto::envelope::seal_to(&self.state.sc.pk_bytes(), material, info, b"")
                    .unwrap();
            (URL_SAFE_NO_PAD.encode(enc), URL_SAFE_NO_PAD.encode(ct))
        }

        /// A plain grant on (op, r) by passkey `cid` (`key` signs β), delivering
        /// `material` as a vault key sealed for `seal_for`.
        fn k_grant(
            &self,
            (op, r): (&crate::protocol::operation::Operation, &str),
            cid: &str,
            key: &p256::ecdsa::SigningKey,
            material: &[u8],
            seal_for: &str,
        ) -> Grant {
            let beta = crate::crypto::binding::binding_for_op(
                crate::crypto::binding::DOMAIN_STANDARD,
                &STANDARD.decode(r).unwrap(),
                &serde_json::to_value(op).unwrap(),
            )
            .unwrap();
            let mut g = plain_grant(op.clone(), r);
            g.credential_id = cid.into();
            g.assertion = Some(assertion_over(key, &beta));
            let (enc, ct) = self.seal(
                material,
                &crate::crypto::envelope::grant_k_seal_info(seal_for),
            );
            g.k_enc = Some(enc);
            g.k_ct = Some(ct);
            self.sign_id(g)
        }

        /// Sign the grant's identity (C3) as the person whose passkey `g`
        /// names (the admin, B or C), over the grant's own op, r and K seal,
        /// for THIS daemon's `sc_pk`, approving the op raised with `g.r`.
        fn sign_id(&self, mut g: Grant) -> Grant {
            let op_id = self.ids.borrow()[&g.r].clone();
            let root = match g.credential_id.as_str() {
                ADMIN_CID => 0x11u8,
                C_CID => 0x33,
                _ => 0x22,
            };
            let uik = crate::crypto::vault_key::UikRoot::from_root([root; 32]);
            let id = uik.user_id();
            let input = self.id_input(&g, &op_id, &id);
            g.id_sig = Some(URL_SAFE_NO_PAD.encode(uik.signing().sign(&input)));
            g.id = Some(id);
            g
        }

        /// The C3 signing input of `g` approving `op_id` as `id`.
        fn id_input(&self, g: &Grant, op_id: &str, id: &str) -> Vec<u8> {
            let beta = crate::crypto::binding::binding_for_op(
                crate::crypto::binding::DOMAIN_STANDARD,
                &STANDARD.decode(&g.r).unwrap(),
                &serde_json::to_value(&g.o).unwrap(),
            )
            .unwrap();
            let dec = |s: &Option<String>| {
                s.as_deref()
                    .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                    .unwrap_or_default()
            };
            crate::identity::grant_id_input(
                self.vault,
                op_id,
                &beta,
                &decode_credential_id(&g.credential_id).unwrap(),
                &dec(&g.k_enc),
                &dec(&g.k_ct),
                &self.state.sc.pk_bytes(),
                id,
            )
        }

        async fn approve(&self, id: &str, grant: Grant) -> Result<Value> {
            approve_op(State(self.state.clone()), Path(id.into()), Json(grant))
                .await
                .map(|Json(v)| v)
        }

        /// The op is still pending, never counted toward auto-reject, and its
        /// single-use challenge is still live.
        fn assert_untouched(&self, id: &str, r: &str) {
            let store = self.state.approvals.lock().unwrap();
            let rec = store.get(id).unwrap();
            assert!(matches!(rec.status, ApprovalStatus::Pending));
            assert_eq!(rec.fail_count, 0);
            drop(store);
            assert!(
                self.state.challenges.lock().unwrap().peek(r),
                "challenge not consumed"
            );
        }
    }

    /// A real ES256 WebAuthn assertion over `challenge` for the test relying
    /// party (`localhost`).
    fn assertion_over(
        key: &p256::ecdsa::SigningKey,
        challenge: &[u8; 32],
    ) -> crate::passkey::webauthn::AssertionData {
        use p256::ecdsa::{signature::Signer, Signature};
        use sha2::{Digest, Sha256};
        let mut auth_data = Sha256::digest(b"localhost").to_vec();
        auth_data.push(0x01); // user present
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": "http://localhost",
        }))
        .unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let sig: Signature = key.sign(&signed);
        crate::passkey::webauthn::AssertionData {
            credential_id: None,
            authenticator_data: STANDARD.encode(&auth_data),
            client_data_json: STANDARD.encode(&client_data),
            signature: STANDARD.encode(sig.to_der().as_bytes()),
        }
    }

    /// An admin approves B's op by delivering the vault key, never a root:
    /// B's daemon opens the vault with it and applies the op. The 32-byte `K`
    /// and the 64-byte bundle (`id_seed ‖ content`) both work.
    #[tokio::test]
    async fn an_admins_vault_key_grant_applies_another_members_op() {
        let d = b_daemon("-kadmin");
        let (op, r, id) = d.raise("FOO");
        let v = d
            .approve(
                &id,
                d.k_grant((&op, &r), ADMIN_CID, &d.admin, &VAULT_K, &id),
            )
            .await
            .unwrap();
        assert_eq!(v["value"], "foo-value");
        assert!(matches!(
            d.state
                .approvals
                .lock()
                .unwrap()
                .get_any(&id)
                .unwrap()
                .status,
            ApprovalStatus::Approved
        ));
        assert!(
            !d.state.challenges.lock().unwrap().peek(&r),
            "consumed once applied"
        );

        let bundle = [VAULT_K, VAULT_K].concat();
        let (op, r, id) = d.raise("BAR");
        let v = d
            .approve(&id, d.k_grant((&op, &r), ADMIN_CID, &d.admin, &bundle, &id))
            .await
            .unwrap();
        assert_eq!(v["value"], "bar-value");
    }

    /// The same vault-key grant from a member who is neither the requester nor
    /// an admin (their passkey on B's daemon all the same) is refused with
    /// `approver_not_authorized` before validation: the op stays pending for
    /// the requester or an admin, who can still approve it.
    #[tokio::test]
    async fn a_members_vault_key_grant_for_anothers_op_is_refused() {
        let d = b_daemon("-kmember");
        let (op, r, id) = d.raise("FOO");
        let err = d
            .approve(&id, d.k_grant((&op, &r), C_CID, &d.c, &VAULT_K, &id))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::ApproverNotAuthorized(_)), "{err}");
        assert_eq!(err.code().0.as_str(), "approver_not_authorized");
        assert_eq!(err.code().0.status(), 403);
        d.assert_untouched(&id, &r);
        let v = d
            .approve(
                &id,
                d.k_grant((&op, &r), ADMIN_CID, &d.admin, &VAULT_K, &id),
            )
            .await
            .unwrap();
        assert_eq!(v["value"], "foo-value");
    }

    /// A malformed or mis-sealed vault key (bound to another op, sealed under
    /// the grant-secret domain, a half pair, not base64url, a wrong length) is
    /// refused without consuming the op; the right grant then applies.
    #[tokio::test]
    async fn a_mis_sealed_vault_key_is_refused_without_consuming_the_op() {
        let d = b_daemon("-kseal");
        let (op, r, id) = d.raise("FOO");
        let (other_op, other_r, other_id) = d.raise("BAR");
        let good = || d.k_grant((&op, &r), ADMIN_CID, &d.admin, &VAULT_K, &id);
        let mut bad: Vec<(&str, Grant)> = Vec::new();
        bad.push((
            "sealed for another op",
            d.k_grant((&op, &r), ADMIN_CID, &d.admin, &VAULT_K, &other_id),
        ));
        let mut g = good();
        let (enc, ct) = d.seal(&VAULT_K, &crate::crypto::envelope::grant_seal_info(&id));
        (g.k_enc, g.k_ct) = (Some(enc), Some(ct));
        bad.push(("sealed under the grant-secret domain", d.sign_id(g)));
        let mut g = good();
        g.k_ct = None;
        bad.push(("half pair", g));
        let mut g = good();
        g.k_enc = Some("not base64url!".into());
        bad.push(("not base64url", g));
        let mut g = good();
        let (enc, ct) = d.seal(
            &[0x42u8; 48],
            &crate::crypto::envelope::grant_k_seal_info(&id),
        );
        (g.k_enc, g.k_ct) = (Some(enc), Some(ct));
        bad.push(("48 bytes", d.sign_id(g)));
        for (why, grant) in bad {
            let err = d.approve(&id, grant).await.unwrap_err();
            assert!(matches!(err, AppError::BadRequest(_)), "{why}: {err}");
            d.assert_untouched(&id, &r);
        }
        // A wrong vault key (well sealed) opens nothing: the apply fails, the
        // value never leaves.
        let err = d
            .approve(
                &other_id,
                d.k_grant(
                    (&other_op, &other_r),
                    ADMIN_CID,
                    &d.admin,
                    &[7u8; 32],
                    &other_id,
                ),
            )
            .await;
        assert!(err.is_err(), "a wrong vault key applies nothing");
        let v = d.approve(&id, good()).await.unwrap();
        assert_eq!(v["value"], "foo-value");
    }

    /// A grant delivers exactly one of the sealed secret (`wk_*`), the sealed
    /// vault key (`k_*`) or the plaintext wrapping key: both, or neither, is
    /// refused up front, the op untouched.
    #[tokio::test]
    async fn a_grant_with_both_or_neither_delivery_is_refused() {
        let d = b_daemon("-kforms");
        let (op, r, id) = d.raise("FOO");
        let good = || d.k_grant((&op, &r), ADMIN_CID, &d.admin, &VAULT_K, &id);
        let mut both = good();
        let (enc, ct) = d.seal(
            &[0x11u8; 32],
            &crate::crypto::envelope::grant_seal_info(&id),
        );
        (both.wk_enc, both.wk_ct) = (Some(enc), Some(ct));
        let mut plain_and_k = good();
        plain_and_k.wrapping_key = Some(STANDARD.encode([0x11u8; 32]));
        let mut neither = good();
        (neither.k_enc, neither.k_ct) = (None, None);
        for (why, grant) in [
            ("wk_* and k_*", both),
            ("wrapping_key and k_*", plain_and_k),
            ("neither", neither),
        ] {
            let err = d.approve(&id, grant).await.unwrap_err();
            assert!(matches!(err, AppError::BadRequest(_)), "{why}: {err}");
            d.assert_untouched(&id, &r);
        }
        d.approve(&id, good()).await.unwrap();
    }

    /// The requester is the paired account (`account_uik`) alone: an admin's
    /// passkey in the registry, or a seat an older adoption keyed under an
    /// admin's passkey, never makes them a requester. Without a pinned account
    /// the fallback is this device's own passkeys, minus every credential the
    /// membership served as another member's approval material.
    #[test]
    fn the_requester_is_the_paired_account() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, admin_id, b_id, _c, mut pv) = authority_vault();
        let b = UikRoot::from_root([0x22u8; 32]);
        pv.set_uik_cred(
            "Yw".into(),
            b_id.clone(),
            b.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            Vec::new(),
        );
        // A stale seat: the admin keyed under their passkey, with its pubkey.
        let admin = UikRoot::from_root([0x11u8; 32]);
        pv.set_uik_cred(
            ADMIN_CID.into(),
            admin_id.clone(),
            admin.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Admin,
            Vec::new(),
        );
        pv.set_registry_pubkey(ADMIN_CID, "x", "y", "").unwrap();
        let only = |id: &str| -> BTreeSet<String> { [id.to_string()].into() };
        assert_eq!(requester_identities(&pv, Some(b_id.clone())), only(&b_id));
        assert_eq!(
            requester_identities(&pv, Some("us_other".into())),
            only("us_other")
        );
        // The approver label (as the membership serves it) takes the admin out
        // of the fallback too.
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .approver_cids
            .insert(ADMIN_CID.into(), admin_id.clone());
        assert_eq!(requester_identities(&pv, None), only(&b_id));
        // So the admin approving B's op is an admin, never "the requester".
        assert_eq!(
            pv.approval_authority(
                vault,
                &requester_identities(&pv, Some(b_id.clone())),
                &admin_id
            ),
            ApprovalAuthority::Admin
        );
    }

    /// One admin gesture over two of B's ops, each row delivering the vault key
    /// sealed for its own op: both apply. A row whose key is sealed for its
    /// sibling is a recoverable `batch_verify_failed`, its op untouched.
    #[tokio::test]
    async fn an_admins_batch_delivers_the_vault_key_per_op() {
        use crate::crypto::batch::{batch_challenge, batch_root};
        let d = b_daemon("-kbatch");
        let (op1, r1, id1) = d.raise("FOO");
        let (op2, r2, id2) = d.raise("BAR");
        let beta = |op: &crate::protocol::operation::Operation, r: &str| {
            crate::crypto::binding::binding_for_op(
                crate::crypto::binding::DOMAIN_STANDARD,
                &STANDARD.decode(r).unwrap(),
                &serde_json::to_value(op).unwrap(),
            )
            .unwrap()
        };
        let root = batch_root(&[beta(&op1, &r1), beta(&op2, &r2)]).unwrap();
        let assertion = assertion_over(&d.admin, &batch_challenge(&root));
        let ids = vec![id1.clone(), id2.clone()];
        let row = |op: &crate::protocol::operation::Operation, r: &str, seal_for: &str| {
            let mut g = batch_grant(op.clone(), r, ids.clone());
            g.credential_id = ADMIN_CID.into();
            g.batch.as_mut().unwrap().assertion = assertion.clone();
            let (enc, ct) = d.seal(
                &VAULT_K,
                &crate::crypto::envelope::grant_k_seal_info(seal_for),
            );
            (g.k_enc, g.k_ct) = (Some(enc), Some(ct));
            d.sign_id(g)
        };
        let err = d.approve(&id2, row(&op2, &r2, &id1)).await.unwrap_err();
        assert!(matches!(err, AppError::BatchVerify(_)), "{err}");
        d.assert_untouched(&id2, &r2);

        let v1 = d.approve(&id1, row(&op1, &r1, &id1)).await.unwrap();
        let v2 = d.approve(&id2, row(&op2, &r2, &id2)).await.unwrap();
        assert_eq!(
            (v1["value"].as_str(), v2["value"].as_str()),
            (Some("foo-value"), Some("bar-value"))
        );
    }

    // ── grant v3: the vault key + the approver's identity signature ────────

    /// An unlock secret (`wk_*` sealed, or the plaintext `wrapping_key`) is
    /// refused on every vault with `wk_refused_v2`, before anything is opened:
    /// the op stays pending with its challenge live.
    #[tokio::test]
    async fn an_unlock_secret_is_refused_and_the_op_stays_pending() {
        let d = b_daemon("-v3wk");
        let (op, r, id) = d.raise("FOO");
        let mut sealed = d.k_grant((&op, &r), "Yw", &d.c, &VAULT_K, &id);
        let (enc, ct) = d.seal(
            &[0x22u8; 32],
            &crate::crypto::envelope::grant_seal_info(&id),
        );
        (sealed.k_enc, sealed.k_ct) = (None, None);
        (sealed.wk_enc, sealed.wk_ct) = (Some(enc), Some(ct));
        let mut plain = d.k_grant((&op, &r), "Yw", &d.c, &VAULT_K, &id);
        (plain.k_enc, plain.k_ct) = (None, None);
        plain.wrapping_key = Some(STANDARD.encode([0x22u8; 32]));
        for (why, g) in [("wk_*", sealed), ("wrapping_key", plain)] {
            let err = d.approve(&id, g).await.unwrap_err();
            assert!(matches!(err, AppError::WkRefused(_)), "{why}: {err}");
            assert_eq!(err.code().0.as_str(), "wk_refused_v2");
            d.assert_untouched(&id, &r);
        }
    }

    /// The identity signature is checked before anything else: missing,
    /// tampered, bound to another daemon key, by an unknown identity, or by
    /// someone other than the owner of the passkey that asserted, it is
    /// `grant_id_invalid` and the op stays pending. The honest grant applies.
    #[tokio::test]
    async fn a_bad_identity_signature_is_refused_and_the_op_stays_pending() {
        use crate::crypto::vault_key::UikRoot;
        let d = b_daemon("-v3id");
        let (op, r, id) = d.raise("FOO");
        let good = || d.k_grant((&op, &r), ADMIN_CID, &d.admin, &VAULT_K, &id);
        let sign_as = |mut g: Grant, root: u8, sc_pk: &[u8]| {
            let uik = UikRoot::from_root([root; 32]);
            let mut input = d.id_input(&g, &id, &uik.user_id());
            if sc_pk != d.state.sc.pk_bytes().as_slice() {
                let beta = crate::crypto::binding::binding_for_op(
                    crate::crypto::binding::DOMAIN_STANDARD,
                    &STANDARD.decode(&g.r).unwrap(),
                    &serde_json::to_value(&g.o).unwrap(),
                )
                .unwrap();
                input = crate::identity::grant_id_input(
                    d.vault,
                    &id,
                    &beta,
                    &decode_credential_id(&g.credential_id).unwrap(),
                    &URL_SAFE_NO_PAD.decode(g.k_enc.as_deref().unwrap()).unwrap(),
                    &URL_SAFE_NO_PAD.decode(g.k_ct.as_deref().unwrap()).unwrap(),
                    sc_pk,
                    &uik.user_id(),
                );
            }
            g.id = Some(uik.user_id());
            g.id_sig = Some(URL_SAFE_NO_PAD.encode(uik.signing().sign(&input)));
            g
        };
        let mut bad: Vec<(&str, Grant)> = Vec::new();
        let mut g = good();
        g.id = None;
        bad.push(("no id", g));
        let mut g = good();
        g.id_sig = None;
        bad.push(("no signature", g));
        let mut g = good();
        let mut sig = URL_SAFE_NO_PAD
            .decode(g.id_sig.as_deref().unwrap())
            .unwrap();
        sig[0] ^= 1;
        g.id_sig = Some(URL_SAFE_NO_PAD.encode(sig));
        bad.push(("tampered", g));
        let me = d.state.sc.pk_bytes();
        bad.push(("bound to another daemon", sign_as(good(), 0x11, &[7u8; 32])));
        // C signs correctly as C, but the passkey that asserted is the admin's.
        bad.push(("someone else's passkey", sign_as(good(), 0x33, &me)));
        bad.push(("unknown identity", sign_as(good(), 0x77, &me)));
        // Signed over a sibling op's id: the row is bound to its own op.
        let (_o2, _r2, other) = d.raise("BAR");
        let mut g = good();
        let uik = UikRoot::from_root([0x11u8; 32]);
        g.id_sig = Some(URL_SAFE_NO_PAD.encode(uik.signing().sign(&d.id_input(
            &g,
            &other,
            &uik.user_id(),
        ))));
        bad.push(("signed for another op", g));
        for (why, g) in bad {
            let err = d.approve(&id, g).await.unwrap_err();
            assert!(matches!(err, AppError::GrantIdInvalid(_)), "{why}: {err}");
            assert_eq!(err.code().0.as_str(), "grant_id_invalid", "{why}");
            d.assert_untouched(&id, &r);
        }
        let v = d.approve(&id, good()).await.unwrap();
        assert_eq!(v["value"], "foo-value");
    }

    /// A personal vault (no identities in its keyset): the approver is proven
    /// by the account key pinned at pairing, and only the paired account
    /// approves.
    #[test]
    fn the_paired_account_key_proves_the_requester() {
        use crate::crypto::vault_key::UikRoot;
        let state = test_state_in("-v3pin");
        let me = UikRoot::from_root([0x55u8; 32]);
        let op = team_export_op("v-personal", "FOO");
        let r = b64r(5);
        let mut g = plain_grant(op.clone(), &r);
        g.credential_id = "Yw".into();
        g.k_enc = Some(URL_SAFE_NO_PAD.encode([1u8; 32]));
        g.k_ct = Some(URL_SAFE_NO_PAD.encode([2u8; 48]));
        let beta = crate::crypto::binding::binding_for_op(
            crate::crypto::binding::DOMAIN_STANDARD,
            &STANDARD.decode(&r).unwrap(),
            &serde_json::to_value(&op).unwrap(),
        )
        .unwrap();
        let input = crate::identity::grant_id_input(
            "v-personal",
            "op-1",
            &beta,
            b"c",
            &[1u8; 32],
            &[2u8; 48],
            &state.sc.pk_bytes(),
            &me.user_id(),
        );
        g.id = Some(me.user_id());
        g.id_sig = Some(URL_SAFE_NO_PAD.encode(me.signing().sign(&input)));
        pin_account_key(me.signing().public_bytes());
        let signer =
            verify_grant_identity(&state, None, "v-personal", "op-1", &g, &op, &r).unwrap();
        assert_eq!(signer, me.user_id());
        check_approval_authority(None, "v-personal", &signer).unwrap();
        // Another account pinned: the signer's key is unknown here.
        pin_account_key(UikRoot::from_root([0x66u8; 32]).signing().public_bytes());
        let err =
            verify_grant_identity(&state, None, "v-personal", "op-1", &g, &op, &r).unwrap_err();
        assert!(matches!(err, AppError::GrantIdInvalid(_)), "{err}");
        pin_account(None);
    }
}
