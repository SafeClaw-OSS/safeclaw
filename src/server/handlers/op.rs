//! `POST /v/{vid}/op` — R-side operation creation.
//!
//! Body: a canonical sudp `Operation`. The custodian stores it as a pending
//! approval, issues a fresh challenge `r`, and returns `{ op_id, r, expires_at }`.
//! U later authorizes via `POST /op/{op_id}/approve` (binding β computed over r).
//!
//! All flows route through here — R-driven (Use/Export) AND U-direct
//! (Enroll/Write/console-Export). The two-RTT shape is uniform.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};

use crate::audit;
use crate::error::{AppError, Result};
use crate::protocol::operation::{ActType, Operation};
use crate::state::{AppState, ApprovalEvent};

pub async fn create(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Json(op): Json<Operation>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;
    reject_broker_kind(&op.act.kind)?;
    // F-11: validate op.act.target length. A 256-char cap prevents
    // unbounded strings from reaching audit rows and downstream handlers.
    // Character set is not enforced globally (target syntax is act-kind
    // specific), but the length cap applies universally.
    if op.act.target.len() > 256 {
        return Err(AppError::BadRequest(
            "op.act.target too long (max 256 chars)".into(),
        ));
    }
    // Locked-state gate (H3 / PROTOCOL.md §6.3): when the vault is Locked,
    // only the unlock ceremony (and first-time Enroll, which auto-unlocks)
    // is admissible. Everything else gets a canned 409 so the caller knows
    // to drive a `Custom("vault-unlock")` op first.
    let is_lifecycle_bypass = matches!(&op.act.kind, ActType::Enroll)
        || matches!(&op.act.kind, ActType::Custom(name) if name == "vault-unlock");
    if !is_lifecycle_bypass && state.is_vault_locked(&vault_id) {
        return Err(AppError::VaultLocked);
    }
    // ONE approval window (SSOT, user decision 2026-07-14): ops that arrive
    // without an explicit Valid window — the CLI ceremonies (unlock / set /
    // connect) — inherit the vault's `aux.policy.timeout`, the SAME knob the
    // broker's ask path uses, so the grant-page countdown, the value stash,
    // and the op's own expiry can never disagree. A locked vault (the unlock
    // ceremony) can't read its policy and takes the 30-min default.
    let mut op = op;
    // Requester attribution: verified from the agent's proof over this exact
    // op, else none (see `attribute_agent`).
    let agent = attribute_agent(&headers, &vault_id, &mut op, crate::util::now_unix());
    // connection-add: the approval card (bound keys per slot, written vs
    // referenced, destinations, sharing) is computed HERE from the unlocked
    // session state and stamped into the signed scope, overwriting anything
    // the requester sent in those fields; apply re-derives and compares
    // (`connection_add::assert_card`).
    if matches!(&op.act.kind, ActType::Custom(name) if name == "connection-add") {
        crate::server::handlers::connection_add::stamp_at_mint(&state, &vault_id, &mut op)
            .map_err(AppError::BadRequest)?;
    }
    if op.valid.exp.is_none() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        op.valid.exp = Some(now_unix + state.policy_approval_hold(&vault_id));
    }
    let ip: IpAddr = addr.ip();
    let r = {
        let mut store = state.challenges.lock().unwrap();
        store.issue(ip).ok_or(AppError::TooManyRequests)?
    };
    // E1 (design/approvals-inbox.md D2): an Export's plaintext is bound to the
    // process that created it. A random per-op waiter secret goes back ONLY in
    // this response (never in SSE, never to the relay, never logged); the
    // record keeps its SHA-256, and `GET /op/{id}` releases the value only to
    // a poll presenting it.
    let waiter_secret: Option<String> = if op.act.kind == ActType::Export {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rand::RngCore as _;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Some(URL_SAFE_NO_PAD.encode(b))
    } else {
        None
    };
    let (op_id, expires_at) = {
        let mut store = state.approvals.lock().unwrap();
        let id = store.create_bound(vault_id.clone(), op.clone(), r.clone(), None, agent.clone());
        if let Some(secret) = &waiter_secret {
            store.set_waiter(&id, secret);
        }
        let exp = store.get(&id).map(|r| r.expires_at_unix).unwrap_or(0);
        (id, exp)
    };

    // Persist a `pending` audit row so `GET /v/{vid}/approvals?status=pending`
    // can return current pendings on page load (in-memory ApprovalStore is
    // process-bound). Best-effort — audit failure must NOT block op creation.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(&vault_id) {
        // F-22: cap pending ops per vault to prevent SQLite table flooding.
        const MAX_PENDING_PER_VAULT: i64 = 500;
        match store.count_pending() {
            Ok(n) if n >= MAX_PENDING_PER_VAULT => {
                return Err(AppError::TooManyRequests);
            }
            Err(e) => {
                tracing::warn!(vault = %vault_id, "audit count_pending failed: {}", e);
                // non-fatal — let the op through rather than blocking legitimate use
            }
            _ => {}
        }
        let mut row = audit::row_from_op(&op_id, &op, now, expires_at as i64);
        row.agent_prefix = agent.clone();
        if let Err(e) = store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending failed: {}", e);
        }
    }

    // Slice-2 web approval: if a cloud op-relay is configured, register this
    // pending op and poll for the browser-deposited grant in the background.
    // No-op when relay_url is unset (purely local daemon).
    crate::relay::client::spawn_register_and_poll(
        state.clone(),
        vault_id.clone(),
        op_id.clone(),
        serde_json::to_value(&op).unwrap_or(Value::Null),
        r.clone(),
        expires_at,
        agent.clone(), // the verified requesting agent, if any
        vec![],        // only `use` ops join intent chains
    );

    // Requester-side supersede: a lifecycle ceremony (unlock/lock) is a
    // singleton — at most one should be live per vault. When a new one is
    // created (e.g. the user Ctrl-C'd `sc unlock` and retried), withdraw the
    // stale prior op so the console stops showing "1 approval waiting". Only
    // ceremonies supersede; Use/Export ops can legitimately be concurrent.
    if let ActType::Custom(name) = &op.act.kind {
        if name == "vault-unlock" || name == "vault-lock" {
            let prev = {
                let mut live = state.live_ceremony_ops.lock().unwrap();
                live.insert((vault_id.clone(), name.clone()), op_id.clone())
            };
            if let Some(prev_id) = prev {
                if prev_id != op_id {
                    cancel_superseded(&state, &vault_id, &prev_id, now);
                }
            }
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: vault_id,
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    // `op` = the op exactly as stored (and as relayed for approval), which may
    // differ from the request body (a defaulted `valid.exp`, a stamped
    // connection-add card). A local signer must sign THIS.
    let mut resp = json!({
        "op_id": op_id,
        "r": r,
        "expires_at": expires_at,
        "op": serde_json::to_value(&op).unwrap_or(Value::Null),
    });
    if let Some(secret) = waiter_secret {
        resp["waiter_secret"] = json!(secret);
    }
    Ok(Json(resp))
}

/// Requester attribution for an op created on this LOCAL API (the CLI
/// ceremonies). A requester-supplied `scope.agent` is always dropped; the
/// agent is stamped only from a valid proof of possession over exactly this
/// op as received (header [`crate::agent_pop::OP_POP_HEADER`], verified by
/// [`crate::agent_pop::verify_op_pop`]): the same `scope.agent` `ag_…` id a
/// proxy-originated Use op carries, so the approval names the agent. A
/// missing, malformed, stale, or mismatched proof yields no attribution.
///
/// This is display and consent information, not a security boundary: any
/// local process can omit the proof (the op then reads as from a terminal),
/// and nothing is authorized by it. It is therefore not checked against the
/// vault's agents table (a locked vault, the unlock ceremony, cannot read
/// it): the claim is only "the holder of this agent key asked", which the
/// proof establishes either way.
fn attribute_agent(
    headers: &HeaderMap,
    vault_id: &str,
    op: &mut Operation,
    now: u64,
) -> Option<String> {
    // Verify BEFORE any mutation: the proof covers the op as sent.
    let verified = headers
        .get(crate::agent_pop::OP_POP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| crate::agent_pop::verify_op_pop(t, vault_id, op, now));
    if let Some(o) = op.act.scope.as_object_mut() {
        o.remove("agent");
    }
    let ag = verified?;
    if op.act.scope.is_null() {
        op.act.scope = json!({});
    }
    op.act
        .scope
        .as_object_mut()?
        .insert("agent".into(), Value::String(ag.clone()));
    Some(ag)
}

/// Withdraw a ceremony op that a newer one just superseded. Local: flip the
/// stale in-memory record terminal + stamp its audit row `cancelled`. Cloud:
/// withdraw it from the relay (device-key auth, no passkey — no credential is
/// touched). All best-effort; the backend cancel only affects a `pending` op.
fn cancel_superseded(state: &Arc<AppState>, vault_id: &str, op_id: &str, now: i64) {
    const REASON: &str = "superseded by a newer request";
    let was_pending = {
        let mut store = state.approvals.lock().unwrap();
        store.reject(op_id, REASON).is_some()
    };
    if was_pending {
        if let Ok(store) = state.audits.for_vault(vault_id) {
            if let Err(e) = store.finalize(
                op_id,
                audit::STATUS_CANCELLED,
                now,
                None,
                Some(REASON),
                None,
            ) {
                tracing::warn!(vault = %vault_id, op = %op_id, "audit finalize cancelled failed: {}", e);
            }
        }
        state.emit_event(ApprovalEvent {
            vault_id: vault_id.to_string(),
            approval_id: op_id.to_string(),
            kind: "cancelled".into(),
            op_summary: None,
            response_preview: None,
            reason: Some(REASON.into()),
        });
    }
    crate::relay::client::spawn_cancel(
        state.clone(),
        vault_id.to_string(),
        op_id.to_string(),
        None, // legacy reason-less withdraw (contract §2)
    );
}

/// Local record reason for a requester withdrawal (contract §1).
pub const WITHDRAWN_REASON: &str = "withdrawn by requester";
/// Local record reason for the E1 liveness backstop.
pub const ABANDONED_REASON: &str = "abandoned by requester";

/// Liveness backstop window: a pending Export whose waiter has not polled
/// (with its secret) for this long is withdrawn as abandoned (design
/// D1-E). The CLI polls every ≤ 5 s, well inside it.
pub const WAITER_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// Withdraw a pending op on its requester's behalf: terminal
/// `Rejected{reason}` locally, audit `cancelled`, SSE `cancelled`, relay row
/// cancelled with `relay_reason`. NEVER `reject_op` — that reads as a user
/// denial (and resolves an intent chain); a withdrawal is neither. Returns
/// whether the op was still pending.
fn withdraw(
    state: &Arc<AppState>,
    vault_id: &str,
    op_id: &str,
    reason: &str,
    relay_reason: crate::relay::client::CancelReason,
) -> bool {
    let was_pending = {
        let mut store = state.approvals.lock().unwrap();
        store.reject(op_id, reason).is_some()
    };
    if !was_pending {
        return false;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(vault_id) {
        if let Err(e) = store.finalize(
            op_id,
            audit::STATUS_CANCELLED,
            now,
            None,
            Some(reason),
            None,
        ) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit finalize cancelled failed: {}", e);
        }
    }
    state.emit_event(ApprovalEvent {
        vault_id: vault_id.to_string(),
        approval_id: op_id.to_string(),
        kind: "cancelled".into(),
        op_summary: None,
        response_preview: None,
        reason: Some(reason.into()),
    });
    crate::relay::client::spawn_cancel(
        state.clone(),
        vault_id.to_string(),
        op_id.to_string(),
        Some(relay_reason),
    );
    true
}

/// `POST /op/{op_id}/cancel` — requester withdrawal (design D1-E, contract
/// §1). Body `{ "waiter_secret"?: string }`; an op that has a waiter secret
/// (every Export) can be withdrawn only by presenting it (constant-time).
/// `sc get` and every `remote_approve` waiter call this on Ctrl-C, SIGTERM
/// and timeout, so dead retries leave the inbox without any intent matching.
pub async fn cancel(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>> {
    let secret = body
        .as_ref()
        .and_then(|b| b.get("waiter_secret"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let vault_id = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
        if rec.waiter_hash.is_some() && !rec.waiter_matches(secret.as_deref()) {
            return Err(AppError::Forbidden(
                "this request can be withdrawn only by the process that created it".into(),
            ));
        }
        if !matches!(rec.status, crate::approval::ApprovalStatus::Pending) {
            return Err(AppError::Conflict("op not pending".into()));
        }
        rec.vault_id.clone()
    };
    if !withdraw(
        &state,
        &vault_id,
        &op_id,
        WITHDRAWN_REASON,
        crate::relay::client::CancelReason::Withdrawn,
    ) {
        return Err(AppError::Conflict("op not pending".into()));
    }
    Ok(Json(
        json!({ "ok": true, "op_id": op_id, "status": "rejected", "reason": WITHDRAWN_REASON }),
    ))
}

/// One reaper pass: withdraw every pending Export whose waiter has been
/// silent for `idle` (kill -9'd `sc get`). Returns the withdrawn ids.
pub fn reap_abandoned_exports(state: &Arc<AppState>, idle: std::time::Duration) -> Vec<String> {
    let stale = state.approvals.lock().unwrap().abandoned_exports(idle);
    let mut out = Vec::new();
    for (op_id, vault_id) in stale {
        if withdraw(
            state,
            &vault_id,
            &op_id,
            ABANDONED_REASON,
            crate::relay::client::CancelReason::Abandoned,
        ) {
            tracing::info!(op = %op_id, "export waiter went silent; request withdrawn (abandoned)");
            out.push(op_id);
        }
    }
    out
}

/// Background liveness backstop for E1 (spawned once at daemon start).
pub async fn reap_abandoned_exports_loop(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        reap_abandoned_exports(&state, WAITER_IDLE);
    }
}

/// Reject op kinds that are broker-plane primitives. Today: `Use`.
///
/// Reasoning: a Use op forwards an upstream HTTP request and is the unit
/// SaaS bills on. It must originate from the broker path (proxy port for
/// the network-gate deployment; SaaS-stamped JSON-API for a future
/// crypto-gate deployment) — never from the control-plane endpoint, which
/// has no billing gate by construction.
///
/// Control-plane ops (Enroll, Write, Export, Custom("vault-unlock"/...))
/// pass through; they're user-initiated state changes authorized by a
/// passkey-signed grant.
fn reject_broker_kind(kind: &ActType) -> Result<()> {
    if matches!(kind, ActType::Use) {
        return Err(AppError::BadRequest(
            "Use ops must be created via the broker path, not the control-plane op endpoint".into(),
        ));
    }
    // A whole-blob Write is retired: refuse it up front so nobody is asked to
    // approve an op that can't apply (approve refuses it too).
    if matches!(kind, ActType::Write) {
        return Err(AppError::BadRequest(
            crate::server::handlers::approve::WHOLE_BLOB_WRITE_RETIRED.into(),
        ));
    }
    Ok(())
}

pub fn validate_vault_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 {
        return Err(AppError::BadRequest(
            "invalid vault_id (1-128 chars)".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest("vault_id has illegal chars".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_use_kind() {
        let r = reject_broker_kind(&ActType::Use);
        assert!(matches!(r, Err(AppError::BadRequest(_))));
    }

    #[test]
    fn reject_retired_whole_blob_write() {
        match reject_broker_kind(&ActType::Write) {
            Err(AppError::BadRequest(msg)) => assert!(msg.contains("Upgrade"), "{msg}"),
            other => panic!("whole-blob Write must be refused, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn accept_control_plane_kinds() {
        for kind in [
            ActType::Enroll,
            ActType::Export,
            ActType::Custom("vault-unlock".into()),
            ActType::Custom("vault-lock".into()),
            ActType::Custom("vault-delete".into()),
        ] {
            assert!(
                reject_broker_kind(&kind).is_ok(),
                "kind {:?} should pass",
                kind
            );
        }
    }

    fn test_state() -> AppState {
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-op-{}",
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
        AppState::new(cfg)
    }

    /// RED LINE (verified invariant — see the export/allow discussion): an
    /// `Export` hands over the RAW secret (irreversible ownership transfer),
    /// so it MUST always require a passkey grant and must NEVER be
    /// auto-executed by the read/write `allow` policy default (cb124ca).
    ///
    /// The protection is architectural, not a policy line: `Use` (the only
    /// kind the `allow` fast-path can run) is forced onto the broker path by
    /// `reject_broker_kind`, while the control-plane `/op` endpoint consults
    /// NO policy for ANY kind — it always parks a pending op needing
    /// `/op/{id}/approve`. This test locks that: an Export on an UNLOCKED,
    /// default-`allow` vault still returns a pending `{op_id, r}` and reveals
    /// no secret inline. If someone ever wires policy-allow auto-execution
    /// into the Export path, this goes red.
    #[tokio::test]
    async fn export_is_always_pending_never_auto_executed_under_allow_default() {
        use crate::protocol::operation::{Act, Bind, Valid};

        let state = Arc::new(test_state());
        // Unlock with the default cache → the read/write `allow` default is
        // in force. This is the exact regime that must NOT reach Export.
        state.unlock_vault(
            "v1".into(),
            crate::state::SecretsCache::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );

        let op = Operation {
            act: Act {
                kind: ActType::Export,
                target: "native-secrets.github_token".into(),
                scope: Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, Some(300)),
        };

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let resp = create(
            State(state.clone()),
            ConnectInfo(addr),
            Path("v1".into()),
            HeaderMap::new(),
            Json(op),
        )
        .await
        .expect("Export op-create should succeed (and park a pending op)");

        let body = resp.0;
        // Pending: an op_id + challenge were issued, awaiting a passkey grant.
        assert!(
            body.get("op_id").and_then(|v| v.as_str()).is_some(),
            "Export must return a pending op_id, got {body}"
        );
        assert!(
            body.get("r").is_some(),
            "pending Export must carry a challenge `r`, got {body}"
        );
        // E1: the creator (and only the creator) gets a waiter secret.
        assert!(
            body.get("waiter_secret")
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                == Some(43),
            "Export create must return a 32-byte base64url waiter_secret, got {body}"
        );
        // Nothing executed inline: no raw secret / reveal payload leaked.
        for leak in ["value", "secret", "plaintext", "revealed"] {
            assert!(
                body.get(leak).is_none(),
                "Export create must NOT reveal '{leak}' inline (allow default leaked into Export!): {body}"
            );
        }
    }

    fn export_op() -> Operation {
        use crate::protocol::operation::{Act, Bind, Valid};
        Operation {
            act: Act {
                kind: ActType::Export,
                target: "GITHUB_TOKEN".into(),
                scope: Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, Some(u64::MAX / 2)),
        }
    }

    async fn create_unlocked(state: &Arc<AppState>, op: Operation) -> Value {
        if state.is_vault_locked("v1") {
            state.unlock_vault(
                "v1".into(),
                crate::state::SecretsCache::default(),
                zeroize::Zeroizing::new(Vec::new()),
            );
        }
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        create(
            State(state.clone()),
            ConnectInfo(addr),
            Path("v1".into()),
            HeaderMap::new(),
            Json(op),
        )
        .await
        .unwrap()
        .0
    }

    async fn create_with(state: &Arc<AppState>, op: Operation, headers: HeaderMap) -> Value {
        if state.is_vault_locked("v1") {
            state.unlock_vault(
                "v1".into(),
                crate::state::SecretsCache::default(),
                zeroize::Zeroizing::new(Vec::new()),
            );
        }
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        create(
            State(state.clone()),
            ConnectInfo(addr),
            Path("v1".into()),
            headers,
            Json(op),
        )
        .await
        .unwrap()
        .0
    }

    fn agent_signer() -> crate::agent_pop::AgentProxyPopSigner {
        let id = crate::identity::SigningIdentity::from_seed(&[7u8; 32]);
        let ag = crate::identity::derive_id(crate::identity::IdKind::Agent, &id.public_bytes());
        crate::agent_pop::AgentProxyPopSigner::new(id, ag)
    }

    fn pop_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(crate::agent_pop::OP_POP_HEADER, token.parse().unwrap());
        h
    }

    fn rm_op(scope: Value) -> Operation {
        serde_json::from_value(json!({
            "act": { "type": { "custom": "secret-rm" }, "target": "GITHUB_TOKEN", "scope": scope },
            "bind": { "redeemer": "v1" },
            "valid": { "iat": 0, "multiplicity": 1 }
        }))
        .unwrap()
    }

    /// The stored op's `scope.agent`, the record's agent, and the audit row's.
    fn attribution(state: &AppState, body: &Value) -> (Option<String>, Option<String>) {
        let id = body["op_id"].as_str().unwrap();
        let rec = state.approvals.lock().unwrap().get(id).unwrap().clone();
        let scope_agent = rec
            .op
            .act
            .scope
            .get("agent")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(
            body["op"]["act"]["scope"]
                .get("agent")
                .and_then(|v| v.as_str()),
            scope_agent.as_deref(),
            "the response op (what a local signer signs) matches the stored op"
        );
        (scope_agent, rec.agent_prefix)
    }

    /// A CLI ceremony run by an agent carries a proof over the exact op; the
    /// daemon stamps the agent into the signed scope (as a proxy Use op
    /// carries it) and onto the record.
    #[tokio::test]
    async fn valid_op_pop_stamps_the_agent() {
        let state = Arc::new(test_state());
        let s = agent_signer();
        let op = rm_op(Value::Null);
        let tok = s.op_token("v1", &op, crate::util::now_unix()).unwrap();
        let body = create_with(&state, op, pop_headers(&tok)).await;
        let (scope_agent, rec_agent) = attribution(&state, &body);
        assert_eq!(scope_agent.as_deref(), Some(s.agent_id()));
        assert_eq!(rec_agent.as_deref(), Some(s.agent_id()));
    }

    /// No proof, a proof over a different op, a proof for another vault, or a
    /// garbage header: nothing is stamped, and a requester-supplied
    /// `scope.agent` never survives.
    #[tokio::test]
    async fn absent_or_tampered_op_pop_stamps_nothing() {
        let state = Arc::new(test_state());
        let s = agent_signer();
        let now = crate::util::now_unix();
        let claimed = json!({ "agent": s.agent_id() });

        // Absent proof, forged claim in the scope.
        let body = create_with(&state, rm_op(claimed.clone()), HeaderMap::new()).await;
        assert_eq!(attribution(&state, &body), (None, None));

        // Proof signed over the op WITHOUT the claim, sent with it (tampered).
        let tok = s.op_token("v1", &rm_op(Value::Null), now).unwrap();
        let body = create_with(&state, rm_op(claimed.clone()), pop_headers(&tok)).await;
        assert_eq!(attribution(&state, &body), (None, None));

        // Proof for another vault.
        let tok = s.op_token("v2", &rm_op(Value::Null), now).unwrap();
        let body = create_with(&state, rm_op(Value::Null), pop_headers(&tok)).await;
        assert_eq!(attribution(&state, &body), (None, None));

        // A stale proof and a malformed one.
        let tok = s.op_token("v1", &rm_op(Value::Null), now - 3600).unwrap();
        let body = create_with(&state, rm_op(Value::Null), pop_headers(&tok)).await;
        assert_eq!(attribution(&state, &body), (None, None));
        let body = create_with(&state, rm_op(Value::Null), pop_headers("scpop1.x.y.z")).await;
        assert_eq!(attribution(&state, &body), (None, None));
    }

    fn status_of(state: &AppState, id: &str) -> crate::approval::ApprovalStatus {
        state
            .approvals
            .lock()
            .unwrap()
            .get(id)
            .unwrap()
            .status
            .clone()
    }

    /// Only Export ops get a waiter secret; the record keeps its hash only.
    #[tokio::test]
    async fn waiter_secret_only_for_export_and_stored_hashed() {
        let state = Arc::new(test_state());
        let body = create_unlocked(&state, export_op()).await;
        let id = body["op_id"].as_str().unwrap().to_string();
        let secret = body["waiter_secret"].as_str().unwrap().to_string();
        {
            let s = state.approvals.lock().unwrap();
            let rec = s.get(&id).unwrap();
            assert_eq!(
                rec.waiter_hash,
                Some(crate::approval::store::waiter_digest(&secret))
            );
        }
        let mut lock = export_op();
        lock.act.kind = ActType::Custom("vault-lock".into());
        lock.act.target = String::new();
        let body = create_unlocked(&state, lock).await;
        assert!(body.get("waiter_secret").is_none(), "{body}");
    }

    /// `POST /op/{id}/cancel`: an Export needs its waiter secret; success is a
    /// requester withdrawal (`withdrawn by requester`), never a user reject.
    #[tokio::test]
    async fn cancel_requires_waiter_secret_and_withdraws() {
        let state = Arc::new(test_state());
        let body = create_unlocked(&state, export_op()).await;
        let id = body["op_id"].as_str().unwrap().to_string();
        let secret = body["waiter_secret"].as_str().unwrap().to_string();

        for bad in [
            None,
            Some(json!({})),
            Some(json!({ "waiter_secret": "nope" })),
        ] {
            let err = cancel(State(state.clone()), Path(id.clone()), bad.map(Json))
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::Forbidden(_)), "{err}");
            assert!(matches!(
                status_of(&state, &id),
                crate::approval::ApprovalStatus::Pending
            ));
        }
        let ok = cancel(
            State(state.clone()),
            Path(id.clone()),
            Some(Json(json!({ "waiter_secret": secret }))),
        )
        .await
        .unwrap();
        assert_eq!(ok.0["reason"], WITHDRAWN_REASON);
        match status_of(&state, &id) {
            crate::approval::ApprovalStatus::Rejected { reason } => {
                assert_eq!(reason, WITHDRAWN_REASON)
            }
            other => panic!("expected withdrawn, got {other:?}"),
        }
        // Already resolved → 409, nothing changes.
        let err = cancel(
            State(state.clone()),
            Path(id.clone()),
            Some(Json(json!({ "waiter_secret": secret }))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));

        // A non-Export op (no waiter secret on record) is withdrawable by id.
        let mut lock = export_op();
        lock.act.kind = ActType::Custom("vault-lock".into());
        lock.act.target = String::new();
        let body = create_unlocked(&state, lock).await;
        let lid = body["op_id"].as_str().unwrap().to_string();
        let _ = cancel(State(state.clone()), Path(lid.clone()), None)
            .await
            .unwrap();
        assert!(matches!(
            status_of(&state, &lid),
            crate::approval::ApprovalStatus::Rejected { .. }
        ));
    }

    /// The liveness reaper withdraws a pending Export whose waiter went silent
    /// past the window (kill -9'd `sc get`) as `abandoned`, and leaves a live
    /// one alone.
    #[tokio::test]
    async fn reaper_withdraws_abandoned_exports() {
        let state = Arc::new(test_state());
        let stale = create_unlocked(&state, export_op()).await["op_id"]
            .as_str()
            .unwrap()
            .to_string();
        let live = create_unlocked(&state, export_op()).await["op_id"]
            .as_str()
            .unwrap()
            .to_string();
        state
            .approvals
            .lock()
            .unwrap()
            .get_mut_for_test(&stale)
            .unwrap()
            .last_waiter_poll = std::time::Instant::now() - std::time::Duration::from_secs(61);

        let reaped = reap_abandoned_exports(&state, WAITER_IDLE);
        assert_eq!(reaped, vec![stale.clone()]);
        match status_of(&state, &stale) {
            crate::approval::ApprovalStatus::Rejected { reason } => {
                assert_eq!(reason, ABANDONED_REASON)
            }
            other => panic!("expected abandoned, got {other:?}"),
        }
        assert!(matches!(
            status_of(&state, &live),
            crate::approval::ApprovalStatus::Pending
        ));
        // Idempotent: nothing left to reap.
        assert!(reap_abandoned_exports(&state, WAITER_IDLE).is_empty());
    }
}
