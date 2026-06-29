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
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};

/// HPKE `info` prefix for the pending-passkey deposit seal. The full info
/// string is `PENDING_PASSKEY_INFO_PREFIX ‖ vault_id ‖ 0x1F ‖ cid_new` —
/// binding the seal to (vault, cid) so a deposit prepared for one pairing
/// can't be opened against another. Frontend builds the same string in
/// `lib/passkey-vault-primitive.ts`.
const PENDING_PASSKEY_INFO_PREFIX: &[u8] = b"safeclaw/v1/pending-passkey";
use serde_json::{json, Value};

use crate::approval::ApprovalStatus;
use crate::audit::{STATUS_APPROVED, STATUS_REJECTED};
use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{
    as_enroll_credential, as_export_path, as_write_patch, decode_credential_id,
    discriminator, ActType,
};
use crate::protocol::{render_operation, validate_grant, Grant};
use crate::server::handlers::metadata::{decrypt_vault_view, decrypt_vault_view_keep_key};
use crate::storage::plaintext::VaultPlaintextView;
use crate::state::{ApprovalEvent, AppState, SecretsCache};
use crate::storage::sealed_vault::{
    build_initial, find_pubkey, read as read_vault, replace_after_write, write_atomic,
};

/// `GET /op/{op_id}` — JSON poll: status + cached value + render(o).
///
/// The agent (and the CLI's browser-callback flow) polls this for the op's
/// state. There is no HTML branch: the human approves on safeclaw.pro (the
/// op-relay carries the sealed grant back to the daemon), so the daemon serves
/// no approval page of its own (2026-06-23 zero-inbound pivot).
pub async fn get_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match get_op_json(state, op_id).await {
        Ok(j) => j.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn get_op_json(
    state: Arc<AppState>,
    op_id: String,
) -> Result<Json<Value>> {
    let store = state.approvals.lock().unwrap();
    let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
    // Consumed ops: the approve window is closed. Return a minimal tombstone
    // — no op content — to limit the exposure window for the agent request
    // body and upstream URL that live in op.act.scope. The op_id's 122-bit
    // entropy is the access-control mechanism for in-flight ops; once the
    // op is consumed, that window should close.
    if matches!(rec.status, ApprovalStatus::Consumed) {
        return Ok(Json(json!({
            "op_id": rec.id,
            "status": "consumed",
        })));
    }

    let act_kind = discriminator(&rec.op.act);
    let display = render_operation(&rec.op);
    let path = match &rec.op.act.kind {
        ActType::Export => Some(rec.op.act.target.clone()),
        _ => None,
    };
    let op_json = serde_json::to_value(&rec.op)?;
    let (status, value) = match &rec.status {
        ApprovalStatus::Pending => ("pending", None),
        ApprovalStatus::Approved => ("approved", rec.cached_value.clone()),
        ApprovalStatus::Rejected { .. } => ("rejected", None),
        ApprovalStatus::Consumed => unreachable!("handled above"),
    };
    Ok(Json(json!({
        "op_id": rec.id,
        "r": rec.r,
        "status": status,
        "act": act_kind,
        "path": path,
        "display": display,
        "op": op_json,
        "value": value,
        "expires_at": rec.expires_at_unix,
    })))
}

/// `POST /op/{op_id}/approve` — U submits the signed grant. T validates and
/// dispatches the act (Enroll / Write / Export / Use).
pub async fn approve_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    Json(mut grant): Json<Grant>,
) -> Result<Json<Value>> {
    // 1. Look up the pending op.
    let (vault_id, approval_op) = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
        if !matches!(rec.status, ApprovalStatus::Pending) {
            return Err(AppError::Conflict("op not pending".into()));
        }
        if rec.fail_count >= crate::approval::store::MAX_APPROVE_ATTEMPTS {
            return Err(AppError::TooManyRequests);
        }
        (rec.vault_id.clone(), rec.op.clone())
    };

    // 2. grant.o must equal the stored op (canonical equality).
    let canonical_grant_op = serde_json::to_value(&grant.o)?;
    let canonical_stored_op = serde_json::to_value(&approval_op)?;
    if canonical_grant_op != canonical_stored_op {
        return Err(AppError::BadRequest(
            "grant.o does not match the stored op".into(),
        ));
    }

    // 3. Serialize vault reads/writes per vault (F-17).
    // Two concurrent approve calls on the same vault both read the same
    // on-disk state and race to write_atomic — the second rename wins
    // silently. This per-vault async mutex ensures the full read-validate-
    // write cycle is atomic per vault without blocking unrelated vaults.
    let vault_write_lock = {
        let mut locks = state.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault_id.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _vault_write_guard = vault_write_lock.lock().await;

    // 3b. Resolve credential pubkey lookup.
    //
    // For Enroll, the credential is brand-new (not in vault yet) — pubkey is
    // taken from the op's scope. For Write/Export/Use, the credential must be
    // already enrolled — look it up in the existing vault.
    let vault_path = state.vaults.vault_path(&vault_id)?;
    let existing_vault = read_vault(&vault_path)?;
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        existing_vault.as_ref().and_then(|v| find_pubkey(v, cred_id_b64))
    };
    // 3c. HPKE-unseal W_c if the grant carries a sealed wrapping key (the web /
    // op-relay path). The browser sealed W* to our `sc_pk` with
    // `info = grant_seal_info(op_id)` so any cloud intermediary carrying the
    // grant never saw W*. Populate `grant.wrapping_key` with the opened bytes
    // so the rest of validation is identical to the legacy plaintext path.
    // (Legacy local op-page ships plaintext `wrapping_key` and skips this.)
    if grant.wk_enc.is_some() || grant.wk_ct.is_some() {
        let enc_b64 = grant.wk_enc.as_deref().ok_or_else(|| {
            AppError::BadRequest("sealed wrapping key needs both wk_enc and wk_ct (wk_enc missing)".into())
        })?;
        let ct_b64 = grant.wk_ct.as_deref().ok_or_else(|| {
            AppError::BadRequest("sealed wrapping key needs both wk_enc and wk_ct (wk_ct missing)".into())
        })?;
        let enc = URL_SAFE_NO_PAD
            .decode(enc_b64)
            .map_err(|_| AppError::BadRequest("wk_enc not base64url".into()))?;
        let ct = URL_SAFE_NO_PAD
            .decode(ct_b64)
            .map_err(|_| AppError::BadRequest("wk_ct not base64url".into()))?;
        let info = crate::crypto::envelope::grant_seal_info(&op_id);
        let wk = state.sc.open(&enc, &ct, &info, b"")?;
        if wk.len() != 32 {
            return Err(AppError::BadRequest("sealed wrapping_key must be 32 bytes".into()));
        }
        grant.wrapping_key = Some(STANDARD.encode(&wk));
    }

    let mut validated = {
        let result = {
            let mut chs = state.challenges.lock().unwrap();
            validate_grant(
                &grant,
                &mut chs,
                &state.config.origin,
                &state.config.rp_id,
                lookup_credential,
            )
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
    let mut audit_upstream_status: Option<i64> = None;
    let (response, cached_value) = match &validated.op.act.kind {
        ActType::Enroll if validated.op.act.target == "passkeys" => {
            // Add-passkey-to-existing-vault path. PROTOCOL.md §3.4 maps
            // `target = "passkeys"` to "register a new credential against
            // the already-enrolled vault". K stays the same (no state-key
            // rotation), but a new SealedCredential entry gets appended
            // with K wrapped under the new credential's W_c.
            //
            // Same- and cross-device add-passkey both go through the
            // pending-passkey deposit (`storage::pending_passkey`):
            //   - Stage 1 (any device with the new credential): POST
            //     /v/{vid}/pending-passkeys with HPKE-sealed user_key_initial.
            //   - Stage 2 (any device with an existing vault-enrolled
            //     credential, possibly the same device): this op, with
            //     `scope.new = { credential_id }` referring to the pending.
            //
            // grant.opt is NOT consulted — the new credential's W_c lives
            // exclusively in the daemon-stored pending-passkey blob.
            let vault = existing_vault.clone().ok_or_else(|| {
                AppError::Conflict("vault not initialized — first-time enroll required".into())
            })?;
            // scope.new should just carry { credential_id } — that's the
            // pointer to the pending-passkey file. No public-key / W_c
            // material inline.
            let new_cid_str = validated
                .op
                .act
                .scope
                .get("new")
                .and_then(|n| n.get("credential_id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::BadRequest(
                    "add-passkey: scope.new.credential_id required".into(),
                ))?
                .to_string();
            // Pop the pending file (single-use, deleted on read).
            let pending = crate::storage::pending_passkey::load_and_consume(
                &state.vaults,
                &vault_id,
                &new_cid_str,
            )
            .map_err(|_| AppError::NotFound)?;
            // HPKE-open the sealed user_key_initial with daemon's sc_sk.
            // info binds the seal to (vault_id, cid) — the Stage 1 device
            // committed to those at seal time, so a deposit prepared for
            // (vault_A, cidA) can't be replayed against a different vault
            // or cid.
            let enc = URL_SAFE_NO_PAD
                .decode(&pending.enc)
                .map_err(|_| AppError::BadRequest("pending.enc not base64url".into()))?;
            let ct = URL_SAFE_NO_PAD
                .decode(&pending.ct)
                .map_err(|_| AppError::BadRequest("pending.ct not base64url".into()))?;
            let mut info: Vec<u8> = Vec::with_capacity(
                PENDING_PASSKEY_INFO_PREFIX.len() + vault_id.len() + new_cid_str.len() + 2,
            );
            info.extend_from_slice(PENDING_PASSKEY_INFO_PREFIX);
            info.extend_from_slice(vault_id.as_bytes());
            info.push(0x1f); // unit separator
            info.extend_from_slice(new_cid_str.as_bytes());
            let new_w_c = state.sc.open(&enc, &ct, &info, b"")?;
            if new_w_c.len() != 32 {
                return Err(AppError::BadRequest(
                    "sealed user_key_initial must be 32 bytes after open".into(),
                ));
            }
            // Open the vault to recover K. We deliberately don't reuse
            // decrypt_vault_view here because we need K itself, not the
            // ProtectedState view.
            // F-05: move W_c bytes into RedeemedGrant instead of cloning so
            // there is only one copy of the key on the heap at a time.
            let redeemed = sudp::grant::RedeemedGrant {
                o: validated.op.clone(),
                credential_id: validated.credential_id_bytes.clone(),
                wrapping_key: sudp::grant::WrappingKey::from_bytes(
                    std::mem::take(&mut validated.wrapping_key),
                ),
                opt: sudp::grant::GrantOpt::default(),
            };
            let opened = sudp::phases::consumption::open::<sudp::primitives::StdPrimitives>(
                &redeemed, &vault,
            )
            .map_err(|e| AppError::Unauthorized(format!("vault open: {}", e)))?;
            // Wrap K under the new W_c with sudp's canonical wrap primitive.
            use sudp::primitives::{KeyWrap as _KeyWrap, WrapBinding};
            type Wrap = <sudp::primitives::StdPrimitives as sudp::primitives::PrimitiveSuite>::Wrap;
            let new_cid_bytes = decode_credential_id(&new_cid_str)?;
            if vault.find_credential(&new_cid_bytes).is_some() {
                return Err(AppError::Conflict(
                    "credential already enrolled on this vault".into(),
                ));
            }
            let binding = WrapBinding {
                credential_id: &new_cid_bytes,
                version: vault.version,
            };
            let wrapped_for_new = Wrap::wrap(&new_w_c, &opened.k[..], &binding)
                .map_err(|e| AppError::Internal(format!("wrap K under new W_c: {}", e)))?;
            // W_c for the new credential is no longer needed — zeroize immediately.
            let mut new_w_c = new_w_c;
            new_w_c.zeroize();
            // Append to credentials + registry, using the (x, y, prf_salt,
            // device_name) we just popped from the pending file.
            let mut updated = vault.clone();
            let new_prf_salt = STANDARD
                .decode(&pending.prf_salt)
                .map_err(|_| AppError::BadRequest("prf_salt not base64".into()))?;
            updated.credentials.push(sudp::state::SealedCredential {
                credential_id: new_cid_bytes.clone(),
                prf_salt: new_prf_salt,
                wrapped_key: wrapped_for_new,
            });
            let pk = sudp::passkey::WebAuthnPublicKey {
                x: pending.x,
                y: pending.y,
                device_name: pending.device_name,
            };
            updated
                .registry
                .insert::<sudp::passkey::WebAuthn>(&new_cid_bytes, &pk)
                .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
            write_atomic(&vault_path, &updated)?;
            tracing::info!(
                vault = %vault_id,
                cred_count = updated.credentials.len(),
                "vault add-passkey applied (pending-passkey consumed)"
            );
            (
                json!({ "ok": true, "act": "enroll", "target": "passkeys" }),
                None,
            )
        }
        ActType::Enroll => {
            let credential = as_enroll_credential(&validated.op)?;
            if existing_vault.is_some() {
                return Err(AppError::Conflict(
                    "vault already initialized for this vault_id".into(),
                ));
            }
            let payload = grant.setup_payload.as_ref().ok_or_else(|| {
                AppError::BadRequest("enroll grant missing setup_payload".into())
            })?;
            let cid_bytes = decode_credential_id(&credential.credential_id)?;
            let prf_salt = STANDARD
                .decode(&credential.prf_salt)
                .map_err(|_| AppError::BadRequest("prf_salt not base64".into()))?;
            let wrapped_key = STANDARD
                .decode(&payload.wrapped_key)
                .map_err(|_| AppError::BadRequest("wrapped_key not base64".into()))?;
            let ciphertext = STANDARD
                .decode(&payload.ciphertext)
                .map_err(|_| AppError::BadRequest("ciphertext not base64".into()))?;
            let vault = build_initial(
                cid_bytes,
                credential.public_key_x,
                credential.public_key_y,
                credential.device_name,
                prf_salt,
                wrapped_key,
                ciphertext,
            )?;
            state.vaults.ensure_dir(&vault_id)?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(vault = %vault_id, "vault enroll complete");
            // Auto-unlock after Enroll: the user just proved their passkey,
            // and we already hold W_c. Bootstrapping the cache inline here
            // saves /try (and any first-time-setup flow) a second passkey
            // ceremony before the agent's first /use call. Best-effort — a
            // bootstrap failure leaves the vault Locked (user can manually
            // unlock later) rather than failing the enroll.
            if let Ok((view, k)) = decrypt_vault_view_keep_key(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            ) {
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    "vault auto-unlocked after enroll"
                );
                state.unlock_vault(vault_id.clone(), cache, k);
            }
            (
                json!({ "ok": true, "vault_id": vault_id, "act": "enroll" }),
                None,
            )
        }
        ActType::Write => {
            let patch = as_write_patch(&validated.op)?;
            let mut vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let new_prf_salt = STANDARD
                .decode(&patch.prf_salt_next)
                .map_err(|_| AppError::BadRequest("prf_salt_next not base64".into()))?;
            let new_wrapped_key = STANDARD
                .decode(&patch.wrapped_key)
                .map_err(|_| AppError::BadRequest("wrapped_key not base64".into()))?;
            let new_ciphertext = STANDARD
                .decode(&patch.ciphertext)
                .map_err(|_| AppError::BadRequest("ciphertext not base64".into()))?;
            replace_after_write(
                &mut vault,
                &grant.credential_id,
                new_prf_salt,
                new_wrapped_key,
                new_ciphertext,
            )?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(vault = %vault_id, "vault write applied");
            // Auto-refresh cache from the new ciphertext using the same
            // wrapping_key the grant carries (Write doesn't rotate W_c
            // unless paired with a passkey op). Without this, the
            // daemon's `entries` / `native_keys` / `external_stores`
            // snapshots stay stuck on the pre-Write state until the
            // user manually locks + unlocks — most visible symptom is
            // a freshly-Connected GCP store whose `list()` keys never
            // surface in /v/{vid}/keys-known. Best-effort: a rotation-
            // case decrypt failure leaves the cache stale but doesn't
            // fail the Write.
            if state.is_vault_locked(&vault_id) {
                // Vault was Locked when this Write arrived. Don't
                // auto-unlock from a Write — the user expects unlock
                // to be a deliberate ceremony.
            } else if let Ok((view, k)) = decrypt_vault_view_keep_key(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            ) {
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    external_stores = cache.external_stores.len(),
                    "vault cache re-bootstrapped after write"
                );
                state.unlock_vault(vault_id.clone(), cache, k);
            } else {
                tracing::warn!(
                    vault = %vault_id,
                    "post-write cache refresh skipped — decrypt failed (rotation?); user must lock+unlock to see new state",
                );
            }
            // A Write may have sealed a `<conn>_oauth_pending` from a browser
            // "Connect" — complete the OAuth code→token exchange NOW instead of
            // waiting for the next unlock or cloud-sync pull (the symptom this
            // fixes: the web UI sticks on "Connecting…" after paste because the
            // Write path never kicked the exchange). CONNECTIONS_AND_AUTH.md §4a.
            // Detached + best-effort: process_vault_connects acquires the
            // per-vault write lock itself (not reentrant, so it must run AFTER
            // this handler's guard drops) and no-ops if the vault is locked.
            {
                let state = state.clone();
                let vid = vault_id.clone();
                tokio::spawn(async move {
                    crate::auth::connect::process_vault_connects(&state, &vid).await;
                });
            }
            (json!({ "ok": true, "act": "write" }), None)
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
            let cid_b64 = target
                .strip_prefix("passkeys.")
                .ok_or_else(|| AppError::BadRequest(
                    "revoke target must be 'passkeys.<credential_id>'".into(),
                ))?;
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
            (json!({ "ok": true, "act": "revoke", "target": target }), None)
        }
        ActType::Export => {
            // F-15: reject KEM-sealed Export until it is implemented.
            // If a client submits a grant with bind.recipient set, the raw-reveal
            // path would silently ignore it and return the secret in plain TLS.
            // Block this until a proper HPKE-sealed Export path is available.
            if validated.op.bind.recipient.is_some() {
                return Err(AppError::BadRequest(
                    "KEM-sealed Export not yet implemented; omit bind.recipient".into(),
                ));
            }
            let path = as_export_path(&validated.op)?;
            let vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let view = decrypt_vault_view(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            )?;

            // Editor reveal-all: target = "env" (legacy alias) or "" surfaces
            // every native-secrets item as a plaintext UTF-8 string map.
            // Per-item Export goes through the else branch and looks up a
            // single item by name (no `env.` prefix in v3).
            if path == "env" || path.is_empty() {
                let mut all = serde_json::Map::new();
                for (k, v) in view.native_secrets.iter() {
                    let s = String::from_utf8(v.clone()).map_err(|_| {
                        AppError::Internal("native-secrets item not utf8".into())
                    })?;
                    all.insert(k.clone(), serde_json::Value::String(s));
                }
                let resp = json!({
                    "ok": true, "act": "export", "path": path,
                    "value": serde_json::Value::Object(all),
                });
                let cached = Some(resp["value"].to_string());
                (resp, cached)
            } else {
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
            let vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let outcome = crate::server::broker::execute_use_forward(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
                &state,
                &vault_id,
            )
            .await?;
            // Cache the resolved s_o per PROTOCOL.md §6.2 — but ONLY if
            // the policy decision that drove this op was allow or ask
            // (with TTL). ask-always explicitly never caches (the bytes
            // go out of scope here and Rust drops them; we don't
            // re-export them anywhere).
            //
            // The `policy_context` was stamped on the ApprovalRecord at
            // /use time; we read it here without mutating state. Cache
            // write happens *after* a successful forward, so a failed
            // upstream call doesn't pollute the cache.
            {
                let pc_for_cache = state
                    .approvals
                    .lock()
                    .unwrap()
                    .get(&op_id)
                    .and_then(|r| r.policy_context.clone());
                if let Some(pc) = pc_for_cache {
                    // Key the resolved-secret cache by the **connection**
                    // (CONNECTION_SCHEMA.md §6) so two accounts of one service
                    // never share a slot. Falls back to `service` for the default
                    // connection (conn == service).
                    let conn = validated
                        .op
                        .act
                        .scope
                        .get("connection_id")
                        .or_else(|| validated.op.act.scope.get("service"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !conn.is_empty() {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let expires_at = match pc.level {
                            crate::core::policy::AccessLevel::Allow => None, // ∞ until lock
                            crate::core::policy::AccessLevel::Ask => Some(now + pc.ttl_seconds),
                            _ => Some(0), // sentinel: don't cache (shouldn't be reached)
                        };
                        if expires_at != Some(0) {
                            state.cache_insert(
                                &vault_id,
                                &conn,
                                outcome.s_o.clone(),
                                expires_at,
                            );
                        }
                    }
                }
            }
            audit_upstream_status = Some(outcome.response.status as i64);
            let body = serde_json::to_string(&outcome.response)?;
            (
                json!({ "ok": true, "act": "use", "response": serde_json::from_str::<Value>(&body).unwrap_or(Value::Null) }),
                Some(body),
            )
        }
        ActType::Custom(name) => match name.as_str() {
            // Lifecycle op (H3 / PROTOCOL.md §6.3): decrypt vault, bootstrap
            // secrets_cache for allow-policy services, transition to Unlocked,
            // and return all target plaintexts to the requester (the same
            // shape Export-with-target="env" returned, so /try's editor
            // doesn't need a separate reveal call).
            "vault-unlock" => {
                let vault = existing_vault
                    .clone()
                    .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
                let (view, unlock_key) = decrypt_vault_view_keep_key(
                    &validated.op,
                    &validated.wrapping_key,
                    &validated.credential_id_bytes,
                    &vault,
                )?;
                // Editor response: native-secrets items as utf8 strings + the
                // full v3 aux so the editor can render the stores list and
                // build a new aux when the user writes.
                let mut kv = serde_json::Map::new();
                for (k, v) in view.native_secrets.iter() {
                    let s = String::from_utf8(v.clone()).map_err(|_| {
                        AppError::Internal("native-secrets item not utf8".into())
                    })?;
                    kv.insert(k.clone(), Value::String(s));
                }
                let aux_json = serde_json::to_value(&view.aux)?;
                // Bootstrap cache: every allow-policy service's auth value
                // resolved via the v3 store_order. Native-only at unlock time
                // — external adapters (gcp/1p/aws) fetch lazily at /use time.
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    "vault unlocked"
                );
                state.unlock_vault(vault_id.clone(), cache, unlock_key);
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
                        crate::auth::connect::process_vault_connects(&state, &vid).await;
                    });
                }
                let value = json!({ "kv": Value::Object(kv), "aux": aux_json });
                let resp = json!({
                    "ok": true, "act": "vault-unlock",
                    "value": value,
                });
                let cached = Some(resp["value"].to_string());
                (resp, cached)
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
                // Close the cached AuditStore SQLite handle BEFORE removing
                // the directory. On Linux, unlinking a file that still has
                // an open fd leaves the inode alive: any subsequent
                // `state.audits.for_vault(vid)` call returns the cached
                // Arc<AuditStore> and reads/writes against the now-orphan
                // inode. Recreating the same vault_id (deterministic from
                // user_id, so very common after delete) then sees the old
                // approvals "from 50 minutes ago" instead of an empty log.
                // Matches the admin DELETE path's ordering (admin.rs).
                state.audits.forget(&vault_id);
                state.vaults.remove(&vault_id).map_err(|e| {
                    AppError::Internal(format!("vault dir remove: {}", e))
                })?;
                {
                    let mut states = state.vault_states.lock().unwrap();
                    states.remove(&vault_id);
                }
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
                let cid_b64 = target
                    .strip_prefix("passkeys.")
                    .ok_or_else(|| AppError::BadRequest(
                        "rename-passkey target must be 'passkeys.<credential_id>'".into(),
                    ))?;
                let new_name = validated
                    .op
                    .act
                    .scope
                    .get("device_name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::BadRequest(
                        "rename-passkey scope.device_name required".into(),
                    ))?
                    .trim()
                    .to_string();
                if new_name.is_empty() {
                    return Err(AppError::BadRequest(
                        "device_name cannot be empty".into(),
                    ));
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
                    .ok_or_else(|| AppError::BadRequest(
                        "target credential not enrolled on this vault".into(),
                    ))?;
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

    // 5. Mark approved + emit event. We also pull the policy_context off
    // the record before mutation so we can write into the rule-approvals
    // cache below — without this, an `ask`-with-TTL approval would never
    // short-circuit the next matching request.
    let (rec_id, rec_vault_id, response_preview, policy_ctx_for_cache) = {
        let mut store = state.approvals.lock().unwrap();
        let rec = store.approve(&op_id, cached_value.clone()).ok_or_else(|| {
            AppError::Conflict("op no longer pending after validation".into())
        })?;
        let preview = match &validated.op.act.kind {
            ActType::Use => cached_value
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok()),
            _ => None,
        };
        // Only Use ops carry a policy_context (other op kinds bypass the
        // policy gate). Cache writes are gated by Ask level — AskAlways is
        // explicitly excluded at op-create time so it'll be None here.
        let pc = if matches!(validated.op.act.kind, ActType::Use) {
            rec.policy_context.clone()
        } else {
            None
        };
        (rec.id.clone(), rec.vault_id.clone(), preview, pc)
    };

    // Cache write: an Ask-level approval scopes a TTL'd "next matching
    // request fast-paths" effect. Service id pulled off the op's scope
    // (which `use_broker` populates verbatim). No-op when:
    //   - The op wasn't a Use (policy_ctx_for_cache is None)
    //   - The level was Allow / AskAlways / Deny (not stored)
    //   - The vault relocked between approve and now (record_ask_approval
    //     is a no-op then)
    if let Some(pc) = policy_ctx_for_cache {
        if pc.level == crate::core::policy::AccessLevel::Ask {
            // The grant is scoped to the **connection** (CONNECTION_SCHEMA.md §6):
            // approving account A's request never fast-paths account B. Falls back
            // to `service` for the default connection (conn == service).
            let conn = validated
                .op
                .act
                .scope
                .get("connection_id")
                .or_else(|| validated.op.act.scope.get("service"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Method scopes the grant (a read-approval can't fast-path a
            // later write). Pulled off the op's scope, same as `connection_id`.
            let req_method = validated
                .op
                .act
                .scope
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !conn.is_empty() && !req_method.is_empty() {
                state.record_ask_approval(
                    &rec_vault_id,
                    &conn,
                    pc.rule_id,
                    &req_method,
                    pc.ttl_seconds,
                );
            }
        }
    }

    // Audit: pending → approved. Best-effort; daemon UX must not depend on
    // audit being healthy.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(&rec_vault_id) {
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
        approval_id: rec_id,
        kind: "approved".into(),
        op_summary: None,
        response_preview,
        reason: None,
    });

    Ok(Json(response))
}

pub async fn reject_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<Value>> {
    let (rec_id, rec_vault_id) = {
        let mut store = state.approvals.lock().unwrap();
        let rec = store
            .reject(&op_id, "user denied")
            .ok_or(AppError::NotFound)?;
        (rec.id.clone(), rec.vault_id.clone())
    };

    // Audit: pending → rejected.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(&rec_vault_id) {
        if let Err(e) = store.finalize(&op_id, STATUS_REJECTED, now, None, Some("user denied"), None) {
            tracing::warn!(vault = %rec_vault_id, op = %op_id, "audit finalize rejected failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: rec_vault_id,
        approval_id: rec_id.clone(),
        kind: "rejected".into(),
        op_summary: None,
        response_preview: None,
        reason: Some("user denied".into()),
    });

    Ok(Json(json!({ "ok": true, "op_id": rec_id, "status": "rejected" })))
}


/// Build the per-service `secrets_cache` from a decrypted v3 view. The cache
/// carries three things per session:
///   1. `entries` — resolved auth bytes for every service whose required
///      item is currently available (any store). Per-rule evaluation at /use
///      time decides whether to USE them (Allow), prompt (Ask / AskAlways),
///      or block (Deny) — so we don't pre-filter to allow-default services
///      anymore: a rule-level Allow on a service whose default was Ask still
///      needs the bytes ready for fast-path forwarding.
///   2. `policy_rules` — merged effective rule list per service (built-in
///      rules with user `rule_overrides` applied by id). The /use handler
///      walks this through `evaluate_policy`.
///   3. `policy_defaults` — verbatim snapshot of `aux.policy_defaults` so
///      the evaluator can layer user globals on top of the compiled-in
///      `PolicyDefaults::default()` without re-decrypting the vault.
pub(crate) fn bootstrap_cache_from_view(
    view: &VaultPlaintextView,
    state: &AppState,
) -> SecretsCache {
    let mut cache = SecretsCache::default();
    cache.policy_defaults = view.aux.policy_defaults.clone();
    cache.audit_retention_days = view.aux.audit_retention_days;
    // Routing snapshot (CONNECTION_SCHEMA.md §6): `connection_id → {service,
    // config}`. The per-service loop below bootstraps every *default* connection
    // (conn == service); a second pass after it covers *named* connections.
    cache.connections = view
        .aux
        .connections
        .iter()
        .map(|(c, conn)| (c.clone(), conn.clone()))
        .collect();
    // Snapshot native-store item names (names only, never values). Surface
    // for GET /v/{vid}/keys-known so the frontend can compute "which
    // services are reachable" without re-walking the kv map.
    for name in view.native_secrets.keys() {
        cache.native_keys.insert(name.clone());
    }
    // Snapshot per-service user-authored basic R/W. Sparse — only services
    // the user actually customized show up. Layered over the registry's
    // service-default during evaluate.
    for (svc, svc_state) in view.aux.service_state.iter() {
        if let Some(levels) = svc_state.levels.as_ref() {
            cache.service_levels.insert(svc.clone(), levels.clone());
        }
    }
    // Snapshot external stores' adapter inputs so GET /v/{vid}/keys-known
    // can list() them later without re-decrypting the vault. Only kinds
    // we have an adapter for today — others are skipped (they live in
    // store_order but never resolve).
    for (store_id, store) in view.aux.stores.iter() {
        if store.kind != "gcp-secret-manager" {
            continue;
        }
        let Some(creds_item) = store
            .extra
            .get("credentials_item")
            .and_then(|v| v.as_str())
        else { continue };
        let Some(sa_json) = view.native_secrets.get(creds_item).cloned() else { continue };
        cache
            .external_stores
            // F-19: wrap SA JSON bytes in Zeroizing so they are zeroed on drop.
            .insert(store_id.clone(), (store.clone(), zeroize::Zeroizing::new(sa_json)));
    }
    for (service_id, _) in state.services.iter_sorted() {
        // PROTOCOL.md §6.2: only services whose default read level is
        // `allow` get their auth value loaded at unlock. ask / ask-always
        // services have memory_ttl = rule.ttl / 0 respectively, so the
        // bytes shouldn't sit in cache pre-approval. They're filled
        // lazily by `approve_op` after the user passkey gesture (ask) or
        // never (ask-always — fresh-decrypted-per-request via the
        // grant's W_c and immediately zeroized).
        if state.services.default_read_level(service_id)
            == crate::core::policy::AccessLevel::Allow
        {
            if let Some(item_name) = state.services.service_env_key(service_id) {
                if let Some(val) = view.resolve_value_native(&item_name) {
                    cache.entries.insert(
                        service_id.to_string(),
                        crate::state::CacheEntry {
                            value: val.to_vec(),
                            expires_at: None, // allow = lives whole unlocked session
                        },
                    );
                }
            }

            // v3 multi-secret: resolve every `{{secret.NAME}}` the recipe's
            // upstream templates (URL + headers + query) reference so the
            // allow fast-path can render multi-secret recipes without a vault
            // view. Single-secret recipes yield a one-entry map; oauth recipes
            // reference no `{{secret.*}}` and so populate nothing here (their
            // token is minted from the refresh_token at forward time).
            if let Some(svc) = state.services.get(service_id) {
                if let Some(u) = svc.upstream.first() {
                    let mut names = crate::server::broker::referenced_secrets(&u.url);
                    for v in u.headers.values().chain(u.query.values()) {
                        for n in crate::server::broker::referenced_secrets(v) {
                            if !names.contains(&n) {
                                names.push(n);
                            }
                        }
                    }
                    let mut map: std::collections::HashMap<String, Vec<u8>> =
                        std::collections::HashMap::new();
                    for name in names {
                        if let Some(val) = view.resolve_value_native(&name) {
                            map.insert(name, val.to_vec());
                        }
                    }
                    if !map.is_empty() {
                        cache.allow_secrets.insert(service_id.to_string(), map);
                    }
                }
            }
        }

        // Policy rule lists are runtime metadata, not raw secrets — load
        // for every service regardless of access level so the per-request
        // evaluator can walk them. (PROTOCOL.md §6.2 lists policy rules
        // under "Runtime metadata, 无 secret, 可一直驻留".)
        let Some(policy_file) = state.services.policy_file(service_id) else {
            continue;
        };
        let built_in = policy_file.to_policy_rules();
        if built_in.is_empty() {
            continue;
        }
        let user_overrides = view
            .aux
            .service_state
            .get(service_id)
            .map(|s| s.rule_overrides.clone())
            .unwrap_or_default();
        let merged = crate::core::policy::merge_rule_overrides(&built_in, &user_overrides);
        cache
            .policy_rules
            .insert(service_id.to_string(), merged);
    }

    // Named connections (`conn_id != service_id`) carry namespaced secrets
    // `<conn>:<ROLE>` (CONNECTION_SCHEMA.md §3). The per-service loop above
    // already covered every default connection (conn == service, bare name);
    // here we add the named ones, keyed by connection_id, resolving each role at
    // its §3 address but storing the multi-secret map under the BARE name so the
    // render path matches `{{secret.<role>}}`. (Allow-level only — ask-level
    // connections resolve lazily from the op's namespaced `target` at approve.)
    for (conn, c) in view.aux.connections.iter() {
        let service = &c.service;
        if conn == service {
            continue; // default — already bootstrapped above
        }
        if state.services.default_read_level(service)
            != crate::core::policy::AccessLevel::Allow
        {
            continue;
        }
        if let Some(role) = state.services.service_env_key(service) {
            let addr = crate::storage::plaintext::secret_address(conn, service, &role);
            if let Some(val) = view.resolve_value_native(&addr) {
                cache.entries.insert(
                    conn.clone(),
                    crate::state::CacheEntry { value: val.to_vec(), expires_at: None },
                );
            }
        }
        if let Some(svc) = state.services.get(service) {
            if let Some(u) = svc.upstream.first() {
                let mut names = crate::server::broker::referenced_secrets(&u.url);
                for v in u.headers.values().chain(u.query.values()) {
                    for n in crate::server::broker::referenced_secrets(v) {
                        if !names.contains(&n) {
                            names.push(n);
                        }
                    }
                }
                let mut map: std::collections::HashMap<String, Vec<u8>> =
                    std::collections::HashMap::new();
                for name in names {
                    let addr = crate::storage::plaintext::secret_address(conn, service, &name);
                    if let Some(val) = view.resolve_value_native(&addr) {
                        map.insert(name, val.to_vec()); // bare name → render match
                    }
                }
                if !map.is_empty() {
                    cache.allow_secrets.insert(conn.clone(), map);
                }
            }
        }
    }
    cache
}

