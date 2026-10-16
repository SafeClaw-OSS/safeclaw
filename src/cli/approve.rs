//! Shared passkey-approval driver for control-plane ops.
//!
//! ONE code path for every CLI command that needs the user to authorize an op
//! with their passkey. Two arms, picked by whether the daemon is cloud-paired:
//!
//!   • **Remote** (cloud-paired): the user approves in a browser at
//!     `{frontend_origin}/grant/{op_id}` — the ONLY surface a user on a
//!     different machine than this zero-inbound localhost daemon can reach.
//!     The daemon registered the op with the cloud op-relay at create time
//!     (`op.rs` → `relay::client::spawn_register_and_poll`); the browser
//!     opens K, HPKE-seals it with its identity signature and deposits the grant; the daemon polls the
//!     relay and applies it. The CLI just surfaces the link and polls the
//!     daemon for the op to resolve — no local gesture.
//!
//!   • **Local** (self-host, no cloud pairing): the on-box ceremony — the
//!     daemon serves the WebAuthn page on localhost, the CLI spawns a
//!     localhost callback, derives W_c from the PRF result, opens K in its own
//!     process and submits a grant v3 (sealed K + identity signature). Only
//!     reachable when the user is on the daemon's machine.
//!
//! Both arms drive the SAME op through the SAME `/op/{id}/approve` endpoint;
//! they differ only in WHERE the passkey gesture happens. Neither delivers W_c
//! or an identity root to the daemon. This is the single path the design demands — `unlock`/`lock`
//! (and any future approval-only op) route through here so the link is correct
//! everywhere by construction.

use std::time::{Duration, Instant};
use std::io::IsTerminal;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

use crate::cli::webauthn::*;

/// Unwrap the daemon act's result object from an [`approve_op`] response. The
/// REMOTE arm returns the poll body `{status, value:<json-string>}` (value =
/// the op's `cached_value`); the LOCAL arm returns the act result object
/// directly. Both collapse to the same object when the daemon op sets
/// `cached_value = result.to_string()` (as the `service-*` / `secret-rm` /
/// `connection-rm` ops do).
pub(crate) fn act_result(body: &Value) -> Value {
    match body.get("value") {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
        Some(v) => v.clone(),
        None => body.clone(),
    }
}

/// Browser-gesture knobs threaded from the calling command (the local arm
/// uses them; the remote arm ignores them — the gesture is in the browser).
pub struct ApproveOpts {
    pub no_browser: bool,
    pub cb_port: Option<u16>,
    /// Local on-box gesture timeout (seconds).
    pub timeout: u64,
    /// In a non-interactive remote unlock/lock, return after printing the link.
    pub return_after_remote_link: bool,
}

/// Fallback remote-approval wait, used only until the first successful poll
/// reveals the op's REAL `expires_at` — from then on the CLI waits out exactly
/// the window the grant page shows the user. (A fixed 280s here once had the
/// CLI give up at ~5min while the page still displayed a valid ~30min op.)
const REMOTE_APPROVE_TIMEOUT_SECS: u64 = 280;
const REMOTE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Deposit secret VALUES with the local daemon ahead of a write op
/// (`connection-add` / `secret-set`) and return the `values_digest` the op's
/// `act.scope` must carry. The op JSON travels to the cloud grant page, so the
/// values themselves never ride it — only this salted commitment does (the
/// salt stays on the daemon, so a weak value can't be brute-forced from it).
pub async fn deposit_values(
    custodian: &str,
    vault: &str,
    values: &std::collections::BTreeMap<String, String>,
) -> Result<String, String> {
    let client = http_client()?;
    let url = format!(
        "{}/v/{}/op-payload",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .post(&url)
        .json(&json!({ "values": values }))
        .send()
        .await
        .map_err(|e| format!("deposit values: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "deposit values HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    body["values_digest"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "no values_digest in response".into())
}

/// Try the unlocked local fast-path for `sc set`: while the vault is OPEN the
/// daemon writes the secret directly under its resident `K` — no op, no passkey.
/// Returns `Some(response)` when written, `None` when the daemon reports the
/// vault is LOCKED (the caller then falls back to the passkey ceremony). Any
/// other failure is a real error. The value rides the local control plane only.
pub async fn set_secret_unlocked(
    custodian: &str,
    vault: &str,
    key: &str,
    value: &str,
    hosts: &[String],
    no_broker: bool,
) -> Result<Option<Value>, String> {
    let client = http_client()?;
    let url = format!(
        "{}/v/{}/secret",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .post(&url)
        .json(&json!({
            "key": key,
            "value": value,
            "hosts": hosts,
            "no_broker": no_broker,
        }))
        .send()
        .await
        .map_err(|e| format!("set secret: {}", e))?;
    // An OLDER running daemon has no /v/{vid}/secret route (404/405) — e.g.
    // right after `sc upgrade`, before the daemon restarts. Fall back to the
    // ceremony instead of failing the whole set on a route miss.
    if matches!(resp.status().as_u16(), 404 | 405) {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!(
            "set secret HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    if body
        .get("written")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(Some(body));
    }
    // Anchoring a NEW egress host is a trust-surface widening (same act as
    // widen-host) — the daemon never writes it passkey-free. Say why before
    // the ceremony starts so the fallback doesn't read as a malfunction.
    if body
        .get("needs_approval")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let hosts: Vec<&str> = body
            .get("new_hosts")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        eprintln!(
            "  anchoring a new host ({}) needs one passkey approval",
            hosts.join(", ")
        );
    }
    Ok(None) // locked or needs-approval — fall back to the passkey ceremony
}

/// Create `op` on the daemon and drive it to a passkey approval. Returns the
/// daemon's approve response JSON (e.g. the unlock's `{kv, aux}` value) on
/// success. `label` is a human verb ("Unlock vault") used in prompts.
pub async fn approve_op(
    custodian: &str,
    vault: &str,
    op: &Value,
    label: &str,
    opts: &ApproveOpts,
) -> Result<Value, String> {
    // Fetch passkey material — also the check that the vault actually exists on
    // this daemon (clear error instead of a later opaque create-op failure).
    let meta = fetch_passkey_meta(custodian, vault).await?;

    // Create the op. On a paired daemon this ALSO registers it with the cloud
    // op-relay + starts the daemon's background poll (op.rs handles that). An
    // Export comes back with its waiter secret (E1): the only credential that
    // releases the value, kept in memory, never printed.
    let created = create_op_full(custodian, vault, op).await?;
    let waiter = created.waiter_secret.as_deref();

    // Paired ⇒ the user is (potentially) on another machine and can only reach
    // the cloud approval page. Local ⇒ the on-box ceremony.
    if crate::cli::active::frontend_origin().is_some() {
        remote_approve(
            custodian,
            &created.op_id,
            label,
            waiter,
            opts.return_after_remote_link,
        )
        .await
    } else {
        // Sign the op as the daemon stored it (see CreatedOp::op).
        let stored = created.op.as_ref().unwrap_or(op);
        let ceremony = local_ceremony(
            custodian,
            &created.op_id,
            &created.r,
            stored,
            &meta,
            label,
            opts,
        );
        // The local gesture has no poll loop of its own: keep an Export's
        // waiter alive for the daemon's liveness backstop while it runs.
        let heartbeat = waiter.map(|w| {
            let url = op_url(custodian, &created.op_id);
            let w = w.to_string();
            tokio::spawn(async move {
                let Ok(client) = http_client() else { return };
                loop {
                    let _ = client.get(&url).header(WAITER_HEADER, &w).send().await;
                    tokio::time::sleep(WAITER_HEARTBEAT).await;
                }
            })
        });
        let res = tokio::select! {
            r = ceremony => r,
            _ = shutdown_signal() => Err("interrupted".to_string()),
        };
        if let Some(h) = heartbeat {
            h.abort();
        }
        if let Err(e) = res {
            // Stopped waiting (interrupt, gesture timeout, failed approve):
            // withdraw our own op so it doesn't linger as a pending request.
            if cancel_op(custodian, &created.op_id, waiter).await {
                return Err(format!("{} (request withdrawn)", e));
            }
            return Err(e);
        }
        res
    }
}

/// Request header carrying an Export's waiter secret (mirror of the daemon's
/// `approve::WAITER_HEADER`).
const WAITER_HEADER: &str = "x-safeclaw-waiter";
/// Local-arm keep-alive cadence; well under the daemon's 60 s backstop.
const WAITER_HEARTBEAT: Duration = Duration::from_secs(5);

fn op_url(custodian: &str, op_id: &str) -> String {
    format!(
        "{}/op/{}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(op_id)
    )
}

/// Resolves on Ctrl-C or SIGTERM. A signal handler that can't be installed
/// never resolves (it must not read as an interrupt).
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => ctrl_c.await,
        }
    }
    #[cfg(not(unix))]
    ctrl_c.await;
}

/// Requester withdrawal (`POST /op/{id}/cancel`): best-effort, short timeout.
/// Returns true when the daemon withdrew the op. Never a user rejection.
async fn cancel_op(custodian: &str, op_id: &str, waiter: Option<&str>) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    else {
        return false;
    };
    let body = match waiter {
        Some(w) => json!({ "waiter_secret": w }),
        None => json!({}),
    };
    matches!(
        client
            .post(format!("{}/cancel", op_url(custodian, op_id)))
            .json(&body)
            .send()
            .await,
        Ok(r) if r.status().is_success()
    )
}

/// Remote arm: surface the cloud `/grant/{op_id}` link and poll the local
/// daemon until the op resolves (its relay poller applies the browser-deposited
/// grant via loopback approve). Ctrl-C, SIGTERM or giving up withdraws the op
/// (`POST /op/{id}/cancel`), so an abandoned wait never lingers in the inbox.
async fn remote_approve(
    custodian: &str,
    op_id: &str,
    label: &str,
    waiter: Option<&str>,
    return_after_link: bool,
) -> Result<Value, String> {
    let url = crate::cli::active::grant_url(op_id);
    eprintln!();
    eprintln!(
        "To {}, open this link and tap your passkey:",
        label.to_lowercase()
    );
    eprintln!("  {}", url);
    if return_after_link && (!std::io::stdin().is_terminal() || !std::io::stderr().is_terminal()) {
        eprintln!("{}", crate::cli::human_action::wait_command(op_id));
        crate::cli::human_action::report(&url, None, None);
        return Ok(Value::Null);
    }
    eprintln!();
    eprintln!("Waiting for approval…");
    crate::cli::human_action::report(&url, None, None);

    let outcome = tokio::select! {
        r = remote_wait(custodian, op_id, waiter) => r,
        _ = shutdown_signal() => {
            let withdrawn = cancel_op(custodian, op_id, waiter).await;
            return Err(if withdrawn {
                "interrupted. The approval request was withdrawn".into()
            } else {
                "interrupted".into()
            });
        }
    };
    match outcome {
        Ok(v) => Ok(v),
        Err(RemoteWaitErr::Failed(e)) => Err(e),
        Err(RemoteWaitErr::TimedOut { deadline_from_op }) => {
            let withdrawn = cancel_op(custodian, op_id, waiter).await;
            if deadline_from_op {
                // We read the op's real expiry and waited its whole window out.
                return Err(format!(
                    "the approval window expired. Re-run the command for a fresh link (was {})",
                    url
                ));
            }
            if withdrawn {
                return Err(format!(
                    "stopped waiting after {}s and withdrew the request. Re-run the command \
                     for a fresh link",
                    REMOTE_APPROVE_TIMEOUT_SECS
                ));
            }
            // Never got a clean status read (daemon busy / restarting) — but the
            // op WAS registered and its cloud link is almost certainly still
            // live, so don't claim it expired.
            Err(format!(
                "stopped waiting after {}s. If you haven't approved it yet the link is still \
                 live; approve it then re-run, or `sc op wait {}` to keep waiting. link: {}",
                REMOTE_APPROVE_TIMEOUT_SECS, op_id, url
            ))
        }
    }
}

enum RemoteWaitErr {
    /// The op resolved negatively (rejected / superseded).
    Failed(String),
    /// We gave up waiting.
    TimedOut { deadline_from_op: bool },
}

/// The remote arm's poll loop. Sends the waiter header on every poll (an
/// Export's value is released only to it, and each such poll keeps the op
/// alive against the daemon's abandoned-waiter backstop).
async fn remote_wait(
    custodian: &str,
    op_id: &str,
    waiter: Option<&str>,
) -> Result<Value, RemoteWaitErr> {
    let client = http_client().map_err(RemoteWaitErr::Failed)?;
    let poll_url = op_url(custodian, op_id);
    let mut deadline = Instant::now() + Duration::from_secs(REMOTE_APPROVE_TIMEOUT_SECS);
    let mut deadline_from_op = false;
    loop {
        if Instant::now() >= deadline {
            return Err(RemoteWaitErr::TimedOut { deadline_from_op });
        }
        tokio::time::sleep(REMOTE_POLL_INTERVAL).await;
        let mut req = client.get(&poll_url);
        if let Some(w) = waiter {
            req = req.header(WAITER_HEADER, w);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(_) => continue, // transient; keep polling
        };
        // A 404 is NOT proof of expiry: the daemon may be restarting, or the op
        // record was momentarily reaped while the cloud op (and its relay
        // applier) is still live and approvable. Treat it as transient and keep
        // polling — the deadline (the op's own expires_at) is what decides.
        if resp.status().as_u16() == 404 {
            continue;
        }
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Adopt the op's real expiry once: wait exactly as long as the grant
        // page says the op is live (+ grace for the relay round-trip).
        if !deadline_from_op {
            if let Some(exp) = body.get("expires_at").and_then(|v| v.as_u64()) {
                let now = now_unix();
                if exp > now {
                    deadline = Instant::now() + Duration::from_secs(exp - now + 10);
                    deadline_from_op = true;
                }
            }
        }
        match body.get("status").and_then(|s| s.as_str()).unwrap_or("") {
            // The daemon flips the op to approved once it applies the relayed
            // grant; "consumed" can win if something polled it first. Both mean
            // the gesture landed and the act ran.
            // "ok" = the gesture landed + the act ran; "consumed" if something
            // polled it first.
            "ok" | "consumed" => {
                eprintln!("  approved ✓");
                return Ok(body);
            }
            "rejected" => {
                use crate::cli::op::{not_approved, NotApproved};
                let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                return Err(RemoteWaitErr::Failed(match not_approved(reason) {
                    NotApproved::Superseded => "approval superseded by a newer request \
                         (not a user rejection). Re-run the command"
                        .into(),
                    NotApproved::Withdrawn => "the approval request was withdrawn \
                         (not a user rejection). Re-run the command"
                        .into(),
                    NotApproved::Other(r) => format!("not approved: {}", r),
                    NotApproved::Rejected => "approval was rejected".into(),
                }));
            }
            _ => {} // pending — keep polling
        }
    }
}

/// Local arm: the on-box WebAuthn ceremony, grant v3 like the browser's. The
/// CLI receives the PRF result over a localhost callback and, in THIS process,
/// derives `W_c`, unwraps the identity root from the keyset's custody wrap,
/// opens `K` from the identity's K-seal, seals `K` to the daemon's `sc_pk`
/// and signs the grant identity (C3) with the root. Only `K` (sealed) and the
/// signature reach the daemon; `W_c` and the root never leave this process.
async fn local_ceremony(
    custodian: &str,
    op_id: &str,
    r: &str,
    op: &Value,
    meta: &PasskeyMeta,
    label: &str,
    opts: &ApproveOpts,
) -> Result<Value, String> {
    let r_bytes = STANDARD.decode(r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, op)?;
    let vault_id = op
        .pointer("/bind/redeemer")
        .and_then(|v| v.as_str())
        .ok_or("op has no bind.redeemer")?
        .to_string();
    // Everything the CLI needs besides the gesture, fetched BEFORE the user
    // taps, so an unsupported vault fails without a wasted gesture.
    let keyset = fetch_keyset(custodian, &vault_id).await?;
    if keyset.uik.is_none() {
        return Err(
            "this vault has no identity key on this machine, so it can't be approved here; \
             approve it in the SafeClaw console (pair this machine with `sc login`)"
                .into(),
        );
    }
    let sc_pk = fetch_sc_pk(custodian).await?;

    eprintln!("safeclaw {}: touch passkey…", label.to_lowercase());
    let result = do_browser_gesture(
        custodian,
        op_id,
        &beta,
        Some(PRF_EVAL_SALT),
        &meta.credential_id,
        label,
        opts.no_browser,
        opts.timeout,
        false,
        opts.cb_port,
    )
    .await?;

    let prf_first = result
        .prf_first
        .clone()
        .ok_or("gesture didn't return prf_first")?;
    let prf_first_bytes = zeroize::Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&prf_first)
            .map_err(|e| format!("decode prf_first: {}", e))?,
    );
    let user_key = zeroize::Zeroizing::new(prf_to_user_key(&prf_first_bytes)?);
    let cred_id_raw = URL_SAFE_NO_PAD
        .decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let prf_salt_bytes = STANDARD
        .decode(&meta.prf_salt)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&meta.prf_salt))
        .map_err(|e| format!("decode prf_salt: {}", e))?;
    let w_c = zeroize::Zeroizing::new(
        crate::crypto::kdf::derive_wrapping_key(
            &user_key,
            &prf_salt_bytes,
            &cred_id_raw,
            crate::crypto::kdf::WRAP_VERSION,
        )
        .map_err(|e| format!("derive wrapping key: {}", e))?,
    );
    let grant = build_local_grant(
        &keyset,
        &w_c[..],
        &cred_id_raw,
        &vault_id,
        op_id,
        op,
        r,
        &beta,
        &sc_pk,
        &meta.credential_id,
        assertion_json(
            &result.credential_id,
            &result.authenticator_data,
            &result.client_data_json,
            &result.signature,
        ),
    )?;
    let client = http_client()?;
    let resp = client
        .post(format!(
            "{}/op/{}/approve",
            custodian.trim_end_matches('/'),
            urlencoding::encode(op_id)
        ))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "approve HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await.unwrap_or(Value::Null))
}

/// The grant v3 body of the local ceremony (pure; unit-tested): unwrap the
/// identity root from this passkey's custody wrap under `w_c`, open `K`, seal
/// it to `sc_pk` for `op_id`, and sign C3 with the root.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_local_grant(
    keyset: &crate::storage::sealed_vault::Keyset,
    w_c: &[u8],
    cred_id_raw: &[u8],
    vault_id: &str,
    op_id: &str,
    op: &Value,
    r: &str,
    beta: &[u8],
    sc_pk: &[u8],
    credential_id: &str,
    assertion: Value,
) -> Result<Value, String> {
    let wrapped_root = keyset
        .credentials
        .iter()
        .find(|c| c.credential_id == cred_id_raw)
        .map(|c| c.wrapped_key.clone())
        .ok_or(
            "this passkey's identity key isn't held on this machine; approve in the SafeClaw \
             console (pair this machine with `sc login`)",
        )?;
    let root = crate::crypto::vault_key::unwrap_uik_root(w_c, cred_id_raw, &wrapped_root)
        .map_err(|e| format!("open your identity key: {}", e))?;
    let uik = crate::crypto::vault_key::UikRoot::from_root(*root);
    let k = crate::server::handlers::metadata::acquire_k_from_keyset(
        keyset,
        crate::protocol::grant::GrantKey::Custody(&root[..]),
        cred_id_raw,
        vault_id,
    )
    .map_err(|e| format!("open the vault key: {}", e))?;
    // The delivered material is the bundle a v2 open produces, without the
    // previous-generation keys the daemon re-attaches from its own keyset.
    let material = &k[..k.len().min(64)];
    let (k_enc, k_ct) = crate::crypto::envelope::seal_to(
        sc_pk,
        material,
        &crate::crypto::envelope::grant_k_seal_info(op_id),
        b"",
    )
    .map_err(|e| format!("seal the vault key: {}", e))?;
    let id = uik.user_id();
    let input = crate::identity::grant_id_input(
        vault_id, op_id, beta, cred_id_raw, &k_enc, &k_ct, sc_pk, &id,
    );
    let id_sig = uik.signing().sign(&input);
    Ok(json!({
        "o": op,
        "r": r,
        "credential_id": credential_id,
        "k_enc": URL_SAFE_NO_PAD.encode(&k_enc),
        "k_ct": URL_SAFE_NO_PAD.encode(&k_ct),
        "id": id,
        "id_sig": URL_SAFE_NO_PAD.encode(id_sig),
        "assertion": assertion,
    }))
}

/// The vault's keyset from the local daemon (`GET /v/{vid}/keyset`).
async fn fetch_keyset(
    custodian: &str,
    vault: &str,
) -> Result<crate::storage::sealed_vault::Keyset, String> {
    let url = format!(
        "{}/v/{}/keyset",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = http_client()?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("keyset: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "this vault's keys aren't on this machine (HTTP {}); approve it in the SafeClaw console",
            resp.status()
        ));
    }
    let mut body: Value = resp.json().await.map_err(|e| format!("keyset: {}", e))?;
    serde_json::from_value(body["keyset"].take()).map_err(|e| format!("keyset: {}", e))
}

/// The local daemon's grant-seal key (`GET /pubkey`, raw 32 bytes).
async fn fetch_sc_pk(custodian: &str) -> Result<Vec<u8>, String> {
    let url = format!("{}/pubkey", custodian.trim_end_matches('/'));
    let body: Value = http_client()?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("pubkey: {}", e))?
        .json()
        .await
        .map_err(|e| format!("pubkey: {}", e))?;
    let pk = body["sc_pk"]
        .as_str()
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .filter(|v| v.len() == 32)
        .ok_or("the daemon returned no sc_pk")?;
    Ok(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The local ceremony's grant carries only the sealed K and the identity
    /// signature: K opens with the daemon's key, the signature verifies under
    /// the identity the custody wrap holds, and neither W_c nor the root is in
    /// the body.
    #[test]
    fn local_grant_delivers_k_and_signs_the_identity() {
        use crate::crypto::vault_key::{seal_k_to_uik, wrap_uik_root, UikRoot};
        use crate::storage::sealed_vault::PerItemVault;
        let vid = "vault-local";
        let root = [0x33u8; 32];
        let uik = UikRoot::from_root(root);
        let w_c = [0x55u8; 32];
        let cid = b"cred-local".to_vec();
        let mut pv = PerItemVault::build_initial(
            cid.clone(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            wrap_uik_root(&w_c, &cid, &root).unwrap(),
        )
        .unwrap();
        let k = [0x9au8; 32];
        let enc_pub = uik.encryption_public().unwrap();
        let (encapped, ct) = seal_k_to_uik(&enc_pub, vid, &k).unwrap();
        pv.set_uik_cred(
            URL_SAFE_NO_PAD.encode(&cid),
            uik.user_id(),
            uik.signing().public_bytes().to_vec(),
            enc_pub,
            encapped,
            ct,
            crate::storage::plaintext::MemberRole::Admin,
            Vec::new(),
        );
        let sc = crate::crypto::envelope::ScKeyPair::load_or_generate().unwrap();
        let sc_pk = sc.pk_bytes();
        let op = json!({ "act": { "type": "export", "target": "FOO", "scope": {} } });
        let r = STANDARD.encode([7u8; 16]);
        let beta = compute_beta(&[7u8; 16], &op).unwrap();
        let g = build_local_grant(
            &pv.keyset,
            &w_c,
            &cid,
            vid,
            "op-1",
            &op,
            &r,
            &beta,
            &sc_pk,
            &URL_SAFE_NO_PAD.encode(&cid),
            json!({}),
        )
        .unwrap();
        let text = g.to_string();
        assert!(!text.contains(&STANDARD.encode(w_c)) && !text.contains(&URL_SAFE_NO_PAD.encode(w_c)));
        assert!(!text.contains(&URL_SAFE_NO_PAD.encode(root)) && !text.contains(&STANDARD.encode(root)));
        assert!(g.get("wrapping_key").is_none() && g.get("wk_enc").is_none());
        let dec = |f: &str| URL_SAFE_NO_PAD.decode(g[f].as_str().unwrap()).unwrap();
        let (k_enc, k_ct) = (dec("k_enc"), dec("k_ct"));
        let opened = sc
            .open(&k_enc, &k_ct, &crate::crypto::envelope::grant_k_seal_info("op-1"), b"")
            .unwrap();
        assert_eq!(opened, k);
        assert_eq!(g["id"], uik.user_id());
        let input = crate::identity::grant_id_input(
            vid, "op-1", &beta, &cid, &k_enc, &k_ct, &sc_pk, &uik.user_id(),
        );
        let sig: [u8; 64] = dec("id_sig").try_into().unwrap();
        assert!(crate::identity::verify(&uik.signing().public_bytes(), &input, &sig));
        // A wrong W_c opens nothing.
        assert!(build_local_grant(
            &pv.keyset, &[0u8; 32], &cid, vid, "op-1", &op, &r, &beta, &sc_pk, "x", json!({})
        )
        .is_err());
    }
}
