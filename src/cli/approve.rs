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
//!     derives + HPKE-seals W_c and deposits the grant; the daemon polls the
//!     relay and applies it. The CLI just surfaces the link and polls the
//!     daemon for the op to resolve — no local gesture, no CLI-side W_c.
//!
//!   • **Local** (self-host, no cloud pairing): the on-box ceremony — the
//!     daemon serves the WebAuthn page on localhost, the CLI spawns a
//!     localhost callback, derives W_c from the PRF result, and submits the
//!     grant. Only reachable when the user is on the daemon's machine.
//!
//! Both arms drive the SAME op through the SAME `/op/{id}/approve` endpoint;
//! they differ only in WHERE the passkey gesture happens and how W_c reaches
//! the daemon. This is the single path the design demands — `unlock`/`lock`
//! (and any future approval-only op) route through here so the link is correct
//! everywhere by construction.

use std::time::{Duration, Instant};

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
}

/// Cap the remote-approval wait just under the daemon's 300s op TTL — the user
/// is doing a cross-device dance (open the link on their phone/laptop, tap a
/// passkey), so give them the whole window rather than the short local-gesture
/// timeout.
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
    // op-relay + starts the daemon's background poll (op.rs handles that).
    let (op_id, r) = create_op(custodian, vault, op).await?;

    // Paired ⇒ the user is (potentially) on another machine and can only reach
    // the cloud approval page. Local ⇒ the on-box ceremony.
    if crate::cli::active::frontend_origin().is_some() {
        remote_approve(custodian, &op_id, label).await
    } else {
        local_ceremony(custodian, &op_id, &r, op, &meta, label, opts).await
    }
}

/// Remote arm: surface the cloud `/grant/{op_id}` link and poll the local
/// daemon until the op resolves (its relay poller applies the browser-deposited
/// grant via loopback approve).
async fn remote_approve(custodian: &str, op_id: &str, label: &str) -> Result<Value, String> {
    let url = crate::cli::active::grant_url(op_id);
    eprintln!();
    eprintln!(
        "To {}, open this link and tap your passkey:",
        label.to_lowercase()
    );
    eprintln!("  {}", url);
    eprintln!();
    eprintln!("Waiting for approval…");

    let client = http_client()?;
    let poll_url = format!(
        "{}/op/{}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(op_id)
    );
    let deadline = Instant::now() + Duration::from_secs(REMOTE_APPROVE_TIMEOUT_SECS);
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for approval — open {} and tap your passkey, then retry",
                url
            ));
        }
        tokio::time::sleep(REMOTE_POLL_INTERVAL).await;
        let resp = match client.get(&poll_url).send().await {
            Ok(r) => r,
            Err(_) => continue, // transient; keep polling
        };
        if resp.status().as_u16() == 404 {
            return Err("approval expired before it was completed".into());
        }
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
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
            "rejected" => return Err("approval was rejected".into()),
            _ => {} // pending — keep polling
        }
    }
}

/// Local arm: the on-box WebAuthn ceremony. CLI receives the PRF result over a
/// localhost callback, derives W_c, and submits a plaintext-W_c grant (the
/// transport never leaves the machine). For approval-only ops the daemon does
/// all the work from this grant's W_c.
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

    eprintln!("safeclaw {} — touch passkey…", label.to_lowercase());
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
    let prf_first_bytes = URL_SAFE_NO_PAD
        .decode(&prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD
        .decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let prf_salt_bytes = STANDARD
        .decode(&meta.prf_salt)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&meta.prf_salt))
        .map_err(|e| format!("decode prf_salt: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key,
        &prf_salt_bytes,
        &cred_id_raw,
        crate::crypto::kdf::WRAP_VERSION,
    )
    .map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": op,
        "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(
            &result.credential_id,
            &result.authenticator_data,
            &result.client_data_json,
            &result.signature,
        ),
    });
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
