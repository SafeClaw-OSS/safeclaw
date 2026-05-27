//! `safeclaw write <KEY> <VALUE>` — write a native secret to the vault.
//!
//! Two passkey gestures:
//!   1. Unlock (PRF + assertion) → daemon returns plaintext kv
//!   2. Write (assertion only) → CLI seals modified state → daemon stores
//!
//! All crypto (seal, key-wrap, PRF-to-userKey derivation) happens locally
//! in this Rust binary. The browser page (/op/{id}) is a minimal passkey
//! proxy — it returns assertion + PRF output and nothing else.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

use crate::cli::profile::resolve_active;
use crate::config::WriteArgs;

const WRAP_VERSION: u16 = 1;
const DS_SEAL: &[u8] = b"sudp/v1/seal";

fn seal_ad(version: u16) -> Vec<u8> {
    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&version.to_be_bytes());
    ad
}

pub async fn run(args: WriteArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.custodian.as_deref(), args.vault.as_deref())?;
    let key = args.key.clone();
    let value = args.value.clone();

    eprintln!("safeclaw write {} — two passkey gestures required (unlock + write)", key);

    // 1. Get passkey metadata.
    let meta = fetch_passkey_meta(&custodian, &vault).await?;

    // 2. Unlock gesture (PRF + assertion) → daemon decrypts, we get plaintext + userKey.
    let (kv, aux, user_key_bytes) = do_unlock_gesture(
        &custodian, &vault, &meta, args.no_browser, args.timeout,
    ).await?;

    // 3. Modify kv.
    let mut new_kv = kv;
    new_kv.insert(key.clone(), value);

    // 4. Seal modified state.
    let new_prf_salt = random_bytes(32);
    let new_state_key = random_bytes(32); // fresh K
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let new_wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key_bytes, &new_prf_salt, &cred_id_raw, WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let binding = sudp::primitives::WrapBinding { credential_id: &cred_id_raw, version: WRAP_VERSION };
    let new_wrapped_key = <sudp::primitives::AeadWrap<sudp::primitives::ChaCha20Poly1305>
        as sudp::primitives::KeyWrap>::wrap(&new_wrapping_key, &new_state_key, &binding)
        .map_err(|e| format!("wrap K: {}", e))?;

    let protected_state = build_protected_state(&new_kv, &aux, &meta.credential_id, &new_wrapping_key);
    let canonical_m = sudp::canonical::canonicalize_strict(&protected_state)
        .map_err(|e| format!("canonicalize: {}", e))?;
    let new_ciphertext = <sudp::primitives::ChaCha20Poly1305 as sudp::primitives::Aead>::seal(
        &new_state_key, &canonical_m, &seal_ad(WRAP_VERSION),
    ).map_err(|e| format!("seal M: {}", e))?;

    // 5. Build Write op.
    let write_op = json!({
        "act": {
            "type": "write",
            "target": "env",
            "scope": {
                "ciphertext": STANDARD.encode(&new_ciphertext),
                "wrapped_key": STANDARD.encode(&new_wrapped_key),
                "prf_salt_next": STANDARD.encode(&new_prf_salt),
            }
        },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });

    // 6. Create Write op on daemon.
    let (write_op_id, write_r) = create_op(&custodian, &vault, &write_op).await?;

    // 7. Compute β for Write op.
    let r_bytes = STANDARD.decode(&write_r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &write_op)?;

    // 8. Assertion-only gesture (no PRF).
    eprintln!("safeclaw write — second gesture (assertion for write op)…");
    let assertion = do_assertion_gesture(
        &custodian, &write_op_id, &beta, &meta, args.no_browser, args.timeout,
    ).await?;

    // 9. Submit Write grant.
    let grant = json!({
        "o": write_op,
        "r": write_r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&new_wrapping_key),
        "assertion": assertion,
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&write_op_id)))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("approve HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    eprintln!("safeclaw write — {} written", key);
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PasskeyMeta {
    credential_id: String,
    prf_salt: String,
}

async fn fetch_passkey_meta(custodian: &str, vault: &str) -> Result<PasskeyMeta, String> {
    let client = http_client()?;
    let url = format!("{}/v/{}/passkeys", custodian.trim_end_matches('/'), urlencoding::encode(vault));
    let resp = client.get(&url).send().await.map_err(|e| format!("passkeys: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("passkeys HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let passkeys = body["passkeys"].as_array().ok_or("no passkeys array")?;
    if passkeys.is_empty() {
        return Err("vault has no enrolled passkeys".into());
    }
    let p = &passkeys[0];
    Ok(PasskeyMeta {
        credential_id: p["credential_id"].as_str().ok_or("no credential_id")?.to_string(),
        prf_salt: p["prf_salt"].as_str().ok_or("no prf_salt")?.to_string(),
    })
}

async fn do_unlock_gesture(
    custodian: &str, vault: &str, meta: &PasskeyMeta,
    no_browser: bool, timeout: u64,
) -> Result<(BTreeMap<String, String>, Value, Vec<u8>), String> {
    let unlock_op = json!({
        "act": { "type": { "custom": "vault-unlock" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(custodian, vault, &unlock_op).await?;
    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &unlock_op)?;

    eprintln!("safeclaw write — first gesture (unlock)…");
    let prf_salt_bytes = STANDARD.decode(&meta.prf_salt)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&meta.prf_salt))
        .map_err(|e| format!("decode prf_salt: {}", e))?;
    let cb_result = do_browser_gesture(
        custodian, &op_id, &beta, Some(&prf_salt_bytes), meta, no_browser, timeout,
    ).await?;

    let prf_first = cb_result.prf_first.ok_or("unlock gesture didn't return prf_first")?;
    let prf_first_bytes = URL_SAFE_NO_PAD.decode(&prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;

    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key, &prf_salt_bytes, &cred_id_raw, WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": unlock_op,
        "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": {
            "credentialId": cb_result.credential_id,
            "authenticatorData": cb_result.authenticator_data,
            "clientDataJSON": cb_result.client_data_json,
            "signature": cb_result.signature,
        },
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&op_id)))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("unlock approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("unlock HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse unlock response: {}", e))?;
    let kv_val = &body["value"]["kv"];
    let kv: BTreeMap<String, String> = kv_val.as_object()
        .ok_or("unlock response missing value.kv")?
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();
    let aux = body["value"]["aux"].clone();

    Ok((kv, aux, user_key))
}

async fn do_assertion_gesture(
    custodian: &str, op_id: &str, beta: &[u8], meta: &PasskeyMeta,
    no_browser: bool, timeout: u64,
) -> Result<Value, String> {
    let cb = do_browser_gesture(custodian, op_id, beta, None, meta, no_browser, timeout).await?;
    Ok(json!({
        "credentialId": cb.credential_id,
        "authenticatorData": cb.authenticator_data,
        "clientDataJSON": cb.client_data_json,
        "signature": cb.signature,
    }))
}

#[derive(Debug, Deserialize)]
struct GestureResult {
    status: String,
    credential_id: Option<String>,
    authenticator_data: Option<String>,
    client_data_json: Option<String>,
    signature: Option<String>,
    prf_first: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

async fn do_browser_gesture(
    custodian: &str, op_id: &str, beta: &[u8],
    prf_salt: Option<&[u8]>, meta: &PasskeyMeta,
    no_browser: bool, timeout_secs: u64,
) -> Result<GestureResult, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await
        .map_err(|e| format!("bind: {}", e))?;
    let local_addr = listener.local_addr().map_err(|e| format!("addr: {}", e))?;
    let state_token = random_hex(16);
    let (tx, rx) = oneshot::channel::<GestureResult>();
    let cb_state = Arc::new(CbState { expected_state: state_token.clone(), tx: Mutex::new(Some(tx)) });
    let app = Router::new()
        .route("/done", get(handle_gesture_done))
        .with_state(cb_state);

    let cb_url = format!("http://{}/done", local_addr);
    let mut auth_url = format!(
        "{}/op/{}?challenge={}&cred_id={}&vid={}&cb={}&state={}&label={}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(op_id),
        URL_SAFE_NO_PAD.encode(beta),
        urlencoding::encode(&meta.credential_id),
        urlencoding::encode(op_id.split_at(8.min(op_id.len())).0),
        urlencoding::encode(&cb_url),
        urlencoding::encode(&state_token),
        urlencoding::encode("CLI+operation"),
    );
    if let Some(salt) = prf_salt {
        auth_url.push_str(&format!("&prf_salt={}", URL_SAFE_NO_PAD.encode(salt)));
    }

    eprintln!("If browser doesn't open, visit:");
    eprintln!("  {}", auth_url);
    eprintln!();
    if !no_browser {
        let _ = open_browser(&auth_url);
    }

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    let result = tokio::select! {
        r = rx => r.map_err(|_| "callback channel dropped".to_string())?,
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
            server.abort();
            return Err(format!("timed out after {}s", timeout_secs));
        }
    };
    server.abort();

    if result.status != "ok" {
        return Err(format!("gesture: {}", result.error.as_deref().unwrap_or(&result.status)));
    }
    if result.state.as_deref() != Some(&state_token) {
        return Err("CSRF state mismatch".into());
    }
    Ok(result)
}

struct CbState {
    expected_state: String,
    tx: Mutex<Option<oneshot::Sender<GestureResult>>>,
}

async fn handle_gesture_done(
    State(state): State<Arc<CbState>>,
    Query(params): Query<GestureResult>,
) -> impl IntoResponse {
    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(params);
    }
    (StatusCode::OK, "OK — you can close this tab.\n")
}

async fn create_op(custodian: &str, vault: &str, op: &Value) -> Result<(String, String), String> {
    let client = http_client()?;
    let url = format!("{}/v/{}/op", custodian.trim_end_matches('/'), urlencoding::encode(vault));
    let resp = client.post(&url).json(op).send().await.map_err(|e| format!("create op: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("create op HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let op_id = body["op_id"].as_str().ok_or("no op_id")?.to_string();
    let r = body["r"].as_str().ok_or("no r")?.to_string();
    Ok((op_id, r))
}

fn compute_beta(r: &[u8], op: &Value) -> Result<Vec<u8>, String> {
    let canonical = sudp::canonical::canonicalize_strict(op)
        .map_err(|e| format!("canonicalize op: {}", e))?;
    let domain = b"safeclaw/v1/binding\x00";
    let beta = sudp::beta::compute_beta_from_canonical::<sudp::primitives::Sha256>(
        domain, r, &canonical,
    );
    Ok(beta.to_vec())
}

fn build_protected_state(
    kv: &BTreeMap<String, String>, aux: &Value,
    credential_id_b64: &str, wrapping_key: &[u8],
) -> Value {
    let mut targets = serde_json::Map::new();
    for (k, v) in kv {
        targets.insert(k.clone(), Value::String(STANDARD.encode(v.as_bytes())));
    }
    let mut peers = serde_json::Map::new();
    peers.insert(credential_id_b64.to_string(), Value::String(STANDARD.encode(wrapping_key)));
    json!({ "targets": targets, "peers": peers, "aux": aux })
}

fn wrap_binding_ad(cred_id: &[u8], version: u16) -> Vec<u8> {
    let ds_wrap = b"sudp/v1/wrap";
    let mut ad = Vec::with_capacity(ds_wrap.len() + cred_id.len() + 2);
    ad.extend_from_slice(ds_wrap);
    ad.extend_from_slice(cred_id);
    ad.extend_from_slice(&version.to_be_bytes());
    ad
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{:02x}", b)).collect()
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let candidates: &[&[&str]] = &[&["xdg-open"], &["wslview"], &["x-www-browser"]];
    #[cfg(target_os = "macos")]
    let candidates: &[&[&str]] = &[&["open"]];
    #[cfg(target_os = "windows")]
    let candidates: &[&[&str]] = &[&["cmd", "/C", "start", ""]];
    for cmd in candidates {
        let mut c = std::process::Command::new(cmd[0]);
        for arg in &cmd[1..] { c.arg(arg); }
        c.arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        if c.spawn().is_ok() { return Ok(()); }
    }
    Err("no browser opener".into())
}

fn prf_to_user_key(prf_first: &[u8]) -> Result<Vec<u8>, String> {
    use sudp::primitives::{HkdfSha256, Kdf as _};
    let salt = [0u8; 32];
    let info = b"sudp/v1/webauthn-prf-userkey";
    let k = HkdfSha256::derive_32(prf_first, &salt, info)
        .map_err(|e| format!("HKDF prf_to_user_key: {}", e))?;
    Ok(k.to_vec())
}

pub async fn run_delete(args: crate::config::DeleteArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.custodian.as_deref(), args.vault.as_deref())?;
    let key = args.key.clone();
    eprintln!("safeclaw delete {} — two passkey gestures required (unlock + write)", key);

    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, aux, user_key_bytes) = do_unlock_gesture(
        &custodian, &vault, &meta, args.no_browser, args.timeout,
    ).await?;

    let mut new_kv = kv;
    if new_kv.remove(&key).is_none() {
        return Err(format!("key {} not found in vault", key));
    }

    let new_prf_salt = random_bytes(32);
    let new_state_key = random_bytes(32);
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let new_wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key_bytes, &new_prf_salt, &cred_id_raw, WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let binding = sudp::primitives::WrapBinding { credential_id: &cred_id_raw, version: WRAP_VERSION };
    let new_wrapped_key = <sudp::primitives::AeadWrap<sudp::primitives::ChaCha20Poly1305>
        as sudp::primitives::KeyWrap>::wrap(&new_wrapping_key, &new_state_key, &binding)
        .map_err(|e| format!("wrap K: {}", e))?;

    let protected_state = build_protected_state(&new_kv, &aux, &meta.credential_id, &new_wrapping_key);
    let canonical_m = sudp::canonical::canonicalize_strict(&protected_state)
        .map_err(|e| format!("canonicalize: {}", e))?;
    let new_ciphertext = <sudp::primitives::ChaCha20Poly1305 as sudp::primitives::Aead>::seal(
        &new_state_key, &canonical_m, &seal_ad(WRAP_VERSION),
    ).map_err(|e| format!("seal M: {}", e))?;

    let write_op = json!({
        "act": { "type": "write", "target": "env", "scope": {
            "ciphertext": STANDARD.encode(&new_ciphertext),
            "wrapped_key": STANDARD.encode(&new_wrapped_key),
            "prf_salt_next": STANDARD.encode(&new_prf_salt),
        }},
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });

    let (write_op_id, write_r) = create_op(&custodian, &vault, &write_op).await?;
    let r_bytes = STANDARD.decode(&write_r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &write_op)?;

    eprintln!("safeclaw delete — second gesture (assertion for write op)…");
    let assertion = do_assertion_gesture(
        &custodian, &write_op_id, &beta, &meta, args.no_browser, args.timeout,
    ).await?;

    let grant = json!({
        "o": write_op,
        "r": write_r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&new_wrapping_key),
        "assertion": assertion,
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&write_op_id)))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("approve HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    eprintln!("safeclaw delete — {} removed", key);
    Ok(())
}
