//! Shared browser-gesture infrastructure for CLI commands.
//!
//! All CLI commands that need a passkey gesture open a browser to the
//! daemon's `/op/{op_id}` page (content-negotiated: browser gets HTML,
//! API gets JSON). The page runs `navigator.credentials.get()` (or
//! `create()` for enroll) and returns the result to a localhost callback
//! the CLI spawns.

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
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

#[derive(Debug, Deserialize)]
pub struct GestureResult {
    pub status: String,
    pub credential_id: Option<String>,
    pub authenticator_data: Option<String>,
    pub client_data_json: Option<String>,
    pub signature: Option<String>,
    pub prf_first: Option<String>,
    pub attestation_object: Option<String>,
    pub public_key_x: Option<String>,
    pub public_key_y: Option<String>,
    pub error: Option<String>,
    pub state: Option<String>,
}

pub fn assertion_json(
    credential_id: &Option<String>,
    authenticator_data: &Option<String>,
    client_data_json: &Option<String>,
    signature: &Option<String>,
) -> Value {
    serde_json::json!({
        "credentialId": credential_id,
        "authenticatorData": authenticator_data,
        "clientDataJSON": client_data_json,
        "signature": signature,
    })
}

pub async fn do_browser_gesture(
    custodian: &str,
    op_id: &str,
    beta: &[u8],
    prf_salt: Option<&[u8]>,
    cred_id: &str,
    label: &str,
    no_browser: bool,
    timeout_secs: u64,
    enroll: bool,
    cb_port: Option<u16>,
) -> Result<GestureResult, String> {
    let bind_addr = format!("127.0.0.1:{}", cb_port.unwrap_or(0));
    let listener = TcpListener::bind(&bind_addr).await
        .map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    let local_addr = listener.local_addr().map_err(|e| format!("addr: {}", e))?;
    let state_token = random_hex(16);
    let (tx, rx) = oneshot::channel::<GestureResult>();
    let cb_state = Arc::new(CbState { expected_state: state_token.clone(), tx: Mutex::new(Some(tx)) });
    let app = Router::new()
        .route("/done", get(handle_done))
        .with_state(cb_state);

    let cb_url = format!("http://{}/done", local_addr);
    let mut auth_url = format!(
        "{}/op/{}?challenge={}&cred_id={}&cb={}&state={}&label={}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(op_id),
        URL_SAFE_NO_PAD.encode(beta),
        urlencoding::encode(cred_id),
        urlencoding::encode(&cb_url),
        urlencoding::encode(&state_token),
        urlencoding::encode(label),
    );
    if let Some(salt) = prf_salt {
        auth_url.push_str(&format!("&prf_salt={}", URL_SAFE_NO_PAD.encode(salt)));
    }
    if enroll {
        auth_url.push_str("&enroll=1");
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

pub async fn create_op(custodian: &str, vault: &str, op: &Value) -> Result<(String, String), String> {
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

pub fn compute_beta(r: &[u8], op: &Value) -> Result<Vec<u8>, String> {
    let canonical = sudp::canonical::canonicalize_strict(op)
        .map_err(|e| format!("canonicalize op: {}", e))?;
    let domain = b"safeclaw/v1/binding\x00";
    let beta = sudp::beta::compute_beta_from_canonical::<sudp::primitives::Sha256>(
        domain, r, &canonical,
    );
    Ok(beta.to_vec())
}

pub fn prf_to_user_key(prf_first: &[u8]) -> Result<Vec<u8>, String> {
    use sudp::primitives::{HkdfSha256, Kdf as _};
    let salt = [0u8; 32];
    let info = b"sudp/v1/webauthn-prf-userkey";
    let k = HkdfSha256::derive_32(prf_first, &salt, info)
        .map_err(|e| format!("HKDF prf_to_user_key: {}", e))?;
    Ok(k.to_vec())
}

#[derive(Debug, Clone)]
pub struct PasskeyMeta {
    pub credential_id: String,
    pub prf_salt: String,
}

pub async fn fetch_passkey_meta(custodian: &str, vault: &str) -> Result<PasskeyMeta, String> {
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

pub fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{:02x}", b)).collect()
}

struct CbState {
    expected_state: String,
    tx: Mutex<Option<oneshot::Sender<GestureResult>>>,
}

async fn handle_done(
    State(state): State<Arc<CbState>>,
    Query(params): Query<GestureResult>,
) -> impl IntoResponse {
    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(params);
    }
    (StatusCode::OK, "OK — you can close this tab.\n")
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
