//! `safeclaw read <KEY>` — reveal a single native secret to stdout.
//!
//! Mirrors `safeclaw unlock`'s browser-callback driver — opens the custodian's
//! `/cli/auth?op=export&key=...` page, listens on a random localhost port,
//! waits for the page to redirect back with the op id. The plaintext value
//! is **never** put in the URL — we fetch it out-of-band via
//! `GET /op/{op_id}` after the callback confirms approval.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use rand::RngCore;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

use crate::cli::profile::resolve_active;
use crate::config::ReadArgs;

#[derive(Debug, Deserialize)]
struct CallbackParams {
    status: Option<String>,
    error: Option<String>,
    state: Option<String>,
    op_id: Option<String>,
}

struct CbState {
    expected_state: String,
    tx: Mutex<Option<oneshot::Sender<Outcome>>>,
}

enum Outcome {
    Ok { op_id: String },
    Cancelled,
    Error(String),
    BadState,
}

pub async fn run(args: ReadArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(
        args.custodian.as_deref(),
        args.vault.as_deref(),
        args.profile.as_deref(),
    )?;
    let key = args.key.trim().to_string();
    if key.is_empty() {
        return Err("key cannot be empty".into());
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind localhost: {}", e))?;
    let local_addr = listener.local_addr().map_err(|e| format!("local_addr: {}", e))?;
    let state_token = random_hex(16);

    let (tx, rx) = oneshot::channel::<Outcome>();
    let cb_state = Arc::new(CbState {
        expected_state: state_token.clone(),
        tx: Mutex::new(Some(tx)),
    });
    let app = Router::new()
        .route("/done", get(handle_done))
        .with_state(cb_state.clone());

    let cb = format!("http://{}/done", local_addr);
    let auth_url = format!(
        "{}/cli/auth?op=export&vault={}&key={}&cb={}&state={}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault),
        urlencoding::encode(&key),
        urlencoding::encode(&cb),
        urlencoding::encode(&state_token),
    );

    eprintln!("safeclaw read {} — opening browser…", key);
    eprintln!("If your browser doesn't open, visit this URL manually:");
    eprintln!("  {}", auth_url);
    eprintln!();

    if !args.no_browser {
        if let Err(e) = open_browser(&auth_url) {
            eprintln!("(could not auto-open browser: {}) — visit the URL above.", e);
        }
    }

    let server_task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let outcome = tokio::select! {
        outcome = rx => outcome.unwrap_or(Outcome::Error("callback channel dropped".into())),
        _ = tokio::time::sleep(Duration::from_secs(args.timeout)) => {
            server_task.abort();
            return Err(format!("timed out after {}s waiting for browser callback", args.timeout));
        }
    };
    server_task.abort();

    match outcome {
        Outcome::Ok { op_id } => fetch_and_print(&custodian, &op_id).await,
        Outcome::Cancelled => Err("user cancelled the ceremony".into()),
        Outcome::Error(e) => Err(format!("browser page reported error: {}", e)),
        Outcome::BadState => Err("callback state mismatch (CSRF guard)".into()),
    }
}

/// Fetch the approved Export op's cached value and print it to stdout.
async fn fetch_and_print(custodian: &str, op_id: &str) -> Result<(), String> {
    let url = format!(
        "{}/op/{}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(op_id)
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("fetch op: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "GET /op/{} returned HTTP {}",
            op_id,
            resp.status()
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "custodian did not return a `value` field — op may have been consumed already".to_string()
        })?;
    // stdout, no trailing newline padding — same as `cat`. Lets shell
    // pipelines pipe into `pbcopy` / `xclip` / etc cleanly.
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes()).map_err(|e| format!("stdout write: {}", e))?;
    out.write_all(b"\n").ok();
    Ok(())
}

async fn handle_done(
    State(state): State<Arc<CbState>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let s = params.state.unwrap_or_default();
    let outcome = if s != state.expected_state {
        Outcome::BadState
    } else {
        match params.status.as_deref() {
            Some("ok") => match params.op_id {
                Some(id) if !id.is_empty() => Outcome::Ok { op_id: id },
                _ => Outcome::Error("page reported ok but didn't return op_id".into()),
            },
            Some("cancelled") => Outcome::Cancelled,
            _ => Outcome::Error(params.error.unwrap_or_else(|| "unknown".into())),
        }
    };
    let body = match &outcome {
        Outcome::Ok { .. } => "OK — you can close this tab and return to the terminal.\n",
        Outcome::Cancelled => "Cancelled — return to the terminal.\n",
        Outcome::Error(_) => "Error — see terminal for details.\n",
        Outcome::BadState => "Bad state — return to the terminal.\n",
    };
    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(outcome);
    }
    (StatusCode::OK, body)
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
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
        for arg in &cmd[1..] {
            c.arg(arg);
        }
        c.arg(url);
        c.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if c.spawn().is_ok() {
            return Ok(());
        }
    }
    Err("no browser opener available".into())
}
