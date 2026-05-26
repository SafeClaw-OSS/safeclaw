//! `safeclaw unlock` / `safeclaw lock` — drives the daemon's `/cli/auth`
//! browser page over a localhost callback.
//!
//! Flow:
//!   1. Resolve `(daemon, vault)` from CLI flags or active profile.
//!   2. Bind a tiny axum server on `127.0.0.1:RANDOM` (one route, `/done`).
//!   3. Generate a 16-byte hex `state` token (CSRF).
//!   4. Try to open the user's default browser at
//!      `<daemon>/cli/auth?op=<unlock|lock>&vault=<vid>&cb=<cb>&state=<token>`.
//!      Fall back to printing the URL.
//!   5. Block up to `timeout` seconds waiting for the callback's GET.
//!   6. Verify `state` matches; report the page's `status` (ok/error/cancelled).

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
use tokio::sync::Mutex;
use tokio::sync::oneshot;

use crate::cli::profile::{load as load_profiles, ProfileConfig, DEFAULT_PROFILE};
use crate::config::UnlockArgs;

#[derive(Debug, Deserialize)]
struct CallbackParams {
    status: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

struct CallbackState {
    expected_state: String,
    tx: Mutex<Option<oneshot::Sender<CallbackOutcome>>>,
}

enum CallbackOutcome {
    Ok,
    Cancelled,
    Error(String),
    BadState,
}

/// Public entry point — dispatch to the unified driver below with the right
/// op label.
pub async fn run_unlock(args: UnlockArgs) -> Result<(), String> {
    drive("unlock", args).await
}
pub async fn run_lock(args: UnlockArgs) -> Result<(), String> {
    drive("lock", args).await
}

async fn drive(op_label: &str, args: UnlockArgs) -> Result<(), String> {
    let (daemon, vault) = resolve_profile(&args)?;

    // 1. Bind localhost listener on a random port.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind localhost: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {}", e))?;

    // 2. Generate state token for CSRF.
    let state_token = random_hex(16);

    // 3. Wire up the callback server.
    let (tx, rx) = oneshot::channel::<CallbackOutcome>();
    let app_state = Arc::new(CallbackState {
        expected_state: state_token.clone(),
        tx: Mutex::new(Some(tx)),
    });
    let app = Router::new()
        .route("/done", get(handle_done))
        .with_state(app_state.clone());

    // 4. Build the URL we want the browser to open.
    let cb = format!("http://{}/done", local_addr);
    let auth_url = format!(
        "{}/cli/auth?op={}&vault={}&cb={}&state={}",
        daemon.trim_end_matches('/'),
        op_label,
        urlencoding::encode(&vault),
        urlencoding::encode(&cb),
        urlencoding::encode(&state_token),
    );

    println!("safeclaw {} — opening browser…", op_label);
    println!("  daemon: {}", daemon);
    println!("  vault:  {}", vault);
    println!("  cb:     {}", cb);
    println!();
    println!("If your browser doesn't open, visit this URL manually:");
    println!("  {}", auth_url);
    println!();

    if !args.no_browser {
        if let Err(e) = open_browser(&auth_url) {
            eprintln!("(could not auto-open browser: {}) — visit the URL above.", e);
        }
    }

    // 5. Spawn the callback server in a task; await either the channel or
    // the timeout. The server is dropped (and the listener closed) when we
    // exit the select! arm — no graceful shutdown needed, the OS reclaims.
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let outcome = tokio::select! {
        outcome = rx => outcome.unwrap_or(CallbackOutcome::Error("callback channel dropped".into())),
        _ = tokio::time::sleep(Duration::from_secs(args.timeout)) => {
            server_task.abort();
            return Err(format!("timed out after {}s waiting for browser callback", args.timeout));
        }
    };
    server_task.abort();

    match outcome {
        CallbackOutcome::Ok => {
            println!("safeclaw {} — ok", op_label);
            Ok(())
        }
        CallbackOutcome::Cancelled => Err("user cancelled the ceremony".into()),
        CallbackOutcome::Error(e) => Err(format!("browser page reported error: {}", e)),
        CallbackOutcome::BadState => Err("callback state mismatch (CSRF guard)".into()),
    }
}

async fn handle_done(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let s = params.state.unwrap_or_default();
    let outcome = if s != state.expected_state {
        CallbackOutcome::BadState
    } else {
        match params.status.as_deref() {
            Some("ok") => CallbackOutcome::Ok,
            Some("cancelled") => CallbackOutcome::Cancelled,
            _ => CallbackOutcome::Error(
                params
                    .error
                    .unwrap_or_else(|| "unknown".into()),
            ),
        }
    };

    let body = match &outcome {
        CallbackOutcome::Ok => "OK — you can close this tab and return to the terminal.\n",
        CallbackOutcome::Cancelled => "Cancelled — return to the terminal.\n",
        CallbackOutcome::Error(_) => "Error — see terminal for details.\n",
        CallbackOutcome::BadState => "Bad state — return to the terminal.\n",
    };

    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(outcome);
    }
    (StatusCode::OK, body)
}

/// Pick `(daemon, vault)` from explicit flags first, falling back to the
/// active profile in `~/.config/safeclaw/config.toml`.
fn resolve_profile(args: &UnlockArgs) -> Result<(String, String), String> {
    if let (Some(d), Some(v)) = (args.daemon.as_ref(), args.vault.as_ref()) {
        return Ok((d.clone(), v.clone()));
    }
    let cfg: ProfileConfig = load_profiles()?;
    let profile_name = args
        .profile
        .clone()
        .or_else(|| cfg.default_profile.clone())
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let p = cfg
        .profiles
        .get(&profile_name)
        .ok_or_else(|| {
            format!(
                "profile '{}' not found in config — run `safeclaw login` first",
                profile_name
            )
        })?;
    Ok((
        args.daemon.clone().unwrap_or_else(|| p.daemon.clone()),
        args.vault.clone().unwrap_or_else(|| p.vault.clone()),
    ))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Best-effort browser open. Try `xdg-open` (linux), `open` (macOS), `start`
/// (windows) — first one that succeeds wins.
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
