//! `safeclaw vaults ...` — local profile management + vault lifecycle ops.
//!
//! - `vaults ls` is pure local config inspection (no custodian round-trip).
//! - `vaults delete <id>` is the destructive vault-wipe via the standard
//!   browser-callback passkey ceremony (`/cli/auth?op=vault-delete`).
//!   Requires `--yes-i-mean-it` to bypass the confirmation prompt.

use std::io::{self, Write as _};
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

use crate::cli::profile::{load as load_profiles, resolve_active};
use crate::config::{VaultDeleteArgs, VaultsSubcommand};

pub async fn run(sub: VaultsSubcommand) -> Result<(), String> {
    match sub {
        VaultsSubcommand::Ls => run_ls(),
        VaultsSubcommand::Delete(a) => run_delete(a).await,
    }
}

fn run_ls() -> Result<(), String> {
    let cfg = load_profiles()?;
    if cfg.profiles.is_empty() {
        println!("(no profiles — run `safeclaw login` to add one)");
        return Ok(());
    }
    let active = cfg.default_profile.as_deref();
    let name_w = cfg
        .profiles
        .keys()
        .map(|k| k.len())
        .max()
        .unwrap_or(0)
        .max(4);
    let daemon_w = cfg
        .profiles
        .values()
        .map(|p| p.custodian.len())
        .max()
        .unwrap_or(0)
        .max(6);
    println!(
        "  {:<nw$}  {:<dw$}  {}",
        "NAME",
        "DAEMON",
        "VAULT",
        nw = name_w + 1,
        dw = daemon_w
    );
    for (name, p) in &cfg.profiles {
        let marker = if Some(name.as_str()) == active { "*" } else { " " };
        println!(
            "  {}{:<nw$}  {:<dw$}  {}",
            marker,
            name,
            p.custodian,
            p.vault,
            nw = name_w,
            dw = daemon_w
        );
    }
    Ok(())
}

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
    // op_id is unused for vault-delete but kept on the wire for symmetry with
    // export / unlock / lock — gives future callers something to correlate
    // against the audit row if needed.
    Ok {
        #[allow(dead_code)]
        op_id: Option<String>,
    },
    Cancelled,
    Error(String),
    BadState,
}

async fn run_delete(args: VaultDeleteArgs) -> Result<(), String> {
    if !args.yes_i_mean_it {
        return Err(
            "destructive — pass --yes-i-mean-it to confirm vault deletion".into(),
        );
    }
    // Use the explicit vault arg for the destructive op; the profile only
    // drives the custodian URL fallback.
    let (custodian, _) = resolve_active(
        args.custodian.as_deref(),
        Some(args.vault.as_str()),
        args.profile.as_deref(),
    )?;
    let vault = args.vault.trim().to_string();
    if vault.is_empty() {
        return Err("vault id cannot be empty".into());
    }

    // Final-stop interactive confirmation — even with --yes-i-mean-it,
    // require the user to retype the vault id. Skip if stdin isn't a tty
    // (CI / piping users explicitly accept the risk by passing the flag).
    if atty_isatty_stdin() {
        eprint!("Type vault id `{}` to confirm permanent deletion: ", vault);
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        if buf.trim() != vault {
            return Err("confirmation mismatch — aborted".into());
        }
    }

    // Spawn callback server.
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
        "{}/cli/auth?op=vault-delete&vault={}&cb={}&state={}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault),
        urlencoding::encode(&cb),
        urlencoding::encode(&state_token),
    );
    eprintln!("safeclaw vaults delete {} — opening browser…", vault);
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
        Outcome::Ok { .. } => {
            eprintln!("safeclaw vaults delete — ok (vault {} wiped)", vault);
            Ok(())
        }
        Outcome::Cancelled => Err("user cancelled the ceremony".into()),
        Outcome::Error(e) => Err(format!("browser page reported error: {}", e)),
        Outcome::BadState => Err("callback state mismatch (CSRF guard)".into()),
    }
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
            Some("ok") => Outcome::Ok { op_id: params.op_id },
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

/// Crude isatty check using the libc fd. Avoids pulling the `atty` crate.
fn atty_isatty_stdin() -> bool {
    // SAFETY: file descriptor 0 (stdin) is always present.
    unsafe { libc_isatty(0) != 0 }
}

#[link(name = "c")]
extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}
