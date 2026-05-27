//! `safeclaw vault ...` — vault lifecycle ops.
//!
//! - `vault ls` queries the daemon's `GET /admin/vaults`. Requires
//!   `SAFECLAW_ADMIN_KEY` to be set both on the daemon (otherwise the
//!   admin surface is disabled) and on the CLI side as `$SAFECLAW_ADMIN_KEY`.
//! - `vault delete <id>` is the destructive vault-wipe via the standard
//!   browser-callback passkey ceremony (a SUDP grant on a `Custom`
//!   vault-delete op, surfaced as `/op/{op_id}` in the browser).
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

use crate::cli::profile::resolve_active;
use crate::config::{ProfileSelectArgs, VaultDeleteArgs, VaultSubcommand};

pub async fn run(sub: VaultSubcommand) -> Result<(), String> {
    match sub {
        VaultSubcommand::Ls(a) => run_ls(a).await,
        VaultSubcommand::Delete(a) => run_delete(a).await,
    }
}

async fn run_ls(args: ProfileSelectArgs) -> Result<(), String> {
    // Vault list is admin-scoped (cross-vault enumeration). The CLI only
    // needs the custodian root, not a vault id; pass a placeholder vault
    // so resolve_active is happy if the config has none.
    let custodian = match args.custodian.as_deref() {
        Some(c) => c.to_string(),
        None => {
            // Reuse resolve_active for the custodian half; ignore the vault.
            // If the user has no config at all, default to localhost so
            // OSS users on a fresh machine still get a reasonable error
            // from the admin endpoint instead of "no custodian configured".
            resolve_active(None, args.vault.as_deref())
                .map(|(c, _)| c)
                .unwrap_or_else(|_| "http://127.0.0.1:23294".to_string())
        }
    };
    let admin_key = std::env::var("SAFECLAW_ADMIN_KEY").map_err(|_| {
        "vault ls needs $SAFECLAW_ADMIN_KEY (the daemon's SAFECLAW_ADMIN_KEY \
         env). Self-host: set it on the daemon; SaaS: this command is \
         operator-only and not exposed."
            .to_string()
    })?;
    let url = format!("{}/admin/vaults", custodian.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .header("X-Admin-Key", admin_key)
        .send()
        .await
        .map_err(|e| format!("reach custodian: {}", e))?;
    let status = resp.status();
    if status.as_u16() == 403 {
        return Err(
            "custodian returned 403 — daemon has no SAFECLAW_ADMIN_KEY set, or yours doesn't match"
                .into(),
        );
    }
    if !status.is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            status,
            resp.text().await.unwrap_or_default()
        ));
    }
    #[derive(Deserialize)]
    struct Body {
        vaults: Vec<String>,
    }
    let body: Body = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    if body.vaults.is_empty() {
        println!("(no vaults on {})", custodian);
        return Ok(());
    }
    // Mark which one is "active" from the perspective of this CLI's config.
    let active = match args.vault.as_deref() {
        Some(v) => Some(v.to_string()),
        None => resolve_active(Some(&custodian), None).ok().map(|(_, v)| v),
    };
    println!("vaults on {}", custodian);
    for v in &body.vaults {
        let marker = if active.as_deref() == Some(v.as_str()) {
            "*"
        } else {
            " "
        };
        println!("  {} {}", marker, v);
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
    // Use the explicit vault arg for the destructive op; the active
    // config only drives the custodian URL fallback.
    let (custodian, _) = resolve_active(
        args.custodian.as_deref(),
        Some(args.vault.as_str()),
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
    eprintln!("safeclaw vault delete {} — opening browser…", vault);
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
            eprintln!("safeclaw vault delete — ok (vault {} wiped)", vault);
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
