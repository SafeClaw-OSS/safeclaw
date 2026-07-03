//! `sc run` — the thin env-paster over the resident proxy + CA.
//!
//! `sc run -- <cmd…>` execs the child with the proxy/CA env bundle merged into
//! the inherited environment; `sc run --export-env` prints the same bundle as
//! shell `export` lines. It spins up NOTHING (the CA and proxy are resident,
//! owned by the daemon) and pastes NO plaintext secret — the agent writes the
//! phantom itself; the proxy substitutes at egress. Spec §6.

use std::path::Path;

use crate::cli::active::resolve_active;
use crate::cli::env::shell_quote;
use crate::cli::proxy_env::{
    build_bundle, control_plane_up, probe_via, proxy_base, resident_ca_path,
};
use crate::config::RunArgs;

pub async fn run(args: RunArgs) -> Result<(), String> {
    // clap already makes --export-env and a command mutually exclusive; require
    // that exactly one is present.
    if !args.export_env && args.cmd.is_empty() {
        return Err(
            "nothing to run — `sc run -- <cmd>` to run a command, or `sc run --export-env`".into(),
        );
    }

    let (_daemon, vid) = resolve_active(args.vault.as_deref())?;
    let ca = resident_ca_path();
    preflight(&ca).await?;

    let ca_str = ca.to_string_lossy().to_string();
    // Chain onto an already-configured git helper rather than clobber it.
    let parent_count = std::env::var("GIT_CONFIG_COUNT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let bundle = build_bundle(&vid, &ca_str, parent_count);

    if args.export_env {
        for (k, v) in &bundle {
            println!("export {}={}", k, shell_quote(v));
        }
        return Ok(());
    }

    exec_child(&args.cmd, &bundle)
}

/// The CA must exist and SafeClaw must be reachable (proxy answers, else the
/// control plane is at least up). Otherwise a friendly `sc up` hint — never a
/// mystery TLS / connection error inside the child.
async fn preflight(ca: &Path) -> Result<(), String> {
    if !ca.exists() {
        return Err(format!(
            "SafeClaw CA not found at {} — the daemon generates it on first start. Run `sc up`, then retry.",
            ca.display()
        ));
    }
    if probe_via(&proxy_base()).await {
        return Ok(());
    }
    if control_plane_up().await {
        // Daemon is up but the proxy probe didn't answer yet (just started, or a
        // slow bind). Proceed — the child's first request will still route.
        eprintln!("note: SafeClaw's proxy didn't answer the probe yet; continuing (the daemon is up).");
        return Ok(());
    }
    Err("SafeClaw isn't running — bring it up with `sc up`, then retry.".into())
}

/// Exec the child with the bundle merged into the inherited env. On unix this
/// REPLACES the current process (so signals / exit status pass through
/// naturally); it only returns on failure.
#[cfg(unix)]
fn exec_child(cmd: &[String], bundle: &[(String, String)]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let (prog, rest) = cmd.split_first().ok_or("no command to run")?;
    let mut c = std::process::Command::new(prog);
    c.args(rest);
    for (k, v) in bundle {
        c.env(k, v);
    }
    // exec never returns on success.
    let err = c.exec();
    Err(format!("exec {}: {}", prog, err))
}

/// Non-unix fallback: spawn + wait, propagating the child's exit code.
#[cfg(not(unix))]
fn exec_child(cmd: &[String], bundle: &[(String, String)]) -> Result<(), String> {
    let (prog, rest) = cmd.split_first().ok_or("no command to run")?;
    let mut c = std::process::Command::new(prog);
    c.args(rest);
    for (k, v) in bundle {
        c.env(k, v);
    }
    let status = c.status().map_err(|e| format!("spawn {}: {}", prog, e))?;
    std::process::exit(status.code().unwrap_or(1));
}
