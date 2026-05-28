//! `sc start` / `stop` / `restart` / `logs` — user-level systemd lifecycle.
//!
//! These commands install a per-user systemd unit at
//! `~/.config/systemd/user/safeclaw.service` and drive it via
//! `systemctl --user`. Linux only.
//!
//! Why user-level (not system-level)?
//! - No sudo required — the daemon runs as the same user that called `sc start`.
//! - Vault state lives under `$HOME/.safeclaw/`, owned by the same user.
//! - Encapsulates "this user's SafeClaw daemon" cleanly. Multi-user hosts
//!   work too, each user gets their own daemon.
//!
//! Operators running SafeClaw as a system service (root-owned, the dev VM
//! shape) should write their own `/etc/systemd/system/safeclaw.service`
//! and not touch these commands.

use std::process::Command as ProcCommand;
use crate::config::LogsArgs;

const UNIT_BASENAME: &str = "safeclaw.service";

#[cfg(target_os = "linux")]
pub async fn run_start_systemd() -> Result<(), String> {
    let bin = std::env::current_exe()
        .map_err(|e| format!("can't find current binary path: {}", e))?;
    let bin_str = bin.to_string_lossy().to_string();

    // Collect any SAFECLAW_* env vars set in the calling shell — these
    // become Environment= lines in the unit. The user controls config
    // by setting env vars *before* `sc start`; flags are ignored here
    // (they'd be invisible after install, which is worse).
    let mut env_lines = Vec::new();
    for (k, v) in std::env::vars() {
        if k.starts_with("SAFECLAW_") {
            // systemd unit syntax: quote the value to allow spaces/=.
            // Escape any " inside.
            let v_escaped = v.replace('"', "\\\"");
            env_lines.push(format!("Environment=\"{}={}\"", k, v_escaped));
        }
    }
    let env_block = if env_lines.is_empty() { String::new() } else { format!("{}\n", env_lines.join("\n")) };

    let unit = format!(
        "[Unit]\n\
         Description=SafeClaw daemon (user)\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         {env_block}\
         ExecStart={bin} start --foreground\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        env_block = env_block,
        bin = bin_str,
    );

    let unit_dir = dirs::config_dir()
        .ok_or("can't locate user config dir (XDG_CONFIG_HOME)")?
        .join("systemd/user");
    std::fs::create_dir_all(&unit_dir)
        .map_err(|e| format!("create {}: {}", unit_dir.display(), e))?;
    let unit_path = unit_dir.join(UNIT_BASENAME);
    std::fs::write(&unit_path, &unit)
        .map_err(|e| format!("write {}: {}", unit_path.display(), e))?;
    // Unit may embed SAFECLAW_ADMIN_KEY and other secrets via
    // Environment= lines. Tighten to user-only so other accounts on a
    // multi-user host can't read them.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {}", unit_path.display(), e))?;
    }

    run_systemctl(&["daemon-reload"], "daemon-reload")?;
    run_systemctl(&["enable", "--now", UNIT_BASENAME], "enable+start")?;

    eprintln!("✓ daemon enabled and running ({})", unit_path.display());
    eprintln!("  binary:   {}", bin_str);
    if !env_lines.is_empty() {
        eprintln!("  env:      {} SAFECLAW_* var(s) embedded", env_lines.len());
    }
    eprintln!();
    eprintln!("  next: `safeclaw vault create` to make your first vault");
    eprintln!("        `safeclaw c logs -f` to tail, `safeclaw c stop` to stop, `safeclaw c restart` to reload");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn run_start_systemd() -> Result<(), String> {
    Err("`sc c start` (systemd mode) is Linux-only. Use `sc c start --foreground` to run in this process.".into())
}

#[cfg(target_os = "linux")]
pub fn run_stop() -> Result<(), String> {
    ensure_unit_installed()?;
    run_systemctl(&["stop", UNIT_BASENAME], "stop")?;
    eprintln!("✓ daemon stopped");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_stop() -> Result<(), String> {
    Err("`sc c stop` (systemd mode) is Linux-only.".into())
}

#[cfg(target_os = "linux")]
pub fn run_restart() -> Result<(), String> {
    ensure_unit_installed()?;
    run_systemctl(&["restart", UNIT_BASENAME], "restart")?;
    eprintln!("✓ daemon restarted");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_restart() -> Result<(), String> {
    Err("`sc c restart` (systemd mode) is Linux-only.".into())
}

#[cfg(target_os = "linux")]
pub fn run_logs(args: LogsArgs) -> Result<(), String> {
    ensure_unit_installed()?;
    let n = args.lines.to_string();
    let mut cmd = ProcCommand::new("journalctl");
    cmd.args(["--user", "-u", UNIT_BASENAME, "-n", &n]);
    if args.follow {
        cmd.arg("-f");
    }
    // Inherit stdio so journalctl prints directly + Ctrl-C works.
    let status = cmd.status()
        .map_err(|e| format!("spawn journalctl: {}", e))?;
    if !status.success() {
        return Err(format!("journalctl exited with status {}", status));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_logs(_args: LogsArgs) -> Result<(), String> {
    Err("`sc c logs` (systemd mode) is Linux-only.".into())
}

#[cfg(target_os = "linux")]
fn ensure_unit_installed() -> Result<(), String> {
    let unit_path = dirs::config_dir()
        .ok_or("can't locate user config dir")?
        .join("systemd/user")
        .join(UNIT_BASENAME);
    if !unit_path.exists() {
        return Err(format!(
            "no systemd unit at {} — run `sc c start` first to install it",
            unit_path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str], action: &str) -> Result<(), String> {
    let mut cmd = ProcCommand::new("systemctl");
    cmd.arg("--user");
    cmd.args(args);
    let output = cmd.output()
        .map_err(|e| format!("spawn systemctl: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("systemctl --user {} failed: {}", action, stderr.trim()));
    }
    Ok(())
}
