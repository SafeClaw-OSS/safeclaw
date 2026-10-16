//! Agent-driven, non-interactive setup state machine.

use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::cli::human_action::{self, SetupEntry, SetupStatus};
use crate::config::{SetupArgs, SetupPhase};

struct Context {
    name: String,
    profile: Option<String>,
    setup_dir: PathBuf,
}

enum Progress {
    Continue,
    Emitted,
}

pub async fn run(args: SetupArgs, json_output: bool) -> Result<(), i32> {
    if args.detect_agent {
        if let Some(name) = crate::cli::agent_detect::detect() {
            println!("{}", name);
            return Ok(());
        }
        return Err(1);
    }

    if args.background {
        return run_background(args).await;
    }

    let name = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(crate::cli::agent_detect::detect);
    let name = match name {
        Some(name) => name,
        None => {
            emit_error(
                json_output,
                "A short agent name is required.",
                "sc setup --name <a short name for this agent, e.g. claude-code>",
            );
            return Err(2);
        }
    };

    let context = match preconditions(name, args.profile.clone()).await {
        Ok(context) => context,
        Err((message, fix, code)) => {
            emit_error(json_output, &message, &fix);
            return Err(code);
        }
    };

    loop {
        match handle_prior_background(&context, args.wait, json_output).await? {
            Progress::Continue => {}
            Progress::Emitted => return Ok(()),
        }

        let identity_path = match crate::identity_file::agent_identity_path(&context.name) {
            Ok(path) => path,
            Err(e) => {
                emit_error(json_output, &e, &base_command(&context));
                return Err(1);
            }
        };
        let cfg = crate::cli::active::load().unwrap_or_default();
        if !device_paired(&cfg) || !identity_path.is_file() {
            match spawn_and_report(&context, SetupPhase::Pairing, json_output).await? {
                Progress::Continue => continue,
                Progress::Emitted => return Ok(()),
            }
        }

        let cfg = crate::cli::active::load().unwrap_or_default();
        let control = crate::cli::active::control_root(&cfg);
        if !crate::cli::status::probe_local_daemon(&control).await.up {
            if let Err(e) = crate::cli::service::ensure_running_with_fallback().await {
                emit_error(
                    json_output,
                    &format!("The SafeClaw daemon could not be started: {}", e),
                    &base_command(&context),
                );
                return Err(1);
            }
        }

        let broker_url = format!(
            "{}:{}",
            crate::cli::active::device_daemon_host(&cfg),
            crate::config::PROXY_PORT
        );
        let env_path = identity_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("agent.env");
        let env_body = format!(
            "SAFECLAW_BROKER_URL={}\nSAFECLAW_AGENT_IDENTITY={}\n",
            broker_url,
            crate::cli::agent::env_value(&identity_path.display().to_string())
        );
        if let Err(e) = write_if_changed(&env_path, env_body.as_bytes()) {
            emit_error(json_output, &e, &base_command(&context));
            return Err(1);
        }

        let skill = match crate::cli::skill::install(false) {
            Ok(report) => report,
            Err(e) => {
                emit_error(
                    json_output,
                    &format!("The SafeClaw skill could not be installed: {}", e),
                    "sc skill install",
                );
                return Err(1);
            }
        };

        let mut notes = Vec::new();
        if skill.modified {
            notes.push(
                "The existing SafeClaw skill was modified, so it was left unchanged.".to_string(),
            );
        }
        notes.extend(skill.notes.clone());
        let vault_guidance = setup_vault_guidance(crate::cli::active::known_vaults().len());
        emit_done(
            json_output,
            &context.name,
            &env_path,
            &skill.paths,
            &notes,
            vault_guidance.as_ref(),
        );
        return Ok(());
    }
}

async fn preconditions(
    name: String,
    profile: Option<String>,
) -> Result<Context, (String, String, i32)> {
    let cfg = crate::cli::active::load().map_err(|e| {
        (
            format!("SafeClaw configuration could not be read: {}", e),
            format!(
                "Fix ~/.safeclaw/config.toml, then re-run: {}",
                setup_command(&name, profile.as_deref())
            ),
            1,
        )
    })?;
    let cloud = match profile.as_deref() {
        Some(profile) => crate::cli::login::env_selector_to_url(profile)
            .map_err(|e| (e, setup_command(&name, Some(profile)), 2))?,
        None => cfg
            .cloud_backend
            .clone()
            .filter(|s| !s.is_empty())
            .map(Ok)
            .unwrap_or_else(|| crate::cli::login::resolve_custodian(None))
            .map_err(|e| (e, setup_command(&name, None), 1))?,
    };
    let cloud = cloud.trim_end_matches('/').to_string();
    let has_pairing = cfg
        .cloud_backend
        .as_deref()
        .is_some_and(|backend| !backend.is_empty());
    if has_pairing {
        if let (Some(selected), Some(paired)) = (profile.as_deref(), cfg.cloud_backend.as_deref()) {
            if paired.trim_end_matches('/') != cloud {
                return Err((
                    format!(
                        "This machine is already paired to {}, not the {} profile.",
                        paired.trim_end_matches('/'),
                        selected
                    ),
                    format!("sc login --profile {}", selected),
                    1,
                ));
            }
        }
    }

    let home = dirs::home_dir().ok_or_else(|| {
        (
            "SafeClaw could not locate the home directory.".to_string(),
            format!(
                "Re-run outside the sandbox with network access: {}",
                setup_command(&name, profile.as_deref())
            ),
            1,
        )
    })?;
    let safeclaw_dir = home.join(".safeclaw");
    let setup_dir = safeclaw_dir.join("setup");
    let retry = format!(
        "Re-run outside the sandbox with network access: {}",
        setup_command(&name, profile.as_deref())
    );
    if let Err(e) = human_action::ensure_private_dir(&safeclaw_dir)
        .and_then(|_| human_action::ensure_private_dir(&setup_dir))
    {
        return Err((
            format!("SafeClaw's setup directory is not usable: {}", e),
            retry,
            1,
        ));
    }

    Ok(Context {
        name,
        profile,
        setup_dir,
    })
}

fn device_paired(cfg: &crate::cli::active::CliConfig) -> bool {
    cfg.cloud_backend.as_deref().is_some_and(|s| !s.is_empty())
        && crate::sync::device_key().is_some()
}

async fn handle_prior_background(
    context: &Context,
    wait: bool,
    json_output: bool,
) -> Result<Progress, i32> {
    let lock = context.setup_dir.join("lock");
    let status_path = context.setup_dir.join("status.json");
    let lock_pid = read_pid(&lock);
    if let Some(pid) = lock_pid {
        if human_action::pid_is_live(pid) {
            if wait {
                if let Ok(status) = human_action::read(&status_path) {
                    if let Some(result) = name_mismatch(context, &status, json_output) {
                        return result;
                    }
                }
                return wait_for_existing(context, pid, json_output).await;
            }
            return status_now(context, pid, json_output).await;
        }
        let _ = fs::remove_file(&lock);
        return consume_dead_status(context, &status_path, json_output);
    }

    if status_path.exists() {
        return consume_dead_status(context, &status_path, json_output);
    }
    Ok(Progress::Continue)
}

async fn status_now(context: &Context, pid: u32, json_output: bool) -> Result<Progress, i32> {
    let status_path = context.setup_dir.join("status.json");
    match human_action::read(&status_path) {
        Ok(status) => {
            if let Some(result) = name_mismatch(context, &status, json_output) {
                return result;
            }
            if status.state == "approved" {
                finish_approved(context, pid).await;
                Ok(Progress::Continue)
            } else if status.state == "failed" {
                failed_status(context, status, json_output)
            } else if actionable(&status) {
                emit_action(json_output, context, &status);
                Ok(Progress::Emitted)
            } else {
                emit_waiting(
                    json_output,
                    &next_command(context, effective_profile(context, &status)),
                );
                Ok(Progress::Emitted)
            }
        }
        _ => {
            emit_waiting(
                json_output,
                &next_command(context, context.profile.as_deref()),
            );
            Ok(Progress::Emitted)
        }
    }
}

async fn wait_for_existing(
    context: &Context,
    pid: u32,
    json_output: bool,
) -> Result<Progress, i32> {
    let seconds = std::env::var("SAFECLAW_SETUP_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(90);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status_path = context.setup_dir.join("status.json");
    let mut profile = context.profile.clone();
    loop {
        if let Ok(status) = human_action::read(&status_path) {
            if let Some(result) = name_mismatch(context, &status, json_output) {
                return result;
            }
            profile = context.profile.clone().or(status.profile.clone());
            if status.state == "approved" {
                finish_approved(context, pid).await;
                return Ok(Progress::Continue);
            }
            if status.state == "failed" {
                return failed_status(context, status, json_output);
            }
        }
        if !human_action::pid_is_live(pid) {
            return consume_dead_status(context, &status_path, json_output);
        }
        if Instant::now() >= deadline {
            emit_waiting(json_output, &next_command(context, profile.as_deref()));
            return Ok(Progress::Emitted);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn consume_dead_status(
    context: &Context,
    status_path: &Path,
    json_output: bool,
) -> Result<Progress, i32> {
    match human_action::read(status_path) {
        Ok(status) if status.state == "approved" => {
            let _ = fs::remove_file(status_path);
            Ok(Progress::Continue)
        }
        Ok(status) if status.state == "failed" => failed_status(context, status, json_output),
        _ => {
            let _ = fs::remove_file(status_path);
            emit_error(
                json_output,
                "The setup background process stopped before the approval finished.",
                &base_command(context),
            );
            Err(1)
        }
    }
}

fn failed_status(
    context: &Context,
    status: SetupStatus,
    json_output: bool,
) -> Result<Progress, i32> {
    let profile = context.profile.clone().or(status.profile.clone());
    let message = status
        .message
        .unwrap_or_else(|| "The setup background process failed.".to_string());
    let lower = message.to_ascii_lowercase();
    let code = if lower.contains("expired")
        || lower.contains("declined")
        || lower.contains("denied")
        || lower.contains("rejected")
    {
        3
    } else {
        1
    };
    let _ = fs::remove_file(context.setup_dir.join("status.json"));
    let _ = fs::remove_file(context.setup_dir.join("lock"));
    emit_error(
        json_output,
        &message,
        &setup_command(&context.name, profile.as_deref()),
    );
    Err(code)
}

async fn finish_approved(context: &Context, pid: u32) {
    let lock = context.setup_dir.join("lock");
    for _ in 0..20 {
        if !human_action::pid_is_live(pid) || !lock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = fs::remove_file(context.setup_dir.join("status.json"));
    if !human_action::pid_is_live(pid) {
        let _ = fs::remove_file(lock);
    }
}

async fn spawn_and_report(
    context: &Context,
    phase: SetupPhase,
    json_output: bool,
) -> Result<Progress, i32> {
    let pid = match spawn_background(context, phase) {
        Ok(pid) => pid,
        Err(e) => {
            emit_error(json_output, &e, &base_command(context));
            return Err(1);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let status_path = context.setup_dir.join("status.json");
    loop {
        if let Ok(status) = human_action::read(&status_path) {
            if status.state == "failed" {
                return failed_status(context, status, json_output);
            }
            if status.state == "approved" {
                finish_approved(context, pid).await;
                return Ok(Progress::Continue);
            }
            if actionable(&status) {
                emit_action(json_output, context, &status);
                return Ok(Progress::Emitted);
            }
        }
        if !human_action::pid_is_live(pid) {
            return consume_dead_status(context, &status_path, json_output);
        }
        if Instant::now() >= deadline {
            emit_waiting(
                json_output,
                &next_command(context, context.profile.as_deref()),
            );
            return Ok(Progress::Emitted);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn spawn_background(context: &Context, phase: SetupPhase) -> Result<u32, String> {
    let lock_path = context.setup_dir.join("lock");
    let status_path = context.setup_dir.join("status.json");
    let mut lock_options = OpenOptions::new();
    lock_options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let mut lock = lock_options.open(&lock_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            "another setup background process is starting; re-run the same setup command"
                .to_string()
        } else {
            format!("create {}: {}", lock_path.display(), e)
        }
    })?;
    writeln!(lock, "{}", std::process::id())
        .map_err(|e| format!("write {}: {}", lock_path.display(), e))?;
    let _ = fs::remove_file(&status_path);

    let log_path = context.setup_dir.join("background.log");
    let mut log_options = OpenOptions::new();
    log_options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        log_options.mode(0o600);
    }
    let stdout = log_options
        .open(&log_path)
        .map_err(|e| format!("open {}: {}", log_path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {}", log_path.display(), e))?;
    }
    let stderr = stdout
        .try_clone()
        .map_err(|e| format!("open {} for stderr: {}", log_path.display(), e))?;
    let binary = std::env::current_exe().map_err(|e| format!("locate current binary: {}", e))?;
    let mut command = Command::new(binary);
    command
        .arg("setup")
        .arg("--background")
        .arg("--phase")
        .arg(phase_name(phase))
        .arg("--name")
        .arg(&context.name)
        .env(human_action::STATUS_ENV, &status_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(profile) = context.profile.as_deref() {
        command.arg("--profile").arg(profile);
    }
    human_action::detach_session(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = fs::remove_file(&lock_path);
            return Err(format!("start setup background process: {}", e));
        }
    };
    if let Err(e) = write_pid_file(&lock_path, child.id()) {
        let _ = child.kill();
        let _ = fs::remove_file(&lock_path);
        return Err(e);
    }
    Ok(child.id())
}

fn setup_entries(name: &str) -> Result<Vec<SetupEntry>, String> {
    let cfg = crate::cli::active::load().unwrap_or_default();
    let mut entries = Vec::new();
    if !device_paired(&cfg) {
        entries.push(SetupEntry {
            kind: "device".into(),
            name: crate::cli::login::device_name(None),
        });
    }
    if !crate::identity_file::agent_identity_path(name)?.is_file() {
        entries.push(SetupEntry {
            kind: "agent".into(),
            name: name.to_string(),
        });
    }
    Ok(entries)
}

struct PreparedAgent {
    path: PathBuf,
    seed: zeroize::Zeroizing<[u8; 32]>,
    id: String,
    signer: crate::identity::SigningIdentity,
}

/// Pair every missing setup principal with one code, verify the complete set,
/// then persist the device and agent material.
async fn pair_missing_and_persist(name: &str, profile: Option<&str>) -> Result<(), String> {
    let cfg = crate::cli::active::load().unwrap_or_default();
    let need_device = !device_paired(&cfg);
    let agent_path = crate::identity_file::agent_identity_path(name)?;
    let need_agent = !agent_path.is_file();
    if !need_device && !need_agent {
        return Ok(());
    }

    let cloud = if need_device {
        match profile {
            Some(profile) => crate::cli::login::resolve_custodian(Some(profile))?,
            None => cfg
                .cloud_backend
                .clone()
                .filter(|value| !value.is_empty())
                .map(Ok)
                .unwrap_or_else(|| crate::cli::login::resolve_custodian(None))?,
        }
    } else {
        cfg.cloud_backend
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or("this device isn't paired. Run sc login first")?
    };
    let cloud = cloud.trim_end_matches('/').to_string();
    let origin = if need_device {
        crate::cli::active::console_origin_for_backend(&cloud)
    } else {
        crate::cli::active::console_origin()
            .ok_or("this machine isn't paired to SafeClaw yet. Run sc login first")?
    };
    let pinned = if need_device {
        None
    } else {
        Some(
            crate::cli::active::account_uik_pub()
                .ok_or("this machine's pairing predates verified pairing. Run sc login first")?,
        )
    };

    let device_name = crate::cli::login::device_name(None);
    let device = need_device
        .then(crate::cli::login::prepare_device)
        .transpose()?;
    let agent = if need_agent {
        let (seed, id) = crate::identity_file::mint(crate::identity::IdKind::Agent);
        let (signer, _) = crate::identity_file::resolve(crate::identity::IdKind::Agent, &seed);
        Some(PreparedAgent {
            path: agent_path,
            seed,
            id,
            signer,
        })
    } else {
        None
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;
    let entries = match (&device, &agent) {
        (Some(device), Some(agent)) => vec![
            crate::cli::pair_flow::PairPrincipal {
                kind: "device",
                name: &device_name,
                id: &device.id,
                signer: &device.signer,
                sc_pk: Some(device.sc_pk),
            },
            crate::cli::pair_flow::PairPrincipal {
                kind: "agent",
                name,
                id: &agent.id,
                signer: &agent.signer,
                sc_pk: None,
            },
        ],
        (Some(device), None) => vec![crate::cli::pair_flow::PairPrincipal {
            kind: "device",
            name: &device_name,
            id: &device.id,
            signer: &device.signer,
            sc_pk: Some(device.sc_pk),
        }],
        (None, Some(agent)) => vec![crate::cli::pair_flow::PairPrincipal {
            kind: "agent",
            name,
            id: &agent.id,
            signer: &agent.signer,
            sc_pk: None,
        }],
        (None, None) => unreachable!("missing set checked above"),
    };
    let paired = crate::cli::pair_flow::pair(
        &client,
        &crate::cli::pair_flow::PairRequest {
            entries,
            cloud: &cloud,
            origin: &origin,
            restart: "sc setup",
        },
    )
    .await?;

    if let Some(pinned) = pinned {
        if paired.uik_pub != pinned {
            return Err(format!(
                "the agent was approved by another account ({}) than the one this machine is paired to; it was not set up",
                paired.uik_id
            ));
        }
    }

    if let Some(device) = &device {
        let agents = paired
            .entries
            .iter()
            .filter(|entry| entry.kind == "agent")
            .map(|entry| entry.id.clone())
            .collect();
        crate::cli::login::persist_device_approval(&paired, device, &cloud, true, agents)?;
    }
    if let Some(agent) = &agent {
        crate::identity_file::write(&agent.path, crate::identity::IdKind::Agent, &agent.seed)?;
    }
    if device.is_some() {
        crate::cli::login::bring_up(false).await?;
    }
    Ok(())
}

async fn run_background(args: SetupArgs) -> Result<(), i32> {
    let phase = match args.phase {
        Some(phase) => phase,
        None => return Err(2),
    };
    let name = match args.name.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(name) => name.to_string(),
        None => return Err(2),
    };
    let status_path = match std::env::var_os(human_action::STATUS_ENV) {
        Some(path) => PathBuf::from(path),
        None => return Err(1),
    };
    let pid = std::process::id();
    let phase_text = phase_name(phase);
    let entries = match setup_entries(&name) {
        Ok(entries) if !entries.is_empty() => entries,
        Ok(_) => return Ok(()),
        Err(_) => return Err(1),
    };
    let starting = SetupStatus::new(
        phase_text,
        "starting",
        pid,
        entries.clone(),
        args.profile.clone(),
    );
    if human_action::write(&status_path, &starting).is_err() {
        return Err(1);
    }

    let result = match phase {
        SetupPhase::Pairing => pair_missing_and_persist(&name, args.profile.as_deref()).await,
    };

    let (state, message, exit) = match result {
        Ok(()) => ("approved", None, 0),
        Err(detail) => {
            eprintln!("setup {} background process failed: {}", phase_text, detail);
            let lower = detail.to_ascii_lowercase();
            if lower.contains("expired") {
                (
                    "failed",
                    Some(format!("The {} approval expired.", phase_text)),
                    3,
                )
            } else if lower.contains("declined")
                || lower.contains("denied")
                || lower.contains("rejected")
            {
                (
                    "failed",
                    Some(format!("The {} approval was declined.", phase_text)),
                    3,
                )
            } else {
                (
                    "failed",
                    Some(format!(
                        "The {} setup background process failed. See ~/.safeclaw/setup/background.log.",
                        phase_text
                    )),
                    1,
                )
            }
        }
    };
    let mut final_status = human_action::read(&status_path).unwrap_or_else(|_| {
        SetupStatus::new(phase_text, state, pid, entries, args.profile.clone())
    });
    final_status.state = state.to_string();
    final_status.message = message;
    final_status.updated_at = crate::util::now_unix();
    let _ = human_action::write(&status_path, &final_status);
    remove_own_lock(&status_path, pid);
    if exit == 0 {
        Ok(())
    } else {
        Err(exit)
    }
}

fn remove_own_lock(status_path: &Path, pid: u32) {
    let Some(dir) = status_path.parent() else {
        return;
    };
    let lock = dir.join("lock");
    if read_pid(&lock) == Some(pid) {
        let _ = fs::remove_file(lock);
    }
}

fn phase_name(phase: SetupPhase) -> &'static str {
    match phase {
        SetupPhase::Pairing => "pairing",
    }
}

fn actionable(status: &SetupStatus) -> bool {
    status.state == "needs_user" && status.url.is_some() && status.code.is_some()
}

fn name_mismatch(
    context: &Context,
    status: &SetupStatus,
    json_output: bool,
) -> Option<Result<Progress, i32>> {
    if let Some((message, fix)) = name_mismatch_details(&context.name, status) {
        emit_error(json_output, &message, &fix);
        Some(Err(1))
    } else {
        None
    }
}

fn name_mismatch_details(current_name: &str, status: &SetupStatus) -> Option<(String, String)> {
    let paired_name = status
        .entries
        .iter()
        .find(|entry| entry.kind == "agent")
        .map(|entry| entry.name.as_str());
    if paired_name.is_some_and(|name| name != current_name) {
        let paired_name = paired_name.unwrap_or_default();
        Some((
            format!("Setup for agent '{}' is in progress.", paired_name),
            setup_wait_command(paired_name, status.profile.as_deref()),
        ))
    } else {
        None
    }
}

fn effective_profile<'a>(context: &'a Context, status: &'a SetupStatus) -> Option<&'a str> {
    context.profile.as_deref().or(status.profile.as_deref())
}

fn next_command(context: &Context, profile: Option<&str>) -> String {
    setup_wait_command(&context.name, profile)
}

fn setup_wait_command(name: &str, profile: Option<&str>) -> String {
    let mut command = setup_command(name, profile);
    command.push_str(" --wait");
    command
}

fn base_command(context: &Context) -> String {
    setup_command(&context.name, context.profile.as_deref())
}

fn setup_command(name: &str, profile: Option<&str>) -> String {
    let mut command = format!("sc setup --name {}", shell_word(name));
    if let Some(profile) = profile {
        command.push_str(&format!(" --profile {}", shell_word(profile)));
    }
    command
}

fn setup_vault_guidance(known_vault_count: usize) -> Option<(String, String)> {
    match known_vault_count {
        0 => None,
        1 => Some(("The vault is locked.".to_string(), "sc unlock".to_string())),
        _ => Some((
            "The vaults are locked. List them with sc vault ls, then run sc unlock --vault <name>."
                .to_string(),
            "sc vault ls".to_string(),
        )),
    }
}

fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn emit_action(json_output: bool, context: &Context, status: &SetupStatus) {
    let url = status.url.as_deref().unwrap_or("");
    let code = status.code.as_deref();
    let instruction = pairing_instruction(&status.entries, code.is_some());
    let setup_name = status
        .entries
        .iter()
        .find(|entry| entry.kind == "agent")
        .map(|entry| entry.name.as_str())
        .unwrap_or(&context.name);
    let next = setup_wait_command(setup_name, effective_profile(context, status));
    if json_output {
        let mut object = Map::new();
        object.insert("status".into(), json!("action_required"));
        object.insert("message".into(), json!(format!("{}.", instruction)));
        object.insert("url".into(), json!(url));
        if let Some(code) = code {
            object.insert("code".into(), json!(code));
        }
        if let Some(seconds) = status.expires_in {
            object.insert("expires_in".into(), json!(seconds));
        }
        object.insert("next_step".into(), json!(next));
        println!("{}", Value::Object(object));
    } else {
        println!("{}:", instruction);
        println!("  {}", url);
        if let Some(code) = code {
            match expiry_phrase(status.expires_in) {
                Some(expiry) => println!("  Code: {} ({})", code, expiry),
                None => println!("  Code: {}", code),
            }
        }
        println!("Next: {}", next);
    }
}

fn pairing_instruction(entries: &[SetupEntry], has_code: bool) -> String {
    let device = entries.iter().any(|entry| entry.kind == "device");
    let agent = entries.iter().find(|entry| entry.kind == "agent");
    let subject = match (device, agent) {
        (true, Some(agent)) => format!("this machine and agent {}", agent.name),
        (true, None) => "this machine".to_string(),
        (false, Some(agent)) => format!("agent {}", agent.name),
        (false, None) => "the selected principals".to_string(),
    };
    let action = if has_code {
        "enter the code"
    } else {
        "tap your passkey"
    };
    format!("To pair {}, open this link and {}", subject, action)
}

fn expiry_phrase(expires_in: Option<u64>) -> Option<String> {
    let seconds = expires_in?;
    if seconds < 60 {
        return Some("expires soon".to_string());
    }
    let minutes = seconds.saturating_add(59) / 60;
    Some(format!(
        "expires in about {} {}",
        minutes,
        if minutes == 1 { "minute" } else { "minutes" }
    ))
}

fn emit_waiting(json_output: bool, next: &str) {
    if json_output {
        println!("{}", json!({ "status": "waiting", "next_step": next }));
    } else {
        println!("Waiting for approval in the browser.");
        println!("Next: {}", next);
    }
}

fn emit_done(
    json_output: bool,
    name: &str,
    env_file: &Path,
    skill_paths: &[PathBuf],
    notes: &[String],
    vault_guidance: Option<&(String, String)>,
) {
    let load_env = format!(
        "set -a; . {}; set +a",
        shell_word(&env_file.display().to_string())
    );
    if json_output {
        let paths: Vec<String> = skill_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        let mut messages = notes.to_vec();
        if let Some((message, _)) = vault_guidance {
            messages.push(message.clone());
        }
        if messages.is_empty() {
            messages.push("SafeClaw setup is complete.".to_string());
        }
        let mut object = Map::new();
        object.insert("status".into(), json!("done"));
        object.insert("name".into(), json!(name));
        object.insert("env_file".into(), json!(env_file.display().to_string()));
        object.insert("skill_paths".into(), json!(paths));
        object.insert("message".into(), json!(messages.join(" ")));
        object.insert("load_env".into(), json!(load_env));
        if let Some((_, next_step)) = vault_guidance {
            object.insert("next_step".into(), json!(next_step));
        }
        println!("{}", Value::Object(object));
    } else {
        println!("Agent {} is set up.", name);
        for note in notes {
            println!("{}", note);
        }
        println!("To run sc as {}, load its environment:", name);
        println!("  {}", load_env);
        if let Some((message, next_step)) = vault_guidance {
            println!("{}", message);
            println!("Next: {}", next_step);
        }
    }
}

fn emit_error(json_output: bool, message: &str, fix: &str) {
    if json_output {
        println!(
            "{}",
            json!({ "status": "error", "message": message, "fix": fix })
        );
    } else {
        println!("Setup error: {}", message);
        println!("Fix: {}", fix);
    }
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 0600 {}: {}", path.display(), e))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    let tmp = path.with_extension(format!("env.tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("create {}: {}", tmp.display(), e))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {}", tmp.display(), e))?;
    }
    fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} to {}: {}", tmp.display(), path.display(), e))?;
    Ok(())
}

#[cfg(test)]
mod setup_tests {
    use super::*;

    #[test]
    fn pairing_wording_names_the_step_and_expiry() {
        let device = SetupEntry {
            kind: "device".into(),
            name: "workstation".into(),
        };
        let agent = SetupEntry {
            kind: "agent".into(),
            name: "codex".into(),
        };
        assert_eq!(
            pairing_instruction(std::slice::from_ref(&device), true),
            "To pair this machine, open this link and enter the code"
        );
        assert_eq!(
            pairing_instruction(std::slice::from_ref(&agent), false),
            "To pair agent codex, open this link and tap your passkey"
        );
        assert_eq!(
            pairing_instruction(&[device, agent], true),
            "To pair this machine and agent codex, open this link and enter the code"
        );
        assert_eq!(
            expiry_phrase(Some(601)).as_deref(),
            Some("expires in about 11 minutes")
        );
        assert_eq!(
            expiry_phrase(Some(60)).as_deref(),
            Some("expires in about 1 minute")
        );
        assert_eq!(expiry_phrase(Some(59)).as_deref(), Some("expires soon"));
        assert_eq!(expiry_phrase(None), None);
    }

    #[test]
    fn status_name_mismatch_waits_for_stored_agent() {
        let status = SetupStatus::new(
            "pairing",
            "needs_user",
            42,
            vec![SetupEntry {
                kind: "agent".into(),
                name: "other".into(),
            }],
            Some("dev".into()),
        );
        let (message, fix) = name_mismatch_details("codex", &status).unwrap();
        assert_eq!(message, "Setup for agent 'other' is in progress.");
        assert_eq!(fix, "sc setup --name other --profile dev --wait");
    }

    #[test]
    fn rerun_inherits_stored_profile_only_without_explicit_profile() {
        let context = Context {
            name: "codex".into(),
            profile: None,
            setup_dir: PathBuf::from("/tmp/setup"),
        };
        let status = SetupStatus::new(
            "pairing",
            "needs_user",
            42,
            vec![SetupEntry {
                kind: "agent".into(),
                name: "codex".into(),
            }],
            Some("dev".into()),
        );
        assert_eq!(effective_profile(&context, &status), Some("dev"));

        let explicit = Context {
            name: "codex".into(),
            profile: Some("prod".into()),
            setup_dir: PathBuf::from("/tmp/setup"),
        };
        assert_eq!(effective_profile(&explicit, &status), Some("prod"));
        assert_eq!(
            next_command(&context, effective_profile(&context, &status)),
            "sc setup --name codex --profile dev --wait"
        );
    }

    #[test]
    fn setup_vault_guidance_selects_unlock_step() {
        assert!(setup_vault_guidance(0).is_none());

        let (message, next) = setup_vault_guidance(1).unwrap();
        assert_eq!(message, "The vault is locked.");
        assert_eq!(next, "sc unlock");

        let (message, next) = setup_vault_guidance(2).unwrap();
        assert_eq!(
            message,
            "The vaults are locked. List them with sc vault ls, then run sc unlock --vault <name>."
        );
        assert_eq!(next, "sc vault ls");
    }
}

fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn write_pid_file(path: &Path, pid: u32) -> Result<(), String> {
    fs::write(path, format!("{}\n", pid))
        .map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {}", path.display(), e))?;
    }
    Ok(())
}
