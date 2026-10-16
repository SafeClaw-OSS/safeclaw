//! Agent-driven, non-interactive setup state machine.

use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::cli::human_action::{self, SetupStatus};
use crate::config::{LoginArgs, SetupArgs, SetupPhase};

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

        let cfg = crate::cli::active::load().unwrap_or_default();
        if !device_paired(&cfg) {
            match spawn_and_report(&context, SetupPhase::Device, json_output).await? {
                Progress::Continue => continue,
                Progress::Emitted => return Ok(()),
            }
        }

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

        let identity_path = match crate::identity_file::agent_identity_path(&context.name) {
            Ok(path) => path,
            Err(e) => {
                emit_error(json_output, &e, &base_command(&context));
                return Err(1);
            }
        };
        if !identity_path.is_file() {
            match spawn_and_report(&context, SetupPhase::Agent, json_output).await? {
                Progress::Continue => continue,
                Progress::Emitted => return Ok(()),
            }
        }

        let cfg = crate::cli::active::load().unwrap_or_default();
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

        let mut messages = Vec::new();
        if skill.modified {
            messages.push("The existing SafeClaw skill was modified, so it was left unchanged.".to_string());
        }
        messages.extend(skill.notes.clone());

        if messages.is_empty() {
            messages.push("SafeClaw setup is complete.".to_string());
        }
        let vault_guidance = setup_vault_guidance(crate::cli::active::known_vaults().len());
        let done_message = vault_guidance
            .as_ref()
            .map(|(message, _)| message.clone())
            .unwrap_or_else(|| messages.join(" "));
        emit_done(
            json_output,
            &context.name,
            &env_path,
            &skill.paths,
            &done_message,
            vault_guidance.as_ref().map(|(_, next)| next.as_str()),
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
                    format!("Ask the user to run: sc login --profile {}", selected),
                    1,
                ));
            }
        }
        if crate::sync::device_key().is_none() {
            let fix = match profile.as_deref() {
                Some(profile) => format!("Ask the user to run: sc login --profile {}", profile),
                None => "Ask the user to run: sc login".to_string(),
            };
            return Err((
                "This machine has pairing configuration but its device credential is missing."
                    .to_string(),
                fix,
                1,
            ));
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

async fn status_now(
    context: &Context,
    pid: u32,
    json_output: bool,
) -> Result<Progress, i32> {
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
            emit_waiting(json_output, &next_command(context, context.profile.as_deref()));
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
            emit_waiting(json_output, &next_command(context, context.profile.as_deref()));
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
            "another setup background process is starting; re-run the same setup command".to_string()
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
    let starting = SetupStatus::new(
        phase_text,
        "starting",
        pid,
        name.clone(),
        args.profile.clone(),
    );
    if human_action::write(&status_path, &starting).is_err() {
        return Err(1);
    }

    let result = match phase {
        SetupPhase::Device => {
            let paired = crate::cli::login::pair_and_persist(
                LoginArgs {
                    device_name: None,
                    profile: args.profile.clone(),
                    insecure: false,
                },
                false,
            )
            .await;
            match paired {
                Ok(()) => crate::cli::login::bring_up(false).await,
                Err(e) => Err(e),
            }
        }
        SetupPhase::Agent => crate::cli::agent::add_and_persist(&name).await.map(|_| ()),
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
    let mut final_status = human_action::read(&status_path)
        .unwrap_or_else(|_| SetupStatus::new(phase_text, state, pid, name.clone(), args.profile.clone()));
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
        SetupPhase::Device => "device",
        SetupPhase::Agent => "agent",
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
    if !status.name.is_empty() && status.name != current_name {
        Some((
            format!("Setup for agent '{}' is in progress.", status.name),
            setup_wait_command(&status.name, status.profile.as_deref()),
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
    let mut command = format!(
        "{} setup --name {}",
        shell_word(&running_binary()),
        shell_word(name)
    );
    if let Some(profile) = profile {
        command.push_str(&format!(" --profile {}", shell_word(profile)));
    }
    command
}

fn running_binary() -> String {
    let current = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return "sc".to_string(),
    };
    let current = fs::canonicalize(&current).unwrap_or(current);
    let resolved = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join("sc"))
        .filter(|path| executable_on_path(path))
        .filter_map(|path| fs::canonicalize(path).ok())
        .next();
    if resolved.as_ref() == Some(&current) {
        "sc".to_string()
    } else {
        current.display().to_string()
    }
}

fn setup_vault_guidance(known_vault_count: usize) -> Option<(String, String)> {
    let binary = shell_word(&running_binary());
    match known_vault_count {
        0 => None,
        1 => Some((
            "The vault is locked.".to_string(),
            format!("{} unlock", binary),
        )),
        _ => Some((
            "The vault is locked. Pick the vault to use: sc vault ls, then sc unlock --vault <name>."
                .to_string(),
            format!("{} vault ls", binary),
        )),
    }
}

fn executable_on_path(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
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
    let expires_in = status.expires_in;
    let say = {
        let code = status.code.as_deref().unwrap_or("");
        let subject = if status.phase == "device" {
            format!("this machine ({})", crate::cli::login::device_name(None))
        } else {
            format!("this agent ({})", status.name)
        };
        pairing_say(&subject, url, code, expires_in)
    };
    let next = if status.name.is_empty() {
        next_command(context, effective_profile(context, status))
    } else {
        setup_wait_command(&status.name, effective_profile(context, status))
    };
    if json_output {
        let mut object = Map::new();
        object.insert("status".into(), json!("action_required"));
        object.insert("say".into(), json!(say));
        object.insert("url".into(), json!(url));
        if let Some(code) = status.code.as_deref() {
            object.insert("code".into(), json!(code));
        }
        if let Some(seconds) = expires_in {
            object.insert("expires_in".into(), json!(seconds));
        }
        object.insert("next_step".into(), json!(next));
        println!("{}", Value::Object(object));
    } else {
        println!("Action required: {}", say);
        println!("URL: {}", url);
        if let Some(code) = status.code.as_deref() {
            println!("Code: {}", code);
        }
        println!("Next: {}", next);
    }
}

fn pairing_say(subject: &str, url: &str, code: &str, expires_in: Option<u64>) -> String {
    let expiry = match expires_in {
        Some(seconds) if seconds < 60 => "The code expires soon.".to_string(),
        Some(seconds) => {
            let minutes = (seconds.saturating_add(59)) / 60;
            format!(
                "The code expires in about {} {}.",
                minutes,
                if minutes == 1 { "minute" } else { "minutes" }
            )
        }
        None => "The code expires soon.".to_string(),
    };
    format!(
        "Ask the user to open {} and enter the code {} to pair {}. {}",
        url, code, subject, expiry
    )
}

fn emit_waiting(json_output: bool, next: &str) {
    if json_output {
        println!("{}", json!({ "status": "waiting", "next_step": next }));
    } else {
        println!("The user has not finished the browser approval yet.");
        println!("Next: {}", next);
    }
}

fn emit_done(
    json_output: bool,
    name: &str,
    env_file: &Path,
    skill_paths: &[PathBuf],
    message: &str,
    next_step: Option<&str>,
) {
    let paths: Vec<String> = skill_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    if json_output {
        let mut object = Map::new();
        object.insert("status".into(), json!("done"));
        object.insert("name".into(), json!(name));
        object.insert("env_file".into(), json!(env_file.display().to_string()));
        object.insert("skill_paths".into(), json!(paths));
        object.insert("message".into(), json!(message));
        object.insert(
            "load_env".into(),
            json!(format!("set -a; . {}; set +a", shell_word(&env_file.display().to_string()))),
        );
        if let Some(next_step) = next_step {
            object.insert("next_step".into(), json!(next_step));
        }
        println!("{}", Value::Object(object));
    } else {
        println!("SafeClaw setup is done for agent '{}'.", name);
        println!("Environment file: {}", env_file.display());
        for path in skill_paths {
            println!("Skill path: {}", path.display());
        }
        println!("Done: {}", message);
        if let Some(next_step) = next_step {
            println!("Next: {}", next_step);
        }
        println!(
            "Before using sc run in a new session, load this agent's environment: set -a; . {}; set +a",
            shell_word(&env_file.display().to_string())
        );
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
    fn pairing_wording_uses_soon_and_singular_minute() {
        let soon = pairing_say("this agent (codex)", "https://example.test", "1234", Some(59));
        assert!(soon.ends_with("The code expires soon."));
        let singular = pairing_say("this agent (codex)", "https://example.test", "1234", Some(60));
        assert!(singular.ends_with("The code expires in about 1 minute."));
        assert!(!singular.contains("1 minutes"));
    }

    #[test]
    fn status_name_mismatch_waits_for_stored_agent() {
        let status = SetupStatus::new("agent", "needs_user", 42, "other", Some("dev".into()));
        let (message, fix) = name_mismatch_details("codex", &status).unwrap();
        assert_eq!(message, "Setup for agent 'other' is in progress.");
        assert!(fix.ends_with(" setup --name other --profile dev --wait"));
    }

    #[test]
    fn rerun_inherits_stored_profile_only_without_explicit_profile() {
        let context = Context {
            name: "codex".into(),
            profile: None,
            setup_dir: PathBuf::from("/tmp/setup"),
        };
        let status = SetupStatus::new("agent", "needs_user", 42, "codex", Some("dev".into()));
        assert_eq!(effective_profile(&context, &status), Some("dev"));

        let explicit = Context {
            name: "codex".into(),
            profile: Some("prod".into()),
            setup_dir: PathBuf::from("/tmp/setup"),
        };
        assert_eq!(effective_profile(&explicit, &status), Some("prod"));
        assert!(next_command(&context, effective_profile(&context, &status))
            .ends_with(" setup --name codex --profile dev --wait"));
    }

    #[test]
    fn setup_vault_guidance_selects_unlock_step() {
        assert!(setup_vault_guidance(0).is_none());

        let (message, next) = setup_vault_guidance(1).unwrap();
        assert_eq!(message, "The vault is locked.");
        assert!(next.ends_with(" unlock"));

        let (message, next) = setup_vault_guidance(2).unwrap();
        assert_eq!(
            message,
            "The vault is locked. Pick the vault to use: sc vault ls, then sc unlock --vault <name>."
        );
        assert!(next.ends_with(" vault ls"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn say_sentence_uses_known_and_unknown_expiry() {
        assert_eq!(
            pairing_say(
                "this machine (box)",
                "https://safeclaw.pro/pair",
                "1234-5678-9012",
                Some(601),
            ),
            "Ask the user to open https://safeclaw.pro/pair and enter the code 1234-5678-9012 to pair this machine (box). The code expires in about 11 minutes."
        );
        assert_eq!(
            pairing_say(
                "this agent (claude-code)",
                "https://safeclaw.pro/pair",
                "1234-5678-9012",
                None,
            ),
            "Ask the user to open https://safeclaw.pro/pair and enter the code 1234-5678-9012 to pair this agent (claude-code). The code expires soon."
        );
    }
}
