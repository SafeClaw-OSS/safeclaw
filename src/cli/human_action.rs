//! Status hand-off between a detached `sc setup` worker and its parent.
//!
//! Ordinary `sc login`, `sc agent add`, and approval commands do not set
//! `SAFECLAW_SETUP_STATUS`, so the hooks in their existing ceremony paths are
//! no-ops and keep their terminal behavior unchanged.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const STATUS_ENV: &str = "SAFECLAW_SETUP_STATUS";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupStatus {
    pub phase: String,
    pub state: String,
    pub url: Option<String>,
    pub code: Option<String>,
    pub expires_at: Option<u64>,
    pub message: Option<String>,
    pub pid: u32,
    pub updated_at: u64,
}

impl SetupStatus {
    pub fn new(phase: &str, state: &str, pid: u32) -> Self {
        Self {
            phase: phase.to_string(),
            state: state.to_string(),
            url: None,
            code: None,
            expires_at: None,
            message: None,
            pid,
            updated_at: crate::util::now_unix(),
        }
    }
}

pub fn read(path: &Path) -> Result<SetupStatus, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))
}

/// Atomic, mode-0600 status write. The temporary file lives beside the target,
/// so rename never crosses a filesystem boundary.
pub fn write(path: &Path, status: &SetupStatus) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let body = serde_json::to_vec(status).map_err(|e| format!("serialize setup status: {}", e))?;
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|e| format!("create {}: {}", tmp.display(), e))?;
    file.write_all(&body)
        .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {}", tmp.display(), e))?;
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

fn configured_path() -> Option<PathBuf> {
    std::env::var_os(STATUS_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Ceremony hook used when a browser action becomes available. It deliberately
/// ignores status-write failures: the ceremony itself must retain its original
/// behavior, and the setup worker will report a phase failure if it exits.
pub fn report(url: &str, code: Option<&str>, expires_at: Option<u64>) {
    let Some(path) = configured_path() else {
        return;
    };
    let Ok(mut status) = read(&path) else {
        return;
    };
    status.state = "needs_user".to_string();
    status.url = Some(url.to_string());
    status.code = code.map(str::to_string);
    status.expires_at = expires_at;
    status.message = None;
    status.updated_at = crate::util::now_unix();
    let _ = write(&path, &status);
}

/// Once the browser's PAKE message has been accepted, the short code is spent.
/// Keep the approval URL visible but remove the code so setup never asks the
/// user to enter it a second time.
pub fn code_consumed() {
    let Some(path) = configured_path() else {
        return;
    };
    let Ok(mut status) = read(&path) else {
        return;
    };
    status.code = None;
    status.updated_at = crate::util::now_unix();
    let _ = write(&path, &status);
}

/// True while `pid` names a live process. Linux gets a syscall-free `/proc`
/// check; other Unix targets use the standard `kill -0` probe.
pub fn pid_is_live(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let stat = Path::new("/proc").join(pid.to_string()).join("stat");
        let Ok(stat) = fs::read_to_string(stat) else {
            return false;
        };
        // `/proc/<pid>/stat`: the state byte follows the final ')' of comm.
        // A killed, unreaped worker is a zombie and must count as dead.
        return stat
            .rsplit_once(')')
            .and_then(|(_, tail)| tail.split_whitespace().next())
            != Some("Z");
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        return std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Put a child in a new session before exec so it survives the invoking
/// agent's process group ending. This is the one permitted unsafe boundary.
#[cfg(unix)]
pub fn detach_session(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    extern "C" {
        fn setsid() -> i32;
    }
    unsafe {
        cmd.pre_exec(|| {
            if setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(not(unix))]
pub fn detach_session(_cmd: &mut std::process::Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let mut want = SetupStatus::new("agent", "needs_user", 42);
        want.url = Some("https://safeclaw.pro/pair".into());
        want.code = Some("1234-5678-9012".into());
        want.expires_at = Some(1_900_000_000);
        want.message = Some("waiting".into());
        write(&path, &want).unwrap();
        assert_eq!(read(&path).unwrap(), want);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
