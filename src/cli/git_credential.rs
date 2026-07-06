//! `sc git-credential <op>` — a git credential helper. **git invokes this, not
//! the user.** `sc run` registers it per-process (no gitconfig writes):
//!
//! ```text
//! GIT_CONFIG_COUNT=1
//! GIT_CONFIG_KEY_0=credential.helper
//! GIT_CONFIG_VALUE_0=!sc git-credential
//! ```
//!
//! On `get` it reads git's `host=` line, finds the connection whose anchored
//! hosts contain that host (via the auth-free localhost registry projection),
//! and — when that connection has exactly ONE injectable secret — emits
//! `username=x` + `password=<its phantom>`. The resident proxy substitutes the
//! phantom for the real credential at egress; git never sees it. Anything
//! ambiguous (several matching connections, or a connection with several
//! injectable secrets) or unknown → emits nothing, so git falls through to the
//! next helper. This is a zero-schema PLACEMENT convenience: it reads no vault
//! secret and emits only a phantom.

use std::io::Read;

use crate::cli::active::resolve_active;
use crate::cli::discovery;
use crate::config::GitCredentialArgs;

pub async fn run(args: GitCredentialArgs) -> Result<(), String> {
    // git speaks the credential protocol on stdin as `key=value` lines
    // (protocol=…, host=…, path=…). Only `get` produces output.
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);

    if args.operation != "get" {
        // We persist nothing, so store/erase are no-ops (git falls back).
        return Ok(());
    }
    emit_get(&input).await
}

async fn emit_get(input: &str) -> Result<(), String> {
    // No host to match on → decline silently.
    let Some(raw_host) = field(input, "host") else {
        return Ok(());
    };
    let host = bare_host(&raw_host);

    // Resolve the active vault from config (the human's `sc login` state). Any
    // failure below MUST stay silent: a git credential helper that errors would
    // break the git command, and declining just lets git try the next helper.
    let Ok((daemon, vault)) = resolve_active(None) else {
        return Ok(());
    };
    let Ok(conns) = discovery::connections(&daemon, &vault).await else {
        return Ok(());
    };

    // Connections whose anchored hosts contain the asked host (exact FQDN).
    let matches: Vec<&discovery::ConnRow> = conns
        .iter()
        .filter(|c| c.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
        .collect();
    // Exactly one connection, with exactly one injectable secret → emit it.
    if matches.len() != 1 {
        return Ok(());
    }
    let conn = matches[0];
    if conn.phantoms.len() != 1 {
        return Ok(());
    }
    let phantom = &conn.phantoms[0];

    // git credential reply. The username is a placeholder (the phantom carries
    // the real credential); it must be non-empty for git to use the password.
    print!("username=x\npassword={}\n", phantom);
    Ok(())
}

/// The value of a `key=value` line on git's stdin, trimmed and non-empty.
fn field(input: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    input
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Drop a trailing `:<port>` from an authority, leaving the host
/// (`example.com:8443` → `example.com`). Leaves IPv6 / hostless forms untouched.
fn bare_host(authority: &str) -> &str {
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_reads_host() {
        assert_eq!(
            field("protocol=https\nhost=github.com\n", "host").as_deref(),
            Some("github.com")
        );
        assert_eq!(field("protocol=https\n", "host"), None);
    }

    #[test]
    fn bare_host_strips_port() {
        assert_eq!(bare_host("github.com:8443"), "github.com");
        assert_eq!(bare_host("github.com"), "github.com");
    }
}
