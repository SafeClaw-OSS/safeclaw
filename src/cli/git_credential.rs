//! `sc git-credential <op>` — a git credential helper. **git invokes this, not
//! the user.** It is registered with:
//!
//! ```text
//! git config --global credential."http://localhost:23295".helper "!sc git-credential"
//! ```
//!
//! When git needs to authenticate to the SafeClaw broker (for the streaming
//! smart-HTTP git route), it runs `sc git-credential get` and reads back the
//! agent's broker key as the Basic password. The key is read from the
//! environment (`$SAFECLAW_API_KEY`) **at call time** and never written to disk
//! — so it lives exactly where it already does (the agent's env), and a key
//! rotation is picked up on the next git command with no reconfiguration.
//!
//! The broker then validates the key, scrubs it, and injects the real upstream
//! credential (the GitHub/GitLab PAT) at egress — so git never sees the PAT, and
//! the broker never forwards the agent key upstream.
//!
//! **Defense in depth:** the key is emitted ONLY when git's request host matches
//! the SafeClaw broker host (from `$SAFECLAW_VAULT_URL`). If the helper is ever
//! misconfigured to fire for another host (e.g. github.com directly), it stays
//! silent — the agent key can never leak to a non-broker host.

use std::io::Read;

use crate::config::GitCredentialArgs;

pub fn run(args: GitCredentialArgs) -> Result<(), String> {
    // git speaks the credential protocol on stdin as `key=value` lines
    // (protocol=…, host=…, path=…). Read it; we use `host=` for the safety check.
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);

    match args.operation.as_str() {
        "get" => emit_get(&input),
        // We persist nothing, so storing/erasing is a no-op (git will fall back
        // to any other configured helper for those).
        _ => Ok(()),
    }
}

fn emit_get(input: &str) -> Result<(), String> {
    // The agent key lives in the environment — same place every other SafeClaw
    // call reads it. Absent ⇒ emit nothing; git fails fast (with
    // GIT_TERMINAL_PROMPT=0) instead of prompting.
    let key = match std::env::var("SAFECLAW_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => return Ok(()),
    };

    // Fail closed: only answer for the SafeClaw broker host.
    if !host_is_broker(input) {
        return Ok(());
    }

    // git credential reply. The broker ignores the username (it validates the
    // password against the agent-key hash-set), but it must be non-empty.
    print!("username=safeclaw\npassword={}\n", key);
    Ok(())
}

/// True iff git's request host (the `host=` line on stdin) is the SafeClaw
/// daemon's host, taken from `$SAFECLAW_VAULT_URL`. Compared **host-only** (the
/// port is stripped): the daemon's admin port (`SAFECLAW_VAULT_URL`) and its
/// broker/`/stream/` port differ, but share the same host — and matching the
/// host alone still blocks a *different* host (e.g. github.com) from ever
/// receiving the key. Fail closed: a missing host on either side returns false.
fn host_is_broker(input: &str) -> bool {
    let req_host = match input
        .lines()
        .find_map(|l| l.strip_prefix("host="))
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        Some(h) => h,
        None => return false,
    };
    match std::env::var("SAFECLAW_VAULT_URL")
        .ok()
        .as_deref()
        .and_then(url_host)
    {
        Some(broker) => bare_host(&broker) == bare_host(req_host),
        None => false,
    }
}

/// The `host[:port]` authority of a URL (`http://localhost:23295/v/x` →
/// `localhost:23295`).
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    Some(after_scheme.split('/').next().unwrap_or(after_scheme).to_string())
}

/// Drop a trailing `:<port>` from an authority, leaving the host
/// (`127.0.0.1:23295` → `127.0.0.1`). Leaves IPv6/hostless forms untouched.
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
    fn url_host_extracts_authority() {
        assert_eq!(url_host("http://localhost:23295/v/abc").as_deref(), Some("localhost:23295"));
        assert_eq!(url_host("https://api.github.com").as_deref(), Some("api.github.com"));
        assert_eq!(url_host("not a url"), None);
    }

    #[test]
    fn bare_host_strips_port() {
        assert_eq!(bare_host("127.0.0.1:23295"), "127.0.0.1");
        assert_eq!(bare_host("localhost"), "localhost");
        assert_eq!(bare_host("api.safeclaw.pro"), "api.safeclaw.pro");
    }

    #[test]
    fn host_is_broker_matches_only_the_broker() {
        // SAFECLAW_VAULT_URL is process-global; guard the test behind it being set
        // to the value we expect (other tests don't touch it).
        // NB: it points at the ADMIN port (23294); git talks to the BROKER port
        // (23295). Same host, different port → must still match (host-only).
        std::env::set_var("SAFECLAW_VAULT_URL", "http://127.0.0.1:23294/v/abc");
        assert!(host_is_broker("protocol=http\nhost=127.0.0.1:23295\n"));
        // Same host, no port given → still matches.
        assert!(host_is_broker("protocol=http\nhost=127.0.0.1\n"));
        // A different host (e.g. github.com directly) is refused — no key leak.
        assert!(!host_is_broker("protocol=https\nhost=github.com\n"));
        // No host line → fail closed.
        assert!(!host_is_broker("protocol=http\n"));
        std::env::remove_var("SAFECLAW_VAULT_URL");
        // No broker URL → fail closed.
        assert!(!host_is_broker("host=127.0.0.1:23295\n"));
    }
}
