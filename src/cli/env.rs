//! `safeclaw env` — print shell `export` lines for the DEVICE/human's shell.
//!
//! Output is meant to be evaluated by the user's shell:
//!
//! ```bash
//! eval "$(safeclaw env)"
//! ```
//!
//! `sc env` is the DEVICE/human's tool (CREDENTIAL_BROKER.md §14) — it emits the
//! routing vars only, NEVER a key:
//!
//! - `SAFECLAW_BROKER_URL` — the resident daemon's API face
//!   (`http://127.0.0.1:<PROXY_PORT>`), for reference / manual `/health` / `/ca`.
//! - `SAFECLAW_VAULT_ID`   — the active vault; this PINS the shell's vault
//!   (`resolve_active` reads it), the `AWS_PROFILE` analog.
//!
//! The AGENT's config (these routing vars PLUS its per-agent `SAFECLAW_API_KEY`)
//! is minted whole by `sc agent add`, not here: agent ≡ api-key, account-level,
//! so each agent holds its own key and `sc env` (device scope) must never emit
//! one — that would collapse every agent on the device to one key. `sc run`
//! derives the proxy URL live from the daemon face + that key, so neither tool
//! bakes a `SAFECLAW_PROXY_URL`. See
//! [[project_vault_agent_architecture_2026_06_25]] / CREDENTIAL_BROKER.md §14.
//!
//! Falls back to printing comments + a clear hint if no config has been
//! written yet — `eval "$(safeclaw env)"` then no-ops safely instead of
//! exporting empty strings.

use crate::cli::active::{device_daemon_host, device_default_vault, load as load_config};
use crate::config::PROXY_PORT;

pub fn run() -> Result<(), String> {
    let cfg = load_config()?;
    // Device atoms only — never the process env (`sc env` MINTS the pin; a
    // re-eval that read its own prior output would freeze stale values).
    let Some(vault) = device_default_vault(&cfg) else {
        println!("# safeclaw: no vault on this device — run `sc login` or `sc vault create` first");
        return Ok(());
    };
    let broker_url = format!("{}:{}", device_daemon_host(&cfg), PROXY_PORT);
    println!("export SAFECLAW_BROKER_URL={}", shell_quote(&broker_url));
    println!("export SAFECLAW_VAULT_ID={}", shell_quote(&vault));
    Ok(())
}

/// POSIX-safe single-quote escaping. Wraps the value in `'...'` and
/// turns inner `'` into the canonical `'\''` close-escape-reopen
/// sequence. Empty strings stay as `''`. Single-quoting also makes git's
/// `!sc git-credential` helper marker literal (no history expansion). Shared
/// with `sc run --export-env`.
pub(crate) fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("ab c"), "'ab c'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
