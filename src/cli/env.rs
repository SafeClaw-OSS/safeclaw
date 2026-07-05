//! `safeclaw env` — print shell `export` lines for the DEVICE/human's shell.
//!
//! Output is meant to be evaluated by the user's shell:
//!
//! ```bash
//! eval "$(safeclaw env)"
//! ```
//!
//! `sc env` is the DEVICE/human's tool (AGENT_SURFACE §4/§11) — it emits the
//! routing vars only, NEVER a key:
//!
//! - `SAFECLAW_DAEMON_URL` — the resident daemon's API face
//!   (`http://127.0.0.1:<PROXY_PORT>`), for reference / manual `/health` / `/ca`.
//! - `SAFECLAW_VAULT_ID`   — the active vault; this PINS the shell's vault
//!   (`resolve_active` reads it), the `AWS_PROFILE` analog.
//!
//! The AGENT's config (all four vars INCL its per-agent `SAFECLAW_API_KEY` +
//! `SAFECLAW_PROXY_URL`) comes from its INSTALL PROMPT, not here: agent ≡
//! api-key, account-level, so each agent holds its own key and `sc env` (device
//! scope) must never emit one — that would collapse every agent on the device to
//! one key. See [[project_vault_agent_architecture_2026_06_25]] / AGENT_SURFACE §11.
//!
//! Falls back to printing comments + a clear hint if no config has been
//! written yet — `eval "$(safeclaw env)"` then no-ops safely instead of
//! exporting empty strings.

use crate::cli::active::load as load_config;
use crate::config::PROXY_PORT;

pub fn run() -> Result<(), String> {
    let cfg = load_config()?;
    if cfg.daemon.is_none() {
        println!("# safeclaw: no active config — run `safeclaw vault create` first");
        return Ok(());
    }
    let vault = match cfg.vault {
        Some(v) => v,
        None => {
            println!("# safeclaw: active config has no vault — run `safeclaw vault create` first");
            return Ok(());
        }
    };
    // The API face is the resident local daemon, always loopback:PROXY_PORT.
    let daemon_url = format!("http://127.0.0.1:{}", PROXY_PORT);
    println!("export SAFECLAW_DAEMON_URL={}", shell_quote(&daemon_url));
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
