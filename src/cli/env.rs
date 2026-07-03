//! `safeclaw env` — print shell `export` lines for the active vault.
//!
//! Output is meant to be evaluated by the user's shell:
//!
//! ```bash
//! eval "$(safeclaw env)"
//! ```
//!
//! One env var is emitted — the active vault URL:
//!
//! - `SAFECLAW_VAULT_URL` — `${custodian_root}/v/${vid}` from active config
//!
//! The agent's broker bearer (`SAFECLAW_API_KEY`) is NOT emitted here: agent ≡
//! api-key, account-level, so each agent gets its own key from `sc agent add`
//! (shown once) and the user sets it in that agent's environment. `sc env` only
//! resolves which vault to point at. See
//! [[project_vault_agent_architecture_2026_06_25]].
//!
//! Falls back to printing comments + a clear hint if no config has been
//! written yet — `eval "$(safeclaw env)"` then no-ops safely instead of
//! exporting empty strings.

use crate::cli::active::load as load_config;

pub fn run() -> Result<(), String> {
    let cfg = load_config()?;
    let custodian = match cfg.daemon {
        Some(c) => c,
        None => {
            println!("# safeclaw: no active config — run `safeclaw vault create` first");
            return Ok(());
        }
    };
    let vault = match cfg.vault {
        Some(v) => v,
        None => {
            println!("# safeclaw: active config has no vault — run `safeclaw vault create` first");
            return Ok(());
        }
    };
    let vault_url = format!("{}/v/{}", custodian.trim_end_matches('/'), vault);
    println!("export SAFECLAW_VAULT_URL={}", shell_quote(&vault_url));
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
