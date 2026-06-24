//! `safeclaw env` — print shell `export` lines for the active vault.
//!
//! Output is meant to be evaluated by the user's shell:
//!
//! ```bash
//! eval "$(safeclaw env)"
//! ```
//!
//! Two env vars are emitted, matching the deployment-agnostic skill
//! template (see [[architecture-final-2026-05-27]] §"Skill template"):
//!
//! - `SAFECLAW_VAULT_URL` — `${custodian_root}/v/${vid}` from active config
//! - `SAFECLAW_API_KEY`   — pass-through from caller's env (so re-eval
//!                          doesn't clobber a manually-set key)
//!
//! Falls back to printing comments + a clear hint if no config has been
//! written yet — `eval "$(safeclaw env)"` then no-ops safely instead of
//! exporting empty strings.

use crate::cli::active::load as load_config;

pub fn run() -> Result<(), String> {
    let cfg = load_config()?;
    let custodian = match cfg.custodian {
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
    // SaaS: pass through a manually-set $SAFECLAW_API_KEY. Self-hosted
    // localhost: emit the provisioned api-key (~/.safeclaw/api-key) so a
    // locally-launched agent satisfies the daemon's broker gate.
    let api_key = crate::cli::active::resolve_api_key(&custodian);
    println!("export SAFECLAW_API_KEY={}", shell_quote(&api_key));
    Ok(())
}

/// POSIX-safe single-quote escaping. Wraps the value in `'...'` and
/// turns inner `'` into the canonical `'\''` close-escape-reopen
/// sequence. Empty strings stay as `''`.
fn shell_quote(s: &str) -> String {
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
