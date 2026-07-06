//! `safeclaw doctor` — quick self-check for "is my CLI set up right?"
//!
//! Read-only. Reports on:
//!   - active profile (which custodian + vault)
//!   - custodian reachability (`/health`)
//!   - whether the vault dir exists on the custodian (vault id resolves)
//!   - whether `$SAFECLAW_API_KEY` is set (informational — the agent's
//!     identity; required for credential substitution, §8)
//!
//! Each check prints a single line `[ok|warn|fail] message`. Exits with
//! non-zero status if any line is `fail` — so CI scripts can gate on it.

use std::time::Duration;

use crate::cli::active::{config_path, resolve_active};
use crate::config::CommonArgs;

#[derive(Debug, Clone, Copy)]
enum Mark {
    Ok,
    Warn,
    Fail,
}

impl Mark {
    fn label(self) -> &'static str {
        match self {
            Mark::Ok => "ok  ",
            Mark::Warn => "warn",
            Mark::Fail => "fail",
        }
    }
}

struct Report {
    rows: Vec<(Mark, String)>,
}

impl Report {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn push(&mut self, mark: Mark, msg: impl Into<String>) {
        self.rows.push((mark, msg.into()));
    }
    fn print_and_status(&self) -> bool {
        for (m, msg) in &self.rows {
            println!("  [{}] {}", m.label(), msg);
        }
        !self.rows.iter().any(|(m, _)| matches!(m, Mark::Fail))
    }
}

pub async fn run(args: CommonArgs) -> Result<(), String> {
    let mut report = Report::new();

    // Config file
    match config_path() {
        Ok(p) if p.exists() => report.push(Mark::Ok, format!("config: {}", p.display())),
        Ok(p) => report.push(
            Mark::Warn,
            format!("config: {} (missing — run `safeclaw vault create`)", p.display()),
        ),
        Err(e) => report.push(Mark::Fail, format!("config path: {}", e)),
    }

    // Active config resolution
    let resolved = resolve_active(args.vault.as_deref());
    let (custodian, vault) = match resolved {
        Ok(pair) => {
            report.push(
                Mark::Ok,
                format!("active: custodian={} vault={}", pair.0, pair.1),
            );
            pair
        }
        Err(e) => {
            report.push(Mark::Fail, format!("active config: {}", e));
            let _ = report.print_and_status();
            return Err("active-config resolution failed".into());
        }
    };

    // Custodian health
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let health_url = format!("{}/health", custodian.trim_end_matches('/'));
    match client.get(&health_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let version = body
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let count = body.get("vault_count").and_then(|v| v.as_u64()).unwrap_or(0);
                report.push(
                    Mark::Ok,
                    format!(
                        "custodian: reachable (version {}, {} vault(s))",
                        version, count
                    ),
                );
            } else {
                report.push(
                    Mark::Fail,
                    format!("custodian: {} returned HTTP {}", custodian, status),
                );
            }
        }
        Err(e) => report.push(Mark::Fail, format!("custodian: unreachable — {}", e)),
    }

    // Vault dir exists?
    let passkeys_url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault)
    );
    match client.get(&passkeys_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let exists = body
                .get("vault_exists")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let n = body
                .get("passkeys")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if exists {
                report.push(
                    Mark::Ok,
                    format!("vault: enrolled ({} passkey(s))", n),
                );
            } else {
                report.push(
                    Mark::Warn,
                    "vault: not yet enrolled (use the console /try or /vault to set one up)",
                );
            }
        }
        Ok(resp) => report.push(
            Mark::Warn,
            format!("vault probe: HTTP {}", resp.status()),
        ),
        Err(e) => report.push(Mark::Warn, format!("vault probe: {}", e)),
    }

    // SAFECLAW_API_KEY (informational): the AGENT's identity. The proxy
    // verifies it before any phantom substitution (§8) — localhost included —
    // so an agent's env must carry one (minted by `sc agent add`); a human
    // shell without it just can't broker credentials, everything else works.
    match std::env::var("SAFECLAW_API_KEY") {
        Ok(v) if !v.is_empty() => report.push(
            Mark::Ok,
            format!("$SAFECLAW_API_KEY: set ({} chars)", v.len()),
        ),
        _ => report.push(
            Mark::Ok,
            "$SAFECLAW_API_KEY: unset (fine for a human shell — credential \
             substitution needs an agent env, minted by `sc agent add`)",
        ),
    }

    let ok = report.print_and_status();
    if ok {
        Ok(())
    } else {
        Err("one or more checks failed".into())
    }
}
