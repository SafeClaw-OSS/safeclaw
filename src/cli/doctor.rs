//! `safeclaw doctor` — quick self-check for "is my CLI set up right?"
//!
//! Read-only. Reports on:
//!   - active profile (which custodian + vault)
//!   - custodian reachability (`/health`)
//!   - whether the vault dir exists on the custodian (vault id resolves)
//!   - whether `$SAFECLAW_API_KEY` is set (informational only — local
//!     daemons typically don't need it; SaaS does)
//!
//! Each check prints a single line `[ok|warn|fail] message`. Exits with
//! non-zero status if any line is `fail` — so CI scripts can gate on it.

use std::time::Duration;

use crate::cli::profile::{config_path, resolve_active};
use crate::config::ProfileSelectArgs;

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

pub async fn run(args: ProfileSelectArgs) -> Result<(), String> {
    let mut report = Report::new();

    // Config file
    match config_path() {
        Ok(p) if p.exists() => report.push(Mark::Ok, format!("config: {}", p.display())),
        Ok(p) => report.push(
            Mark::Warn,
            format!("config: {} (missing — run `safeclaw login`)", p.display()),
        ),
        Err(e) => report.push(Mark::Fail, format!("config path: {}", e)),
    }

    // Active config resolution
    let resolved = resolve_active(
        args.custodian.as_deref(),
        args.vault.as_deref(),
    );
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

    // SAFECLAW_API_KEY (informational). Only matters for daemons that
    // sit behind the SaaS auth boundary (typically https + non-localhost
    // host). Local daemons accept any caller — the env var is moot.
    let needs_api_key = match url::Url::parse(&custodian) {
        Ok(u) => {
            u.scheme() == "https"
                && !matches!(u.host_str(), Some("localhost") | Some("127.0.0.1") | Some("[::1]"))
        }
        Err(_) => false,
    };
    match std::env::var("SAFECLAW_API_KEY") {
        Ok(v) if !v.is_empty() => report.push(
            Mark::Ok,
            format!("$SAFECLAW_API_KEY: set ({} chars)", v.len()),
        ),
        _ if needs_api_key => report.push(
            Mark::Warn,
            "$SAFECLAW_API_KEY: unset (SaaS daemons need this — export in your shell)",
        ),
        _ => report.push(
            Mark::Ok,
            "$SAFECLAW_API_KEY: unset (not required for local custodian)",
        ),
    }

    let ok = report.print_and_status();
    if ok {
        Ok(())
    } else {
        Err("one or more checks failed".into())
    }
}
