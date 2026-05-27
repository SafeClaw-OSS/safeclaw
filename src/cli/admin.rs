//! `safeclaw admin ...` — operator-only daemon ops.
//!
//! Each subcommand requires `$SAFECLAW_ADMIN_KEY` to be set on the CLI
//! side AND match the daemon's `SAFECLAW_ADMIN_KEY` env. In SaaS
//! deployments only the SafeClaw team holds this key; OSS users
//! self-running the daemon are their own operator.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::profile::resolve_active;
use crate::config::{AdminAuditLsArgs, AdminAuditSubcommand, AdminSubcommand};

pub async fn run(sub: AdminSubcommand) -> Result<(), String> {
    match sub {
        AdminSubcommand::Audit(a) => match a.sub {
            AdminAuditSubcommand::Ls(args) => audit_ls(args).await,
        },
    }
}

fn admin_key() -> Result<String, String> {
    std::env::var("SAFECLAW_ADMIN_KEY").map_err(|_| {
        "this command requires $SAFECLAW_ADMIN_KEY (must match the daemon's \
         SAFECLAW_ADMIN_KEY env). Self-host: set it; SaaS: not exposed."
            .to_string()
    })
}

#[derive(Debug, Deserialize)]
struct ApprovalsBody {
    entries: Vec<ApprovalRow>,
}

#[derive(Debug, Deserialize)]
struct ApprovalRow {
    #[serde(default)]
    op_id: String,
    #[serde(default)]
    act_type: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    created_at: Option<String>,
}

async fn audit_ls(args: AdminAuditLsArgs) -> Result<(), String> {
    let key = admin_key()?;
    let (custodian, vault) = resolve_active(args.custodian.as_deref(), args.vault.as_deref())?;
    let limit = args.limit.min(200);
    let url = format!(
        "{}/v/{}/approvals?limit={}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault),
        limit,
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .header("X-Admin-Key", &key)
        .send()
        .await
        .map_err(|e| format!("reach custodian: {}", e))?;
    let status = resp.status();
    if status.as_u16() == 403 {
        return Err("custodian returned 403 — admin key mismatch or admin endpoints disabled".into());
    }
    if !status.is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            status,
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: ApprovalsBody = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    if body.entries.is_empty() {
        println!("(no audit rows for vault {})", vault);
        return Ok(());
    }
    println!(
        "  {:<24}  {:<14}  {:<10}  {}",
        "WHEN", "ACT", "STATUS", "TARGET / OP"
    );
    for row in &body.entries {
        let when = row.created_at.as_deref().unwrap_or("?");
        let act = if row.act_type.is_empty() { "?" } else { &row.act_type };
        let stat = if row.status.is_empty() { "?" } else { &row.status };
        let tgt = row.target.as_deref().unwrap_or(&row.op_id);
        println!("  {:<24}  {:<14}  {:<10}  {}", when, act, stat, tgt);
    }
    Ok(())
}

