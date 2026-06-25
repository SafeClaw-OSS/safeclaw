//! Daemon read-only diagnostics: `sc pubkey` (HPKE outer-envelope key) and
//! `sc menu` (public service catalog). Daemon lifecycle (up / down / restart /
//! logs / serve) lives in `service` + `up`; vault/daemon status in `status`.

use crate::cli::active::resolve_active;
use crate::config::CommonArgs;

pub async fn pubkey(args: CommonArgs) -> Result<(), String> {
    fetch_print(args, "/pubkey").await
}

pub async fn menu(args: CommonArgs) -> Result<(), String> {
    fetch_print(args, "/menu").await
}

async fn fetch_print(_args: CommonArgs, path: &str) -> Result<(), String> {
    let daemon = resolve_daemon_url()?;
    let url = format!("{}{}", daemon.trim_end_matches('/'), path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach daemon: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
    Ok(())
}

/// The daemon URL — `$SAFECLAW_VAULT_URL` / active config, else localhost.
fn resolve_daemon_url() -> Result<String, String> {
    if let Ok((c, _)) = resolve_active(None) {
        return Ok(c);
    }
    Ok("http://localhost:23294".to_string())
}
