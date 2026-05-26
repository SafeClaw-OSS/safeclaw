//! `safeclaw status` — daemon reachability + version probe.
//!
//! Read-only, no passkey ceremony, no vault context. Hits the daemon's
//! `GET /c/health` and pretty-prints the result. Exit code is non-zero
//! on transport / parse failure so shell scripts can gate on it.

use crate::config::StatusArgs;

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let url = format!("{}/c/health", args.daemon.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach daemon at {}: {}", args.daemon, e))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse response: {}", e))?;

    // Expected shape: {"ok": true, "name": "safeclaw", "version": "...", "tenant_count": N}
    if !status.is_success() {
        return Err(format!(
            "daemon returned HTTP {}: {}",
            status,
            body
        ));
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    let tenants = body.get("tenant_count").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("safeclaw — daemon ok");
    println!("  url:     {}", args.daemon);
    println!("  name:    {}", name);
    println!("  version: {}", version);
    println!("  tenants: {}", tenants);
    Ok(())
}
