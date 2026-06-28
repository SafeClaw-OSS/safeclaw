//! `safeclaw sync` — force an on-demand cloud pull + complete any pending OAuth
//! connect, without waiting for the background watcher. Handy right after a web
//! "Connect" if the console is still showing "Connecting…": it pulls the latest
//! sealed blob and runs the `<conn>_oauth_pending` → exchange → refresh_token
//! step now. No passkey — it only advances already-sealed state.

use crate::cli::active::resolve_active;
use crate::config::SyncArgs;

pub async fn run(args: SyncArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    let url = format!(
        "{}/v/{}/sync",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault),
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client
        .post(&url)
        .send()
        .await
        .map_err(|e| format!("reach daemon at {}: {}", custodian, e))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse daemon response: {}", e))?;
    if body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let pulled = body.get("pulled").and_then(|v| v.as_bool()).unwrap_or(false);
        eprintln!(
            "safeclaw sync — ok ({})",
            if pulled {
                "pulled new state from cloud"
            } else {
                "already current; completed any pending connect"
            }
        );
        Ok(())
    } else {
        Err(body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("sync failed")
            .to_string())
    }
}
