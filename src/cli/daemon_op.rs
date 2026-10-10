//! The CLI side of the daemon's op endpoints: create an op on the local
//! daemon (`POST /v/{vid}/op`) and the small HTTP helpers the approval driver
//! shares. The passkey gesture itself happens in the console, never here.

use std::time::Duration;

use serde_json::Value;

pub async fn create_op(
    custodian: &str,
    vault: &str,
    op: &Value,
) -> Result<(String, String), String> {
    let c = create_op_full(custodian, vault, op).await?;
    Ok((c.op_id, c.r))
}

/// A created op as the daemon returned it. `waiter_secret` is present for an
/// Export only (E1): the one credential that releases its value and lets this
/// process withdraw it. Never printed or logged.
pub struct CreatedOp {
    pub op_id: String,
    pub r: String,
    pub waiter_secret: Option<String>,
}

/// [`create_op`] keeping the Export `waiter_secret`.
pub async fn create_op_full(custodian: &str, vault: &str, op: &Value) -> Result<CreatedOp, String> {
    let client = http_client()?;
    let url = format!(
        "{}/v/{}/op",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .post(&url)
        .json(op)
        .send()
        .await
        .map_err(|e| format!("create op: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        // Surface the daemon's human message (e.g. the 423 "vault locked. Run
        // `sc unlock`" hint) instead of a raw JSON error envelope.
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or(body);
        return Err(format!("create op HTTP {}: {}", status, msg));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let op_id = body["op_id"].as_str().ok_or("no op_id")?.to_string();
    let r = body["r"].as_str().ok_or("no r")?.to_string();
    let waiter_secret = body["waiter_secret"].as_str().map(str::to_string);
    Ok(CreatedOp {
        op_id,
        r,
        waiter_secret,
    })
}

pub fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
