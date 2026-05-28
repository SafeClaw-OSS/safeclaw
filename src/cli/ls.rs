//! `safeclaw ls` — list secret names known to the active vault.
//!
//! Hits the custodian's `GET /v/{vid}/keys-known` (cache-driven; no passkey
//! ceremony). Vault must be Unlocked — the custodian returns 409 otherwise,
//! which we map to a "run `safeclaw unlock` first" hint.
//!
//! Output is one row per key with its source tag. Same key surfacing from
//! multiple sources prints multiple rows; whichever source wins resolution
//! is decided at /use time per the per-vault `store_order`, not here.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::resolve_active;
use crate::config::CommonArgs;

#[derive(Debug, Deserialize)]
struct KeysKnown {
    native_keys: Vec<String>,
    #[serde(default)]
    stores: Vec<StoreKeys>,
    #[serde(default)]
    store_errors: Vec<StoreError>,
}

#[derive(Debug, Deserialize)]
struct StoreKeys {
    id: String,
    kind: String,
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StoreError {
    store_id: String,
    error: String,
}

pub async fn run(args: CommonArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(
        args.custodian.as_deref(),
        args.vault.as_deref(),
    )?;

    let url = format!(
        "{}/v/{}/keys-known",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault)
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach custodian at {}: {}", custodian, e))?;

    if resp.status().as_u16() == 409 {
        return Err("vault locked — run `safeclaw unlock` first".into());
    }
    if !resp.status().is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: KeysKnown = resp.json().await.map_err(|e| format!("parse: {}", e))?;

    let mut rows: Vec<(String, String)> = Vec::new();
    for k in &body.native_keys {
        rows.push((k.clone(), "native".into()));
    }
    for s in &body.stores {
        for k in &s.keys {
            rows.push((k.clone(), format!("{} ({})", s.id, s.kind)));
        }
    }

    if rows.is_empty() {
        println!("(no keys — vault is empty or no external stores connected)");
    } else {
        let name_w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0).max(8);
        for (k, src) in &rows {
            println!("  {:<width$}  {}", k, src, width = name_w);
        }
    }

    for e in &body.store_errors {
        eprintln!("note: store {} list failed — {}", e.store_id, e.error);
    }

    Ok(())
}
