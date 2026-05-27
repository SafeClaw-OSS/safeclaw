//! `safeclaw unlock` / `safeclaw lock` — CLI creates the op, browser does
//! passkey gesture only, CLI builds grant + submits.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::json;

use crate::cli::gesture::*;
use crate::cli::profile::resolve_active;
use crate::config::UnlockArgs;

pub async fn run_unlock(args: UnlockArgs) -> Result<(), String> {
    drive("vault-unlock", "Unlock vault", args).await
}
pub async fn run_lock(args: UnlockArgs) -> Result<(), String> {
    drive("vault-lock", "Lock vault", args).await
}

async fn drive(custom_op: &str, label: &str, args: UnlockArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.custodian.as_deref(), args.vault.as_deref())?;
    let meta = fetch_passkey_meta(&custodian, &vault).await?;

    let op = json!({
        "act": { "type": { "custom": custom_op }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(&custodian, &vault, &op).await?;
    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &op)?;

    let prf_salt_bytes = STANDARD.decode(&meta.prf_salt)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&meta.prf_salt))
        .map_err(|e| format!("decode prf_salt: {}", e))?;

    eprintln!("safeclaw {} — touch passkey…", label.to_lowercase());
    let result = do_browser_gesture(
        &custodian, &op_id, &beta,
        Some(&prf_salt_bytes), &meta.credential_id,
        label, args.no_browser, args.timeout, false,
    ).await?;

    let prf_first = result.prf_first.ok_or("gesture didn't return prf_first")?;
    let prf_first_bytes = URL_SAFE_NO_PAD.decode(&prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key, &prf_salt_bytes, &cred_id_raw, crate::crypto::kdf::WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": op,
        "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&op_id)))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("approve HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    eprintln!("safeclaw {} — ok", label.to_lowercase());
    Ok(())
}
