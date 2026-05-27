//! `safeclaw write <KEY> <VALUE>` / `safeclaw delete <KEY>`
//!
//! Two passkey gestures: unlock (PRF + assertion) for current state,
//! then write (assertion only) to seal + submit. All crypto local.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

use crate::cli::profile::resolve_active;
use crate::cli::webauthn::*;
use crate::config::{DeleteArgs, WriteArgs};
use crate::crypto::kdf::WRAP_VERSION;

const DS_SEAL: &[u8] = b"sudp/v1/seal";

pub async fn run(args: WriteArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.custodian.as_deref(), args.vault.as_deref())?;
    let key = args.key.clone();
    let value = args.value.clone();
    eprintln!("safeclaw write {} — two passkey gestures (unlock + write)", key);

    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, aux, user_key) = do_unlock(&custodian, &vault, &meta, args.no_browser, args.timeout, args.cb_port).await?;

    let mut new_kv = kv;
    new_kv.insert(key.clone(), value);

    seal_and_submit_write(&custodian, &vault, &meta, &user_key, &new_kv, &aux, args.no_browser, args.timeout, args.cb_port).await?;
    eprintln!("safeclaw write — {} written", key);
    Ok(())
}

pub async fn run_delete(args: DeleteArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.custodian.as_deref(), args.vault.as_deref())?;
    let key = args.key.clone();
    eprintln!("safeclaw delete {} — two passkey gestures (unlock + write)", key);

    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, aux, user_key) = do_unlock(&custodian, &vault, &meta, args.no_browser, args.timeout, args.cb_port).await?;

    let mut new_kv = kv;
    if new_kv.remove(&key).is_none() {
        return Err(format!("key {} not found in vault", key));
    }

    seal_and_submit_write(&custodian, &vault, &meta, &user_key, &new_kv, &aux, args.no_browser, args.timeout, args.cb_port).await?;
    eprintln!("safeclaw delete — {} removed", key);
    Ok(())
}

async fn do_unlock(
    custodian: &str, vault: &str, meta: &PasskeyMeta,
    no_browser: bool, timeout: u64, cb_port: Option<u16>,
) -> Result<(BTreeMap<String, String>, Value, Vec<u8>), String> {
    let op = json!({
        "act": { "type": { "custom": "vault-unlock" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(custodian, vault, &op).await?;
    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &op)?;
    let prf_salt_bytes = decode_prf_salt(&meta.prf_salt)?;

    eprintln!("  gesture 1/2: unlock — touch passkey…");
    let result = do_browser_gesture(
        custodian, &op_id, &beta,
        Some(PRF_EVAL_SALT), &meta.credential_id,
        "Unlock vault", no_browser, timeout, false, cb_port,
    ).await?;

    let prf_first = result.prf_first.as_deref()
        .ok_or("unlock gesture didn't return prf_first")?;
    let prf_first_bytes = URL_SAFE_NO_PAD.decode(prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key, &prf_salt_bytes, &cred_id_raw, WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": op, "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&op_id)))
        .json(&grant).send().await.map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("unlock HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let kv: BTreeMap<String, String> = body["value"]["kv"].as_object()
        .ok_or("unlock missing value.kv")?
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();
    let aux = body["value"]["aux"].clone();
    Ok((kv, aux, user_key))
}

async fn seal_and_submit_write(
    custodian: &str, vault: &str, meta: &PasskeyMeta,
    user_key: &[u8], kv: &BTreeMap<String, String>, aux: &Value,
    no_browser: bool, timeout: u64, cb_port: Option<u16>,
) -> Result<(), String> {
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let new_prf_salt = random_bytes(32);
    let new_k = random_bytes(32);
    let new_wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        user_key, &new_prf_salt, &cred_id_raw, WRAP_VERSION,
    ).map_err(|e| format!("derive: {}", e))?;

    let binding = sudp::primitives::WrapBinding { credential_id: &cred_id_raw, version: WRAP_VERSION };
    let new_wrapped_key = <sudp::primitives::AeadWrap<sudp::primitives::ChaCha20Poly1305>
        as sudp::primitives::KeyWrap>::wrap(&new_wrapping_key, &new_k, &binding)
        .map_err(|e| format!("wrap K: {}", e))?;

    let m = build_protected_state(kv, aux, &meta.credential_id, &new_wrapping_key);
    let canonical = sudp::canonical::canonicalize_strict(&m).map_err(|e| format!("canonical: {}", e))?;
    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&WRAP_VERSION.to_be_bytes());
    let ct = <sudp::primitives::ChaCha20Poly1305 as sudp::primitives::Aead>::seal(&new_k, &canonical, &ad)
        .map_err(|e| format!("seal: {}", e))?;

    let write_op = json!({
        "act": { "type": "write", "target": "env", "scope": {
            "ciphertext": STANDARD.encode(&ct),
            "wrapped_key": STANDARD.encode(&new_wrapped_key),
            "prf_salt_next": STANDARD.encode(&new_prf_salt),
        }},
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(custodian, vault, &write_op).await?;
    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &write_op)?;

    eprintln!("  gesture 2/2: write — touch passkey…");
    let result = do_browser_gesture(
        custodian, &op_id, &beta,
        None, &meta.credential_id,
        "Write vault", no_browser, timeout, false, cb_port,
    ).await?;

    let grant = json!({
        "o": write_op, "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&new_wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&op_id)))
        .json(&grant).send().await.map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("write HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(())
}

fn build_protected_state(kv: &BTreeMap<String, String>, aux: &Value, cred_id_b64: &str, wrapping_key: &[u8]) -> Value {
    let mut targets = serde_json::Map::new();
    for (k, v) in kv {
        targets.insert(k.clone(), Value::String(STANDARD.encode(v.as_bytes())));
    }
    let mut peers = serde_json::Map::new();
    peers.insert(cred_id_b64.to_string(), Value::String(STANDARD.encode(wrapping_key)));
    json!({ "targets": targets, "peers": peers, "aux": aux })
}

fn decode_prf_salt(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| format!("decode prf_salt: {}", e))
}
