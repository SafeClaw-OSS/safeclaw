use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::auth::{authenticate_bytes, AuthenticatedRequest, PasskeyEntry};
use crate::auth::webauthn::{verify_assertion, AssertionData};
use crate::crypto::{
    aes_encrypt, decrypt_vault, derive_kek, derive_response_key, encrypt_vault,
    generate_dek, jwk_sk_d_bytes, unwrap_dek, wrap_dek,
};
use crate::crypto::keys::credential_id_to_filename;
use crate::error::{AppError, Result};
use crate::state::AppState;

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "locked": state.vault.is_locked(),
        "uptime": uptime,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ── VM Public Key ─────────────────────────────────────────────────────────────

pub async fn vm_pk(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "vmPk": state.vm_keypair.pk }))
}

// ── Status (unauthenticated basic / authenticated full) ───────────────────────

pub async fn status_basic(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    let passkeys_info: Vec<Value> = if passkeys_path.exists() {
        let data: HashMap<String, PasskeyEntry> =
            serde_json::from_str(&fs::read_to_string(&passkeys_path).unwrap_or_default())
                .unwrap_or_default();
        data.iter()
            .map(|(id, e)| json!({ "id": id, "deviceName": e.device_name }))
            .collect()
    } else {
        vec![]
    };

    Json(json!({
        "locked": state.vault.is_locked(),
        "uptime": state.start_time.elapsed().as_secs_f64(),
        "services": state.vault.service_names(),
        "passkeys": passkeys_info,
    }))
}

pub async fn status_authenticated(
    State(state): State<Arc<AppState>>,
    bytes: Bytes,
) -> Result<impl IntoResponse> {
    // If body is empty / trivial, return basic status (compat with admin.html's GET-style call)
    let trimmed = bytes.trim_ascii();
    if trimmed.is_empty() || trimmed == b"{}" {
        let passkeys_path = state.config.data_dir.join("passkeys.json");
        let passkeys: HashMap<String, PasskeyEntry> = if passkeys_path.exists() {
            serde_json::from_str(&fs::read_to_string(&passkeys_path).unwrap_or_default())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        return Ok(Json(json!({
            "locked": state.vault.is_locked(),
            "uptime": state.start_time.elapsed().as_secs_f64(),
            "services": state.vault.service_names(),
            "passkeys": passkeys.keys().collect::<Vec<_>>(),
        })));
    }

    let auth = authenticate_bytes(&bytes, &state)?;
    let passkeys = &auth.passkeys;

    Ok(Json(json!({
        "locked": state.vault.is_locked(),
        "uptime": state.start_time.elapsed().as_secs_f64(),
        "services": state.vault.service_names(),
        "passkeys": passkeys.keys().collect::<Vec<_>>(),
    })))
}

// ── Setup ─────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct SetupBody {
    pub payload: String,                     // base64 E2E payload
    pub assertions: Option<Vec<Value>>,      // outer assertions (from HTML, may be null)
}

pub async fn setup(
    State(state): State<Arc<AppState>>,
    bytes: Bytes,
) -> Result<impl IntoResponse> {
    let body: SetupBody = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("Invalid setup request body".into()))?;

    // Decode and E2E-decrypt the payload
    let wire_bytes = STANDARD
        .decode(&body.payload)
        .map_err(|e| AppError::BadRequest(format!("Invalid payload base64: {}", e)))?;

    let vm_sk_d = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
    let plaintext = crate::crypto::ecies::e2e_decrypt(&wire_bytes, &vm_sk_d)?;

    let parsed: Value = serde_json::from_slice(&plaintext)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;

    let nonce_b64 = parsed.get("nonce").and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing nonce".into()))?;

    let nonce_bytes = STANDARD.decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce: {}", e)))?;

    // Check nonce
    {
        let mut ns = state.nonces.lock().unwrap();
        if !ns.check_and_insert(&nonce_bytes) {
            return Err(AppError::BadRequest("Nonce already used".into()));
        }
    }

    // Extract passkeys array (public key info, no assertions)
    let passkeys_arr = parsed.get("passkeys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::BadRequest("Missing passkeys array".into()))?;

    let user_keys_arr = parsed.get("userKeys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::BadRequest("Missing userKeys array".into()))?;

    // Extract secrets (encrypted vault storage) and config (webhook-only, never stored)
    let secrets = parsed.get("secrets")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing secrets".into()))?;

    let setup_config = parsed.get("config").cloned();

    // If vault already exists, require existing passkey auth before overwrite
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    if passkeys_path.exists() {
        let existing_passkeys: HashMap<String, PasskeyEntry> =
            serde_json::from_str(&fs::read_to_string(&passkeys_path)?)
                .map_err(|e| AppError::Internal(format!("Failed to read passkeys.json: {}", e)))?;

        let existing_cred_id = parsed.get("existingCredentialId").and_then(|v| v.as_str());
        let existing_assertion_val = parsed.get("existingAssertion").cloned();

        let cid = existing_cred_id
            .ok_or_else(|| AppError::Unauthorized("Vault exists: existing passkey required".into()))?;

        let entry = existing_passkeys.get(cid)
            .ok_or_else(|| AppError::Unauthorized("Existing credential not found".into()))?;

        let existing_assertion: AssertionData = serde_json::from_value(
            existing_assertion_val.ok_or_else(|| AppError::Unauthorized("Missing existing assertion".into()))?,
        ).map_err(|e| AppError::BadRequest(format!("Invalid existing assertion: {}", e)))?;

        if !entry.x.is_empty() && !entry.y.is_empty() {
            verify_assertion(
                &existing_assertion,
                &entry.x,
                &entry.y,
                &state.config.effective_origin(),
                &state.config.effective_rp_id(),
            )?;
        }
    }

    // Verify each new passkey's assertion (from outer body.assertions OR inner parsed.assertions)
    // The HTML sends assertions in the outer body; inner payload might also have them
    let inner_assertions = parsed.get("assertions").and_then(|v| v.as_array()).cloned();
    let outer_assertions = body.assertions.clone();
    let assertions_src = inner_assertions.or(outer_assertions);

    for (i, pk_val) in passkeys_arr.iter().enumerate() {
        let x = pk_val.get("x").and_then(|v| v.as_str()).unwrap_or("");
        let y = pk_val.get("y").and_then(|v| v.as_str()).unwrap_or("");

        // Only verify if we have both the assertion and the public key coords
        if !x.is_empty() && !y.is_empty() {
            if let Some(ref assertions) = assertions_src {
                if let Some(assertion_val) = assertions.get(i) {
                    if let Ok(assertion) = serde_json::from_value::<AssertionData>(assertion_val.clone()) {
                        verify_assertion(
                            &assertion,
                            x,
                            y,
                            &state.config.effective_origin(),
                            &state.config.effective_rp_id(),
                        )?;
                    }
                }
            }
        }
    }

    // Generate DEK and encrypt vault
    fs::create_dir_all(&state.config.data_dir)?;
    let dek = generate_dek();
    let vault_enc = encrypt_vault(&dek, serde_json::to_string(&secrets)?.as_bytes())?;
    fs::write(state.config.data_dir.join("vault.enc"), &vault_enc)?;

    // Build passkeys map and write wrapped DEKs per credential
    let mut passkeys_map: HashMap<String, PasskeyEntry> = HashMap::new();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    for (i, pk_val) in passkeys_arr.iter().enumerate() {
        let cred_id = pk_val.get("credentialId").and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("Missing credentialId for passkey {}", i)))?;
        let x = pk_val.get("x").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let y = pk_val.get("y").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let device_name = pk_val.get("deviceName").and_then(|v| v.as_str()).unwrap_or("").to_string();

        passkeys_map.insert(cred_id.to_string(), PasskeyEntry {
            x,
            y,
            device_name,
            created_at: now_ms,
        });

        // Derive KEK for this passkey and wrap DEK
        let user_key_b64 = user_keys_arr.get(i)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("Missing userKey for passkey {}", i)))?;
        let user_key_bytes = STANDARD.decode(user_key_b64)
            .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

        let vm_sk_d_local = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
        let mut kek = derive_kek(&user_key_bytes, &vm_sk_d_local)?;
        let wrapped = wrap_dek(&dek, &kek)?;
        kek.zeroize();

        let fname = credential_id_to_filename(cred_id)?;
        fs::write(
            state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname)),
            &wrapped,
        )?;
    }

    // Write passkeys.json
    fs::write(&passkeys_path, serde_json::to_string(&passkeys_map)?)?;

    // Unlock proxy immediately after setup
    state.vault.set_secrets(secrets);

    // Fire on-setup webhook with config data (never secrets)
    if let Some(ref hook_url) = state.config.on_setup_hook {
        if let Some(ref config_data) = setup_config {
            let hook_url = hook_url.clone();
            let config_json = config_data.clone();
            // Fire-and-forget in background — don't block setup response
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                match client
                    .post(&hook_url)
                    .json(&config_json)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                {
                    Ok(resp) => {
                        tracing::info!("on-setup hook responded: {}", resp.status());
                    }
                    Err(e) => {
                        tracing::warn!("on-setup hook failed: {}", e);
                    }
                }
            });
        }
    }

    Ok(Json(json!({ "ok": true })))
}

// ── Vault Unlock ──────────────────────────────────────────────────────────────

pub async fn vault_unlock(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD.decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized("No wrapped DEK for this credential".into()));
    }

    let vm_sk_d = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
    let mut kek = derive_kek(&user_key, &vm_sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = fs::read(state.config.data_dir.join("vault.enc"))?;
    let secrets_bytes = decrypt_vault(&dek, &vault_enc)?;
    dek.zeroize();

    let secrets: Value = serde_json::from_slice(&secrets_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse vault: {}", e)))?;

    state.vault.set_secrets(secrets);

    Ok(Json(json!({ "ok": true })))
}

// ── Vault Lock ────────────────────────────────────────────────────────────────

/// Lock the vault (no auth required — locking is safe and unauthenticated in the HTML flow)
pub async fn vault_lock_noauth(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.vault.lock();
    Json(json!({ "ok": true }))
}

/// Lock the vault (auth required — new API path)
pub async fn vault_lock(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth; // auth verified by extractor
    state.vault.lock();
    Ok(Json(json!({ "ok": true })))
}

// ── Vault Credentials ─────────────────────────────────────────────────────────

pub async fn vault_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let nonce_b64 = auth.get_str("nonce")?;

    let user_key = STANDARD.decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;
    let nonce_bytes = STANDARD.decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized("No wrapped DEK for this credential".into()));
    }

    let vm_sk_d = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
    let mut kek = derive_kek(&user_key, &vm_sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = fs::read(state.config.data_dir.join("vault.enc"))?;
    let secrets_bytes = decrypt_vault(&dek, &vault_enc)?;
    dek.zeroize();

    // Encrypt secrets with response key for client
    let mut response_key = derive_response_key(&user_key, &nonce_bytes)?;
    let sealed = aes_encrypt(&response_key, &secrets_bytes)?;
    response_key.zeroize();

    Ok(Json(json!({ "sealed": STANDARD.encode(&sealed) })))
}

// ── Vault Update ──────────────────────────────────────────────────────────────

pub async fn vault_update(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD.decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let new_secrets = auth.payload.get("newSecrets")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing newSecrets".into()))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized("No wrapped DEK for this credential".into()));
    }

    let vm_sk_d = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
    let mut kek = derive_kek(&user_key, &vm_sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = encrypt_vault(&dek, serde_json::to_string(&new_secrets)?.as_bytes())?;
    dek.zeroize();
    fs::write(state.config.data_dir.join("vault.enc"), &vault_enc)?;

    state.vault.set_secrets(new_secrets);

    Ok(Json(json!({ "ok": true })))
}

// ── Identity: Add Passkey ─────────────────────────────────────────────────────

pub async fn identity_add_passkey(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD.decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let new_passkey = auth.payload.get("newPasskey")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing newPasskey".into()))?;
    let new_user_key_b64 = auth.payload.get("newUserKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing newUserKey".into()))?;
    let new_cred_id = new_passkey.get("credentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing credentialId in newPasskey".into()))?;

    // Unwrap DEK with existing credential
    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized("No wrapped DEK for this credential".into()));
    }

    let vm_sk_d = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
    let mut kek = derive_kek(&user_key, &vm_sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    // Wrap DEK for new passkey
    let new_user_key = STANDARD.decode(new_user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid newUserKey: {}", e)))?;
    let mut new_kek = derive_kek(&new_user_key, &vm_sk_d)?;
    let new_wrapped = wrap_dek(&dek, &new_kek)?;
    dek.zeroize();
    new_kek.zeroize();

    let new_fname = credential_id_to_filename(new_cred_id)?;
    fs::write(
        state.config.data_dir.join(format!("wrapped_dek_{}.bin", new_fname)),
        &new_wrapped,
    )?;

    // Update passkeys.json
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    let mut passkeys = auth.passkeys.clone();
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    passkeys.insert(new_cred_id.to_string(), PasskeyEntry {
        x: new_passkey.get("x").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        y: new_passkey.get("y").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        device_name: new_passkey.get("deviceName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        created_at: now_ms,
    });
    fs::write(&passkeys_path, serde_json::to_string(&passkeys)?)?;

    Ok(Json(json!({ "ok": true })))
}

// ── Identity: Remove Passkey ──────────────────────────────────────────────────

pub async fn identity_remove_passkey(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let remove_id = auth.payload.get("removeCredentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing removeCredentialId".into()))?
        .to_string();

    if !auth.passkeys.contains_key(&remove_id) {
        return Err(AppError::BadRequest("Credential to remove not found".into()));
    }
    if auth.passkeys.len() <= 1 {
        return Err(AppError::BadRequest("Cannot remove the last passkey".into()));
    }

    let mut passkeys = auth.passkeys.clone();
    passkeys.remove(&remove_id);

    let passkeys_path = state.config.data_dir.join("passkeys.json");
    fs::write(&passkeys_path, serde_json::to_string(&passkeys)?)?;

    // Remove wrapped DEK file
    let fname = credential_id_to_filename(&remove_id)?;
    let wrapped_path = state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname));
    if wrapped_path.exists() {
        let _ = fs::remove_file(&wrapped_path);
    }

    Ok(Json(json!({ "ok": true })))
}

// ── System: Restart ───────────────────────────────────────────────────────────

pub async fn system_restart(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth;
    state.vault.lock();
    let resp = Json(json!({ "ok": true })).into_response();
    // Exit after sending response
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::process::exit(0);
    });
    Ok(resp)
}

// ── System: Shutdown ──────────────────────────────────────────────────────────

pub async fn system_shutdown(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth;
    state.vault.lock();
    let resp = Json(json!({ "ok": true })).into_response();
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::process::exit(1);
    });
    Ok(resp)
}
