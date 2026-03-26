use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::approval::ApprovalDecision;
use crate::auth::{AuthenticatedRequest, PasskeyEntry};
use crate::auth::webauthn::{verify_assertion, AssertionData};
use crate::crypto::{
    aes_encrypt, decrypt_vault, derive_kek, derive_response_key, encrypt_vault,
    generate_dek, jwk_sk_d_bytes, unwrap_dek, wrap_dek,
};
use crate::crypto::keys::credential_id_to_filename;
use crate::error::{AppError, Result};
use crate::policy::PushSubscription;
use crate::state::AppState;

// ── Health ─────────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "locked": state.vault.is_locked(),
        "uptime": uptime,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ── VM Public Key ──────────────────────────────────────────────────────────────

pub async fn server_pk(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "pk": state.keypair.pk }))
}

// ── Vault Index Helpers ────────────────────────────────────────────────────────

fn read_index(state: &AppState) -> Value {
    let path = state.config.data_dir.join("index.json");
    if let Ok(content) = fs::read_to_string(&path) {
        serde_json::from_str(&content).unwrap_or_else(|_| json!({ "services": [], "files": [] }))
    } else {
        json!({ "services": [], "files": [] })
    }
}

fn write_index(state: &AppState, secrets: &Value) -> std::io::Result<()> {
    let services: Vec<String> = secrets
        .get("services")
        .and_then(|s| s.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    let files: Vec<Value> = secrets
        .get("files")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();

    let index = json!({ "services": services, "files": files });
    fs::write(
        state.config.data_dir.join("index.json"),
        serde_json::to_string(&index)?,
    )
}

// ── Vault Decrypt/Encrypt Helpers ──────────────────────────────────────────────

/// Decrypt vault.enc into a JSON Value using passkey auth credentials.
fn decrypt_vault_json(state: &AppState, auth: &AuthenticatedRequest) -> Result<Value> {
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = fs::read(state.config.data_dir.join("vault.enc"))?;
    let secrets_bytes = decrypt_vault(&dek, &vault_enc)?;
    dek.zeroize();

    serde_json::from_slice(&secrets_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse vault: {}", e)))
}

/// Decrypt vault, apply a mutation, re-encrypt and write back.
/// Also updates the in-memory VaultState and index.json.
fn with_vault_mut<F>(state: &AppState, auth: &AuthenticatedRequest, f: F) -> Result<()>
where
    F: FnOnce(&mut Value) -> Result<()>,
{
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = fs::read(state.config.data_dir.join("vault.enc"))?;
    let secrets_bytes = decrypt_vault(&dek, &vault_enc)?;
    let mut secrets: Value = serde_json::from_slice(&secrets_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse vault: {}", e)))?;

    // Apply mutation
    f(&mut secrets)?;

    // Re-encrypt and write
    let new_enc =
        encrypt_vault(&dek, serde_json::to_string(&secrets)?.as_bytes())?;
    dek.zeroize();

    fs::write(state.config.data_dir.join("vault.enc"), &new_enc)?;
    let _ = write_index(state, &secrets);
    state.vault.set_secrets(secrets);

    Ok(())
}

// ── Setup ──────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct SetupBody {
    pub payload: String,
    pub assertions: Option<Vec<Value>>,
}

pub async fn setup(
    State(state): State<Arc<AppState>>,
    bytes: Bytes,
) -> Result<impl IntoResponse> {
    let body: SetupBody = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("Invalid setup request body".into()))?;

    let wire_bytes = STANDARD
        .decode(&body.payload)
        .map_err(|e| AppError::BadRequest(format!("Invalid payload base64: {}", e)))?;

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let plaintext = crate::crypto::ecies::e2e_decrypt(&wire_bytes, &sk_d)?;

    let parsed: Value = serde_json::from_slice(&plaintext)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;

    let nonce_b64 = parsed
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing nonce".into()))?;

    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce: {}", e)))?;

    {
        let mut ns = state.nonces.lock().unwrap();
        if !ns.check_and_insert(&nonce_bytes) {
            return Err(AppError::BadRequest("Nonce already used".into()));
        }
    }

    let passkeys_arr = parsed
        .get("passkeys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::BadRequest("Missing passkeys array".into()))?;

    let user_keys_arr = parsed
        .get("userKeys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::BadRequest("Missing userKeys array".into()))?;

    let secrets = parsed
        .get("secrets")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing secrets".into()))?;

    let setup_config = parsed.get("config").cloned();

    // If vault already exists, require existing passkey auth before overwrite
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    if passkeys_path.exists() {
        let existing_passkeys: HashMap<String, PasskeyEntry> =
            serde_json::from_str(&fs::read_to_string(&passkeys_path)?)
                .map_err(|e| AppError::Internal(format!("Failed to read passkeys.json: {}", e)))?;

        let existing_cred_id = parsed
            .get("existingCredentialId")
            .and_then(|v| v.as_str());
        let existing_assertion_val = parsed.get("existingAssertion").cloned();

        let cid = existing_cred_id.ok_or_else(|| {
            AppError::Unauthorized("Vault exists: existing passkey required".into())
        })?;

        let entry = existing_passkeys
            .get(cid)
            .ok_or_else(|| AppError::Unauthorized("Existing credential not found".into()))?;

        let existing_assertion: AssertionData = serde_json::from_value(
            existing_assertion_val.ok_or_else(|| {
                AppError::Unauthorized("Missing existing assertion".into())
            })?,
        )
        .map_err(|e| AppError::BadRequest(format!("Invalid existing assertion: {}", e)))?;

        if entry.x.is_empty() || entry.y.is_empty() {
            return Err(AppError::Unauthorized(
                "Existing passkey has missing coordinates".into(),
            ));
        }
        verify_assertion(
            &existing_assertion,
            &entry.x,
            &entry.y,
            &state.config.effective_origin(),
            &state.config.effective_rp_id(),
        )?;
    }

    let inner_assertions = parsed
        .get("assertions")
        .and_then(|v| v.as_array())
        .cloned();
    let outer_assertions = body.assertions.clone();
    let assertions_src = inner_assertions.or(outer_assertions);

    for (i, pk_val) in passkeys_arr.iter().enumerate() {
        let x = pk_val.get("x").and_then(|v| v.as_str()).unwrap_or("");
        let y = pk_val.get("y").and_then(|v| v.as_str()).unwrap_or("");

        if x.is_empty() || y.is_empty() {
            return Err(AppError::BadRequest(format!(
                "Passkey {} has missing x/y coordinates",
                i
            )));
        }

        let assertions = assertions_src
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Missing assertions array".into()))?;
        let assertion_val = assertions
            .get(i)
            .ok_or_else(|| AppError::BadRequest(format!("Missing assertion for passkey {}", i)))?;
        let assertion: AssertionData = serde_json::from_value(assertion_val.clone())
            .map_err(|e| {
                AppError::BadRequest(format!("Invalid assertion for passkey {}: {}", i, e))
            })?;
        verify_assertion(
            &assertion,
            x,
            y,
            &state.config.effective_origin(),
            &state.config.effective_rp_id(),
        )?;
    }

    fs::create_dir_all(&state.config.data_dir)?;
    let dek = generate_dek();
    let vault_enc = encrypt_vault(&dek, serde_json::to_string(&secrets)?.as_bytes())?;
    fs::write(state.config.data_dir.join("vault.enc"), &vault_enc)?;

    let mut passkeys_map: HashMap<String, PasskeyEntry> = HashMap::new();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    for (i, pk_val) in passkeys_arr.iter().enumerate() {
        let cred_id = pk_val
            .get("credentialId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::BadRequest(format!("Missing credentialId for passkey {}", i))
            })?;
        let x = pk_val
            .get("x")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let y = pk_val
            .get("y")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if x.is_empty() || y.is_empty() {
            return Err(AppError::BadRequest(format!(
                "Passkey {} has missing x/y coordinates",
                i
            )));
        }
        let device_name = pk_val
            .get("deviceName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        passkeys_map.insert(
            cred_id.to_string(),
            PasskeyEntry {
                x,
                y,
                device_name,
                created_at: now_ms,
            },
        );

        let user_key_b64 = user_keys_arr
            .get(i)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("Missing userKey for passkey {}", i)))?;
        let user_key_bytes = STANDARD
            .decode(user_key_b64)
            .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

        let sk_d_local = jwk_sk_d_bytes(&state.keypair.sk)?;
        let mut kek = derive_kek(&user_key_bytes, &sk_d_local)?;
        let wrapped = wrap_dek(&dek, &kek)?;
        kek.zeroize();

        let fname = credential_id_to_filename(cred_id)?;
        fs::write(
            state
                .config
                .data_dir
                .join(format!("wrapped_dek_{}.bin", fname)),
            &wrapped,
        )?;
    }

    fs::write(&passkeys_path, serde_json::to_string(&passkeys_map)?)?;

    // Write index.json
    let _ = write_index(&state, &secrets);

    // Unlock proxy immediately after setup
    state.vault.set_secrets(secrets);

    // Fire on-setup webhook
    if let Some(ref hook_url) = state.config.on_setup_hook {
        if let Some(ref config_data) = setup_config {
            let hook_url = hook_url.clone();
            let config_json = config_data.clone();
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

// ── Vault Unlock ───────────────────────────────────────────────────────────────

pub async fn vault_unlock(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
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

// ── Vault Lock ─────────────────────────────────────────────────────────────────

pub async fn vault_lock(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth;
    state.vault.lock();
    Ok(Json(json!({ "ok": true })))
}

// ── Vault Credentials ──────────────────────────────────────────────────────────

pub async fn vault_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let nonce_b64 = auth.get_str("nonce")?;

    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = fs::read(state.config.data_dir.join("vault.enc"))?;
    let secrets_bytes = decrypt_vault(&dek, &vault_enc)?;
    dek.zeroize();

    let mut response_key = derive_response_key(&user_key, &nonce_bytes)?;
    let sealed = aes_encrypt(&response_key, &secrets_bytes)?;
    response_key.zeroize();

    Ok(Json(json!({ "sealed": STANDARD.encode(&sealed) })))
}

// ── Vault Update ───────────────────────────────────────────────────────────────

pub async fn vault_update(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let new_secrets = auth
        .payload
        .get("newSecrets")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing newSecrets".into()))?;

    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let vault_enc = encrypt_vault(&dek, serde_json::to_string(&new_secrets)?.as_bytes())?;
    dek.zeroize();
    fs::write(state.config.data_dir.join("vault.enc"), &vault_enc)?;

    let _ = write_index(&state, &new_secrets);
    state.vault.set_secrets(new_secrets);

    Ok(Json(json!({ "ok": true })))
}

// ── Vault Service CRUD ─────────────────────────────────────────────────────────

/// GET /vault/services — list service names (no passkey required)
pub async fn vault_services_list(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let index = read_index(&state);
    let services = index
        .get("services")
        .cloned()
        .unwrap_or_else(|| json!([]));
    Json(json!({ "services": services }))
}

/// POST /vault/services/add — add or replace a service (passkey required)
pub async fn vault_services_add(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let name = auth
        .payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing service name".into()))?
        .to_string();

    let config = auth
        .payload
        .get("config")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing service config".into()))?;

    with_vault_mut(&state, &auth, move |secrets| {
        let services = secrets
            .get_mut("services")
            .and_then(|s| s.as_object_mut())
            .ok_or_else(|| AppError::Internal("Vault missing 'services' object".into()))?;
        services.insert(name, config);
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

/// POST /vault/services/update — update an existing service (passkey required)
pub async fn vault_services_update(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let name = auth
        .payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing service name".into()))?
        .to_string();

    let config = auth
        .payload
        .get("config")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing service config".into()))?;

    with_vault_mut(&state, &auth, move |secrets| {
        let services = secrets
            .get_mut("services")
            .and_then(|s| s.as_object_mut())
            .ok_or_else(|| AppError::Internal("Vault missing 'services' object".into()))?;
        if !services.contains_key(&name) {
            return Err(AppError::NotFound);
        }
        services.insert(name, config);
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

/// POST /vault/services/remove — remove a service (passkey required)
pub async fn vault_services_remove(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let name = auth
        .payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing service name".into()))?
        .to_string();

    with_vault_mut(&state, &auth, move |secrets| {
        let services = secrets
            .get_mut("services")
            .and_then(|s| s.as_object_mut())
            .ok_or_else(|| AppError::Internal("Vault missing 'services' object".into()))?;
        services.remove(&name);
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

// ── Policy Defaults ────────────────────────────────────────────────────────────

/// GET /vault/policy — read policy defaults (no passkey)
pub async fn vault_policy_get(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let defaults = state.vault.get_policy_defaults();
    Json(json!({ "policy_defaults": defaults }))
}

/// POST /vault/policy/update — update policy defaults (passkey required)
pub async fn vault_policy_update(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let new_defaults = auth
        .payload
        .get("policy_defaults")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing policy_defaults".into()))?;

    with_vault_mut(&state, &auth, move |secrets| {
        secrets["policy_defaults"] = new_defaults;
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

// ── Files ──────────────────────────────────────────────────────────────────────

/// GET /vault/files — list files (no passkey, from index)
pub async fn vault_files_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let index = read_index(&state);
    let files = index.get("files").cloned().unwrap_or_else(|| json!([]));
    Json(json!({ "files": files }))
}

/// POST /vault/files/upload — encrypt and store a file (passkey required)
/// Payload: { "name": "...", "data": "<base64>" }
pub async fn vault_files_upload(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let file_name = auth
        .payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing file name".into()))?
        .to_string();

    let data_b64 = auth
        .payload
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing file data".into()))?;

    let file_bytes = STANDARD
        .decode(data_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid file data base64: {}", e)))?;

    let file_size = file_bytes.len();
    let file_id = uuid::Uuid::new_v4().to_string();

    // Decrypt vault to get DEK context
    let vault_val = decrypt_vault_json(&state, &auth)?;
    let _ = vault_val; // We just needed to verify auth; DEK is already zeroized inside

    // We need the DEK to encrypt the file — redo decrypt to get DEK
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    // Encrypt the file
    let encrypted_file = crate::crypto::aes_encrypt(&dek, &file_bytes)?;
    dek.zeroize();

    // Write encrypted file
    fs::create_dir_all(state.config.data_dir.join("files"))?;
    fs::write(
        state.config.data_dir.join(format!("files/{}.enc", file_id)),
        &encrypted_file,
    )?;

    // Update vault JSON with file metadata
    with_vault_mut(&state, &auth, {
        let file_id2 = file_id.clone();
        let file_name2 = file_name.clone();
        move |secrets| {
            if secrets.get("files").is_none() {
                secrets["files"] = json!([]);
            }
            if let Some(arr) = secrets["files"].as_array_mut() {
                arr.push(json!({
                    "id": file_id2,
                    "name": file_name2,
                    "size": file_size,
                }));
            }
            Ok(())
        }
    })?;

    Ok(Json(json!({ "ok": true, "id": file_id })))
}

/// POST /vault/files/read — decrypt and return a file E2E (passkey required)
/// Payload: { "id": "...", "nonce": "<base64>" }
pub async fn vault_files_read(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let file_id = auth
        .payload
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing file id".into()))?
        .to_string();

    let nonce_b64 = auth.get_str("nonce")?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce: {}", e)))?;

    // Sanitize file_id (UUID format only)
    if !file_id.chars().all(|c| c.is_alphanumeric() || c == '-') || file_id.len() > 40 {
        return Err(AppError::BadRequest("Invalid file id".into()));
    }

    let enc_path = state
        .config
        .data_dir
        .join(format!("files/{}.enc", file_id));
    if !enc_path.exists() {
        return Err(AppError::NotFound);
    }

    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    // Decrypt file
    let enc_data = fs::read(&enc_path)?;
    let plaintext = crate::crypto::aes_decrypt(&dek, &enc_data)?;
    dek.zeroize();

    // E2E encrypt for client
    let mut response_key = derive_response_key(&user_key, &nonce_bytes)?;
    let sealed = aes_encrypt(&response_key, &plaintext)?;
    response_key.zeroize();

    Ok(Json(json!({ "sealed": STANDARD.encode(&sealed) })))
}

/// POST /vault/files/remove — delete an encrypted file (passkey required)
pub async fn vault_files_remove(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let file_id = auth
        .payload
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing file id".into()))?
        .to_string();

    // Sanitize
    if !file_id.chars().all(|c| c.is_alphanumeric() || c == '-') || file_id.len() > 40 {
        return Err(AppError::BadRequest("Invalid file id".into()));
    }

    let enc_path = state
        .config
        .data_dir
        .join(format!("files/{}.enc", file_id));
    if enc_path.exists() {
        fs::remove_file(&enc_path)?;
    }

    // Remove from vault JSON
    with_vault_mut(&state, &auth, {
        let file_id2 = file_id.clone();
        move |secrets| {
            if let Some(files) = secrets.get_mut("files").and_then(|f| f.as_array_mut()) {
                files.retain(|f| f.get("id").and_then(|v| v.as_str()) != Some(&file_id2));
            }
            Ok(())
        }
    })?;

    Ok(Json(json!({ "ok": true })))
}

// ── Push Notification Subscriptions ───────────────────────────────────────────

/// POST /vault/notifications/subscribe — add push subscription (passkey required)
pub async fn vault_notifications_subscribe(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let sub = auth
        .payload
        .get("subscription")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing subscription".into()))?;

    // Validate basic structure
    let _: PushSubscription = serde_json::from_value(sub.clone())
        .map_err(|e| AppError::BadRequest(format!("Invalid subscription: {}", e)))?;

    with_vault_mut(&state, &auth, move |secrets| {
        if secrets.get("push_subscriptions").is_none() {
            secrets["push_subscriptions"] = json!([]);
        }
        if let Some(arr) = secrets["push_subscriptions"].as_array_mut() {
            arr.push(sub);
        }
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

// ── Notifications ──────────────────────────────────────────────────────────────

/// GET /notifications — return and clear pending in-memory notifications (no passkey required).
/// Web Push (RFC 8030) is a future enhancement; the admin page polls this endpoint instead.
pub async fn notifications_get(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut notifs = state.notifications.lock().unwrap();
    let result = notifs.clone();
    notifs.clear();
    Json(json!({ "notifications": result }))
}

// ── Approval Endpoints ─────────────────────────────────────────────────────────

/// GET /approve/:id — get approval info (no passkey required)
pub async fn approval_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.audit_log.get_approval(&id) {
        Ok(Some(rec)) => Json(json!({
            "id": rec.id,
            "service": rec.service,
            "method": rec.method,
            "path": rec.path,
            "status": rec.status,
            "created_at": rec.created_at,
            "expires_at": rec.expires_at,
        }))
        .into_response(),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": "approval not found" })),
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("db error: {}", e) })),
        )
            .into_response(),
    }
}

/// GET /approve/:id/status — poll approval status (no passkey required)
pub async fn approval_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Check in-memory pending first (faster)
    let is_pending = state
        .approval_manager
        .pending
        .lock()
        .unwrap()
        .contains_key(&id);

    if is_pending {
        return Json(json!({ "status": "pending" })).into_response();
    }

    match state.audit_log.get_approval(&id) {
        Ok(Some(rec)) => Json(json!({ "status": rec.status })).into_response(),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": "approval not found" })),
        )
            .into_response(),
        Err(_) => Json(json!({ "status": "unknown" })).into_response(),
    }
}

/// GET /approve/pending — list pending approvals (no passkey required)
pub async fn approval_list_pending(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.audit_log.list_pending_approvals() {
        Ok(records) => Json(json!({ "pending": records })).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("db error: {}", e) })),
        )
            .into_response(),
    }
}

/// POST /approve/:id/details — return E2E-encrypted request details (passkey required).
/// Details are in-memory only; cleared automatically when the approval is resolved/timed-out.
pub async fn approval_details(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let nonce_b64 = auth.get_str("nonce")?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce: {}", e)))?;

    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let details: serde_json::Value = {
        let pending = state.approval_manager.pending.lock().unwrap();
        pending
            .get(&id)
            .map(|a| a.details.clone().unwrap_or(serde_json::Value::Null))
            .ok_or(AppError::NotFound)?
    };

    let details_bytes = serde_json::to_vec(&details)
        .map_err(|e| AppError::Internal(format!("Failed to serialize details: {}", e)))?;

    let mut response_key = derive_response_key(&user_key, &nonce_bytes)?;
    let sealed = aes_encrypt(&response_key, &details_bytes)?;
    response_key.zeroize();

    Ok(Json(json!({ "sealed": STANDARD.encode(&sealed) })))
}

/// POST /approve/:id/confirm — approve a pending request (passkey required)
pub async fn approval_confirm(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth; // passkey verified by extractor

    if state
        .approval_manager
        .resolve(&id, ApprovalDecision::Approved)
    {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(AppError::NotFound)
    }
}

/// POST /approve/:id/reject — reject a pending request (passkey required)
pub async fn approval_reject(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth; // passkey verified by extractor

    if state
        .approval_manager
        .resolve(&id, ApprovalDecision::Rejected)
    {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(AppError::NotFound)
    }
}

// ── Identity: Add Passkey ──────────────────────────────────────────────────────

pub async fn identity_add_passkey(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let new_passkey = auth
        .payload
        .get("newPasskey")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing newPasskey".into()))?;
    let new_user_key_b64 = auth
        .payload
        .get("newUserKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing newUserKey".into()))?;
    let new_cred_id = new_passkey
        .get("credentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing credentialId in newPasskey".into()))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    let wrapped = fs::read(&wrapped_path)?;
    let mut dek = unwrap_dek(&wrapped, &kek)?;
    kek.zeroize();

    let new_user_key = STANDARD
        .decode(new_user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid newUserKey: {}", e)))?;
    let mut new_kek = derive_kek(&new_user_key, &sk_d)?;
    let new_wrapped = wrap_dek(&dek, &new_kek)?;
    dek.zeroize();
    new_kek.zeroize();

    let new_fname = credential_id_to_filename(new_cred_id)?;
    fs::write(
        state
            .config
            .data_dir
            .join(format!("wrapped_dek_{}.bin", new_fname)),
        &new_wrapped,
    )?;

    let passkeys_path = state.config.data_dir.join("passkeys.json");
    let mut passkeys = auth.passkeys.clone();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let new_x = new_passkey
        .get("x")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let new_y = new_passkey
        .get("y")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if new_x.is_empty() || new_y.is_empty() {
        return Err(AppError::BadRequest(
            "New passkey has missing x/y coordinates".into(),
        ));
    }
    passkeys.insert(
        new_cred_id.to_string(),
        PasskeyEntry {
            x: new_x,
            y: new_y,
            device_name: new_passkey
                .get("deviceName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            created_at: now_ms,
        },
    );
    fs::write(&passkeys_path, serde_json::to_string(&passkeys)?)?;

    Ok(Json(json!({ "ok": true })))
}

// ── Identity: Remove Passkey ───────────────────────────────────────────────────

pub async fn identity_remove_passkey(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let remove_id = auth
        .payload
        .get("removeCredentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing removeCredentialId".into()))?
        .to_string();

    if !auth.passkeys.contains_key(&remove_id) {
        return Err(AppError::BadRequest(
            "Credential to remove not found".into(),
        ));
    }
    if auth.passkeys.len() <= 1 {
        return Err(AppError::BadRequest(
            "Cannot remove the last passkey".into(),
        ));
    }

    let mut passkeys = auth.passkeys.clone();
    passkeys.remove(&remove_id);

    let passkeys_path = state.config.data_dir.join("passkeys.json");
    fs::write(&passkeys_path, serde_json::to_string(&passkeys)?)?;

    let fname = credential_id_to_filename(&remove_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if wrapped_path.exists() {
        let _ = fs::remove_file(&wrapped_path);
    }

    Ok(Json(json!({ "ok": true })))
}

// ── Admin: Workspace File Generation ──────────────────────────────────────────

/// GET /admin/safeclaw.md — returns a Markdown service table (no passkey required)
pub async fn admin_safeclaw_md(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let locked = state.vault.is_locked();
    let content = {
        let secrets_guard = state.vault.secrets.lock().unwrap();
        if let Some(ref s) = *secrets_guard {
            crate::generate::generate_safeclaw_md(s, false, state.config.proxy_port)
        } else {
            drop(secrets_guard);
            let names = state.vault.service_names.lock().unwrap().clone();
            let services: serde_json::Map<String, Value> =
                names.into_iter().map(|n| (n, Value::Null)).collect();
            let minimal = json!({ "services": services });
            crate::generate::generate_safeclaw_md(&minimal, locked, state.config.proxy_port)
        }
    };
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        content,
    )
}

/// GET /admin/agents-snippet — returns AGENTS.md routing instructions (no passkey required)
pub async fn admin_agents_snippet(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let content = {
        let secrets_guard = state.vault.secrets.lock().unwrap();
        if let Some(ref s) = *secrets_guard {
            crate::generate::generate_agents_md_snippet(s, state.config.proxy_port)
        } else {
            drop(secrets_guard);
            let names = state.vault.service_names.lock().unwrap().clone();
            let services: serde_json::Map<String, Value> =
                names.into_iter().map(|n| (n, Value::Null)).collect();
            let minimal = json!({ "services": services });
            crate::generate::generate_agents_md_snippet(&minimal, state.config.proxy_port)
        }
    };
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        content,
    )
}

// ── System: Restart / Shutdown ─────────────────────────────────────────────────

pub async fn system_restart(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth;
    state.vault.lock();
    let resp = Json(json!({ "ok": true })).into_response();
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::process::exit(0);
    });
    Ok(resp)
}

pub async fn system_shutdown(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth;
    state.vault.lock();
    let resp = Json(json!({ "ok": true })).into_response();
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::process::exit(0);
    });
    Ok(resp)
}
