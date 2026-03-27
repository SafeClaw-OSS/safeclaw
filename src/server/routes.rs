use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
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
    let vapid_public_key = state.vault.vapid_public_key.lock().unwrap().clone();
    Json(json!({
        "status": "ok",
        "locked": state.vault.is_locked(),
        "uptime": uptime,
        "version": env!("CARGO_PKG_VERSION"),
        "vapidPublicKey": vapid_public_key,
    }))
}

// ── VM Public Key ──────────────────────────────────────────────────────────────

pub async fn server_pk(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "pk": state.keypair.pk }))
}

/// GET /challenge — issue a server challenge for replay protection.
/// Returns { challenge: base64 }. TTL 5min, single-use, 60/min/IP.
pub async fn issue_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();
    let mut store = state.challenges.lock().unwrap();
    match store.issue(ip) {
        Some(challenge) => (
            StatusCode::OK,
            Json(json!({ "challenge": challenge })),
        ).into_response(),
        None => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Challenge rate limit exceeded" })),
        ).into_response(),
    }
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
    // Store lightweight service metadata (name + category) — no credentials.
    let services: Vec<Value> = secrets
        .get("services")
        .and_then(|s| s.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(name, cfg)| {
                    let category = cfg
                        .get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or("service");
                    json!({ "name": name, "category": category })
                })
                .collect()
        })
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

    let mut secrets = parsed
        .get("secrets")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing secrets".into()))?;

    // Inject VAPID key pair if not already present (fresh setup or migration)
    if secrets.get("vapid_private_key").is_none() {
        match crate::webpush::generate_vapid_keypair() {
            Ok((priv_b64, _pub_b64)) => {
                secrets.as_object_mut().map(|m| m.insert(
                    "vapid_private_key".into(),
                    serde_json::Value::String(priv_b64),
                ));
                tracing::info!("Generated VAPID key pair for vault");
            }
            Err(e) => tracing::warn!("Failed to generate VAPID keypair: {e}"),
        }
    }

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
            // Enrich config with agentName from passkeys (provisioner needs it for OpenClaw agent.name)
            let mut config_json = config_data.clone();
            if let Some(agent_name) = parsed.get("passkeys")
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|pk| pk.get("agentName"))
                .and_then(|v| v.as_str())
            {
                config_json.as_object_mut()
                    .map(|m| m.insert("agentName".into(), serde_json::Value::String(agent_name.to_string())));
            }
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

    let mut secrets: Value = serde_json::from_slice(&secrets_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse vault: {}", e)))?;

    // Migration: generate VAPID key pair if not present (existing vaults pre-dating Web Push)
    if secrets.get("vapid_private_key").is_none() {
        match crate::webpush::generate_vapid_keypair() {
            Ok((priv_b64, _)) => {
                secrets.as_object_mut().map(|m| m.insert(
                    "vapid_private_key".into(),
                    serde_json::Value::String(priv_b64),
                ));
                // Re-encrypt and persist migrated vault
                let new_enc = encrypt_vault(&dek, serde_json::to_string(&secrets)?.as_bytes())?;
                fs::write(state.config.data_dir.join("vault.enc"), &new_enc)?;
                tracing::info!("Migrated vault: generated VAPID key pair");
            }
            Err(e) => tracing::warn!("VAPID migration failed: {e}"),
        }
    }
    dek.zeroize();

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

#[allow(dead_code)]
pub async fn vault_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let user_key_b64 = auth.get_str("userKey")?;
    let nonce_b64 = auth.replay_token_b64()?;

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

// ── Provisioner Push ───────────────────────────────────────────────────────────

/// Spawn a background task that pushes updated safeclaw.md and AGENTS.md to the
/// local provisioner after a service add/update/remove. Failures are silently
/// discarded — the vault operation has already succeeded.
fn push_to_provisioner(secrets: serde_json::Value, proxy_port: u16) {
    tokio::spawn(async move {
        let md = crate::generate::generate_safeclaw_md(&secrets, false, proxy_port);
        let snippet = crate::generate::generate_agents_md_snippet(&secrets, proxy_port);
        let _ = reqwest::Client::new()
            .post("http://localhost:23296/apply")
            .json(&serde_json::json!({
                "ops": [
                    { "type": "workspace", "file": "safeclaw.md", "content": md },
                    { "type": "workspace", "file": "AGENTS.md", "content": snippet }
                ],
                "restart": false
            }))
            .send()
            .await;
    });
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

    // Push updated workspace files to provisioner
    let proxy_port = state.config.proxy_port;
    if let Some(secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(secrets, proxy_port);
    }

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

    // Push updated workspace files to provisioner
    let proxy_port = state.config.proxy_port;
    if let Some(secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(secrets, proxy_port);
    }

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

    // Push updated workspace files to provisioner
    let proxy_port = state.config.proxy_port;
    if let Some(secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(secrets, proxy_port);
    }

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

    // Auth already verified by AuthenticatedRequest extractor.
    // Derive DEK directly from user key + wrapped DEK on disk.
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

    let nonce_b64 = auth.replay_token_b64()?;
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
        // Migrate flat key to nested structure if needed
        if let Some(old) = secrets.get("push_subscriptions").cloned() {
            if secrets.get("notifications").is_none() {
                secrets["notifications"] = json!({ "subscriptions": old });
            }
            secrets.as_object_mut().map(|m| m.remove("push_subscriptions"));
        }
        if secrets.get("notifications").is_none() {
            secrets["notifications"] = json!({ "subscriptions": [] });
        }
        if let Some(arr) = secrets["notifications"]["subscriptions"].as_array_mut() {
            arr.push(sub);
        }
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

// GET /notifications removed — replaced by Web Push (RFC 8030).

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
    let nonce_b64 = auth.replay_token_b64()?;
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
    // Get service name from the pending approval (needed to extract its auth config)
    let service_name = {
        let pending = state.approval_manager.pending.lock().unwrap();
        pending.get(&id).map(|a| a.service.clone())
    };

    let service_name = match service_name {
        Some(s) => s,
        None => return Err(AppError::NotFound),
    };

    // Decrypt vault and extract the service's auth config to pass through the channel
    let auth_json = decrypt_vault_json(&state, &auth)
        .ok()
        .and_then(|secrets| {
            secrets
                .get("services")
                .and_then(|s| s.get(&service_name))
                .and_then(|svc| svc.get("auth"))
                .cloned()
        });

    if state
        .approval_manager
        .resolve(&id, ApprovalDecision::Approved(auth_json))
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

#[allow(dead_code)]
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

// ── Audit Log ──────────────────────────────────────────────────────────────────

/// GET /audit/log?limit=50 — list recent audit entries (no auth required, contains zero sensitive data).
pub async fn audit_log_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(50u32).min(200);
    match state.audit_log.list_recent(limit) {
        Ok(entries) => Json(json!({ "entries": entries })).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}
