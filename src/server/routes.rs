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

// ApprovalDecision removed (async 202 flow — no more oneshot channel)
use crate::passkey::{AuthenticatedRequest, PasskeyEntry};
use crate::passkey::webauthn::{verify_assertion, AssertionData};
use crate::crypto::{
    aes_encrypt, decrypt_vault, derive_kek, derive_response_key, encrypt_vault,
    generate_dek, jwk_sk_d_bytes, unwrap_dek, wrap_dek,
};
use crate::crypto::keys::credential_id_to_filename;
use crate::error::{AppError, Result};
use crate::notify::PushSubscription;
use crate::state::AppState;

// ── Health ─────────────────────────────────────────────────────────────────────

/// POST /auth/verify — verify passkey identity without unlocking vault.
/// Returns 200 {ok: true, credential_id} if the passkey is registered on this instance.
/// Returns 401 if challenge invalid, signature wrong, or credential not registered.
/// Used by the console gate to block unauthorized access to the UI.
pub async fn auth_verify(
    _state: State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    // AuthenticatedRequest extractor already verified: challenge, credentialId, signature.
    // If we get here, the passkey is valid and registered on this instance.
    Ok(Json(json!({ "ok": true, "credential_id": auth.credential_id })))
}

pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let vapid_public_key = state.vault.vapid_public_key.lock().unwrap().clone();
    // started_at: Unix ms timestamp of when the process started.
    // Clients compute uptime = Date.now() - started_at, so the counter
    // keeps ticking even if the health endpoint becomes temporarily unreachable.
    let started_at = state.started_at_ms;
    Json(json!({
        "status": "ok",
        "locked": state.vault.is_locked(),
        "started_at": started_at,
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
    let mut user_key = STANDARD
        .decode(user_key_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;

    let fname = credential_id_to_filename(&auth.credential_id)?;
    let wrapped_path = state
        .config
        .data_dir
        .join(format!("wrapped_dek_{}.bin", fname));
    if !wrapped_path.exists() {
        user_key.zeroize();
        return Err(AppError::Unauthorized(
            "No wrapped DEK for this credential".into(),
        ));
    }

    let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
    let mut kek = derive_kek(&user_key, &sk_d)?;
    user_key.zeroize();
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
        match crate::notify::webpush::generate_vapid_keypair() {
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

    // D31: assertions MUST come from inside the ECIES envelope (integrity-protected).
    // Never fall back to outer (unencrypted) body — that would bypass AEAD protection.
    let assertions_src = parsed
        .get("assertions")
        .and_then(|v| v.as_array())
        .cloned();

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
    state.vault.set_secrets(secrets.clone());

    // Push full secrets (including services with auth tokens) to provisioner
    push_to_provisioner(secrets, state.config.proxy_port, state.config.effective_admin_url());

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
        match crate::notify::webpush::generate_vapid_keypair() {
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

    // Push AGENTS.md + safeclaw.md to provisioner on unlock
    let proxy_port = state.config.proxy_port;
    let console_url = state.config.effective_admin_url();
    if let Some(unlocked_secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(unlocked_secrets, proxy_port, console_url);
    }

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
    state.vault.set_secrets(new_secrets.clone());

    // Keep VM-side SafeClaw guidance in sync with the latest vault config.
    push_to_provisioner(new_secrets, state.config.proxy_port, state.config.effective_admin_url());

    Ok(Json(json!({ "ok": true })))
}

// ── Provisioner Push ───────────────────────────────────────────────────────────

/// Spawn a background task that pushes updated safeclaw.md and AGENTS.md to the
/// local provisioner after a service add/update/remove. Failures are silently
/// discarded — the vault operation has already succeeded.
fn push_to_provisioner(secrets: serde_json::Value, proxy_port: u16, console_url: String) {
    tokio::spawn(async move {
        let md = crate::cli::generate::generate_safeclaw_md(&secrets, false, proxy_port, &console_url);
        let snippet = crate::cli::generate::generate_agents_md_snippet(&secrets, proxy_port);

        // Extract channel tokens that need to be written into OpenClaw config.
        // Telegram: stored as services.telegram.auth.secret (path auth type).
        let telegram_token = secrets
            .get("services")
            .and_then(|s| s.get("telegram"))
            .and_then(|t| t.get("auth"))
            .and_then(|a| a.get("secret"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_owned());

        let mut ops = vec![
            serde_json::json!({ "type": "workspace", "file": "safeclaw.md", "content": md }),
            serde_json::json!({ "type": "workspace", "file": "AGENTS.md", "content": snippet }),
        ];

        // Restart OpenClaw after guidance sync so newly written skills/docs are
        // picked up immediately. This keeps fresh VMs and post-update sessions
        // on the latest SafeClaw protocol without relying on hot reload.
        let mut needs_restart = true;

        // Build config patch from vault secrets.
        let mut config_patch = serde_json::json!({});

        // Telegram: token + ownerId for OpenClaw channel config.
        if let Some(token) = telegram_token {
            let mut tg_patch = serde_json::json!({ "token": token });
            // Extract ownerId if present (stored alongside token in vault config).
            if let Some(owner_id) = secrets
                .get("services").and_then(|s| s.get("telegram"))
                .and_then(|t| t.get("owner_id").or_else(|| t.get("ownerId")))
                .and_then(|o| o.as_str())
            {
                tg_patch["ownerId"] = serde_json::json!(owner_id);
            }
            config_patch["channels"] = serde_json::json!({ "telegram": tg_patch });
        }

        // Model config (primary + fallback).
        if let Some(model) = secrets.get("model") {
            config_patch["model"] = model.clone();
        }

        // Pass full service data so provisioner can extract auth tokens (e.g. access_token
        // for openai-codex OAuth). Previously only passed `true` as a presence marker,
        // which caused extractAccountId to always fail with "sk-safeclaw-proxy" as apiKey.
        if let Some(svcs) = secrets.get("services").and_then(|s| s.as_object()) {
            config_patch["services"] = serde_json::json!({});
            for (k, v) in svcs {
                config_patch["services"][k] = v.clone();
            }
        }

        if config_patch.as_object().map_or(false, |o| !o.is_empty()) {
            ops.push(serde_json::json!({
                "type": "config",
                "patch": config_patch
            }));
            needs_restart = true;
        }

        // WeChat: push channel op if wechat service exists in vault.
        let has_wechat = secrets
            .get("services")
            .and_then(|s| s.get("wechat"))
            .is_some();
        if has_wechat {
            ops.push(serde_json::json!({
                "type": "channel",
                "patch": { "wechat": true }
            }));
            needs_restart = true;
        }

        // Use host.docker.internal when running inside Docker (host-gateway mapping).
        // Falls back to localhost for non-Docker environments.
        let provisioner_host = if std::path::Path::new("/.dockerenv").exists() {
            "host.docker.internal"
        } else {
            "localhost"
        };
        let _ = reqwest::Client::new()
            .post(format!("http://{}:23296/apply", provisioner_host))
            .json(&serde_json::json!({
                "ops": ops,
                "restart": needs_restart
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
    let console_url = state.config.effective_admin_url();
    if let Some(secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(secrets, proxy_port, console_url);
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
    let console_url = state.config.effective_admin_url();
    if let Some(secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(secrets, proxy_port, console_url);
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
    let console_url = state.config.effective_admin_url();
    if let Some(secrets) = state.vault.secrets.lock().unwrap().clone() {
        push_to_provisioner(secrets, proxy_port, console_url);
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

/// GET /vault/files/:id?approval=:approval_id — read file using short-lived DEK from approval.
/// The DEK was stashed by approval_confirm and is consumed (zeroized) after this read.
pub async fn vault_files_read_approved(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    // Sanitize file_id
    if !file_id.chars().all(|c| c.is_alphanumeric() || c == '-') || file_id.len() > 40 {
        return Err(AppError::BadRequest("Invalid file id".into()));
    }

    let approval_id = params.get("approval").ok_or_else(|| {
        AppError::BadRequest("Missing approval parameter".into())
    })?;
    if approval_id.len() > 64 {
        return Err(AppError::BadRequest("Invalid approval id".into()));
    }

    // Take DEK from pending_deks (one-time use)
    let mut dek = {
        let mut deks = state.vault.pending_deks.lock().unwrap();
        deks.remove(approval_id).ok_or_else(|| {
            AppError::Unauthorized("No DEK available — approval may have expired".into())
        })?
    };

    let enc_path = state.config.data_dir.join(format!("files/{}.enc", file_id));
    if !enc_path.exists() {
        dek.zeroize();
        return Err(AppError::NotFound);
    }

    // Decrypt
    let enc_data = fs::read(&enc_path)?;
    let plaintext = crate::crypto::aes_decrypt(&dek, &enc_data);
    dek.zeroize(); // DEK gone immediately

    let plaintext = plaintext?;

    // Look up filename from index for content-type
    let index = read_index(&state);
    let filename = index.get("files")
        .and_then(|f| f.as_array())
        .and_then(|arr| arr.iter().find(|f| f.get("id").and_then(|v| v.as_str()) == Some(&file_id)))
        .and_then(|f| f.get("name").and_then(|v| v.as_str()))
        .unwrap_or("file");

    let content_type = if filename.ends_with(".json") { "application/json" }
        else if filename.ends_with(".txt") || filename.ends_with(".md") || filename.ends_with(".csv") { "text/plain; charset=utf-8" }
        else if filename.ends_with(".pdf") { "application/pdf" }
        else { "application/octet-stream" };

    Ok((
        axum::http::StatusCode::OK,
        [
            ("content-type", content_type),
        ],
        plaintext,
    ))
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

    // Snapshot current in-memory dead endpoints (removed since last vault write)
    let live_endpoints: std::collections::HashSet<String> = state
        .vault
        .push_subscriptions
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.endpoint.clone())
        .collect();

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
            // Prune dead subscriptions (410/404 since last vault write)
            arr.retain(|s| {
                s.get("endpoint")
                    .and_then(|e| e.as_str())
                    .map(|e| live_endpoints.contains(e))
                    .unwrap_or(true)
            });
            // Deduplicate by endpoint before adding new
            let new_endpoint = sub.get("endpoint").and_then(|e| e.as_str()).unwrap_or("");
            arr.retain(|s| s.get("endpoint").and_then(|e| e.as_str()) != Some(new_endpoint));
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

// GET /approve/:id/status removed — replaced by GET /approve/{id} on proxy port (async 202 flow).

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
    // Get service name from the pending approval
    let service_name = {
        let pending = state.approval_manager.pending.lock().unwrap();
        pending.get(&id).map(|a| a.service.clone())
    };

    let service_name = match service_name {
        Some(s) => s,
        None => return Err(AppError::NotFound),
    };

    // For "files" service: derive DEK and stash it for the upcoming replay request
    if service_name == "files" {
        let user_key_b64 = auth.get_str("userKey")?;
        let user_key = STANDARD.decode(user_key_b64)
            .map_err(|e| AppError::BadRequest(format!("Invalid userKey: {}", e)))?;
        let fname = credential_id_to_filename(&auth.credential_id)?;
        let wrapped_path = state.config.data_dir.join(format!("wrapped_dek_{}.bin", fname));
        let sk_d = jwk_sk_d_bytes(&state.keypair.sk)?;
        let mut kek = derive_kek(&user_key, &sk_d)?;
        let wrapped = fs::read(&wrapped_path)?;
        let dek = unwrap_dek(&wrapped, &kek)?;
        kek.zeroize();

        // Store DEK keyed by approval ID — consumed and zeroized at file read time
        state.vault.pending_deks.lock().unwrap().insert(id.clone(), dek);

        if state.approval_manager.confirm(&id, None) {
            Ok(Json(json!({ "ok": true })))
        } else {
            // Clean up if confirm failed
            use zeroize::Zeroize;
            if let Some(mut d) = state.vault.pending_deks.lock().unwrap().remove(&id) { d.zeroize(); }
            Err(AppError::NotFound)
        }
    } else {
        // Normal service: decrypt vault and extract auth config for replay
        let auth_json = decrypt_vault_json(&state, &auth)
            .ok()
            .and_then(|secrets| {
                secrets
                    .get("services")
                    .and_then(|s| s.get(&service_name))
                    .and_then(|svc| svc.get("auth"))
                    .cloned()
            });

        if state.approval_manager.confirm(&id, auth_json) {
            Ok(Json(json!({ "ok": true })))
        } else {
            Err(AppError::NotFound)
        }
    }
}

/// POST /approve/:id/reject — reject a pending request (passkey required)
pub async fn approval_reject(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let _ = auth; // passkey verified by extractor

    // Fetch approval info before rejecting so we can write the audit entry
    let approval_info = state.audit_log.get_approval(&id).ok().flatten();

    if state.approval_manager.reject(&id) {
        if let Some(rec) = approval_info {
            state.audit_log.log_request(
                &rec.service,
                &rec.method,
                &rec.path,
                "ask",
                "rejected",
                None,
                None,
                Some(&id),
            );
        }
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
    let console_url = state.config.effective_admin_url();
    let content = {
        let secrets_guard = state.vault.secrets.lock().unwrap();
        if let Some(ref s) = *secrets_guard {
            crate::cli::generate::generate_safeclaw_md(s, false, state.config.proxy_port, &console_url)
        } else {
            drop(secrets_guard);
            let names = state.vault.service_names.lock().unwrap().clone();
            let services: serde_json::Map<String, Value> =
                names.into_iter().map(|n| (n, Value::Null)).collect();
            let minimal = json!({ "services": services });
            crate::cli::generate::generate_safeclaw_md(&minimal, locked, state.config.proxy_port, &console_url)
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
            crate::cli::generate::generate_agents_md_snippet(s, state.config.proxy_port)
        } else {
            drop(secrets_guard);
            let names = state.vault.service_names.lock().unwrap().clone();
            let services: serde_json::Map<String, Value> =
                names.into_iter().map(|n| (n, Value::Null)).collect();
            let minimal = json!({ "services": services });
            crate::cli::generate::generate_agents_md_snippet(&minimal, state.config.proxy_port)
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

// ── Admin Upgrade ─────────────────────────────────────────────────────────────

/// POST /admin/upgrade — passkey-protected software update.
///
/// Triggers a self-update by calling the local provisioner's /update endpoint.
/// The provisioner runs `safeclaw update` inside the container (or on host).
///
/// Payload: { scope?: "all" | "templates" }
///   - "all" (default): update binary + templates, restarts safeclaw
///   - "templates": update templates only, no restart needed
pub async fn admin_upgrade(
    State(state): State<Arc<AppState>>,
    _auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let scope = _auth
        .payload
        .get("scope")
        .and_then(|s| s.as_str())
        .unwrap_or("all")
        .to_string();

    if scope != "all" && scope != "templates" {
        return Err(AppError::BadRequest(format!("Invalid scope: {scope}. Use 'all' or 'templates'.")));
    }

    // Call provisioner /update endpoint
    let provisioner_host = if std::path::Path::new("/.dockerenv").exists() {
        "host.docker.internal"
    } else {
        "localhost"
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap_or_default();

    let resp = client
        .post(format!("http://{}:23296/update", provisioner_host))
        .json(&json!({ "scope": scope }))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Provisioner unreachable: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("Provisioner error: {body}")));
    }

    let result: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({ "ok": true }));

    Ok(Json(json!({
        "ok": true,
        "scope": scope,
        "result": result
    })))
}

// ── Audit Log ──────────────────────────────────────────────────────────────────

/// GET /audit/log?limit=50&service=openai&decision=denied&since=2024-01-01T00:00:00
/// List audit entries. No auth required — contains operational metadata only, no secrets.
pub async fn audit_log_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit    = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(50u32).min(500);
    let service  = params.get("service").map(|s| s.as_str());
    let decision = params.get("decision").map(|s| s.as_str());
    let since    = params.get("since").map(|s| s.as_str());
    match state.audit_log.list_entries(limit, service, decision, since) {
        Ok(entries) => Json(json!({ "entries": entries })).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}
