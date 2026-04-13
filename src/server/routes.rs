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

use crate::crypto::binding::{
    binding_for_request, DOMAIN_IDENTITY, DOMAIN_SETUP, DOMAIN_SETUP_OVERWRITE,
};
use crate::crypto::kdf::{derive_kek, derive_response_seal_key};
use crate::crypto::vault_file::{decrypt_vault as vf_decrypt, save_atomic as save_vault};
use crate::crypto::dek_wraps::{
    unwrap_dek, wrap_dek_for_credential, wrap_dek_with_kek, DekWrapManifest, DekWrapEntry,
};
use crate::crypto::{aead, fresh_file_key, fresh_prf_salt, generate_dek, vault_file};
use crate::passkey::webauthn::{verify_assertion, AssertionData, AssertionKind};
use crate::passkey::{authenticate_bytes, AuthenticatedRequest, PasskeyEntry};
use crate::error::{AppError, Result};
use crate::notify::PushSubscription;
use crate::state::AppState;

// ── WebAuthn Related Origin Requests (ROR) ────────────────────────────────────

/// GET /.well-known/webauthn — declare which origins may use this domain's passkeys.
/// Required for cross-origin passkey sharing (e.g. NodPay using SafeClaw passkeys).
pub async fn well_known_webauthn() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        Json(json!({ "origins": ["https://nodpay.ai"] })),
    )
}

// ── Passkey Public Coordinates ────────────────────────────────────────────────

/// GET /passkeys/public — return all registered passkey (x, y) coordinates as hex.
/// Public key material — no auth required. Used by NodPay wallet creation.
pub async fn passkeys_public(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    if !passkeys_path.exists() {
        return Json(json!({ "passkeys": [] })).into_response();
    }
    let passkeys: HashMap<String, PasskeyEntry> = match fs::read_to_string(&passkeys_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(p) => p,
        None => return Json(json!({ "passkeys": [] })).into_response(),
    };

    let entries: Vec<Value> = passkeys
        .iter()
        .map(|(cred_id, entry)| {
            let x_hex = base64_to_hex(&entry.x);
            let y_hex = base64_to_hex(&entry.y);
            json!({
                "credentialId": cred_id,
                "x": x_hex,
                "y": y_hex,
                "deviceName": entry.device_name,
            })
        })
        .collect();

    Json(json!({ "passkeys": entries })).into_response()
}

/// Convert standard base64 to 0x-prefixed hex string.
fn base64_to_hex(b64: &str) -> String {
    match STANDARD.decode(b64) {
        Ok(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            format!("0x{}", hex)
        }
        Err(_) => String::new(),
    }
}

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
    let vapid_public_key = state.vault.vapid.lock().unwrap().as_ref().map(|kp| kp.public_key.clone());
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

// ── Challenge ─────────────────────────────────────────────────────────────────

/// GET /challenge — issue a one-time `server_random` and return the
/// `(credential_id, prf_salt)` list so the client can prepare a channel-bound
/// WebAuthn request.
///
/// The response contains only public material. Single-use, TTL 5min, rate-limited.
/// Pre-setup: returns empty `dek_wraps` list so the setup flow can still
/// use this endpoint for a proper server-issued challenge.
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();
    let server_random = {
        let mut store = state.challenges.lock().unwrap();
        match store.issue(ip) {
            Some(c) => c,
            None => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "challenge rate limit exceeded" })),
                )
                    .into_response();
            }
        }
    };

    let dek_wraps_path = state.config.data_dir.join("dek_wraps.bin");
    let wrapped = if dek_wraps_path.exists() {
        match DekWrapManifest::load(&dek_wraps_path) {
            Ok(m) => m
                .entries
                .iter()
                .map(|e| {
                    json!({
                        "credential_id": STANDARD.encode(&e.credential_id),
                        "prf_salt":      STANDARD.encode(&e.prf_salt),
                    })
                })
                .collect::<Vec<Value>>(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    Json(json!({
        "server_random": server_random,
        "dek_wraps":  wrapped,
    }))
    .into_response()
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

fn write_index(state: &AppState, vault_data: &Value) -> std::io::Result<()> {
    // Store lightweight service metadata (name + category + group) — no credentials.
    // group and category are enriched from service.toml via ServiceRegistry.
    let registry = crate::service::ServiceRegistry::load();
    let services: Vec<Value> = vault_data
        .get("services")
        .and_then(|s| s.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(name, cfg)| {
                    let svc_def = registry.get(name);
                    let category = svc_def
                        .map(|d| d.service.category.as_str())
                        .or_else(|| cfg.get("category").and_then(|v| v.as_str()))
                        .unwrap_or("service");
                    let mut entry = json!({ "name": name, "category": category });
                    // Add group from service.toml (for UI card merging)
                    if let Some(group) = svc_def.and_then(|d| d.service.group.as_deref()) {
                        entry["group"] = json!(group);
                    }
                    // Add display name from service.toml
                    if let Some(display_name) = svc_def.map(|d| d.service.name.as_str()) {
                        entry["display_name"] = json!(display_name);
                    }
                    if let Some(sub) = svc_def.and_then(|d| d.service.sub.as_deref()) {
                        entry["sub"] = json!(sub);
                    }
                    // Upstream: vault data first, then service.toml
                    let has_upstream = cfg.get("upstream").and_then(|u| u.as_str()).is_some()
                        || svc_def.map(|d| !d.upstream.is_empty()).unwrap_or(false);
                    if has_upstream {
                        entry["upstream"] = json!(cfg.get("upstream").and_then(|u| u.as_str())
                            .or_else(|| svc_def.and_then(|d| d.upstream_url()))
                            .unwrap_or("local"));
                    }
                    // Expose wallet metadata (safe address, chains) for integration services
                    if let Some(wallet) = cfg.get("wallet") {
                        let mut meta = serde_json::Map::new();
                        if let Some(safe) = wallet.get("safe") { meta.insert("safe".into(), safe.clone()); }
                        if let Some(chains) = wallet.get("chains") { meta.insert("chains".into(), chains.clone()); }
                        if let Some(rpid) = wallet.get("rpId") { meta.insert("rpId".into(), rpid.clone()); }
                        if let Some(px) = wallet.get("passkeyX") { meta.insert("passkeyX".into(), px.clone()); }
                        if let Some(py) = wallet.get("passkeyY") { meta.insert("passkeyY".into(), py.clone()); }
                        if let Some(rc) = wallet.get("recovery") { meta.insert("recovery".into(), rc.clone()); }
                        entry["wallet"] = Value::Object(meta);
                    }
                    entry
                })
                .collect()
        })
        .unwrap_or_default();

    let files: Vec<Value> = vault_data
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

// ── v2 Vault Decrypt/Write Helpers ─────────────────────────────────────────────

/// Load `dek_wraps.bin` from disk.
fn load_dek_wraps(state: &AppState) -> Result<DekWrapManifest> {
    let path = state.config.data_dir.join("dek_wraps.bin");
    DekWrapManifest::load(&path)
}

/// Save `dek_wraps.bin` atomically.
fn save_dek_wraps(state: &AppState, manifest: &DekWrapManifest) -> Result<()> {
    let path = state.config.data_dir.join("dek_wraps.bin");
    manifest.save_atomic(&path)
}

/// Unwrap the current DEK using the acting credential's userKey.
/// Returns the DEK (32 bytes). Caller is responsible for zeroization.
fn unwrap_current_dek(state: &AppState, auth: &AuthenticatedRequest) -> Result<[u8; 32]> {
    let manifest = load_dek_wraps(state)?;
    let entry = manifest
        .find(&auth.credential_id_bytes)
        .ok_or_else(|| AppError::Unauthorized("no wrap entry for this credential".into()))?;

    if auth.user_key.len() != 32 {
        return Err(AppError::BadRequest("user_key wrong length".into()));
    }
    let mut user_key_arr = [0u8; 32];
    user_key_arr.copy_from_slice(&auth.user_key);
    let dek = unwrap_dek(entry, &user_key_arr)?;
    user_key_arr.zeroize();
    Ok(dek)
}

/// Derive the response-seal key for the acting credential and encrypt a JSON
/// response body. Returns a JSON object `{ "sealed": "<b64>", "credential_id": "<b64>" }`.
///
/// The sealed payload is `nonce (24B) || ciphertext+tag`. The AAD is
/// `"safeclaw/v1/sealed_response\0" || path` to bind the response to its endpoint.
fn seal_response(state: &AppState, auth: &AuthenticatedRequest, plaintext_json: &Value) -> Result<Value> {
    let manifest = load_dek_wraps(state)?;
    let entry = manifest
        .find(&auth.credential_id_bytes)
        .ok_or_else(|| AppError::Internal("no wrap entry for seal".into()))?;

    let mut user_key_arr = [0u8; 32];
    user_key_arr.copy_from_slice(&auth.user_key);
    let mut seal_key = derive_response_seal_key(&user_key_arr, &entry.prf_salt, &auth.credential_id_bytes)?;
    user_key_arr.zeroize();

    let plaintext_bytes = serde_json::to_vec(plaintext_json)
        .map_err(|e| AppError::Internal(format!("seal serialize: {}", e)))?;

    let mut aad = Vec::with_capacity(30 + auth.path.len());
    aad.extend_from_slice(b"safeclaw/v1/sealed_response\x00");
    aad.extend_from_slice(auth.path.as_bytes());

    let nonce = aead::fresh_nonce();
    let ct = aead::encrypt(&seal_key, &nonce, &plaintext_bytes, &aad)?;
    seal_key.zeroize();

    let mut sealed = Vec::with_capacity(24 + ct.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ct);

    Ok(json!({
        "sealed": STANDARD.encode(&sealed),
        "credential_id": auth.credential_id,
    }))
}

/// Read and decrypt `vault.enc` into a JSON Value.
/// The returned value contains `peer_keks` under its reserved key.
fn decrypt_vault_cached(state: &AppState, dek: &[u8; 32]) -> Result<Value> {
    let vault_enc = fs::read(state.config.data_dir.join("vault.enc"))?;
    let plaintext_bytes = vf_decrypt(dek, &vault_enc)?;
    serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| AppError::Internal(format!("vault JSON parse: {}", e)))
}

/// End-to-end v2 write flow (Option D): decrypt, apply mutation, generate new DEK,
/// rotate prf_salt for acting credential, re-wrap for all credentials, atomic commit.
///
/// The closure `f` receives the old plaintext (including `peer_keks`) and must
/// produce the new plaintext (also including `peer_keks`, which this function
/// will overwrite with the authoritative value — so the closure may leave it
/// unchanged).
fn with_vault_mut<F>(state: &AppState, auth: &AuthenticatedRequest, f: F) -> Result<()>
where
    F: FnOnce(&mut Value) -> Result<()>,
{
    // Serialize writes in-process.
    let _guard = state.write_mutex.lock().unwrap();

    // Acting credential must have supplied user_key_next and prf_salt_next
    // (write operations always rotate).
    let user_key_next = auth
        .user_key_next
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("write op requires user_key_next".into()))?;
    let prf_salt_next = auth
        .prf_salt_next
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("write op requires prf_salt_next".into()))?;

    if user_key_next.len() != 32 {
        return Err(AppError::BadRequest("user_key_next wrong length".into()));
    }

    // 1. Unwrap current DEK.
    let mut dek_old = unwrap_current_dek(state, auth)?;

    // 2. Decrypt vault.
    let mut plaintext = decrypt_vault_cached(state, &dek_old)?;
    dek_old.zeroize();

    // 3. Apply caller mutation.
    f(&mut plaintext)?;

    // 4. Ensure peer_keks exists; read current peer KEKs for re-wrapping.
    let mut peer_keks_map: HashMap<String, [u8; 32]> = HashMap::new();
    if let Some(pk_val) = plaintext.get("peer_keks").and_then(|p| p.as_object()) {
        for (cid, kek_val) in pk_val {
            if let Some(kek_b64) = kek_val.as_str() {
                if let Ok(kek_bytes) = STANDARD.decode(kek_b64) {
                    if kek_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&kek_bytes);
                        peer_keks_map.insert(cid.clone(), arr);
                    }
                }
            }
        }
    }

    // 5. Compute acting credential's new KEK.
    let mut user_key_next_arr = [0u8; 32];
    user_key_next_arr.copy_from_slice(user_key_next);
    let mut kek_new = derive_kek(
        &user_key_next_arr,
        prf_salt_next,
        crate::crypto::WRAP_VERSION,
        &auth.credential_id_bytes,
    )?;
    user_key_next_arr.zeroize();

    // 6. Update peer_keks[acting credential] = new KEK.
    peer_keks_map.insert(auth.credential_id.clone(), kek_new);
    let peer_keks_json: serde_json::Map<String, Value> = peer_keks_map
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(STANDARD.encode(v))))
        .collect();
    if let Some(obj) = plaintext.as_object_mut() {
        obj.insert("peer_keks".into(), Value::Object(peer_keks_json));
    }

    // 7. Generate DEK_new and encrypt the new vault plaintext.
    let mut dek_new = generate_dek();
    let plaintext_bytes = serde_json::to_vec(&plaintext)
        .map_err(|e| AppError::Internal(format!("vault serialize: {}", e)))?;

    // 8. Build new wrapped_deks manifest.
    let old_manifest = load_dek_wraps(state).unwrap_or_else(|_| DekWrapManifest::new());
    let mut new_manifest = DekWrapManifest::new();

    // For each existing credential, decide how to wrap the new DEK.
    for entry in &old_manifest.entries {
        let cid_b64 = STANDARD.encode(&entry.credential_id);
        if entry.credential_id == auth.credential_id_bytes {
            // Acting credential: use the new KEK and new prf_salt.
            let new_entry = wrap_dek_with_kek(
                &dek_new,
                &kek_new,
                prf_salt_next,
                &entry.credential_id,
            )?;
            new_manifest.entries.push(new_entry);
        } else {
            // Peer credential: use its cached KEK from peer_keks, preserve its prf_salt.
            let peer_kek = peer_keks_map.get(&cid_b64).ok_or_else(|| {
                AppError::Internal(format!(
                    "peer_keks missing entry for credential {}",
                    cid_b64
                ))
            })?;
            let new_entry =
                wrap_dek_with_kek(&dek_new, peer_kek, &entry.prf_salt, &entry.credential_id)?;
            new_manifest.entries.push(new_entry);
        }
    }

    // 9. Atomic commit: write vault.enc.tmp, write dek_wraps.bin.tmp,
    //    rename dek_wraps.bin, rename vault.enc.
    let vault_path = state.config.data_dir.join("vault.enc");
    save_vault(&vault_path, &dek_new, &plaintext_bytes)?;
    save_dek_wraps(state, &new_manifest)?;

    // 10. Update in-memory vault plaintext.
    state.vault.set_plaintext(plaintext.clone());

    // 11. Update index.
    let _ = write_index(state, &plaintext);

    // 12. Zeroize.
    dek_new.zeroize();
    kek_new.zeroize();
    // Clear peer_keks_map in-place
    for (_, v) in peer_keks_map.iter_mut() {
        v.zeroize();
    }

    Ok(())
}

// ── Setup (v2) ─────────────────────────────────────────────────────────────────

/// POST /vault/setup — initial vault creation (or overwrite if existing).
///
/// v2 schema:
/// ```json
/// {
///   "server_random": "<b64 16B>",        // from GET /challenge
///   "vault": { ... initial vault JSON, must not contain peer_keks ... },
///   "passkeys": [
///     {
///       "credential_id":    "<b64>",
///       "x": "<b64>", "y": "<b64>",
///       "device_name":      "<string>",
///       "prf_salt_initial": "<b64 32B>",
///       "user_key_initial": "<b64 32B>",
///       "assertion":        { authenticator_data, client_data_json, signature }
///     }
///   ],
///   "existing_credential_id": "<b64>" | null,
///   "existing_assertion":     { ... } | null
/// }
/// ```
///
/// Setup uses the standard `GET /session` to obtain a `server_random` from the
/// server-side `ChallengeStore`. When no vault exists yet, `GET /session` returns
/// the random plus an empty `wrapped_deks` list. This gives setup the same
/// server-issued freshness guarantee as every other authenticated operation.
pub async fn setup(
    State(state): State<Arc<AppState>>,
    bytes: Bytes,
) -> Result<impl IntoResponse> {
    let parsed: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("setup body not valid JSON".into()))?;

    // Server-issued one-time challenge. Consumed from ChallengeStore here.
    let server_random_b64 = parsed
        .get("server_random")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing server_random".into()))?
        .to_string();
    let server_random = STANDARD
        .decode(&server_random_b64)
        .map_err(|_| AppError::BadRequest("server_random not base64".into()))?;
    if server_random.len() != 16 {
        return Err(AppError::BadRequest("server_random must be 16 bytes".into()));
    }
    {
        let mut cs = state.challenges.lock().unwrap();
        if !cs.verify(&server_random_b64) {
            return Err(AppError::Unauthorized(
                "invalid or expired server_random".into(),
            ));
        }
    }

    let passkeys_arr = parsed
        .get("passkeys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::BadRequest("missing passkeys array".into()))?;
    if passkeys_arr.is_empty() {
        return Err(AppError::BadRequest("at least one passkey required".into()));
    }

    let mut vault_data = parsed
        .get("vault")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("missing vault".into()))?;

    // Strip any client-supplied peer_keks; we'll install the authoritative map below.
    if let Some(obj) = vault_data.as_object_mut() {
        obj.remove("peer_keks");
    }

    // Inject VAPID key pair if not already present.
    if vault_data.get("vapid_private_key").is_none() {
        if let Ok((priv_b64, _)) = crate::notify::webpush::generate_vapid_keypair() {
            if let Some(obj) = vault_data.as_object_mut() {
                obj.insert(
                    "vapid_private_key".into(),
                    serde_json::Value::String(priv_b64),
                );
            }
        }
    }

    // Overwrite gate: if a vault already exists, require an assertion from an
    // existing credential with setup-overwrite channel binding.
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    if passkeys_path.exists() {
        let existing_passkeys: HashMap<String, PasskeyEntry> =
            serde_json::from_str(&fs::read_to_string(&passkeys_path)?)
                .map_err(|e| AppError::Internal(format!("passkeys.json: {}", e)))?;

        let existing_cred_id = parsed
            .get("existing_credential_id")
            .or_else(|| parsed.get("existingCredentialId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::Unauthorized("vault exists: existing passkey required".into())
            })?;
        let existing_assertion_val = parsed
            .get("existing_assertion")
            .or_else(|| parsed.get("existingAssertion"))
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("missing existing_assertion".into()))?;

        let entry = existing_passkeys
            .get(existing_cred_id)
            .ok_or_else(|| AppError::Unauthorized("unknown existing credential".into()))?;

        let existing_assertion: AssertionData = serde_json::from_value(existing_assertion_val)
            .map_err(|e| AppError::BadRequest(format!("invalid existing_assertion: {}", e)))?;

        // Channel binding: compute expected challenge from the setup body
        // minus the assertion fields (which are computed using the binding).
        // The canonicalizer strips `assertion` and `server_random` automatically.
        let mut body_for_binding = parsed.clone();
        if let Some(obj) = body_for_binding.as_object_mut() {
            obj.remove("existing_assertion");
            obj.remove("existingAssertion");
        }
        let expected_binding = binding_for_request(
            DOMAIN_SETUP_OVERWRITE,
            &server_random,
            "POST",
            "/vault/setup",
            &body_for_binding,
        );

        verify_assertion(
            &existing_assertion,
            &entry.x,
            &entry.y,
            &state.config.effective_origin(),
            &state.config.effective_rp_id(),
            &expected_binding,
            AssertionKind::Get,
        )?;
    }

    // Verify each passkey's assertion. The binding for setup is:
    //   binding = SHA-256("safeclaw/v1/binding-setup\0" || server_random || request_hash)
    let mut body_for_setup_binding = parsed.clone();
    if let Some(obj) = body_for_setup_binding.as_object_mut() {
        // Strip per-passkey assertion fields before computing the hash.
        if let Some(arr) = obj.get_mut("passkeys").and_then(|v| v.as_array_mut()) {
            for pk in arr.iter_mut() {
                if let Some(pkobj) = pk.as_object_mut() {
                    pkobj.remove("assertion");
                }
            }
        }
        obj.remove("existing_assertion");
        obj.remove("existingAssertion");
    }
    let setup_binding = binding_for_request(
        DOMAIN_SETUP,
        &server_random,
        "POST",
        "/vault/setup",
        &body_for_setup_binding,
    );

    let mut passkeys_map: HashMap<String, PasskeyEntry> = HashMap::new();
    let mut collected_initial: Vec<(String, Vec<u8>, [u8; 32], [u8; 32])> = Vec::new();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    for (i, pk_val) in passkeys_arr.iter().enumerate() {
        let cred_id_b64 = pk_val
            .get("credential_id")
            .or_else(|| pk_val.get("credentialId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("passkey {}: missing credential_id", i)))?;
        let cred_id_bytes = STANDARD
            .decode(cred_id_b64)
            .map_err(|_| AppError::BadRequest(format!("passkey {}: credential_id not base64", i)))?;
        let x = pk_val.get("x").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let y = pk_val.get("y").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if x.is_empty() || y.is_empty() {
            return Err(AppError::BadRequest(format!("passkey {}: missing x/y", i)));
        }

        let prf_salt_b64 = pk_val
            .get("prf_salt_initial")
            .or_else(|| pk_val.get("prfSaltInitial"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("passkey {}: missing prf_salt_initial", i)))?;
        let user_key_b64 = pk_val
            .get("user_key_initial")
            .or_else(|| pk_val.get("userKeyInitial"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("passkey {}: missing user_key_initial", i)))?;

        let prf_salt_bytes = STANDARD
            .decode(prf_salt_b64)
            .map_err(|_| AppError::BadRequest(format!("passkey {}: prf_salt_initial not base64", i)))?;
        if prf_salt_bytes.len() != 32 {
            return Err(AppError::BadRequest(format!("passkey {}: prf_salt must be 32B", i)));
        }
        let mut prf_salt_arr = [0u8; 32];
        prf_salt_arr.copy_from_slice(&prf_salt_bytes);

        let user_key_bytes = STANDARD
            .decode(user_key_b64)
            .map_err(|_| AppError::BadRequest(format!("passkey {}: user_key_initial not base64", i)))?;
        if user_key_bytes.len() != 32 {
            return Err(AppError::BadRequest(format!("passkey {}: user_key must be 32B", i)));
        }
        let mut user_key_arr = [0u8; 32];
        user_key_arr.copy_from_slice(&user_key_bytes);

        // Verify this passkey's assertion with setup channel binding.
        let assertion_val = pk_val
            .get("assertion")
            .cloned()
            .ok_or_else(|| AppError::BadRequest(format!("passkey {}: missing assertion", i)))?;
        let assertion: AssertionData = serde_json::from_value(assertion_val)
            .map_err(|e| AppError::BadRequest(format!("passkey {}: invalid assertion: {}", i, e)))?;

        if let Some(ref a_cid) = assertion.credential_id {
            if a_cid != cred_id_b64 {
                return Err(AppError::BadRequest(format!(
                    "passkey {}: assertion credential_id mismatch",
                    i
                )));
            }
        }

        verify_assertion(
            &assertion,
            &x,
            &y,
            &state.config.effective_origin(),
            &state.config.effective_rp_id(),
            &setup_binding,
            AssertionKind::Get,
        )?;

        let device_name = pk_val
            .get("device_name")
            .or_else(|| pk_val.get("deviceName"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        passkeys_map.insert(
            cred_id_b64.to_string(),
            PasskeyEntry {
                x: x.clone(),
                y: y.clone(),
                device_name,
                created_at: now_ms,
            },
        );

        collected_initial.push((cred_id_b64.to_string(), cred_id_bytes, prf_salt_arr, user_key_arr));
    }

    // Build peer_keks and wrapped_deks manifest.
    fs::create_dir_all(&state.config.data_dir)?;

    let mut dek = generate_dek();
    let mut peer_keks_obj = serde_json::Map::new();
    let mut manifest = DekWrapManifest::new();

    for (cid_b64, cid_bytes, prf_salt, mut user_key) in collected_initial {
        let entry = wrap_dek_for_credential(&dek, &user_key, &prf_salt, &cid_bytes)?;
        // Compute and store this credential's current KEK in peer_keks.
        let mut kek = derive_kek(
            &user_key,
            &prf_salt,
            crate::crypto::WRAP_VERSION,
            &cid_bytes,
        )?;
        peer_keks_obj.insert(cid_b64.clone(), Value::String(STANDARD.encode(&kek)));
        kek.zeroize();
        user_key.zeroize();
        manifest.entries.push(entry);
    }

    if let Some(obj) = vault_data.as_object_mut() {
        obj.insert("peer_keks".into(), Value::Object(peer_keks_obj));
    }

    // Encrypt vault and commit files atomically.
    let vault_path = state.config.data_dir.join("vault.enc");
    let plaintext_bytes = serde_json::to_vec(&vault_data)
        .map_err(|e| AppError::Internal(format!("vault serialize: {}", e)))?;
    save_vault(&vault_path, &dek, &plaintext_bytes)?;
    dek.zeroize();

    save_dek_wraps(&state, &manifest)?;

    fs::write(&passkeys_path, serde_json::to_string(&passkeys_map)?)?;

    let _ = write_index(&state, &vault_data);
    state.vault.set_plaintext(vault_data.clone());

    dispatch_cook(
        vault_data,
        state.config.proxy_port,
        state.config.effective_admin_url(),
        state.config.data_dir.clone(),
        state.config.instance_id.clone().unwrap_or_default(),
        None,
    );

    Ok(Json(json!({ "ok": true })))
}

// ── Vault Unlock (v2) ──────────────────────────────────────────────────────────

/// POST /vault/unlock — decrypt vault.enc into server memory.
pub async fn vault_unlock(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let mut dek = unwrap_current_dek(&state, &auth)?;
    let vault_data = decrypt_vault_cached(&state, &dek)?;
    dek.zeroize();
    state.vault.set_plaintext(vault_data);
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

// ── Vault Read ────────────────────────────────────────────────────────────────

/// POST /vault/read — return vault plaintext, sealed with the response seal key.
///
/// The response is encrypted with a credential-specific key derived from
/// `user_key + prf_salt`, providing defense-in-depth beyond TLS.
pub async fn vault_read(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let mut dek = unwrap_current_dek(&state, &auth)?;
    let mut plaintext = decrypt_vault_cached(&state, &dek)?;
    dek.zeroize();

    // Strip peer_keks from the client-visible plaintext.
    if let Some(obj) = plaintext.as_object_mut() {
        obj.remove("peer_keks");
    }

    let output = if let Some(select) = auth.payload.get("select").and_then(|v| v.as_str()) {
        select_paths(&plaintext, select)
    } else {
        plaintext
    };

    Ok(Json(seal_response(&state, &auth, &output)?))
}

/// Extract subtrees from a JSON value by dot-notation path prefixes.
/// `paths` is a comma-separated string like "services.telegram,channels.telegram".
/// Returns a new JSON object preserving the original structure with only matching subtrees.
fn select_paths(full: &Value, paths: &str) -> Value {
    let mut result = serde_json::Map::new();
    for path in paths.split(',') {
        let segments: Vec<&str> = path.trim().split('.').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() { continue; }
        // Walk into `full` to find the value at this path
        let mut cursor = full;
        let mut found = true;
        for seg in &segments {
            match cursor.get(*seg) {
                Some(v) => cursor = v,
                None => { found = false; break; }
            }
        }
        if !found { continue; }
        // Rebuild the path structure in result
        let mut target = &mut result;
        for (i, seg) in segments.iter().enumerate() {
            if i == segments.len() - 1 {
                target.insert(seg.to_string(), cursor.clone());
            } else {
                target = target
                    .entry(seg.to_string())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()))
                    .as_object_mut()
                    .unwrap();
            }
        }
    }
    Value::Object(result)
}

// ── Vault Update (v2) ──────────────────────────────────────────────────────────

/// POST /vault/update — replace vault contents and rotate DEK.
pub async fn vault_update(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let new_vault_data = auth
        .payload
        .get("new_vault")
        .or_else(|| auth.payload.get("newSecrets"))
        .cloned()
        .ok_or_else(|| AppError::BadRequest("missing new_vault".into()))?;

    with_vault_mut(&state, &auth, move |vault_data| {
        // Replace the top-level vault with new_vault_data, but keep peer_keks
        // (with_vault_mut will re-install the authoritative value after this closure).
        let existing_peer_keks = vault_data.get("peer_keks").cloned();
        *vault_data = new_vault_data;
        if let Some(obj) = vault_data.as_object_mut() {
            // Strip any client-supplied peer_keks and restore the existing one;
            // with_vault_mut will mutate it further for the acting credential.
            obj.remove("peer_keks");
            if let Some(pk) = existing_peer_keks {
                obj.insert("peer_keks".into(), pk);
            }
        }
        Ok(())
    })?;

    // Trigger a full cook with the updated vault.
    if let Some(vault_data) = state.vault.plaintext.lock().unwrap().clone() {
        dispatch_cook(
            vault_data,
            state.config.proxy_port,
            state.config.effective_admin_url(),
            state.config.data_dir.clone(),
            state.config.instance_id.clone().unwrap_or_default(),
            None,
        );
    }

    Ok(Json(json!({ "ok": true })))
}

// ── Local Service File Sync ───────────────────────────────────────────────────

/// Write local service files to the data volume so CLI subprocesses can read them.
/// Currently handles NodPay: writes wallet JSON to {data_dir}/.nodpay/wallets/{safe}.json
/// so that `npx nodpay wallets --json` works inside the safeclaw container.
fn sync_local_service_files(vault_data: &serde_json::Value, data_dir: &std::path::Path) {
    let Some(nodpay) = vault_data.get("services").and_then(|s| s.get("nodpay")) else { return };
    let Some(wallet) = nodpay.get("wallet") else { return };
    let Some(safe) = wallet.get("safe").and_then(|s| s.as_str()) else { return };

    let wallets_dir = data_dir.join(".nodpay").join("wallets");
    if let Err(e) = fs::create_dir_all(&wallets_dir) {
        tracing::warn!("Failed to create .nodpay/wallets dir: {e}");
        return;
    }

    // Build wallet JSON matching nodpay CLI's expected format
    let wallet_json = json!({
        "safe": safe,
        "agentSigner": wallet.get("agentSigner")
            .or_else(|| nodpay.get("auth").and_then(|a| a.get("address")))
            .unwrap_or(&json!(null)),
        "humanSignerPasskeyX": wallet.get("passkeyX").unwrap_or(&json!(null)),
        "humanSignerPasskeyY": wallet.get("passkeyY").unwrap_or(&json!(null)),
        "recoverySigner": wallet.get("recovery").unwrap_or(&json!(null)),
        "chains": wallet.get("chains").unwrap_or(&json!([])),
        "rpId": wallet.get("rpId").unwrap_or(&json!(null)),
        "createdAt": wallet.get("createdAt").unwrap_or(&json!(null)),
    });

    let path = wallets_dir.join(format!("{safe}.json"));
    match fs::write(&path, serde_json::to_string_pretty(&wallet_json).unwrap_or_default()) {
        Ok(_) => tracing::info!("Synced NodPay wallet file: {}", path.display()),
        Err(e) => tracing::warn!("Failed to write NodPay wallet file: {e}"),
    }
}

// ── Cook Dispatch ─────────────────────────────────────────────────────────────

/// Spawn a background task that dispatches cook ops to the local cooker endpoint
/// after vault state changes (setup, unlock, service add/update/remove).
/// Builds ops from vault plaintext + service recipes, sends a single POST /cook.
/// Failures are silently discarded — the vault operation has already succeeded.
fn dispatch_cook(vault_data: serde_json::Value, proxy_port: u16, console_url: String, data_dir: std::path::PathBuf, instance_id: String, service_only: Option<String>) {
    // Sync local service files (e.g. NodPay wallet JSON) before dispatching to provisioner.
    sync_local_service_files(&vault_data, &data_dir);

    tokio::spawn(async move {
        let md = crate::cli::generate::generate_safeclaw_md(&vault_data, false, proxy_port, &console_url);
        let snippet = crate::cli::generate::generate_agents_md_snippet(&vault_data, proxy_port);

        // Build steps in recipe format — provisioner executes them directly.
        let mut steps: Vec<serde_json::Value> = vec![];

        // ── System recipes (category = "system") run first, before any service recipes.
        // Currently: openclaw-runtime (gateway lifecycle, model catalog, exec approvals).
        // Skipped when only cooking a single service's recipe.
        if service_only.is_none() {
            let system_recipes = crate::generated_services::compiled_recipe_tomls();
            let system_services = crate::generated_services::compiled_service_tomls();
            for (id, _toml_str) in system_services {
                // Only include system-category services
                if let Ok(def) = toml::from_str::<crate::service::ServiceDef>(_toml_str) {
                    if def.service.category != "system" { continue; }
                }
                if let Some(recipe) = crate::cooker::load_recipe(id) {
                    for step in &recipe.steps {
                        if let Ok(val) = serde_json::to_value(step) {
                            steps.push(val);
                        }
                    }
                }
            }
        }

        // Workspace files
        steps.push(serde_json::json!({
            "title": "Write safeclaw.md",
            "target": "openclaw",
            "files": [{ "path": ".openclaw/workspace/safeclaw.md", "content": md }]
        }));
        steps.push(serde_json::json!({
            "title": "Update AGENTS.md",
            "target": "openclaw",
            "files": [{ "path": ".openclaw/workspace/AGENTS.md", "content": snippet, "upsert_block": "SAFECLAW" }]
        }));

        // Vault-driven config: set model via openclaw CLI
        // Skipped when only cooking a single service's recipe.
        if service_only.is_none() {
        if let Some(model) = vault_data.get("model") {
            let model_json = serde_json::to_string(model).unwrap_or_default();
            let escaped = model_json.replace('\'', "'\\''");
            steps.push(serde_json::json!({
                "title": "Set model config",
                "target": "openclaw",
                "run": format!("openclaw config set agents.defaults.model '{}' --strict-json", escaped)
            }));
        }
        } // end service_only.is_none() guard

        // Collect recipe steps for each enabled service (sent as-is, provisioner executes).
        // Built-in recipe steps first, then vault-side steps (overrides/additions).
        if let Some(svcs) = vault_data.get("services").and_then(|s| s.as_object()) {
            let relay_ip = std::env::var("SAFECLAW_RELAY_EGRESS_IP").unwrap_or_default();
            let resolve = |s: &str, svc_id: &str, svc_data: &serde_json::Value| -> std::result::Result<String, String> {
                let mut result = s.replace("{{safeclaw.proxy_port}}", &proxy_port.to_string())
                    .replace("{{safeclaw.admin_port}}", &console_url.split(':').last().unwrap_or("23294"))
                    .replace("{{safeclaw.admin_url}}", &console_url)
                    .replace("{{safeclaw.instance_id}}", &instance_id)
                    .replace("{{safeclaw.relay_egress_ip}}", &relay_ip)
                    .replace("{{service.id}}", svc_id);
                // Resolve {{service.vault.KEY}} — dotted keys for nested access
                while let Some(start) = result.find("{{service.vault.") {
                    let rest = &result[start + 16..];
                    if let Some(end) = rest.find("}}") {
                        let key = &rest[..end];
                        let val = match key.split('.')
                            .fold(Some(svc_data as &serde_json::Value), |acc, part| {
                                acc?.get(part)
                            })
                            .and_then(|v| v.as_str())
                        {
                            Some(v) => v,
                            None => return Err(format!("recipe template variable '{{{{service.vault.{}}}}}' not found in vault data for service '{}'", key, svc_id)),
                        };
                        result = format!("{}{}{}", &result[..start], val, &rest[end + 2..]);
                    } else {
                        break;
                    }
                }
                Ok(result)
            };
            let resolve_step = |step: &serde_json::Value, svc_id: &str, svc_data: &serde_json::Value| -> std::result::Result<serde_json::Value, String> {
                let mut s = step.clone();
                if let Some(files) = s.get_mut("files").and_then(|f| f.as_array_mut()) {
                    for f in files.iter_mut() {
                        if let Some(c) = f.get("content").and_then(|c| c.as_str()) {
                            f["content"] = serde_json::json!(resolve(c, svc_id, svc_data)?);
                        }
                        if let Some(p) = f.get("path").and_then(|p| p.as_str()) {
                            f["path"] = serde_json::json!(resolve(p, svc_id, svc_data)?);
                        }
                    }
                }
                if let Some(r) = s.get("run").and_then(|r| r.as_str()) {
                    s["run"] = serde_json::json!(resolve(r, svc_id, svc_data)?);
                }
                Ok(s)
            };
            'svc_loop: for (svc_id, svc_data) in svcs {
                if let Some(ref only) = service_only {
                    if svc_id != only { continue; }
                }
                // Recipe source: vault config.recipe.steps (full replace) → built-in TOML
                let recipe_steps: Option<Vec<serde_json::Value>> = svc_data
                    .get("recipe")
                    .and_then(|r| r.get("steps"))
                    .and_then(|s| s.as_array())
                    .map(|arr| arr.clone())
                    .or_else(|| {
                        crate::cooker::load_recipe(svc_id).map(|recipe| {
                            recipe.steps.iter()
                                .filter_map(|step| serde_json::to_value(step).ok())
                                .collect()
                        })
                    });

                if let Some(recipe_steps) = recipe_steps {
                    for step in &recipe_steps {
                        match resolve_step(step, svc_id, svc_data) {
                            Ok(resolved) => steps.push(resolved),
                            Err(e) => {
                                tracing::error!("Recipe resolution failed for service '{}': {}", svc_id, e);
                                continue 'svc_loop;
                            }
                        }
                    }
                }
            }
        }


        let provisioner_host = if std::path::Path::new("/.dockerenv").exists() {
            "host.docker.internal"
        } else {
            "localhost"
        };
        let _ = reqwest::Client::new()
            .post(format!("http://{}:23296/cook", provisioner_host))
            .timeout(std::time::Duration::from_secs(120))
            .json(&serde_json::json!({ "steps": steps }))
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

/// GET /vault/services/:name/:key — read a single vault field for a service.
/// Returns the value directly (no passkey required — vault must be unlocked).
/// Only fields declared as [[vault]] in service.toml are accessible.
pub async fn vault_service_field(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((name, key)): axum::extract::Path<(String, String)>,
) -> Result<impl IntoResponse> {
    // Validate: only declared vault fields are readable
    let fields = state.services.vault_fields(&name);
    if !fields.iter().any(|f| f.name == key) {
        return Err(AppError::BadRequest(format!("no such vault field: {}.{}", name, key)));
    }

    let plaintext = state.vault.plaintext.lock().unwrap();
    let plaintext = plaintext.as_ref()
        .ok_or_else(|| AppError::BadRequest("vault is locked".into()))?;

    let value = plaintext
        .get("services")
        .and_then(|s| s.get(&name))
        .and_then(|svc| svc.get(&key))
        .cloned()
        .ok_or_else(|| AppError::BadRequest(format!("field not found: {}.{}", name, key)))?;

    Ok(Json(value))
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

    // Validate declared vault fields are present
    for field in state.services.vault_fields(&name) {
        if config.get(&field.name).is_none() {
            return Err(AppError::BadRequest(format!(
                "Missing required vault field: {}", field.name
            )));
        }
    }

    let service_id = name.clone();
    with_vault_mut(&state, &auth, move |vault_data| {
        let services = vault_data
            .get_mut("services")
            .and_then(|s| s.as_object_mut())
            .ok_or_else(|| AppError::Internal("Vault missing 'services' object".into()))?;
        services.insert(name, config);
        Ok(())
    })?;

    // Dispatch cook — only run this service's recipe
    let proxy_port = state.config.proxy_port;
    let console_url = state.config.effective_admin_url();
    let data_dir = state.config.data_dir.clone();
    let instance_id = state.config.instance_id.clone().unwrap_or_default();
    if let Some(vault_data) = state.vault.plaintext.lock().unwrap().clone() {
        dispatch_cook(vault_data, proxy_port, console_url, data_dir, instance_id, Some(service_id));
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

    let service_id = name.clone();
    with_vault_mut(&state, &auth, move |vault_data| {
        let services = vault_data
            .get_mut("services")
            .and_then(|s| s.as_object_mut())
            .ok_or_else(|| AppError::Internal("Vault missing 'services' object".into()))?;
        services.remove(&name);
        Ok(())
    })?;

    // Dispatch cook — update workspace files (service removed, no recipe to run)
    let proxy_port = state.config.proxy_port;
    let console_url = state.config.effective_admin_url();
    let data_dir = state.config.data_dir.clone();
    let instance_id = state.config.instance_id.clone().unwrap_or_default();
    if let Some(vault_data) = state.vault.plaintext.lock().unwrap().clone() {
        dispatch_cook(vault_data, proxy_port, console_url, data_dir, instance_id, Some(service_id));
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

    with_vault_mut(&state, &auth, move |vault_data| {
        vault_data["policy_defaults"] = new_defaults;
        Ok(())
    })?;

    Ok(Json(json!({ "ok": true })))
}

// ── Files ──────────────────────────────────────────────────────────────────────

/// Validate file name: reject path traversal, absolute paths, hidden files.
/// The name is a logical path only (physical storage uses UUID), but we still
/// validate strictly since it appears in API responses and frontend rendering.
fn validate_file_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 512 {
        return Err(AppError::BadRequest("Invalid file name length".into()));
    }
    if name.contains("..") {
        return Err(AppError::BadRequest("Path traversal not allowed".into()));
    }
    if name.starts_with('/') || name.contains('\\') || name.contains('\0') {
        return Err(AppError::BadRequest("Invalid characters in file name".into()));
    }
    if name.starts_with('.') || name.contains("/.") {
        return Err(AppError::BadRequest("Hidden paths not allowed".into()));
    }
    if name.contains("//") {
        return Err(AppError::BadRequest("Invalid path".into()));
    }
    Ok(())
}

/// GET /vault/files — list files (no passkey, from index)
pub async fn vault_files_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let index = read_index(&state);
    let files = index.get("files").cloned().unwrap_or_else(|| json!([]));
    Json(json!({ "files": files }))
}

/// GET /vault/files/:id?approval=:approval_id — read file using a short-lived
/// per-file key stashed by `approval_confirm` and consumed on this read.
pub async fn vault_files_read_approved(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    if !file_id.chars().all(|c| c.is_alphanumeric() || c == '-') || file_id.len() > 40 {
        return Err(AppError::BadRequest("invalid file id".into()));
    }

    let approval_id = params
        .get("approval")
        .ok_or_else(|| AppError::BadRequest("missing approval param".into()))?;
    if approval_id.len() > 64 {
        return Err(AppError::BadRequest("invalid approval id".into()));
    }

    // Take the stashed file_key from pending_deks (one-time use).
    let mut file_key = {
        let mut deks = state.vault.cache.pending_deks.lock().unwrap();
        deks.remove(approval_id)
            .ok_or_else(|| AppError::Unauthorized("no file_key available".into()))?
    };

    let enc_path = state
        .config
        .data_dir
        .join(format!("files/{}.enc", file_id));
    if !enc_path.exists() {
        file_key.zeroize();
        return Err(AppError::NotFound);
    }

    let enc_data = fs::read(&enc_path)?;
    let plaintext = vault_file::decrypt_file(&file_key, &file_id, &enc_data);
    file_key.zeroize();
    let plaintext = plaintext?;

    let index = read_index(&state);
    let filename = index
        .get("files")
        .and_then(|f| f.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|f| f.get("id").and_then(|v| v.as_str()) == Some(&file_id))
        })
        .and_then(|f| f.get("name").and_then(|v| v.as_str()))
        .unwrap_or("file");

    let content_type = if filename.ends_with(".json") {
        "application/json"
    } else if filename.ends_with(".txt") || filename.ends_with(".md") || filename.ends_with(".csv") {
        "text/plain; charset=utf-8"
    } else if filename.ends_with(".pdf") {
        "application/pdf"
    } else {
        "application/octet-stream"
    };

    Ok((
        axum::http::StatusCode::OK,
        [("content-type", content_type)],
        plaintext,
    ))
}

/// POST /vault/files/upload — encrypt and store a file under a fresh per-file DEK.
///
/// The file_key is generated randomly, the file is sealed as `files/<uuid>.enc`
/// in v2 format, and the file_key is stored in the vault plaintext's `files`
/// array alongside the file metadata. The vault itself is rotated as part of
/// this operation (this is a write with prf_salt_next rotation).
pub async fn vault_files_upload(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let file_name = auth
        .payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing name".into()))?
        .to_string();
    validate_file_name(&file_name)?;

    let data_b64 = auth
        .payload
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing data".into()))?;
    let file_bytes = STANDARD
        .decode(data_b64)
        .map_err(|_| AppError::BadRequest("data not base64".into()))?;
    let file_size = file_bytes.len();
    let file_id = uuid::Uuid::new_v4().to_string();

    // Generate a fresh file key and seal the file.
    let mut file_key = fresh_file_key();
    let sealed = vault_file::encrypt_file(&file_key, &file_id, &file_bytes)?;

    fs::create_dir_all(state.config.data_dir.join("files"))?;
    fs::write(
        state
            .config
            .data_dir
            .join(format!("files/{}.enc", file_id)),
        &sealed,
    )?;

    let file_key_b64 = STANDARD.encode(&file_key);
    file_key.zeroize();

    with_vault_mut(&state, &auth, {
        let file_id2 = file_id.clone();
        let file_name2 = file_name.clone();
        let file_key_b64 = file_key_b64.clone();
        move |vault_data| {
            if vault_data.get("files").is_none() {
                vault_data["files"] = json!([]);
            }
            if let Some(arr) = vault_data["files"].as_array_mut() {
                arr.push(json!({
                    "id":       file_id2,
                    "name":     file_name2,
                    "size":     file_size,
                    "file_key": file_key_b64,
                }));
            }
            Ok(())
        }
    })?;

    Ok(Json(json!({ "ok": true, "id": file_id })))
}

/// POST /vault/files/read — decrypt and return a file as base64 JSON.
pub async fn vault_files_read(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let file_id = auth
        .payload
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing id".into()))?
        .to_string();

    if !file_id.chars().all(|c| c.is_alphanumeric() || c == '-') || file_id.len() > 40 {
        return Err(AppError::BadRequest("invalid file id".into()));
    }

    let enc_path = state
        .config
        .data_dir
        .join(format!("files/{}.enc", file_id));
    if !enc_path.exists() {
        return Err(AppError::NotFound);
    }

    let mut dek = unwrap_current_dek(&state, &auth)?;
    let plaintext = decrypt_vault_cached(&state, &dek)?;
    dek.zeroize();

    let (file_name, file_key_b64) = plaintext
        .get("files")
        .and_then(|f| f.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|f| f.get("id").and_then(|v| v.as_str()) == Some(&file_id))
        })
        .and_then(|f| {
            let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("file").to_string();
            let fk = f.get("file_key").and_then(|v| v.as_str())?.to_string();
            Some((name, fk))
        })
        .ok_or(AppError::NotFound)?;

    let mut file_key_bytes = STANDARD
        .decode(&file_key_b64)
        .map_err(|_| AppError::Internal("file_key not base64".into()))?;
    if file_key_bytes.len() != 32 {
        file_key_bytes.zeroize();
        return Err(AppError::Internal("file_key wrong length".into()));
    }
    let mut file_key = [0u8; 32];
    file_key.copy_from_slice(&file_key_bytes);
    file_key_bytes.zeroize();

    let enc_data = fs::read(&enc_path)?;
    let file_plain = vault_file::decrypt_file(&file_key, &file_id, &enc_data)?;
    file_key.zeroize();

    let file_response = json!({
        "name": file_name,
        "data": STANDARD.encode(&file_plain),
    });

    Ok(Json(seal_response(&state, &auth, &file_response)?))
}

/// POST /vault/files/delete — delete an encrypted file and its metadata.
pub async fn vault_files_remove(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let file_id = auth
        .payload
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing id".into()))?
        .to_string();

    if !file_id.chars().all(|c| c.is_alphanumeric() || c == '-') || file_id.len() > 40 {
        return Err(AppError::BadRequest("invalid file id".into()));
    }

    let enc_path = state
        .config
        .data_dir
        .join(format!("files/{}.enc", file_id));
    if enc_path.exists() {
        fs::remove_file(&enc_path)?;
    }

    with_vault_mut(&state, &auth, {
        let file_id2 = file_id.clone();
        move |vault_data| {
            if let Some(files) = vault_data.get_mut("files").and_then(|f| f.as_array_mut()) {
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

    with_vault_mut(&state, &auth, move |vault_data| {
        // Migrate flat key to nested structure if needed
        if let Some(old) = vault_data.get("push_subscriptions").cloned() {
            if vault_data.get("notifications").is_none() {
                vault_data["notifications"] = json!({ "subscriptions": old });
            }
            vault_data.as_object_mut().map(|m| m.remove("push_subscriptions"));
        }
        if vault_data.get("notifications").is_none() {
            vault_data["notifications"] = json!({ "subscriptions": [] });
        }
        if let Some(arr) = vault_data["notifications"]["subscriptions"].as_array_mut() {
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

/// POST /approve/:id/details — return approval details as sealed JSON (auth required).
pub async fn approval_details(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let details: serde_json::Value = {
        let pending = state.approval_manager.pending.lock().unwrap();
        pending
            .get(&id)
            .map(|a| a.details.clone().unwrap_or(serde_json::Value::Null))
            .ok_or(AppError::NotFound)?
    };
    Ok(Json(seal_response(&state, &auth, &details)?))
}

/// POST /approve/:id/confirm — approve a pending request.
pub async fn approval_confirm(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let service_name = {
        let pending = state.approval_manager.pending.lock().unwrap();
        pending.get(&id).map(|a| a.service.clone())
    };
    let service_name = service_name.ok_or(AppError::NotFound)?;

    if service_name == "files" {
        // v2: for approval-gated file reads, we need to stash the file's per-file
        // key (not the DEK, since v2 uses per-file keys). The caller must supply
        // `file_id` in the approval confirm body so we know which file_key to
        // stash. If missing, fall back to the generic vault auth path.
        let file_id = auth
            .payload
            .get("file_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(fid) = file_id {
            let mut dek = unwrap_current_dek(&state, &auth)?;
            let plaintext = decrypt_vault_cached(&state, &dek)?;
            dek.zeroize();

            let file_key_b64 = plaintext
                .get("files")
                .and_then(|f| f.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find(|f| f.get("id").and_then(|v| v.as_str()) == Some(&fid))
                })
                .and_then(|f| f.get("file_key").and_then(|v| v.as_str()))
                .ok_or(AppError::NotFound)?
                .to_string();

            let mut fk_bytes = STANDARD
                .decode(&file_key_b64)
                .map_err(|_| AppError::Internal("file_key not base64".into()))?;
            if fk_bytes.len() != 32 {
                fk_bytes.zeroize();
                return Err(AppError::Internal("file_key wrong length".into()));
            }
            let mut fk = [0u8; 32];
            fk.copy_from_slice(&fk_bytes);
            fk_bytes.zeroize();

            state
                .vault
                .cache
                .pending_deks
                .lock()
                .unwrap()
                .insert(id.clone(), fk);

            if state.approval_manager.confirm(&id, None) {
                return Ok(Json(json!({ "ok": true })));
            } else {
                if let Some(mut d) =
                    state.vault.cache.pending_deks.lock().unwrap().remove(&id)
                {
                    d.zeroize();
                }
                return Err(AppError::NotFound);
            }
        } else {
            // No file_id supplied: confirm without stashing (approval completes
            // but any subsequent file read will need a fresh auth'd request).
            if state.approval_manager.confirm(&id, None) {
                return Ok(Json(json!({ "ok": true })));
            }
            return Err(AppError::NotFound);
        }
    }

    // Normal service: decrypt vault, extract auth config for replay.
    let mut dek = unwrap_current_dek(&state, &auth)?;
    let vault_data = decrypt_vault_cached(&state, &dek)?;
    dek.zeroize();

    let auth_json = vault_data
        .get("services")
        .and_then(|s| s.get(&service_name))
        .and_then(|svc| svc.get("auth"))
        .cloned();

    if state.approval_manager.confirm(&id, auth_json) {
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

// ── Identity: Add Passkey (v2) ─────────────────────────────────────────────────

/// POST /passkeys/add — register an additional credential.
///
/// The acting credential's auth path provides `user_key`/`user_key_next` as
/// usual (so its own wrapping rotates). The new credential's material comes
/// in as an inline `new_passkey` object with its own `assertion` field that
/// must verify with channel binding.
pub async fn identity_add_passkey(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let new_passkey = auth
        .payload
        .get("new_passkey")
        .or_else(|| auth.payload.get("newPasskey"))
        .cloned()
        .ok_or_else(|| AppError::BadRequest("missing new_passkey".into()))?;

    let new_cred_id = new_passkey
        .get("credential_id")
        .or_else(|| new_passkey.get("credentialId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing new_passkey.credential_id".into()))?
        .to_string();
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
        return Err(AppError::BadRequest("new_passkey missing x/y".into()));
    }

    let prf_salt_b64 = new_passkey
        .get("prf_salt_initial")
        .or_else(|| new_passkey.get("prfSaltInitial"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing new_passkey.prf_salt_initial".into()))?;
    let user_key_b64 = new_passkey
        .get("user_key_initial")
        .or_else(|| new_passkey.get("userKeyInitial"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing new_passkey.user_key_initial".into()))?;

    let prf_salt_bytes = STANDARD
        .decode(prf_salt_b64)
        .map_err(|_| AppError::BadRequest("prf_salt_initial not base64".into()))?;
    let user_key_bytes = STANDARD
        .decode(user_key_b64)
        .map_err(|_| AppError::BadRequest("user_key_initial not base64".into()))?;
    if prf_salt_bytes.len() != 32 || user_key_bytes.len() != 32 {
        return Err(AppError::BadRequest("prf_salt/user_key must be 32B".into()));
    }
    let mut prf_salt_arr = [0u8; 32];
    prf_salt_arr.copy_from_slice(&prf_salt_bytes);
    let mut user_key_arr = [0u8; 32];
    user_key_arr.copy_from_slice(&user_key_bytes);

    let new_cred_id_bytes = STANDARD
        .decode(&new_cred_id)
        .map_err(|_| AppError::BadRequest("new credential_id not base64".into()))?;

    // Verify the new passkey's own assertion with a nested identity channel binding.
    let new_assertion_val = new_passkey
        .get("assertion")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("missing new_passkey.assertion".into()))?;
    let new_assertion: AssertionData = serde_json::from_value(new_assertion_val)
        .map_err(|e| AppError::BadRequest(format!("invalid new assertion: {}", e)))?;

    // The new credential's assertion binds to: identity domain + server_random
    // + request hash of the top-level body with assertion fields stripped.
    let mut body_for_identity_binding = auth.payload.clone();
    if let Some(obj) = body_for_identity_binding.as_object_mut() {
        obj.remove("assertion");
        // Also strip the nested new_passkey.assertion
        if let Some(np) = obj.get_mut("new_passkey").and_then(|v| v.as_object_mut()) {
            np.remove("assertion");
        }
        if let Some(np) = obj.get_mut("newPasskey").and_then(|v| v.as_object_mut()) {
            np.remove("assertion");
        }
    }
    let identity_binding = binding_for_request(
        DOMAIN_IDENTITY,
        &auth.server_random,
        &auth.method,
        &auth.path,
        &body_for_identity_binding,
    );
    verify_assertion(
        &new_assertion,
        &new_x,
        &new_y,
        &state.config.effective_origin(),
        &state.config.effective_rp_id(),
        &identity_binding,
        AssertionKind::Get,
    )?;

    // Apply the identity change inside a vault write: this rotates DEK and
    // rewraps for all credentials, and adds a new wrapped_deks entry + a new
    // peer_keks entry for the new credential.
    let new_cred_id_clone = new_cred_id.clone();
    let new_cred_id_bytes_clone = new_cred_id_bytes.clone();
    let new_x_clone = new_x.clone();
    let new_y_clone = new_y.clone();
    let new_device_name = new_passkey
        .get("device_name")
        .or_else(|| new_passkey.get("deviceName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Precompute the new credential's KEK so the write closure can install it.
    let mut new_kek = derive_kek(
        &user_key_arr,
        &prf_salt_arr,
        crate::crypto::WRAP_VERSION,
        &new_cred_id_bytes_clone,
    )?;
    let new_kek_b64 = STANDARD.encode(&new_kek);

    with_vault_mut(&state, &auth, move |vault_data| {
        if let Some(obj) = vault_data.as_object_mut() {
            let peer = obj
                .entry("peer_keks".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(pk_obj) = peer.as_object_mut() {
                pk_obj.insert(new_cred_id_clone.clone(), Value::String(new_kek_b64));
            }
        }
        Ok(())
    })?;

    // After with_vault_mut commits, add the new credential's entry to
    // dek_wraps.bin separately (wrapping the *current* DEK via the new KEK).
    // We must unwrap the current DEK via the acting credential first.
    // Actually, the simpler path is: with_vault_mut already rotated the DEK and
    // wrapped it for existing credentials. We need a matching entry for the new
    // credential. We re-read the vault with the newly-current DEK.
    //
    // Approach: unwrap with the new credential's freshly-derived KEK after the
    // write. But the wrapped_deks manifest that with_vault_mut wrote has no
    // entry for the new credential yet. So we have to add one.
    //
    // Steps:
    //   1. Reload wrapped_deks.
    //   2. Find any existing entry, unwrap DEK using acting credential's
    //      user_key_next (since the rotation is done).
    //   3. Wrap DEK under new KEK with the new prf_salt and add to manifest.
    //   4. Save manifest.
    let mut manifest = load_dek_wraps(&state)?;
    let acting_entry = manifest
        .find(&auth.credential_id_bytes)
        .ok_or_else(|| AppError::Internal("acting credential missing after write".into()))?
        .clone();

    // The acting credential's wrapped_deks entry after the write is under
    // user_key_next (the rotation moved its KEK to the next salt). We don't
    // have user_key_next here directly since AuthenticatedRequest zeroized it
    // in with_vault_mut — but the DEK was just generated fresh in the write.
    // Simpler alternative: reload plaintext and read peer_keks[acting] to
    // reconstruct the acting credential's KEK? peer_keks stores the KEK, which
    // can unwrap the new entry.
    let peer_keks_map = state.vault.peer_keks_map();
    let acting_kek = peer_keks_map
        .get(&auth.credential_id)
        .copied()
        .ok_or_else(|| AppError::Internal("peer_keks missing acting credential".into()))?;

    let aad = crate::crypto::wrap_aad(crate::crypto::WRAP_VERSION, &auth.credential_id_bytes);
    let mut dek = aead::decrypt(
        &acting_kek,
        &acting_entry.aead_nonce,
        &acting_entry.wrapped,
        &aad,
    )?;
    let mut dek_arr = [0u8; 32];
    if dek.len() != 32 {
        dek.zeroize();
        return Err(AppError::Internal("DEK wrong length".into()));
    }
    dek_arr.copy_from_slice(&dek);
    dek.zeroize();

    let new_entry =
        wrap_dek_with_kek(&dek_arr, &new_kek, &prf_salt_arr, &new_cred_id_bytes_clone)?;
    dek_arr.zeroize();
    new_kek.zeroize();
    user_key_arr.zeroize();
    prf_salt_arr.zeroize();

    manifest.upsert(new_entry);
    save_dek_wraps(&state, &manifest)?;

    // Update passkeys.json.
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    let mut passkeys = auth.passkeys.clone();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    passkeys.insert(
        new_cred_id.clone(),
        PasskeyEntry {
            x: new_x_clone,
            y: new_y_clone,
            device_name: new_device_name,
            created_at: now_ms,
        },
    );
    fs::write(&passkeys_path, serde_json::to_string(&passkeys)?)?;

    Ok(Json(json!({ "ok": true })))
}

// ── Identity: Remove Passkey (v2) ─────────────────────────────────────────────

/// POST /passkeys/remove — remove a credential.
pub async fn identity_remove_passkey(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedRequest,
) -> Result<impl IntoResponse> {
    let remove_id = auth
        .payload
        .get("remove_credential_id")
        .or_else(|| auth.payload.get("removeCredentialId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing remove_credential_id".into()))?
        .to_string();

    if remove_id == auth.credential_id {
        return Err(AppError::BadRequest(
            "cannot remove the acting credential".into(),
        ));
    }
    if !auth.passkeys.contains_key(&remove_id) {
        return Err(AppError::BadRequest("credential not found".into()));
    }
    if auth.passkeys.len() <= 1 {
        return Err(AppError::BadRequest("cannot remove last passkey".into()));
    }

    let remove_id_bytes = STANDARD
        .decode(&remove_id)
        .map_err(|_| AppError::BadRequest("remove credential_id not base64".into()))?;
    let remove_id_clone = remove_id.clone();

    // Remove from peer_keks inside a vault write.
    with_vault_mut(&state, &auth, move |vault_data| {
        if let Some(obj) = vault_data.as_object_mut() {
            if let Some(pk) = obj.get_mut("peer_keks").and_then(|v| v.as_object_mut()) {
                pk.remove(&remove_id_clone);
            }
        }
        Ok(())
    })?;

    // Remove from dek_wraps.bin manifest.
    let mut manifest = load_dek_wraps(&state)?;
    manifest.remove(&remove_id_bytes);
    save_dek_wraps(&state, &manifest)?;

    // Remove from passkeys.json.
    let mut passkeys = auth.passkeys.clone();
    passkeys.remove(&remove_id);
    fs::write(
        state.config.data_dir.join("passkeys.json"),
        serde_json::to_string(&passkeys)?,
    )?;

    Ok(Json(json!({ "ok": true })))
}

// ── Admin: Workspace File Generation ──────────────────────────────────────────

/// GET /admin/safeclaw.md — returns a Markdown service table (no passkey required)
pub async fn admin_safeclaw_md(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let locked = state.vault.is_locked();
    let console_url = state.config.effective_admin_url();
    let content = {
        let plaintext_guard = state.vault.plaintext.lock().unwrap();
        if let Some(ref s) = *plaintext_guard {
            crate::cli::generate::generate_safeclaw_md(s, false, state.config.proxy_port, &console_url)
        } else {
            drop(plaintext_guard);
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
        let plaintext_guard = state.vault.plaintext.lock().unwrap();
        if let Some(ref s) = *plaintext_guard {
            crate::cli::generate::generate_agents_md_snippet(s, state.config.proxy_port)
        } else {
            drop(plaintext_guard);
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
