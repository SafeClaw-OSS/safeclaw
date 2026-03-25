pub mod nonce;
pub mod webauthn;

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use axum::{
    extract::{FromRequest, Request},
    body::Bytes,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::ecies::e2e_decrypt;
use crate::crypto::keys::jwk_sk_d_bytes;
use crate::error::{AppError, Result};
use crate::state::AppState;
use self::webauthn::{verify_assertion, AssertionData};

/// Passkey entry as stored in passkeys.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyEntry {
    pub x: String, // standard base64
    pub y: String, // standard base64
    #[serde(rename = "deviceName", default)]
    pub device_name: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: u64,
}

/// Result of a successful authenticated request
pub struct AuthenticatedRequest {
    /// Decrypted inner payload as JSON
    pub payload: Value,
    /// Credential ID of the authenticating passkey
    pub credential_id: String,
    /// Full passkeys map from passkeys.json
    pub passkeys: HashMap<String, PasskeyEntry>,
}

impl AuthenticatedRequest {
    /// Get a field from the inner payload
    pub fn get_str(&self, key: &str) -> Result<&str> {
        self.payload
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("Missing field '{}' in payload", key)))
    }
}

/// Axum extractor that performs the full auth flow:
///   1. Read body → parse { payload: base64 }
///   2. Base64-decode payload → JSON bytes (E2E wire format)
///   3. E2E decrypt using VM private key
///   4. Parse inner JSON → extract { nonce, credentialId, assertion }
///   5. Check nonce (in-memory HashSet)
///   6. Load passkey (x, y) from passkeys.json
///   7. Verify WebAuthn P-256 assertion
impl FromRequest<Arc<AppState>> for AuthenticatedRequest {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &Arc<AppState>) -> std::result::Result<Self, Self::Rejection> {
        // Read body bytes
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| AppError::BadRequest("Failed to read request body".into()))?;

        authenticate_bytes(&bytes, state)
    }
}

/// Core authentication logic, extracted so routes can call it with pre-read body bytes too
pub fn authenticate_bytes(bytes: &[u8], state: &Arc<AppState>) -> Result<AuthenticatedRequest> {
    // Parse outer body: { payload: base64 }
    let outer: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| AppError::BadRequest("Invalid JSON body".into()))?;

    let payload_b64 = outer
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing 'payload' field in body".into()))?;

    // Decode base64 → E2E wire bytes
    let wire_bytes = STANDARD
        .decode(payload_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid payload base64: {}", e)))?;

    // E2E decrypt
    let vm_sk_d = jwk_sk_d_bytes(&state.vm_keypair.sk)?;
    let plaintext = e2e_decrypt(&wire_bytes, &vm_sk_d)?;

    // Parse inner payload
    let inner: Value = serde_json::from_slice(&plaintext)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;

    // Extract required fields
    let nonce_b64 = inner
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing 'nonce' in decrypted payload".into()))?;
    let credential_id = inner
        .get("credentialId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing 'credentialId' in decrypted payload".into()))?
        .to_string();

    // Decode nonce from base64
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid nonce base64: {}", e)))?;

    // Check nonce
    {
        let mut nonce_store = state.nonces.lock().unwrap();
        if !nonce_store.check_and_insert(&nonce_bytes) {
            return Err(AppError::BadRequest("Nonce already used".into()));
        }
    }

    // Load passkeys.json
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    if !passkeys_path.exists() {
        return Err(AppError::Unauthorized("Not set up — no passkeys registered".into()));
    }
    let passkeys: HashMap<String, PasskeyEntry> =
        serde_json::from_str(&fs::read_to_string(&passkeys_path)?)
            .map_err(|e| AppError::Internal(format!("Failed to parse passkeys.json: {}", e)))?;

    // Look up the credential
    let entry = passkeys
        .get(&credential_id)
        .ok_or_else(|| AppError::Unauthorized("Unknown credential ID".into()))?;

    // Extract assertion from inner payload
    let assertion: AssertionData = serde_json::from_value(
        inner
            .get("assertion")
            .cloned()
            .ok_or_else(|| AppError::BadRequest("Missing 'assertion' in decrypted payload".into()))?,
    )
    .map_err(|e| AppError::BadRequest(format!("Invalid assertion format: {}", e)))?;

    // Verify assertion (skip if x/y are null — this happens for discoverable credentials
    // where the client didn't extract the public key SPKI)
    if !entry.x.is_empty() && !entry.y.is_empty() {
        verify_assertion(
            &assertion,
            &entry.x,
            &entry.y,
            &state.config.effective_origin(),
            &state.config.effective_rp_id(),
        )?;
    }

    Ok(AuthenticatedRequest {
        payload: inner,
        credential_id,
        passkeys,
    })
}
