//! SafeClaw v1 passkey authentication.
//!
//! This module exposes [`AuthenticatedRequest`], an Axum extractor that parses
//! an incoming request body, runs the full WebAuthn verification chain
//! including the channel binding check, and returns a struct the route
//! handler can use to look up the credential and access the operation payload.
//!
//! Wire format for authenticated requests:
//!
//! ```json
//! {
//!   "server_random": "<b64 16B>",
//!   "credential_id": "<b64>",
//!   "user_key":      "<b64 32B>",
//!   "user_key_next": "<b64 32B>",   // optional, for write-rotation operations
//!   "prf_salt_next": "<b64 32B>",   // optional, paired with user_key_next
//!   "assertion": {
//!     "authenticator_data": "<b64>",
//!     "client_data_json":   "<b64>",
//!     "signature":          "<b64>"
//!   },
//!   /* ... operation-specific fields ... */
//! }
//! ```

pub mod challenge;
pub mod nonce;
pub mod webauthn;

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

use crate::crypto::binding::{binding_for_request, DOMAIN_STANDARD};
use crate::error::{AppError, Result};
use crate::state::AppState;

use self::webauthn::{verify_assertion, AssertionData, AssertionKind};

/// Passkey entry as stored in `data/passkeys.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyEntry {
    pub x: String,
    pub y: String,
    #[serde(rename = "deviceName", default)]
    pub device_name: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: u64,
}

/// An authenticated request extracted from an incoming HTTP POST.
///
/// The presence of this struct in a route handler parameter list triggers full
/// verification including channel binding. On any failure, the Axum extractor
/// returns `401 Unauthorized` before the handler runs.
pub struct AuthenticatedRequest {
    /// HTTP method (for introspection; the binding check already consumed it).
    pub method: String,
    /// URL path.
    pub path: String,
    /// Credential ID as base64 (matches the key in `passkeys.json`).
    pub credential_id: String,
    /// Credential ID as raw bytes (for domain separators).
    pub credential_id_bytes: Vec<u8>,
    /// 32-byte client-derived userKey for the acting credential's current salt.
    pub user_key: Vec<u8>,
    /// 32-byte client-derived userKey for the acting credential's next salt.
    /// Present on write-rotation operations.
    pub user_key_next: Option<Vec<u8>>,
    /// 32-byte fresh prf_salt for the next rotation. Paired with `user_key_next`.
    pub prf_salt_next: Option<[u8; 32]>,
    /// Server-issued one-time challenge consumed by this request.
    pub server_random: Vec<u8>,
    /// Full parsed body as JSON (including `assertion`, `user_key`, etc.).
    pub payload: Value,
    /// Loaded passkeys map from `passkeys.json`, cached for the handler's use.
    pub passkeys: HashMap<String, PasskeyEntry>,
}

impl AuthenticatedRequest {
    /// Access a top-level payload field as a string.
    pub fn get_str(&self, key: &str) -> Result<&str> {
        self.payload
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest(format!("missing field '{}' in payload", key)))
    }

    /// Access a top-level payload field by key (returns None if absent).
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }
}

impl Drop for AuthenticatedRequest {
    fn drop(&mut self) {
        self.user_key.zeroize();
        if let Some(uk) = self.user_key_next.as_mut() {
            uk.zeroize();
        }
        self.prf_salt_next.as_mut().map(|s| s.zeroize());
    }
}

impl FromRequest<Arc<AppState>> for AuthenticatedRequest {
    type Rejection = AppError;

    async fn from_request(
        req: Request,
        state: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| AppError::BadRequest("failed to read body".into()))?;

        authenticate_bytes(&method.to_string(), &path, &bytes, state, DOMAIN_STANDARD)
    }
}

/// Core authentication logic. Exposed so route handlers that pre-read the body
/// (or that need to pass a non-standard binding domain) can call it directly.
pub fn authenticate_bytes(
    method: &str,
    path: &str,
    body_bytes: &[u8],
    state: &Arc<AppState>,
    domain: &[u8],
) -> Result<AuthenticatedRequest> {
    // 1. Parse body as JSON.
    let payload: Value = serde_json::from_slice(body_bytes)
        .map_err(|_| AppError::BadRequest("body is not valid JSON".into()))?;

    // 2. Extract required fields.
    let server_random_b64 = payload
        .get("server_random")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing server_random".into()))?
        .to_string();
    let credential_id = payload
        .get("credential_id")
        .or_else(|| payload.get("credentialId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing credential_id".into()))?
        .to_string();
    let user_key_b64 = payload
        .get("user_key")
        .or_else(|| payload.get("userKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing user_key".into()))?
        .to_string();
    let assertion_val = payload
        .get("assertion")
        .cloned()
        .ok_or_else(|| AppError::BadRequest("missing assertion".into()))?;

    let server_random = STANDARD
        .decode(&server_random_b64)
        .map_err(|_| AppError::BadRequest("server_random not base64".into()))?;
    if server_random.len() != 16 {
        return Err(AppError::BadRequest("server_random must be 16 bytes".into()));
    }

    let credential_id_bytes = STANDARD
        .decode(&credential_id)
        .map_err(|_| AppError::BadRequest("credential_id not base64".into()))?;

    let mut user_key = STANDARD
        .decode(&user_key_b64)
        .map_err(|_| AppError::BadRequest("user_key not base64".into()))?;
    if user_key.len() != 32 {
        user_key.zeroize();
        return Err(AppError::BadRequest("user_key must be 32 bytes".into()));
    }

    // 3. Optional write-rotation fields.
    let user_key_next = if let Some(uk_next_b64) = payload
        .get("user_key_next")
        .or_else(|| payload.get("userKeyNext"))
        .and_then(|v| v.as_str())
    {
        let mut uk = STANDARD
            .decode(uk_next_b64)
            .map_err(|_| AppError::BadRequest("user_key_next not base64".into()))?;
        if uk.len() != 32 {
            uk.zeroize();
            return Err(AppError::BadRequest("user_key_next must be 32 bytes".into()));
        }
        Some(uk)
    } else {
        None
    };

    let prf_salt_next = if let Some(ps_next_b64) = payload
        .get("prf_salt_next")
        .or_else(|| payload.get("prfSaltNext"))
        .and_then(|v| v.as_str())
    {
        let ps = STANDARD
            .decode(ps_next_b64)
            .map_err(|_| AppError::BadRequest("prf_salt_next not base64".into()))?;
        if ps.len() != 32 {
            return Err(AppError::BadRequest("prf_salt_next must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&ps);
        Some(arr)
    } else {
        None
    };

    // user_key_next and prf_salt_next must appear together.
    if user_key_next.is_some() != prf_salt_next.is_some() {
        return Err(AppError::BadRequest(
            "user_key_next and prf_salt_next must be provided together".into(),
        ));
    }

    // 4. Consume server_random from ChallengeStore.
    {
        let mut store = state.challenges.lock().unwrap();
        if !store.verify(&server_random_b64) {
            return Err(AppError::Unauthorized(
                "invalid or expired server_random".into(),
            ));
        }
    }

    // 5. Compute expected binding from the actual request.
    let expected_binding = binding_for_request(domain, &server_random, method, path, &payload);

    // 6. Look up credential in passkeys.json.
    let passkeys_path = state.config.data_dir.join("passkeys.json");
    if !passkeys_path.exists() {
        return Err(AppError::Unauthorized(
            "no passkeys registered on this instance".into(),
        ));
    }
    let passkeys: HashMap<String, PasskeyEntry> =
        serde_json::from_str(&fs::read_to_string(&passkeys_path)?)
            .map_err(|e| AppError::Internal(format!("passkeys.json: {}", e)))?;
    let entry = passkeys
        .get(&credential_id)
        .ok_or_else(|| AppError::Unauthorized("unknown credential".into()))?;

    if entry.x.is_empty() || entry.y.is_empty() {
        return Err(AppError::Unauthorized(
            "credential missing public key coordinates".into(),
        ));
    }

    // 7. Parse and verify the assertion.
    let assertion: AssertionData = serde_json::from_value(assertion_val.clone())
        .map_err(|e| AppError::BadRequest(format!("invalid assertion: {}", e)))?;

    // Defense: if the assertion carries a credentialId, it must match.
    if let Some(ref a_cred_id) = assertion.credential_id {
        if a_cred_id != &credential_id {
            return Err(AppError::Unauthorized(
                "assertion.credentialId != credential_id".into(),
            ));
        }
    }

    verify_assertion(
        &assertion,
        &entry.x,
        &entry.y,
        &state.config.effective_origin(),
        &state.config.effective_rp_id(),
        &expected_binding,
        AssertionKind::Get,
    )?;

    Ok(AuthenticatedRequest {
        method: method.to_string(),
        path: path.to_string(),
        credential_id,
        credential_id_bytes,
        user_key,
        user_key_next,
        prf_salt_next,
        server_random,
        payload,
        passkeys,
    })
}
