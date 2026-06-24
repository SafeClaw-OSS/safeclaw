//! GCP Secret Manager adapter.
//!
//! REST-based to avoid pulling in `google-cloud-rust` (large + churning).
//! The two endpoints we need are stable v1:
//!
//! - `POST https://oauth2.googleapis.com/token` (JWT-bearer grant) → access token
//! - `GET  https://secretmanager.googleapis.com/v1/projects/{p}/secrets/{s}/versions/latest:access`
//! - `GET  https://secretmanager.googleapis.com/v1/projects/{p}/secrets`
//!
//! Credentials = service-account JSON (the standard download from the
//! GCP console). The SA's private key is RSA; we use `jsonwebtoken` to
//! sign the bearer JWT.
//!
//! The OAuth access token is cached in-memory (per-adapter instance, so
//! per-request — fine for now; if /use latency becomes a problem move
//! the cache up into AppState).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::core::forward::HTTP_CLIENT;

use super::super::adapter::{AdapterError, AdapterResult};

const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const SECRET_MANAGER_BASE: &str = "https://secretmanager.googleapis.com/v1";
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// JWT-bearer grant lifetime. Google caps inbound assertions at 1h.
const JWT_LIFETIME_SECS: u64 = 3600;

/// Subset of an SA JSON we actually need.
#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[allow(dead_code)]
    private_key_id: Option<String>,
}

/// JWT claims for the SA-to-OAuth2 token exchange (Google's JWT-bearer
/// grant). `aud` is the token endpoint, `iss` is the SA email, `scope`
/// is the OAuth scope we want.
#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct SecretPayload {
    /// base64-encoded raw bytes of the secret version
    data: String,
}

#[derive(Debug, Deserialize)]
struct AccessSecretResponse {
    payload: SecretPayload,
}

#[derive(Debug, Deserialize)]
struct ListSecret {
    /// "projects/<p>/secrets/<name>"
    name: String,
}

#[derive(Debug, Deserialize)]
struct ListSecretsResponse {
    #[serde(default)]
    secrets: Vec<ListSecret>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    /// Unix epoch seconds when this token expires. We refresh ~60s before.
    expires_at: u64,
}

pub struct GcpSecretManagerAdapter {
    project_id: String,
    sa: ServiceAccountKey,
    /// In-memory access-token cache. Mutex because adapters are shared
    /// across the tokio runtime.
    token: Mutex<Option<CachedToken>>,
}

impl GcpSecretManagerAdapter {
    pub fn new(project_id: String, sa_json: Vec<u8>) -> AdapterResult<Self> {
        let sa: ServiceAccountKey = serde_json::from_slice(&sa_json).map_err(|e| {
            AdapterError::Config(format!(
                "service-account JSON parse failed (expected fields: client_email, private_key): {}",
                e
            ))
        })?;
        Ok(Self {
            project_id,
            sa,
            token: Mutex::new(None),
        })
    }

    /// Get a cached or freshly-minted OAuth access token.
    async fn access_token(&self) -> AdapterResult<String> {
        let now = now_unix();
        {
            let guard = self.token.lock().await;
            if let Some(t) = guard.as_ref() {
                if t.expires_at > now + 60 {
                    return Ok(t.access_token.clone());
                }
            }
        }

        let jwt = self.sign_jwt(now)?;
        let resp = HTTP_CLIENT
            .post(TOKEN_ENDPOINT)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| AdapterError::Backend(format!("token endpoint: {}", e)))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AdapterError::Backend(format!(
                "token endpoint returned {}: {}",
                status, body
            )));
        }
        let tok: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AdapterError::Backend(format!("token response parse: {}", e)))?;
        let cached = CachedToken {
            access_token: tok.access_token.clone(),
            expires_at: now + tok.expires_in,
        };
        *self.token.lock().await = Some(cached);
        Ok(tok.access_token)
    }

    fn sign_jwt(&self, now: u64) -> AdapterResult<String> {
        let claims = JwtClaims {
            iss: &self.sa.client_email,
            scope: SCOPE,
            aud: TOKEN_ENDPOINT,
            iat: now,
            exp: now + JWT_LIFETIME_SECS,
        };
        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(self.sa.private_key.as_bytes()).map_err(|e| {
            AdapterError::Config(format!("SA private_key not valid RSA PEM: {}", e))
        })?;
        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AdapterError::Backend(format!("JWT sign: {}", e)))
    }

    /// Resolve a Secret Manager secret to its `latest` version's payload.
    /// Returns `Ok(None)` on HTTP 404 (callers continue store_order),
    /// `Err(Backend)` on any other failure.
    pub async fn resolve(&self, name: &str) -> AdapterResult<Option<Vec<u8>>> {
        let token = self.access_token().await?;
        let url = format!(
            "{}/projects/{}/secrets/{}/versions/latest:access",
            SECRET_MANAGER_BASE, self.project_id, name
        );
        let resp = HTTP_CLIENT
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| AdapterError::Backend(format!("accessSecretVersion: {}", e)))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AdapterError::Backend(format!(
                "accessSecretVersion returned {}: {}",
                status, body
            )));
        }
        let body: AccessSecretResponse = resp
            .json()
            .await
            .map_err(|e| AdapterError::Backend(format!("response parse: {}", e)))?;
        let raw = STANDARD
            .decode(body.payload.data)
            .map_err(|e| AdapterError::Backend(format!("payload base64: {}", e)))?;
        Ok(Some(raw))
    }

    /// List all secret IDs the SA can `secretAccessor`-access in this
    /// project. UI uses this for the per-store item browser.
    pub async fn list(&self) -> AdapterResult<Vec<String>> {
        let token = self.access_token().await?;
        let url = format!(
            "{}/projects/{}/secrets",
            SECRET_MANAGER_BASE, self.project_id
        );
        let resp = HTTP_CLIENT
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| AdapterError::Backend(format!("listSecrets: {}", e)))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AdapterError::Backend(format!(
                "listSecrets returned {}: {}",
                status, body
            )));
        }
        let body: ListSecretsResponse = resp
            .json()
            .await
            .map_err(|e| AdapterError::Backend(format!("response parse: {}", e)))?;
        let ids = body
            .secrets
            .into_iter()
            .filter_map(|s| s.name.rsplit('/').next().map(|x| x.to_string()))
            .collect();
        Ok(ids)
    }

    /// Validate creds + project access. Calls `listSecrets` once;
    /// success = adapter is healthy enough to attempt resolve later.
    pub async fn health(&self) -> AdapterResult<()> {
        let _ = self.list().await?;
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
