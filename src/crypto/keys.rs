use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{EncodedPoint, PublicKey, SecretKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AppError, Result};

/// JWK representation of a P-256 public key.
/// Wire-compatible with WebCrypto exportKey('jwk', publicKey) for P-256 ECDH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String, // base64url, no padding
    pub y: String, // base64url, no padding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
}

/// JWK representation of a P-256 private key (includes public coordinates).
/// Wire-compatible with WebCrypto exportKey('jwk', privateKey) for P-256 ECDH.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct JwkPrivateKey {
    pub kty: String,
    pub crv: String,
    pub x: String, // base64url, no padding
    pub y: String, // base64url, no padding
    pub d: String, // base64url, no padding — SECRET
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
}

/// Server keypair stored as JWK
#[derive(Clone)]
pub struct ServerKeypair {
    pub pk: JwkPublicKey,
    pub sk: JwkPrivateKey,
}

/// Generate a fresh P-256 keypair
pub fn generate_keypair() -> Result<ServerKeypair> {
    let sk = SecretKey::random(&mut rand::rngs::OsRng);
    keypair_from_secret(sk)
}

fn keypair_from_secret(sk: SecretKey) -> Result<ServerKeypair> {
    let pk = sk.public_key();
    let ep = pk.to_encoded_point(false); // uncompressed: 0x04 || x || y

    let x_bytes = ep
        .x()
        .ok_or_else(|| AppError::Internal("Missing x coordinate".into()))?;
    let y_bytes = ep
        .y()
        .ok_or_else(|| AppError::Internal("Missing y coordinate".into()))?;
    let d_bytes = sk.to_bytes();

    let jwk_pk = JwkPublicKey {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(x_bytes.as_slice()),
        y: URL_SAFE_NO_PAD.encode(y_bytes.as_slice()),
        key_ops: None,
        ext: None,
    };
    let jwk_sk = JwkPrivateKey {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(x_bytes.as_slice()),
        y: URL_SAFE_NO_PAD.encode(y_bytes.as_slice()),
        d: URL_SAFE_NO_PAD.encode(d_bytes.as_slice()),
        key_ops: None,
        ext: None,
    };

    Ok(ServerKeypair { pk: jwk_pk, sk: jwk_sk })
}

/// Load keypair from data directory, or generate and save a new one
pub fn load_or_create_keypair(data_dir: &Path) -> Result<ServerKeypair> {
    let pk_path = data_dir.join("sc_pk.jwk");
    let sk_path = data_dir.join("sc_sk.jwk");

    if pk_path.exists() && sk_path.exists() {
        let pk: JwkPublicKey = serde_json::from_str(&fs::read_to_string(&pk_path)?)
            .map_err(|e| AppError::Internal(format!("Failed to parse sc_pk.jwk: {}", e)))?;
        let sk: JwkPrivateKey = serde_json::from_str(&fs::read_to_string(&sk_path)?)
            .map_err(|e| AppError::Internal(format!("Failed to parse sc_sk.jwk: {}", e)))?;
        return Ok(ServerKeypair { pk, sk });
    }

    fs::create_dir_all(data_dir)?;
    let kp = generate_keypair()?;
    fs::write(&pk_path, serde_json::to_string(&kp.pk)?)?;
    write_secret_file(&sk_path, serde_json::to_string(&kp.sk)?.as_bytes())?;
    Ok(kp)
}

/// Extract raw 32-byte private key bytes from JWK (d field is base64url)
pub fn jwk_sk_d_bytes(jwk: &JwkPrivateKey) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(|e| AppError::Internal(format!("Failed to decode JWK d: {}", e)))?;
    if bytes.len() != 32 {
        return Err(AppError::Internal("Invalid JWK d length (expected 32)".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a P-256 PublicKey from JWK (x, y are base64url)
pub fn jwk_pk_to_public_key(jwk: &JwkPublicKey) -> Result<PublicKey> {
    let x_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| AppError::Internal(format!("Failed to decode JWK x: {}", e)))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|e| AppError::Internal(format!("Failed to decode JWK y: {}", e)))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(AppError::BadRequest("Invalid JWK coordinate length".into()));
    }

    public_key_from_xy(&x_bytes, &y_bytes)
}

/// Build a P-256 PublicKey from raw x/y coordinate bytes (each 32 bytes)
pub fn public_key_from_xy(x: &[u8], y: &[u8]) -> Result<PublicKey> {
    // Build uncompressed SEC1 point: 0x04 || x || y
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);

    let _ep = EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| AppError::BadRequest(format!("Invalid EC point: {}", e)))?;

    // Use from_sec1_bytes which parses SEC1 uncompressed point format
    PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| AppError::BadRequest(format!("Not a valid P-256 public key point: {}", e)))
}

/// Build a P-256 SecretKey from raw 32-byte scalar bytes
pub fn secret_key_from_bytes(bytes: &[u8; 32]) -> Result<SecretKey> {
    SecretKey::from_bytes(bytes.into())
        .map_err(|e| AppError::Internal(format!("Invalid P-256 private key: {}", e)))
}

/// Sanitize a credential ID string for use as a filename component.
/// Replaces base64 special chars with filesystem-safe equivalents.
pub fn credential_id_to_filename(cred_id: &str) -> Result<String> {
    // Reject path traversal
    if cred_id.contains("..") || cred_id.contains('\\') {
        return Err(AppError::BadRequest("Invalid credential ID".into()));
    }
    // Replace base64 standard chars that aren't filename-safe
    // (credential IDs from WebAuthn are standard base64 and may contain +, /, =)
    let sanitized = cred_id
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    // Allow only base64url characters after replacement
    if sanitized.chars().any(|c| !c.is_alphanumeric() && c != '-' && c != '_') {
        return Err(AppError::BadRequest("Credential ID contains invalid characters".into()));
    }
    Ok(sanitized)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data)?;
    Ok(())
}
