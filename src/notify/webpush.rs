//! Web Push (RFC 8030 + RFC 8292 VAPID + RFC 8188 aes128gcm content encoding).
//!
//! Uses only existing crate dependencies: p256, aes-gcm, hkdf, sha2, rand,
//! jwt_simple, reqwest, base64.
//!
//! VAPID private key stored in vault as `vapid_private_key` (base64url, 32 raw bytes).
//! Public key (65-byte uncompressed P-256, base64url) exposed via /health.

use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use rand::RngCore;
use sha2::Sha256;
use tracing::{info, warn};

use super::PushSubscription;

// ── VAPID key management ───────────────────────────────────────────────────────

/// Generate a new VAPID EC P-256 key pair.
/// Returns `(private_key_b64url, public_key_b64url)`.
/// Private key = 32-byte raw scalar (base64url).
/// Public key  = 65-byte uncompressed SEC1 point (base64url).
pub fn generate_vapid_keypair() -> Result<(String, String), String> {
    let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let priv_b64 = URL_SAFE_NO_PAD.encode(sk.to_bytes().as_slice());
    let pub_b64 = vapid_public_key(&priv_b64)?;
    Ok((priv_b64, pub_b64))
}

/// Derive the uncompressed public key (base64url, 65 bytes) from a stored private key.
pub fn vapid_public_key(priv_b64: &str) -> Result<String, String> {
    let priv_bytes = URL_SAFE_NO_PAD
        .decode(priv_b64)
        .map_err(|e| format!("base64: {e}"))?;
    let sk = p256::ecdsa::SigningKey::from_slice(&priv_bytes)
        .map_err(|e| format!("signing key: {e}"))?;
    // Uncompressed P-256 point: 0x04 || x(32) || y(32)
    let uncompressed = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    Ok(URL_SAFE_NO_PAD.encode(&uncompressed))
}

// ── VAPID JWT signing ──────────────────────────────────────────────────────────

/// Build a VAPID Authorization header value for the given push endpoint.
fn vapid_auth_header(priv_b64: &str, endpoint: &str) -> Result<String, String> {
    use jwt_simple::prelude::*;

    let priv_bytes = URL_SAFE_NO_PAD
        .decode(priv_b64)
        .map_err(|e| format!("base64: {e}"))?;
    let kp = ES256KeyPair::from_bytes(&priv_bytes)
        .map_err(|e| format!("key: {e}"))?;

    // aud = scheme://host of endpoint (RFC 8292 §2)
    let aud = endpoint
        .splitn(4, '/')
        .take(3)
        .collect::<Vec<_>>()
        .join("/");

    #[derive(serde::Serialize, serde::Deserialize)]
    struct VapidClaims {
        sub: String,
    }
    let claims = Claims::with_custom_claims(
        VapidClaims { sub: "mailto:safeclaw@localhost".to_string() },
        Duration::from_hours(12),
    ).with_audience(aud);

    let token = kp.sign(claims).map_err(|e| format!("sign: {e}"))?;
    let pub_b64 = vapid_public_key(priv_b64)?;
    Ok(format!("vapid t={token},k={pub_b64}"))
}

// ── RFC 8188 aes128gcm content encryption ─────────────────────────────────────

/// Encrypt plaintext for a push subscription using aes128gcm (RFC 8188 / RFC 8291).
fn ece_encrypt(
    p256dh_b64: &str,
    auth_b64: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let recv_pub_bytes = URL_SAFE_NO_PAD
        .decode(p256dh_b64)
        .map_err(|e| format!("p256dh: {e}"))?;
    let auth_secret = URL_SAFE_NO_PAD
        .decode(auth_b64)
        .map_err(|e| format!("auth: {e}"))?;

    let recv_pub = PublicKey::from_sec1_bytes(&recv_pub_bytes)
        .map_err(|e| format!("recv_pub: {e}"))?;

    let mut rng = rand::thread_rng();
    let sender_secret = EphemeralSecret::random(&mut rng);
    let sender_pub = sender_secret.public_key();
    let sender_pub_bytes = sender_pub.to_encoded_point(false).as_bytes().to_vec();

    let shared = sender_secret.diffie_hellman(&recv_pub);
    let shared_bytes = shared.raw_secret_bytes();

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    // RFC 8291 §3.3: IKM via HKDF with auth secret
    let mut ikm_info = b"WebPush: info\x00".to_vec();
    ikm_info.extend_from_slice(&recv_pub_bytes);
    ikm_info.extend_from_slice(&sender_pub_bytes);

    let (prk, _) = Hkdf::<Sha256>::extract(Some(&auth_secret), shared_bytes.as_ref());
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|_| "HKDF prk error".to_string())?
        .expand(&ikm_info, &mut ikm)
        .map_err(|_| "HKDF expand ikm".to_string())?;

    // RFC 8188 §2.3: derive CEK and nonce from salt + IKM
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    hk.expand(b"Content-Encryption-Key\x00", &mut cek)
        .map_err(|_| "HKDF cek".to_string())?;
    let mut nonce_bytes = [0u8; 12];
    hk.expand(b"Content-Encryption-Nonce\x00", &mut nonce_bytes)
        .map_err(|_| "HKDF nonce".to_string())?;

    // Pad and encrypt (single record, delimiter 0x02)
    let mut padded = plaintext.to_vec();
    padded.push(0x02);

    let cipher = Aes128Gcm::new_from_slice(&cek)
        .map_err(|_| "AES key error".to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_slice())
        .map_err(|e| format!("AES encrypt: {e}"))?;

    // RFC 8188 §2.1 header: salt(16) || rs(4 BE) || idlen(1) || keyid(sender_pub)
    let rs: u32 = 4096;
    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&rs.to_be_bytes());
    out.push(sender_pub_bytes.len() as u8);
    out.extend_from_slice(&sender_pub_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

// ── Public: send notifications ─────────────────────────────────────────────────

/// Send a Web Push notification to all subscriptions.
/// Returns a list of dead endpoint URLs (410 Gone / 404 Not Found) that should be
/// removed from the vault by the caller. Never panics.
pub async fn send_push_notification(
    priv_b64: &str,
    subs: &[PushSubscription],
    payload: serde_json::Value,
) -> Vec<String> {
    let mut dead_endpoints: Vec<String> = Vec::new();

    if subs.is_empty() {
        return dead_endpoints;
    }
    let body_str = payload.to_string();
    let client = reqwest::Client::new();

    for sub in subs {
        let auth_hdr = match vapid_auth_header(priv_b64, &sub.endpoint) {
            Ok(h) => h,
            Err(e) => { warn!("VAPID header error: {e}"); continue; }
        };

        let encrypted = match ece_encrypt(&sub.keys.p256dh, &sub.keys.auth, body_str.as_bytes()) {
            Ok(b) => b,
            Err(e) => { warn!("ECE encrypt error: {e}"); continue; }
        };

        let result = client
            .post(&sub.endpoint)
            .header("Authorization", &auth_hdr)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("TTL", "86400")
            .header("Urgency", "high")
            .body(encrypted)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 201 => {
                info!("Web Push delivered to {}", sub.endpoint);
            }
            Ok(resp) if resp.status().as_u16() == 410 || resp.status().as_u16() == 404 => {
                warn!("Web Push subscription expired ({}): {}", resp.status(), sub.endpoint);
                dead_endpoints.push(sub.endpoint.clone());
            }
            Ok(resp) => {
                warn!("Web Push HTTP {} for {}", resp.status(), sub.endpoint);
            }
            Err(e) => {
                warn!("Web Push send error for {}: {e}", sub.endpoint);
            }
        }
    }

    dead_endpoints
}
