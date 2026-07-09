//! Snaplii's key→JWT exchange (`[auth] type = "snaplii"`).
//!
//! The envelope is BESPOKE — Snaplii's repo cites no auth standard and the
//! wire matches no OAuth grant (JSON `{agent_id, api_key}`, no `grant_type`,
//! no RFC field names) — so it lives here as code rather than as declarative
//! config: parameterizing an unstandardized wire in TOML would mean inventing
//! a private DSL. What IS standard is the output: a JWT (RFC 7519, `exp`
//! drives the cache TTL) presented as a Bearer (RFC 6750). The mint shares
//! the oauth2 access-token cache and single-flight in `broker_flow`.
//!
//! The durable `snp_sk_live_` key can BUY THINGS (within the key's Snaplii-
//! side daily cap); it is the mint's input and therefore never injectable —
//! the agent only ever writes `Bearer __sc__<conn>__` and the broker injects
//! the minted JWT at egress. Neither the key nor the JWT enters the agent.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::forward::HTTP_CLIENT;

pub const TOKEN_URL: &str = "https://aipayment.snaplii.com/v2/auth/token";

/// Fallback TTL when the returned JWT carries no `exp` claim. Snaplii doesn't
/// document its token lifetime; a short window bounds how long a stale token
/// can be served (the next miss re-mints).
const DEFAULT_TTL_SECS: u64 = 600;

/// Exchange the stored api key for a short-lived JWT. Returns
/// `(jwt, expires_at_epoch_secs)`.
///
/// `agent_id` is the CONNECTION id: the user's own handle for the connection
/// doubles as the agent label Snaplii sees, so it stays user-chosen (rename /
/// multi-account = distinct connection ids) without a config field for it.
pub async fn exchange(api_key: &str, agent_id: &str) -> Result<(String, u64), String> {
    let resp = HTTP_CLIENT
        .post(TOKEN_URL)
        .json(&serde_json::json!({ "agent_id": agent_id, "api_key": api_key }))
        .send()
        .await
        .map_err(|e| format!("snaplii token endpoint unreachable: {}", e))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // Body is Snaplii's own error prose (e.g. bad/revoked key) — surface a
        // bounded slice of it; it never contains our secret.
        let snippet: String = body.chars().take(200).collect();
        return Err(format!("snaplii token exchange: HTTP {}: {}", status.as_u16(), snippet));
    }
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| "snaplii token response is not JSON".to_string())?;
    let jwt = find_jwt(&v)
        .ok_or_else(|| "snaplii token response carries no JWT".to_string())?;
    let expires_at = jwt_exp(&jwt).unwrap_or_else(|| now_epoch() + DEFAULT_TTL_SECS);
    Ok((jwt, expires_at))
}

/// The response's token field name is undocumented, so resolution is by SHAPE:
/// prefer conventional field names, then take the first JWT-shaped string
/// anywhere in the document. Robust to Snaplii renaming/nesting the field.
fn find_jwt(v: &serde_json::Value) -> Option<String> {
    for key in ["jwt", "token", "access_token", "session_token"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            if is_jwt_shaped(s) {
                return Some(s.to_string());
            }
        }
    }
    scan_jwt(v)
}

fn scan_jwt(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if is_jwt_shaped(s) => Some(s.clone()),
        serde_json::Value::Object(m) => m.values().find_map(scan_jwt),
        serde_json::Value::Array(a) => a.iter().find_map(scan_jwt),
        _ => None,
    }
}

/// Three dot-separated base64url segments whose header opens a JSON object
/// (`eyJ` = base64("{\"")) — the JWS compact serialization every JWT uses.
fn is_jwt_shaped(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// The `exp` claim (RFC 7519 §4.1.4) from the payload, read WITHOUT signature
/// verification — we don't validate the token, we only schedule its re-mint.
fn jwt_exp(jwt: &str) -> Option<u64> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("exp")?.as_u64()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_jwt(exp: Option<u64>) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = match exp {
            Some(e) => URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"a","exp":{}}}"#, e)),
            None => URL_SAFE_NO_PAD.encode(br#"{"sub":"a"}"#),
        };
        format!("{}.{}.sig-bytes_ok", header, payload)
    }

    #[test]
    fn jwt_shape_and_exp() {
        let t = fake_jwt(Some(1_800_000_000));
        assert!(is_jwt_shaped(&t));
        assert_eq!(jwt_exp(&t), Some(1_800_000_000));
        assert_eq!(jwt_exp(&fake_jwt(None)), None);
        assert!(!is_jwt_shaped("snp_sk_live_abc"));
        assert!(!is_jwt_shaped("a.b")); // two segments
    }

    #[test]
    fn find_jwt_prefers_named_field_then_scans() {
        let t = fake_jwt(Some(1));
        let named = serde_json::json!({ "jwt": t, "note": "x" });
        assert_eq!(find_jwt(&named), Some(t.clone()));
        // Undocumented field name / nested: shape-scan still finds it.
        let nested = serde_json::json!({ "data": { "sessionCredential": t } });
        assert_eq!(find_jwt(&nested), Some(t));
        // No JWT anywhere → None (never inject a non-JWT guess).
        let none = serde_json::json!({ "status": "ok", "id": "abc.def.ghi" });
        assert_eq!(find_jwt(&none), None);
    }
}
