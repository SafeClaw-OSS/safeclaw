// OAuth2 token refresh and injection.

use super::AuthConfig;
use crate::core::forward::HTTP_CLIENT;
use std::time::{SystemTime, UNIX_EPOCH};

/// OAuth2 refresh content type.
/// Providers can override the default form-urlencoded with JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthStyle {
    /// Standard form-urlencoded (OpenAI, Google, etc.)
    Form,
    /// JSON body (Anthropic)
    Json,
}

/// Determine the OAuth2 refresh style from the auth config.
/// Fallback heuristic: checks token_url for known providers.
/// Prefer passing `style_override` from service.toml instead.
fn detect_style(auth: &AuthConfig) -> OAuthStyle {
    if let Some(token_url) = &auth.token_url {
        if token_url.contains("anthropic.com") || token_url.contains("platform.claude.com") {
            return OAuthStyle::Json;
        }
    }
    OAuthStyle::Form
}

/// Attempt to refresh an OAuth2 access token using the refresh_token grant.
/// `style_override` comes from service.toml [auth] oauth_style; falls back to
/// URL-based heuristic if None.
/// Returns (access_token, expires_at_unix_secs) on success.
pub async fn refresh_token(
    auth: &AuthConfig,
    style_override: Option<OAuthStyle>,
) -> Result<(String, u64), String> {
    let token_url = auth
        .token_url
        .as_ref()
        .ok_or("oauth2: missing token_url")?;
    let client_id = auth
        .client_id
        .as_ref()
        .ok_or("oauth2: missing client_id")?;
    let refresh_token = auth
        .refresh_token
        .as_ref()
        .ok_or("oauth2: missing refresh_token")?;

    let style = style_override.unwrap_or_else(|| detect_style(auth));
    tracing::info!("oauth2 refresh: token_url={} style={}", token_url,
        match style { OAuthStyle::Json => "json", OAuthStyle::Form => "form" });

    let resp = match style {
        OAuthStyle::Json => {
            let body = serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            });
            HTTP_CLIENT
                .post(token_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("oauth2 refresh request failed: {}", e))?
        }
        OAuthStyle::Form => {
            let mut form_params = vec![
                ("grant_type", "refresh_token"),
                ("client_id", client_id.as_str()),
                ("refresh_token", refresh_token.as_str()),
            ];
            let client_secret = auth.client_secret.as_deref();
            if let Some(secret) = client_secret {
                form_params.push(("client_secret", secret));
            }
            HTTP_CLIENT
                .post(token_url)
                .form(&form_params)
                .send()
                .await
                .map_err(|e| format!("oauth2 refresh request failed: {}", e))?
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
        tracing::warn!("oauth2 refresh error body: {}", body_text);
        return Err(format!("oauth2 refresh returned HTTP {} — {}", status, body_text));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("oauth2 refresh parse failed: {}", e))?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("oauth2 response missing access_token")?
        .to_string();

    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok((access_token, now_secs + expires_in))
}

/// Result of an authorization-code → token exchange (the CONNECT step,
/// CONNECTIONS_AND_AUTH.md §4a). The durable `refresh_token` is what the
/// daemon persists into the sealed vault; `access_token` is the short-lived
/// credential the daemon can immediately cache so the first agent request
/// after a connect doesn't have to re-mint.
pub struct ExchangedTokens {
    /// Durable credential persisted into the vault as `<conn>_refresh_token`.
    /// `None` if the provider returned no refresh_token (e.g. consent without
    /// `access_type=offline`) — the caller treats that as a connect failure
    /// (there's nothing durable to persist).
    pub refresh_token: Option<String>,
    /// Short-lived access token (~1h). Caller MAY warm the in-memory cache.
    pub access_token: String,
    /// Absolute unix-seconds expiry of `access_token`.
    pub expires_at: u64,
}

/// Build the form-urlencoded params for an authorization_code exchange
/// (RFC 6749 §4.1.3 + RFC 7636). Pure (no I/O) so the wire shape is unit-
/// testable. `client_secret` is appended only when present (PKCE clients omit
/// it; the public Desktop client supplies its non-confidential one).
fn code_exchange_form_params<'a>(
    client_id: &'a str,
    client_secret: Option<&'a str>,
    code: &'a str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
) -> Vec<(&'static str, &'a str)> {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }
    params
}

/// Build the JSON body for an authorization_code exchange. Pure (no I/O).
fn code_exchange_json_body(
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    });
    if let Some(secret) = client_secret {
        body["client_secret"] = serde_json::Value::String(secret.to_string());
    }
    body
}

/// Exchange an authorization `code` for tokens (the OAuth2 CONNECT step,
/// RFC 6749 §4.1.3 + RFC 7636 PKCE). Mirrors [`perform_refresh`]'s wire
/// behavior and error handling but sets `grant_type=authorization_code` and
/// carries `code` + `code_verifier` + `redirect_uri` instead of a
/// refresh_token.
///
/// `client_secret` is the PUBLIC Desktop-client secret (Google's design
/// treats it as non-confidential); a confidential Web-app secret must never
/// reach here. PKCE clients that omit a secret pass `None`.
///
/// Returns the durable refresh_token + the fresh access_token on success.
/// On failure, returns an `Err(String)` with the provider's error body —
/// caller inspects it (e.g. `invalid_grant` for an expired/consumed code) and
/// leaves the pending item in place so the user can retry within the code TTL.
pub async fn exchange_code(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    style: OAuthStyle,
) -> Result<ExchangedTokens, String> {
    tracing::info!(
        "oauth2 code-exchange: token_url={} style={}",
        token_url,
        match style {
            OAuthStyle::Json => "json",
            OAuthStyle::Form => "form",
        }
    );

    let resp = match style {
        OAuthStyle::Json => {
            let body = code_exchange_json_body(
                client_id, client_secret, code, code_verifier, redirect_uri,
            );
            HTTP_CLIENT
                .post(token_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("oauth2 code-exchange request failed: {}", e))?
        }
        OAuthStyle::Form => {
            let form_params = code_exchange_form_params(
                client_id, client_secret, code, code_verifier, redirect_uri,
            );
            HTTP_CLIENT
                .post(token_url)
                .form(&form_params)
                .send()
                .await
                .map_err(|e| format!("oauth2 code-exchange request failed: {}", e))?
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
        tracing::warn!("oauth2 code-exchange error body: {}", body_text);
        return Err(format!("oauth2 code-exchange returned HTTP {} — {}", status, body_text));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("oauth2 code-exchange parse failed: {}", e))?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("oauth2 code-exchange response missing access_token")?
        .to_string();
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(ExchangedTokens {
        refresh_token,
        access_token,
        expires_at: now_secs + expires_in,
    })
}

/// Multi-vault SaaS daemon's refresh-on-use entry point. Same wire
/// behavior as `refresh_token` (which takes the legacy AuthConfig
/// blob), but accepts inputs as primitive params so callers can mix
/// per-vault state (the refresh_token, from `cache.entries`) with
/// per-deployment config (token_url + client_id + optional
/// client_secret, loaded from env vars at daemon startup and threaded
/// through service.toml).
///
/// Returns `(access_token, absolute_expires_at_unix_secs)` on success.
/// On refresh failure, returns an `Err(String)` with the provider's
/// error body — caller inspects this to detect `invalid_grant` and
/// surface a "needs reauth" UI flag.
pub async fn perform_refresh(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token_value: &str,
    style: OAuthStyle,
) -> Result<(String, u64), String> {
    tracing::info!(
        "oauth2 refresh: token_url={} style={}",
        token_url,
        match style {
            OAuthStyle::Json => "json",
            OAuthStyle::Form => "form",
        }
    );

    let resp = match style {
        OAuthStyle::Json => {
            let body = serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_value,
                "client_id": client_id,
            });
            HTTP_CLIENT
                .post(token_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("oauth2 refresh request failed: {}", e))?
        }
        OAuthStyle::Form => {
            let mut form_params = vec![
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", refresh_token_value),
            ];
            if let Some(secret) = client_secret {
                form_params.push(("client_secret", secret));
            }
            HTTP_CLIENT
                .post(token_url)
                .form(&form_params)
                .send()
                .await
                .map_err(|e| format!("oauth2 refresh request failed: {}", e))?
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
        tracing::warn!("oauth2 refresh error body: {}", body_text);
        return Err(format!("oauth2 refresh returned HTTP {} — {}", status, body_text));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("oauth2 refresh parse failed: {}", e))?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("oauth2 response missing access_token")?
        .to_string();
    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok((access_token, now_secs + expires_in))
}

#[cfg(test)]
mod connect_request_tests {
    use super::*;

    // ── form (Google / default) body construction ──────────────────────────

    #[test]
    fn form_params_carry_grant_type_and_pkce_fields() {
        let p = code_exchange_form_params(
            "client-123",
            Some("GOCSPX-secret"),
            "auth-code-A",
            "verif-XYZ",
            "http://127.0.0.1:8765/cb",
        );
        // grant_type is the authorization_code flow (NOT refresh_token).
        assert!(p.contains(&("grant_type", "authorization_code")));
        assert!(p.contains(&("client_id", "client-123")));
        assert!(p.contains(&("code", "auth-code-A")));
        // PKCE verifier (RFC 7636) is present.
        assert!(p.contains(&("code_verifier", "verif-XYZ")));
        assert!(p.contains(&("redirect_uri", "http://127.0.0.1:8765/cb")));
        // public Desktop client secret appended when present.
        assert!(p.contains(&("client_secret", "GOCSPX-secret")));
        // No refresh_token param leaks into a code exchange.
        assert!(!p.iter().any(|(k, _)| *k == "refresh_token"));
    }

    #[test]
    fn form_params_omit_client_secret_for_pkce_only() {
        let p = code_exchange_form_params(
            "client-123", None, "code", "verif", "http://127.0.0.1/cb",
        );
        assert!(!p.iter().any(|(k, _)| *k == "client_secret"));
        assert!(p.contains(&("grant_type", "authorization_code")));
    }

    // ── json (Anthropic-style) body construction ───────────────────────────

    #[test]
    fn json_body_carries_grant_type_and_pkce_fields() {
        let b = code_exchange_json_body(
            "client-123",
            Some("sec"),
            "auth-code-A",
            "verif-XYZ",
            "http://127.0.0.1:8765/cb",
        );
        assert_eq!(b["grant_type"], "authorization_code");
        assert_eq!(b["client_id"], "client-123");
        assert_eq!(b["code"], "auth-code-A");
        assert_eq!(b["code_verifier"], "verif-XYZ");
        assert_eq!(b["redirect_uri"], "http://127.0.0.1:8765/cb");
        assert_eq!(b["client_secret"], "sec");
        assert!(b.get("refresh_token").is_none());
    }

    #[test]
    fn json_body_omits_client_secret_when_absent() {
        let b = code_exchange_json_body(
            "client-123", None, "code", "verif", "http://127.0.0.1/cb",
        );
        assert!(b.get("client_secret").is_none());
        assert_eq!(b["grant_type"], "authorization_code");
    }
}
