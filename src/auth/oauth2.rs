// OAuth2 token refresh and injection.

use super::AuthConfig;
use crate::core::forward::HTTP_CLIENT;
use std::time::{SystemTime, UNIX_EPOCH};

/// OAuth2 refresh content type.
/// Providers can override the default form-urlencoded with JSON.
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

/// Multi-tenant SaaS daemon's refresh-on-use entry point. Same wire
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
