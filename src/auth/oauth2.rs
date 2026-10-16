// OAuth2 wire calls: refresh + authorization-code exchange (pure, no schema).

use crate::core::forward::http_client;
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

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// `client_id` (and `client_secret` when present) in the body — the
    /// default most providers take.
    Post,
    /// `Authorization: Basic client_id:client_secret` (RFC 6749 §2.3.1), and
    /// neither in the body — the style some providers require (GitHub,
    /// Reddit). A client without a secret sends an empty password.
    Basic,
}

impl TokenAuth {
    fn as_str(self) -> &'static str {
        match self {
            TokenAuth::Post => "post",
            TokenAuth::Basic => "basic",
        }
    }
}

/// The `Authorization: Basic` value for a token-endpoint call: id and secret
/// form-urlencoded (RFC 6749 §2.3.1), joined with `:`, base64. A client
/// without a secret has an empty password.
pub fn basic_auth_value(client_id: &str, client_secret: Option<&str>) -> String {
    use base64::Engine as _;
    let enc = |s: &str| {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
    };
    let pair = format!("{}:{}", enc(client_id), enc(client_secret.unwrap_or("")));
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

/// The placeholder a `token_params` value may use: the consent `state` of the
/// pending connect, substituted at exchange time.
pub const STATE_PLACEHOLDER: &str = "{state}";

/// Render a def's extra token/refresh params into `(key, value)` pairs in key
/// order, substituting [`STATE_PLACEHOLDER`]. `Err` when a value asks for the
/// state and `state` is `None` (a pending connect from before the state was
/// recorded): the connect fails with why instead of sending the placeholder.
pub fn render_extra_params(
    params: &std::collections::HashMap<String, String>,
    state: Option<&str>,
) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(params.len());
    for (k, v) in params {
        let rendered = if v.contains(STATE_PLACEHOLDER) {
            let state = state.ok_or_else(|| {
                format!(
                    "this service's token_params need the consent state for '{}', but this pending connect has none recorded; reconnect",
                    k
                )
            })?;
            v.replace(STATE_PLACEHOLDER, state)
        } else {
            v.clone()
        };
        out.push((k.clone(), rendered));
    }
    out.sort();
    Ok(out)
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
    /// OIDC id_token, when the provider returned one. Source of the `exposes`
    /// claim derivations (e.g. openai-codex's `chatgpt_account_id`) and of the
    /// stored id_token slot when the service declares one.
    pub id_token: Option<String>,
}

/// Read a claim from a JWT's payload without verifying the signature — fine
/// here because the token just arrived over TLS from the provider's own /token
/// endpoint (the same trust as every other field of that response). `path`
/// walks nested objects (an OIDC namespace key like
/// `https://api.openai.com/auth` is ONE segment); as a fallback the LEAF
/// segment is also tried as a top-level claim (providers have moved claims
/// between the two across versions). Returns the claim as a string (non-string
/// scalars are JSON-serialized).
pub fn id_token_claim(id_token: &str, path: &[String]) -> Option<String> {
    use base64::Engine as _;
    let payload_b64 = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let mut cur = &payload;
    let walked = 'walk: {
        for seg in path {
            match cur.get(seg) {
                Some(v) => cur = v,
                None => break 'walk None,
            }
        }
        Some(cur)
    };
    let v = walked.or_else(|| path.last().and_then(|leaf| payload.get(leaf)))?;
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// The client params of a token-endpoint body: `client_id` (and
/// `client_secret` when present) for [`TokenAuth::Post`]; none for
/// [`TokenAuth::Basic`] (they ride the Authorization header instead).
fn client_body_params(
    auth: TokenAuth,
    client_id: &str,
    client_secret: Option<&str>,
) -> Vec<(String, String)> {
    match auth {
        TokenAuth::Basic => Vec::new(),
        TokenAuth::Post => {
            let mut out = vec![("client_id".to_string(), client_id.to_string())];
            if let Some(secret) = client_secret {
                out.push(("client_secret".to_string(), secret.to_string()));
            }
            out
        }
    }
}

/// Build the params for an authorization_code exchange (RFC 6749 §4.1.3 +
/// RFC 7636), the protocol params first, then the def's rendered
/// `token_params` (ADDITIONS — the validator refused reserved keys). Pure
/// (no I/O) so the wire shape is unit-testable; the form style sends these
/// urlencoded, the json style as one object.
fn code_exchange_params(
    auth: TokenAuth,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    extra: &[(String, String)],
) -> Vec<(String, String)> {
    let mut params = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("code_verifier".to_string(), code_verifier.to_string()),
        ("redirect_uri".to_string(), redirect_uri.to_string()),
    ];
    params.extend(client_body_params(auth, client_id, client_secret));
    params.extend(extra.iter().cloned());
    params
}

/// Build the params for a refresh (RFC 6749 §6), then the def's
/// `refresh_params` (static ADDITIONS). Pure (no I/O).
fn refresh_params(
    auth: TokenAuth,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token_value: &str,
    extra: &[(String, String)],
) -> Vec<(String, String)> {
    let mut params = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh_token_value.to_string()),
    ];
    params.extend(client_body_params(auth, client_id, client_secret));
    params.extend(extra.iter().cloned());
    params
}

/// Params as the json style sends them: one object (every value a string).
fn params_json(params: &[(String, String)]) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    for (k, v) in params {
        body.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    serde_json::Value::Object(body)
}

/// POST `params` to the token endpoint: the body in `style`, the client in
/// `auth` (a Basic header carries it; post puts it in `params`), and
/// `Accept: application/json` always (some providers default to another
/// representation without it).
async fn post_token_endpoint(
    token_url: &str,
    style: OAuthStyle,
    auth: TokenAuth,
    client_id: &str,
    client_secret: Option<&str>,
    params: &[(String, String)],
) -> Result<reqwest::Response, reqwest::Error> {
    let mut req = http_client()
        .post(token_url)
        .header("Accept", "application/json");
    if auth == TokenAuth::Basic {
        req = req.header("Authorization", basic_auth_value(client_id, client_secret));
    }
    match style {
        OAuthStyle::Json => {
            req.header("Content-Type", "application/json")
                .json(&params_json(params))
                .send()
                .await
        }
        OAuthStyle::Form => req.form(&params).send().await,
    }
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
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    style: OAuthStyle,
    auth: TokenAuth,
    extra: &[(String, String)],
) -> Result<ExchangedTokens, String> {
    tracing::info!(
        "oauth2 code-exchange: token_url={} style={} auth={}",
        token_url,
        match style {
            OAuthStyle::Json => "json",
            OAuthStyle::Form => "form",
        },
        auth.as_str(),
    );

    let params = code_exchange_params(
        auth,
        client_id,
        client_secret,
        code,
        code_verifier,
        redirect_uri,
        extra,
    );
    let resp = post_token_endpoint(token_url, style, auth, client_id, client_secret, &params)
        .await
        .map_err(|e| format!("oauth2 code-exchange request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        tracing::warn!("oauth2 code-exchange error body: {}", body_text);
        return Err(format!(
            "oauth2 code-exchange returned HTTP {}: {}",
            status, body_text
        ));
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
    let id_token = body
        .get("id_token")
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
        id_token,
    })
}

/// OAuth refresh-on-use entry point. Accepts inputs as primitive params so
/// callers can mix per-vault state (the refresh_token, from `cache.entries`)
/// with per-deployment config (token_url + client_id + optional client_secret,
/// resolved from the service definition + its provider).
///
/// Returns `(access_token, absolute_expires_at_unix_secs, rotated_refresh_token)`
/// on success. `rotated_refresh_token` is `Some` when the provider returned a
/// NEW `refresh_token` in the refresh response (OpenAI mints a fresh one on every
/// refresh and invalidates the old; Google does not) — the caller MUST persist it
/// back to the vault, or the next refresh would send a dead token. `None` when the
/// provider omitted it (the stored refresh_token stays valid).
/// On refresh failure, returns an `Err(String)` with the provider's
/// error body — caller inspects this to detect `invalid_grant` and
/// surface a "needs reauth" UI flag.
pub async fn perform_refresh(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token_value: &str,
    style: OAuthStyle,
    auth: TokenAuth,
    extra: &[(String, String)],
) -> Result<(String, u64, Option<String>), String> {
    tracing::info!(
        "oauth2 refresh: token_url={} style={} auth={}",
        token_url,
        match style {
            OAuthStyle::Json => "json",
            OAuthStyle::Form => "form",
        },
        auth.as_str(),
    );

    let params = refresh_params(auth, client_id, client_secret, refresh_token_value, extra);
    let resp = post_token_endpoint(token_url, style, auth, client_id, client_secret, &params)
        .await
        .map_err(|e| format!("oauth2 refresh request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        tracing::warn!("oauth2 refresh error body: {}", body_text);
        return Err(format!(
            "oauth2 refresh returned HTTP {}: {}",
            status, body_text
        ));
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

    // A rotating provider (OpenAI) returns a fresh refresh_token here and
    // invalidates the one we sent; surface it so the caller can persist it.
    let rotated_refresh = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok((access_token, now_secs + expires_in, rotated_refresh))
}

#[cfg(test)]
mod connect_request_tests {
    use super::*;

    /// An unsigned JWT whose payload is `claims` (header/signature irrelevant —
    /// id_token_claim only reads the middle segment).
    fn jwt(claims: serde_json::Value) -> String {
        use base64::Engine as _;
        let enc = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.{}",
            enc(b"{}"),
            enc(claims.to_string().as_bytes()),
            enc(b"sig")
        )
    }

    #[test]
    fn id_token_claim_walks_namespaced_path() {
        let t = jwt(serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-123" }
        }));
        let path = vec![
            "https://api.openai.com/auth".to_string(),
            "chatgpt_account_id".to_string(),
        ];
        assert_eq!(id_token_claim(&t, &path).as_deref(), Some("acct-123"));
    }

    #[test]
    fn id_token_claim_falls_back_to_top_level_leaf() {
        let t = jwt(serde_json::json!({ "chatgpt_account_id": "acct-789" }));
        let path = vec![
            "https://api.openai.com/auth".to_string(),
            "chatgpt_account_id".to_string(),
        ];
        assert_eq!(id_token_claim(&t, &path).as_deref(), Some("acct-789"));
    }

    #[test]
    fn id_token_claim_none_when_absent_or_malformed() {
        let t = jwt(serde_json::json!({ "sub": "x" }));
        assert!(id_token_claim(&t, &["missing".to_string()]).is_none());
        assert!(id_token_claim("not-a-jwt", &["a".to_string()]).is_none());
    }

    fn has(p: &[(String, String)], k: &str, v: &str) -> bool {
        p.iter().any(|(pk, pv)| pk == k && pv == v)
    }

    fn lacks(p: &[(String, String)], k: &str) -> bool {
        !p.iter().any(|(pk, _)| pk == k)
    }

    // ── token-endpoint body construction ────────────────────────────────────

    #[test]
    fn exchange_params_carry_grant_type_pkce_and_extras() {
        let extra = vec![("echo_state".to_string(), "st-42".to_string())];
        let p = code_exchange_params(
            TokenAuth::Post,
            "client-123",
            Some("public-secret"),
            "auth-code-A",
            "verif-XYZ",
            "http://127.0.0.1:8765/cb",
            &extra,
        );
        // grant_type is the authorization_code flow (NOT refresh_token).
        assert!(has(&p, "grant_type", "authorization_code"));
        assert!(has(&p, "client_id", "client-123"));
        assert!(has(&p, "code", "auth-code-A"));
        // PKCE verifier (RFC 7636) is present.
        assert!(has(&p, "code_verifier", "verif-XYZ"));
        assert!(has(&p, "redirect_uri", "http://127.0.0.1:8765/cb"));
        // public client secret appended when present.
        assert!(has(&p, "client_secret", "public-secret"));
        // The def's token_params ride along.
        assert!(has(&p, "echo_state", "st-42"));
        // No refresh_token param leaks into a code exchange.
        assert!(lacks(&p, "refresh_token"));
        // The json style sends the same params as one object.
        let b = params_json(&p);
        assert_eq!(b["grant_type"], "authorization_code");
        assert_eq!(b["code_verifier"], "verif-XYZ");
        assert_eq!(b["client_secret"], "public-secret");
        assert_eq!(b["echo_state"], "st-42");
        assert!(b.get("refresh_token").is_none());
    }

    #[test]
    fn exchange_params_omit_client_secret_for_pkce_only() {
        let p = code_exchange_params(
            TokenAuth::Post,
            "client-123",
            None,
            "code",
            "verif",
            "http://127.0.0.1/cb",
            &[],
        );
        assert!(lacks(&p, "client_secret"));
        assert!(has(&p, "grant_type", "authorization_code"));
        assert!(params_json(&p).get("client_secret").is_none());
    }

    #[test]
    fn refresh_params_carry_the_token_and_extras() {
        let extra = vec![("audience".to_string(), "api".to_string())];
        let p = refresh_params(TokenAuth::Post, "client-123", Some("sec"), "rt-1", &extra);
        assert!(has(&p, "grant_type", "refresh_token"));
        assert!(has(&p, "refresh_token", "rt-1"));
        assert!(has(&p, "client_id", "client-123"));
        assert!(has(&p, "client_secret", "sec"));
        assert!(has(&p, "audience", "api"));
        assert!(lacks(&p, "code"));
    }

    // ── token_auth = "basic" (RFC 6749 §2.3.1) ──────────────────────────────

    #[test]
    fn basic_auth_moves_the_client_out_of_the_body() {
        let p = code_exchange_params(
            TokenAuth::Basic,
            "client-123",
            Some("sec"),
            "code",
            "verif",
            "http://127.0.0.1/cb",
            &[],
        );
        assert!(lacks(&p, "client_id"));
        assert!(lacks(&p, "client_secret"));
        assert!(has(&p, "grant_type", "authorization_code"));
        let r = refresh_params(TokenAuth::Basic, "client-123", Some("sec"), "rt-1", &[]);
        assert!(lacks(&r, "client_id"));
        assert!(lacks(&r, "client_secret"));
        assert!(has(&r, "refresh_token", "rt-1"));
    }

    #[test]
    fn basic_auth_value_is_urlencoded_then_base64() {
        use base64::Engine as _;
        let decode = |v: &str| {
            let b64 = v.strip_prefix("Basic ").unwrap();
            String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(b64).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(decode(&basic_auth_value("abc", Some("s3cret"))), "abc:s3cret");
        // A client without a secret sends an empty password.
        assert_eq!(decode(&basic_auth_value("abc", None)), "abc:");
        // RFC 6749 §2.3.1: id and secret are form-urlencoded before base64.
        assert_eq!(decode(&basic_auth_value("a:b", Some("p w"))), "a%3Ab:p+w");
    }

    // ── {state} substitution in token_params ────────────────────────────────

    #[test]
    fn render_extra_params_substitutes_state_in_key_order() {
        let params: std::collections::HashMap<String, String> = [
            ("b_echo".to_string(), format!("x-{}-y", STATE_PLACEHOLDER)),
            ("a_fixed".to_string(), "1".to_string()),
        ]
        .into();
        let out = render_extra_params(&params, Some("st-7")).unwrap();
        assert_eq!(
            out,
            vec![
                ("a_fixed".to_string(), "1".to_string()),
                ("b_echo".to_string(), "x-st-7-y".to_string()),
            ]
        );
        // A def that asks for the state when the pending connect has none:
        // the connect fails with why, never sends the placeholder.
        let e = render_extra_params(&params, None).unwrap_err();
        assert!(e.contains("consent state"), "{e}");
        assert!(e.contains("reconnect"), "{e}");
        // Static values need no state.
        let fixed: std::collections::HashMap<String, String> =
            [("a".to_string(), "1".to_string())].into();
        assert_eq!(
            render_extra_params(&fixed, None).unwrap(),
            vec![("a".to_string(), "1".to_string())]
        );
    }
}
