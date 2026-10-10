//! The daemon's ONLY channel to the backend: DIK-signed `/device/*` requests
//! (trust-reset contract 1.4, 8.4; design D8, P5).
//!
//! Every request carries `x-sc-device-{id,ts,sig}` over the method, the
//! path+query, the timestamp, SHA-256(body), the `dv_` id and the canonical
//! host of the CONFIGURED backend URL, plus `x-safeclaw-version` for the
//! server's fail-loud floor. There is no bearer token and no fallback: a machine
//! without a device identity cannot talk to the backend at all.
//!
//! Refusals the backend can answer on any route are classified here once
//! ([`refusal`]), so every caller turns them into the same actionable message.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use serde_json::Value;

use crate::device::Device;

/// The header the backend's fail-loud gate reads (contract 3).
pub const HDR_VERSION: &str = "x-safeclaw-version";

/// The configured backend base URL (`sc login` persisted it as `cloud_backend`),
/// trimmed of a trailing slash. `Err` when this machine was never paired.
pub fn configured_backend() -> Result<String, String> {
    let cfg = crate::cli::active::load().map_err(|e| format!("read config: {}", e))?;
    cfg.cloud_backend
        .as_deref()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| crate::device::NOT_PAIRED.to_string())
}

struct Inner {
    base: String,
    device: Device,
}

/// A signed client for one device against one backend. Cheap to clone.
#[derive(Clone)]
pub struct DeviceClient {
    inner: Arc<Inner>,
}

impl DeviceClient {
    /// The configured backend + this machine's device identity. Fails with an
    /// actionable "run `sc login`" message when either is missing.
    pub fn load() -> Result<Self, String> {
        let base = configured_backend()?;
        let device = crate::device::load()?;
        Ok(Self::new(base, device))
    }

    pub fn new(base: impl Into<String>, device: Device) -> Self {
        Self {
            inner: Arc::new(Inner {
                base: base.into().trim_end_matches('/').to_string(),
                device,
            }),
        }
    }

    pub fn base(&self) -> &str {
        &self.inner.base
    }

    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    /// The absolute URL of a backend path (`path` starts with `/`).
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.inner.base, path)
    }

    /// Build a signed request on `client` (callers that need their own client,
    /// e.g. the long-poll and stream timeouts). The body, when present, is
    /// serialized ONCE: the bytes signed are the bytes sent.
    pub fn request(
        &self,
        client: &reqwest::Client,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::RequestBuilder, String> {
        let url = self.url(path);
        let bytes = match body {
            Some(v) => serde_json::to_vec(v).map_err(|e| format!("encode body: {}", e))?,
            None => Vec::new(),
        };
        let mut rb = client
            .request(method.clone(), &url)
            .header(HDR_VERSION, env!("CARGO_PKG_VERSION"));
        if body.is_some() {
            rb = rb
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes.clone());
        }
        crate::device_auth::sign_request(
            rb,
            self.inner.device.signer(),
            method.as_str(),
            &url,
            &bytes,
            crate::util::now_unix(),
        )
    }

    /// Send one signed request with a fresh egress-aware client.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<reqwest::Response, String> {
        let client = crate::cli::egress_proxy::client(timeout)
            .map_err(|e| format!("http client init: {}", e))?;
        self.request(&client, method, path, body)?
            .send()
            .await
            .map_err(|e| crate::cli::neterr::reach_failed(&self.inner.base, &e))
    }

    pub async fn get(&self, path: &str, timeout: Duration) -> Result<reqwest::Response, String> {
        self.send(Method::GET, path, None, timeout).await
    }

    pub async fn post(
        &self,
        path: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<reqwest::Response, String> {
        self.send(Method::POST, path, Some(body), timeout).await
    }
}

/// A refusal the backend can answer on any `/device/*` route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// 403 `SC_UPGRADE_REQUIRED`: this build is below the server's floor.
    UpgradeRequired,
    /// 403 `SC_DEVICE_REVOKED`: the registry row for this `dv_` is revoked or
    /// signed out. The daemon verifies it against its own ledger before acting.
    DeviceRevoked,
    /// 401: the signature did not verify (unknown device, bad signature, or a
    /// clock outside the ±300 s window). `skew` = server time minus ours.
    Unauthorized { skew: Option<i64> },
}

/// Classify a non-2xx answer. `None` for anything that is not one of the
/// device-wide refusals (the caller handles route-specific statuses).
pub fn refusal(status: u16, body: &Value) -> Option<Refusal> {
    let code = body
        .get("code")
        .or_else(|| body.get("error"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match (status, code) {
        (403, "SC_UPGRADE_REQUIRED") | (426, _) => Some(Refusal::UpgradeRequired),
        (403, "SC_DEVICE_REVOKED") => Some(Refusal::DeviceRevoked),
        (401, _) => {
            let skew = body
                .get("server_time")
                .and_then(|v| v.as_i64())
                .map(|t| t - crate::util::now_unix() as i64);
            Some(Refusal::Unauthorized { skew })
        }
        _ => None,
    }
}

/// The ±300 s signature window (contract 1.4).
pub const SIGNATURE_WINDOW_SECS: i64 = 300;

impl Refusal {
    /// The actionable sentence a human sees.
    pub fn message(&self) -> String {
        match self {
            Refusal::UpgradeRequired => {
                "this SafeClaw is too old for the server — run `sc upgrade`".to_string()
            }
            Refusal::DeviceRevoked => "this machine was signed out or revoked — pair it again \
                 with `sc login`"
                .to_string(),
            Refusal::Unauthorized { skew: Some(s) } if s.abs() > SIGNATURE_WINDOW_SECS => format!(
                "this machine's clock is off by {}s — fix the system clock (signed requests are \
                 valid for 5 minutes)",
                s
            ),
            Refusal::Unauthorized { .. } => "the server does not recognize this machine — pair \
                 it again with `sc login`"
                .to_string(),
        }
    }
}

/// Read a non-2xx response into one error string: a device-wide refusal's
/// actionable message, else `"<what> HTTP <status>: <body>"`.
pub async fn error_text(resp: reqwest::Response, what: &str) -> String {
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if let Some(r) = refusal(status, &body) {
        return r.message();
    }
    let detail = body
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| text.chars().take(200).collect());
    if detail.trim().is_empty() {
        format!("{} HTTP {}", what, status)
    } else {
        format!("{} HTTP {}: {}", what, status, detail.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refusals_are_classified_and_actionable() {
        assert_eq!(
            refusal(403, &json!({"code": "SC_UPGRADE_REQUIRED"})),
            Some(Refusal::UpgradeRequired)
        );
        assert!(Refusal::UpgradeRequired.message().contains("sc upgrade"));
        assert_eq!(
            refusal(403, &json!({"error": "SC_DEVICE_REVOKED"})),
            Some(Refusal::DeviceRevoked)
        );
        assert!(Refusal::DeviceRevoked.message().contains("sc login"));
        // A plain 403 (route-specific) is not a device-wide refusal.
        assert_eq!(refusal(403, &json!({"error": "rejected"})), None);
        // 401 with a far-off server clock names the clock, not re-pairing.
        let far = crate::util::now_unix() as i64 + 3600;
        match refusal(401, &json!({"server_time": far})) {
            Some(r @ Refusal::Unauthorized { skew: Some(_) }) => {
                assert!(r.message().contains("clock"), "{}", r.message())
            }
            other => panic!("{other:?}"),
        }
        let near = crate::util::now_unix() as i64;
        let r = refusal(401, &json!({"server_time": near})).unwrap();
        assert!(r.message().contains("sc login"));
        assert!(refusal(401, &Value::Null)
            .unwrap()
            .message()
            .contains("sc login"));
    }

    #[test]
    fn signed_request_carries_version_and_signature_over_sent_bytes() {
        let device = crate::device::tests_support::device(9);
        let c = DeviceClient::new("https://api.dev.safeclaw.pro/", device);
        assert_eq!(
            c.url("/device/me"),
            "https://api.dev.safeclaw.pro/device/me"
        );
        let body = json!({"b": 1, "a": [1, 2]});
        let req = c
            .request(
                &reqwest::Client::new(),
                Method::POST,
                "/device/vaults/v1/audit",
                Some(&body),
            )
            .unwrap()
            .build()
            .unwrap();
        let h = req.headers();
        assert_eq!(h.get(HDR_VERSION).unwrap(), env!("CARGO_PKG_VERSION"));
        let sent = req.body().unwrap().as_bytes().unwrap().to_vec();
        assert_eq!(sent, serde_json::to_vec(&body).unwrap());
        let ts: u64 = h
            .get(crate::device_auth::HDR_DEVICE_TS)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let sig: [u8; 64] = data_encoding::BASE64URL_NOPAD
            .decode(
                h.get(crate::device_auth::HDR_DEVICE_SIG)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let input = crate::identity::device_request_signature_input(
            "POST",
            "/device/vaults/v1/audit",
            ts,
            &sent,
            c.device().id(),
            "api.dev.safeclaw.pro",
        );
        assert!(crate::identity::verify(c.device().sig_pub(), &input, &sig));
    }
}
