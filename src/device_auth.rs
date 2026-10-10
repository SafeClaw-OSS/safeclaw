//! Device-request proof-of-possession (trust-reset contract 1.4, design D8).
//!
//! Railway terminates TLS before the Node backend ever sees the connection, so
//! the daemon can't present a client certificate. Instead it signs EVERY
//! `/device/*` request with its DIK (device identity key) and the backend
//! verifies the signature against the device's unrevoked registry row. This is
//! the only device credential: there are no bearer tokens (P5), and a request
//! without a valid signature is a 401 carrying `{server_time}`. This module owns
//! the signing side; the backend mirrors the verify in
//! `trust-crypto.mjs::verifyDeviceRequest` (vectors: `crypto/trust_reset_vectors.json`).

use crate::identity::{device_request_signature_input, SigningIdentity};
use data_encoding::BASE64URL_NOPAD;

/// The `dv_…` self-id of the signing device (tells the backend which registered
/// pubkey to check).
pub const HDR_DEVICE_ID: &str = "x-sc-device-id";
/// Unix-seconds timestamp the signature was produced at (freshness / replay
/// window; the backend bounds how far it may drift).
pub const HDR_DEVICE_TS: &str = "x-sc-device-ts";
/// base64url (no padding) of the raw-64 Ed25519 signature over
/// [`device_request_signature_input`].
pub const HDR_DEVICE_SIG: &str = "x-sc-device-sig";

/// A device's request signer: its DIK plus its self-id. Built from the loaded
/// device identity ([`crate::device::load`]).
pub struct DeviceRequestSigner {
    identity: SigningIdentity,
    device_id: String,
}

impl DeviceRequestSigner {
    /// Build from a device `SigningIdentity` and its `dv_…` id. The caller is
    /// responsible for passing the id that matches the identity (the identity
    /// file's `load` recomputes+validates it, so use `LoadedIdentity.id`).
    pub fn new(identity: SigningIdentity, device_id: String) -> Self {
        Self {
            identity,
            device_id,
        }
    }

    /// The signing device's `dv_…` id.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Produce the three PoP header (name, value) pairs for one request. `path`
    /// MUST be the on-wire path including any query string, byte-for-byte as it
    /// will reach the backend; `body` is the raw request body (`&[]` for a
    /// bodyless GET); `timestamp` is unix seconds (pass the real clock at the
    /// call site — this module stays clock-free so it's deterministically
    /// testable); `canonical_host` is the configured backend host
    /// ([`canonical_host`] of the configured base URL).
    pub fn headers(
        &self,
        method: &str,
        path: &str,
        timestamp: u64,
        body: &[u8],
        canonical_host: &str,
    ) -> [(&'static str, String); 3] {
        let input = device_request_signature_input(
            method,
            path,
            timestamp,
            body,
            &self.device_id,
            canonical_host,
        );
        let sig = self.identity.sign(&input);
        [
            (HDR_DEVICE_ID, self.device_id.clone()),
            (HDR_DEVICE_TS, timestamp.to_string()),
            (HDR_DEVICE_SIG, BASE64URL_NOPAD.encode(&sig)),
        ]
    }
}

/// The canonical host of a backend base URL (trust-reset contract 1.4): the
/// WHATWG `URL.host` form — lowercase host, plus `:port` only when the port is
/// not the scheme default. Both sides derive it from CONFIGURATION (the daemon's
/// configured backend URL, the backend's configured public host), never from an
/// incoming `Host` header. `None` if the URL doesn't parse or has no host.
pub fn canonical_host(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    Some(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

/// The on-wire path+query of a full URL — exactly what the Node backend sees as
/// `req.url` (path, `?`, query; no scheme/host). Both sides sign THIS so the PoP
/// verifies. `None` if the URL doesn't parse (caller then skips signing rather
/// than sign bytes the backend can't reproduce).
fn path_and_query(full_url: &str) -> Option<String> {
    let u = reqwest::Url::parse(full_url).ok()?;
    Some(match u.query() {
        Some(q) => format!("{}?{}", u.path(), q),
        None => u.path().to_string(),
    })
}

/// Attach the DIK proof-of-possession headers to a daemon→cloud request. Fails
/// loudly instead of sending an unsigned request (which the backend answers with
/// a 401 anyway): a URL that doesn't parse or has no host is an error.
/// `method` = the uppercase HTTP method; `full_url` = the request URL built from
/// the configured backend base (its path+query and host are what get signed);
/// `body` = the EXACT bytes the request sends (`&[]` for a bodyless GET).
pub fn sign_request(
    rb: reqwest::RequestBuilder,
    signer: &DeviceRequestSigner,
    method: &str,
    full_url: &str,
    body: &[u8],
    timestamp: u64,
) -> Result<reqwest::RequestBuilder, String> {
    let path = path_and_query(full_url)
        .ok_or_else(|| format!("cannot sign a request to an unparseable URL: {}", full_url))?;
    let host = canonical_host(full_url).ok_or_else(|| {
        format!(
            "cannot sign a request to a URL without a host: {}",
            full_url
        )
    })?;
    let mut rb = rb;
    for (k, v) in signer.headers(method, &path, timestamp, body, &host) {
        rb = rb.header(k, v);
    }
    Ok(rb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{derive_id, verify, IdKind};

    const HOST: &str = "api.dev.safeclaw.pro";

    fn signer() -> DeviceRequestSigner {
        let seed = [7u8; 32];
        let id = SigningIdentity::from_seed(&seed);
        let dv_id = derive_id(IdKind::Device, &id.public_bytes());
        DeviceRequestSigner::new(id, dv_id)
    }

    #[test]
    fn headers_verify_over_the_rebuilt_input() {
        let s = signer();
        let seed = [7u8; 32];
        let pub_bytes = SigningIdentity::from_seed(&seed).public_bytes();
        let hdrs = s.headers(
            "PUT",
            "/device/vaults/vault-x/items/i1",
            1_700_000_000,
            b"{}",
            HOST,
        );
        // Header names + order are stable.
        assert_eq!(hdrs[0].0, HDR_DEVICE_ID);
        assert_eq!(hdrs[1].0, HDR_DEVICE_TS);
        assert_eq!(hdrs[2].0, HDR_DEVICE_SIG);
        assert_eq!(hdrs[0].1, s.device_id());
        assert_eq!(hdrs[1].1, "1700000000");
        // The signature the backend will check verifies over the input it rebuilds
        // from method/path/ts/body/device_id plus its configured host.
        assert!(s.device_id().starts_with("dv_"));
        let sig: [u8; 64] = BASE64URL_NOPAD
            .decode(hdrs[2].1.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let input = device_request_signature_input(
            "PUT",
            "/device/vaults/vault-x/items/i1",
            1_700_000_000,
            b"{}",
            s.device_id(),
            HOST,
        );
        assert!(verify(&pub_bytes, &input, &sig), "PoP verifies");
    }

    #[test]
    fn path_and_query_matches_backend_req_url() {
        // Node's http `req.url` = path (+ ?query), never scheme/host — sign that.
        assert_eq!(
            path_and_query("https://api.example.com/device/vaults/abc/state?since=5").as_deref(),
            Some("/device/vaults/abc/state?since=5")
        );
        assert_eq!(
            path_and_query("https://api.example.com/device/vaults").as_deref(),
            Some("/device/vaults")
        );
        assert_eq!(path_and_query("not a url"), None);
    }

    #[test]
    fn sign_request_fails_loudly_on_a_bad_url() {
        let client = reqwest::Client::new();
        let rb = client.get("http://x");
        assert!(sign_request(rb, &signer(), "GET", "not a url", b"", 1).is_err());
        let rb = client.get("https://api.dev.safeclaw.pro/device/me");
        let signed = sign_request(
            rb,
            &signer(),
            "GET",
            "https://api.dev.safeclaw.pro/device/me?x=1",
            b"",
            1_700_000_000,
        )
        .unwrap()
        .build()
        .unwrap();
        let h = signed.headers();
        assert_eq!(h.get(HDR_DEVICE_ID).unwrap(), signer().device_id());
        assert_eq!(h.get(HDR_DEVICE_TS).unwrap(), "1700000000");
        // The signature covers path+query and the configured host.
        let sig: [u8; 64] = BASE64URL_NOPAD
            .decode(h.get(HDR_DEVICE_SIG).unwrap().as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let input = device_request_signature_input(
            "GET",
            "/device/me?x=1",
            1_700_000_000,
            b"",
            signer().device_id(),
            HOST,
        );
        let pub_bytes = SigningIdentity::from_seed(&[7u8; 32]).public_bytes();
        assert!(verify(&pub_bytes, &input, &sig));
    }

    #[test]
    fn a_replayed_signature_fails_on_a_different_request() {
        let s = signer();
        let pub_bytes = SigningIdentity::from_seed(&[7u8; 32]).public_bytes();
        let hdrs = s.headers("GET", "/a", 1, b"", HOST);
        let sig: [u8; 64] = BASE64URL_NOPAD
            .decode(hdrs[2].1.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        // Same signature, different path → the rebuilt input differs → reject.
        let other = device_request_signature_input("GET", "/b", 1, b"", s.device_id(), HOST);
        assert!(!verify(&pub_bytes, &other, &sig));
        // Same request against another deployment's host → reject.
        let prod =
            device_request_signature_input("GET", "/a", 1, b"", s.device_id(), "api.safeclaw.pro");
        assert!(!verify(&pub_bytes, &prod, &sig));
    }
}
