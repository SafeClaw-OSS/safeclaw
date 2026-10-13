//! WebAuthn assertion verification — thin adapter over
//! `sudp::passkey::WebAuthn` (the SUDP reference implementation of the
//! `Authenticator` trait for ES256/P-256 + PRF).
//!
//! Verification checks (WebAuthn L3 §7.2 plus SUDP channel binding β):
//!   1. Decode `authenticatorData`, `clientDataJSON`, `signature`.
//!   2. `clientDataJSON.type == "webauthn.get"`.
//!   3. `origin` is one the relying party accepts ([`RelyingParty`]).
//!   4. `base64url_decode(challenge) == β` (channel binding).
//!   5. `authenticatorData.rpIdHash == SHA-256(rpId)`.
//!   6. User Present flag set.
//!   7. ECDSA-P-256 verify of `authenticatorData ‖ SHA-256(clientDataJSON)`.
//!
//! Adapter responsibilities:
//!   - Bridge sudp's `Error::AuthorizationInvalid` → safeclaw's
//!     `AppError::Unauthorized`.
//!   - Adapt the positional API safeclaw call sites use (origin + rp_id passed
//!     in directly) to sudp's `AuthenticatorContext`.
//!
//! SafeClaw currently only verifies `webauthn.get` assertions (registration
//! goes through a separate enrollment path); the historical
//! `AssertionKind::Create` variant was unused and has been removed.

use base64::{engine::general_purpose::STANDARD, Engine};
use sudp::passkey::{WebAuthn, WebAuthnAssertion, WebAuthnPublicKey};
use sudp::primitives::{Authenticator, AuthenticatorContext};

use crate::error::{AppError, Result};

/// Whose assertions the daemon accepts: the RP ID the authenticator signed
/// for (`authenticatorData.rpIdHash` must be its SHA-256) and the exact
/// `clientDataJSON.origin` values allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    pub rp_id: String,
    pub origins: Vec<String>,
}

impl RelyingParty {
    /// One origin, matched exactly: an explicit `--origin` / `--rp-id`, a
    /// self-hosted or localhost daemon.
    pub fn exact(origin: &str, rp_id: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            origins: vec![origin.trim_end_matches('/').to_string()],
        }
    }

    /// The cloud console's relying party, from the console origin the daemon
    /// stored at pairing (`https://<host>`). Passkeys are pinned to the root
    /// RP ID so they work on the root and its subdomains; the root is the
    /// host with one leading `app.` or `www.` label removed
    /// (`app.safeclaw.pro` and `safeclaw.pro` both give `safeclaw.pro`), so
    /// either stored form verifies the same assertions. The accepted origins
    /// are exactly `https://<root>`, `https://app.<root>` and
    /// `https://www.<root>`: a list, not every subdomain, so no other host
    /// under the root can produce an approval. `None` for anything but a bare
    /// https origin on a domain (the caller then matches exactly).
    pub fn console(origin: &str) -> Option<Self> {
        let url = url::Url::parse(origin).ok()?;
        let bare = url.scheme() == "https"
            && url.port().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none();
        let Some(url::Host::Domain(host)) = url.host() else {
            return None;
        };
        if !bare {
            return None;
        }
        let root = ["app.", "www."]
            .iter()
            .find_map(|label| host.strip_prefix(label))
            .filter(|rest| rest.contains('.'))
            .unwrap_or(host);
        Some(Self {
            rp_id: root.to_string(),
            origins: vec![
                format!("https://{}", root),
                format!("https://app.{}", root),
                format!("https://www.{}", root),
            ],
        })
    }

    /// Is `origin` (as `clientDataJSON` reports it) one this party accepts?
    pub fn allows(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }
}

/// The `origin` an assertion's `clientDataJSON` reports, if it decodes.
fn reported_origin(assertion: &AssertionData) -> Option<String> {
    let raw = STANDARD.decode(&assertion.client_data_json).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    json.get("origin")?.as_str().map(str::to_string)
}

/// Assertion data sent by the browser client.
///
/// Re-export of [`sudp::passkey::WebAuthnAssertion`] so safeclaw's own call
/// sites and serde shapes remain unchanged.
pub type AssertionData = WebAuthnAssertion;

/// Verify a WebAuthn `webauthn.get` assertion with channel binding.
///
/// Arguments:
/// - `assertion`: the parsed assertion fields (standard base64).
/// - `x_b64`, `y_b64`: the credential's public-key coordinates, standard base64.
/// - `rp`: the relying party: `clientDataJSON.origin` must be one of its
///   origins, and `authenticatorData.rpIdHash` the hash of its RP ID.
/// - `expected_challenge`: 32-byte β the client should have used as the
///   WebAuthn challenge.
///
/// Returns `Ok(())` on success. Failure returns `AppError::Unauthorized` with
/// a generic message (sudp does not distinguish individual check failures to
/// avoid timing side channels).
pub fn verify_assertion(
    assertion: &AssertionData,
    x_b64: &str,
    y_b64: &str,
    rp: &RelyingParty,
    expected_challenge: &[u8; 32],
) -> Result<()> {
    let failed = || AppError::Unauthorized("WebAuthn assertion verification failed".into());
    // The reported origin must be on the list; sudp then checks it again
    // (exactly), the type, the challenge, rpIdHash against the root RP ID,
    // user presence and the signature over all of it.
    let origin = reported_origin(assertion)
        .filter(|o| rp.allows(o))
        .ok_or_else(failed)?;
    let public_key = WebAuthnPublicKey {
        x: x_b64.to_string(),
        y: y_b64.to_string(),
        device_name: String::new(),
    };
    let context = AuthenticatorContext {
        origin,
        rp_id: rp.rp_id.clone(),
        require_uv: false,
    };
    <WebAuthn as Authenticator>::verify_assertion(
        &public_key,
        expected_challenge,
        assertion,
        &context,
    )
    .map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};

    /// A real ES256 assertion: signed for `rp_id`, reporting `origin`.
    fn assertion(
        key: &SigningKey,
        rp_id: &str,
        origin: &str,
        challenge: &[u8; 32],
    ) -> AssertionData {
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(0x01); // user present
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        }))
        .unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let sig: Signature = key.sign(&signed);
        AssertionData {
            credential_id: None,
            authenticator_data: STANDARD.encode(&auth_data),
            client_data_json: STANDARD.encode(&client_data),
            signature: STANDARD.encode(sig.to_der().as_bytes()),
        }
    }

    fn xy(key: &SigningKey) -> (String, String) {
        let point = key.verifying_key().to_encoded_point(false);
        (
            STANDARD.encode(point.x().unwrap()),
            STANDARD.encode(point.y().unwrap()),
        )
    }

    #[test]
    fn console_relying_party_is_the_root_and_its_app_and_www_origins() {
        for (stored, root) in [
            ("https://safeclaw.pro", "safeclaw.pro"),
            ("https://app.safeclaw.pro", "safeclaw.pro"),
            ("https://www.safeclaw.pro", "safeclaw.pro"),
            ("https://dev.safeclaw.pro", "dev.safeclaw.pro"),
            ("https://app.dev.safeclaw.pro", "dev.safeclaw.pro"),
            ("https://app.example", "app.example"),
        ] {
            let rp = RelyingParty::console(stored).unwrap();
            assert_eq!(rp.rp_id, root, "{stored}");
            assert_eq!(
                rp.origins,
                vec![
                    format!("https://{root}"),
                    format!("https://app.{root}"),
                    format!("https://www.{root}")
                ]
            );
        }
        for not_console in [
            "http://localhost:23293",
            "http://safeclaw.pro",
            "https://safeclaw.pro:8443",
            "https://safeclaw.pro/console",
            "https://127.0.0.1",
            "not a url",
        ] {
            assert!(
                RelyingParty::console(not_console).is_none(),
                "{not_console}"
            );
        }
    }

    #[test]
    fn assertions_verify_on_the_root_app_and_www_only() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let (x, y) = xy(&key);
        let challenge = [7u8; 32];
        for stored in ["https://safeclaw.pro", "https://app.safeclaw.pro"] {
            let rp = RelyingParty::console(stored).unwrap();
            for origin in [
                "https://safeclaw.pro",
                "https://app.safeclaw.pro",
                "https://www.safeclaw.pro",
            ] {
                let a = assertion(&key, "safeclaw.pro", origin, &challenge);
                verify_assertion(&a, &x, &y, &rp, &challenge)
                    .unwrap_or_else(|e| panic!("{stored} / {origin}: {e:?}"));
            }
            for origin in [
                "https://evil.safeclaw.pro",
                "https://app.dev.safeclaw.pro",
                "http://safeclaw.pro",
                "http://app.safeclaw.pro",
                "https://safeclaw.pro.evil.com",
                "https://appsafeclaw.pro",
                "https://safeclaw.pro:8443",
                "https://SAFECLAW.pro",
            ] {
                let a = assertion(&key, "safeclaw.pro", origin, &challenge);
                assert!(
                    verify_assertion(&a, &x, &y, &rp, &challenge).is_err(),
                    "{stored} accepted {origin}"
                );
            }
            // Signed for another RP ID: the hash must be the root's.
            let a = assertion(
                &key,
                "app.safeclaw.pro",
                "https://app.safeclaw.pro",
                &challenge,
            );
            assert!(verify_assertion(&a, &x, &y, &rp, &challenge).is_err());
            // A different challenge never verifies.
            let a = assertion(&key, "safeclaw.pro", "https://safeclaw.pro", &[8u8; 32]);
            assert!(verify_assertion(&a, &x, &y, &rp, &challenge).is_err());
        }
    }

    #[test]
    fn an_explicit_origin_is_matched_exactly() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let (x, y) = xy(&key);
        let challenge = [3u8; 32];
        let rp = RelyingParty::exact("https://vault.example.com/", "vault.example.com");
        let ok = assertion(
            &key,
            "vault.example.com",
            "https://vault.example.com",
            &challenge,
        );
        assert!(verify_assertion(&ok, &x, &y, &rp, &challenge).is_ok());
        let app = assertion(
            &key,
            "vault.example.com",
            "https://app.vault.example.com",
            &challenge,
        );
        assert!(verify_assertion(&app, &x, &y, &rp, &challenge).is_err());
        let local = RelyingParty::exact("http://localhost:23293", "localhost");
        let a = assertion(&key, "localhost", "http://localhost:23293", &challenge);
        assert!(verify_assertion(&a, &x, &y, &local, &challenge).is_ok());
    }
}
