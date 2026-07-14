//! WebAuthn assertion verification — thin adapter over
//! `sudp::passkey::WebAuthn` (the SUDP reference implementation of the
//! `Authenticator` trait for ES256/P-256 + PRF).
//!
//! Verification checks (WebAuthn L3 §7.2 plus SUDP channel binding β):
//!   1. Decode `authenticatorData`, `clientDataJSON`, `signature`.
//!   2. `clientDataJSON.type == "webauthn.get"`.
//!   3. `origin` matches expected.
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

use sudp::passkey::{WebAuthn, WebAuthnAssertion, WebAuthnPublicKey};
use sudp::primitives::{Authenticator, AuthenticatorContext};

use crate::error::{AppError, Result};

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
/// - `expected_origin`: configured origin to compare against `clientDataJSON.origin`.
/// - `rp_id`: WebAuthn relying-party ID (hostname only).
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
    expected_origin: &str,
    rp_id: &str,
    expected_challenge: &[u8; 32],
) -> Result<()> {
    let public_key = WebAuthnPublicKey {
        x: x_b64.to_string(),
        y: y_b64.to_string(),
        device_name: String::new(),
    };
    let context = AuthenticatorContext {
        origin: expected_origin.to_string(),
        rp_id: rp_id.to_string(),
        require_uv: false,
    };
    <WebAuthn as Authenticator>::verify_assertion(
        &public_key,
        expected_challenge,
        assertion,
        &context,
    )
    .map_err(|_| AppError::Unauthorized("WebAuthn assertion verification failed".into()))
}
