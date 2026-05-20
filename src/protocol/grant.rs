//! `Grant` validation pipeline.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::binding::{binding_for_op, DOMAIN_SETUP, DOMAIN_STANDARD};
use crate::error::{AppError, Result};
use crate::passkey::webauthn::{verify_assertion, AssertionData, AssertionKind};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{Act, Operation};

/// Grant submitted to `POST /grant` (or to `/approve/{id}/confirm`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Operation contract.
    pub o: Operation,
    /// Server-issued challenge (base64, 16+ bytes).
    pub r: String,
    /// Acting credential id (base64).
    pub credential_id: String,
    /// PRF-derived userKey (base64, 32B raw).
    pub user_key: String,
    /// WebAuthn assertion.
    pub assertion: AssertionData,
    /// TLS-bound side payload — values that depend on the post-PRF KEK and
    /// therefore cannot be hashed into β at the moment the WebAuthn assertion
    /// is generated. Channel integrity is provided by TLS, not the assertion.
    /// Currently only used by `Act::Setup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_payload: Option<SetupPayload>,
    /// Optional unbound payload (ignored by v0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt: Option<serde_json::Value>,
}

/// Side payload for `Act::Setup`. Carried out-of-band of the canonical op so
/// that β = SHA-256(domain ‖ 0x00 ‖ r ‖ SHA-256(canonical(o))) can be
/// pre-computed before the PRF-bearing WebAuthn `.get()` runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPayload {
    /// Base64 of wrapped DEK (XChaCha20-Poly1305 under KEK derived from
    /// `user_key` + `credential.prf_salt`).
    pub wrapped_dek: String,
    /// Base64 of initial sealed body (XChaCha20-Poly1305 under DEK).
    pub body: String,
}

/// Output of `validate_grant` — what the act dispatcher uses.
pub struct ValidatedGrant {
    pub op: Operation,
    /// Acting credential id (raw bytes).
    pub credential_id_bytes: Vec<u8>,
    /// 32-byte userKey (zeroized on drop).
    pub user_key: Vec<u8>,
    /// `r` consumed (raw bytes).
    pub r_bytes: Vec<u8>,
}

impl Drop for ValidatedGrant {
    fn drop(&mut self) {
        self.user_key.zeroize();
    }
}

/// Validate a grant. The challenge `r` is consumed (single-use).
///
/// `credential_lookup` returns the credential's public key entry or `None` if
/// unknown. For `setup`, the credential is taken from the operation body
/// instead of the lookup.
pub fn validate_grant(
    grant: &Grant,
    challenge_store: &mut crate::passkey::challenge::ChallengeStore,
    origin: &str,
    rp_id: &str,
    credential_lookup: impl FnOnce(&str) -> Option<PasskeyEntry>,
) -> Result<ValidatedGrant> {
    // 1. Consume r (single-use, must be issued by us).
    {
        if !challenge_store.verify(&grant.r) {
            return Err(AppError::Unauthorized(
                "invalid or expired challenge `r`".into(),
            ));
        }
    }

    // 2. Validity window.
    grant.o.valid.check_now()?;

    // 3. Resolve credential public key (from body for setup, from store otherwise).
    let (entry, domain) = match &grant.o.act {
        Act::Setup { credential } => {
            if credential.credential_id != grant.credential_id {
                return Err(AppError::BadRequest(
                    "grant.credential_id != setup.credential.credential_id".into(),
                ));
            }
            let entry = PasskeyEntry {
                x: credential.public_key_x.clone(),
                y: credential.public_key_y.clone(),
                device_name: credential.device_name.clone(),
                created_at: 0,
            };
            (entry, DOMAIN_SETUP)
        }
        _ => {
            let entry = credential_lookup(&grant.credential_id)
                .ok_or_else(|| AppError::Unauthorized("unknown credential".into()))?;
            (entry, DOMAIN_STANDARD)
        }
    };

    // 4. Decode r.
    let r_bytes = STANDARD
        .decode(&grant.r)
        .map_err(|_| AppError::BadRequest("r not base64".into()))?;
    if r_bytes.len() < 16 {
        return Err(AppError::BadRequest("r too short".into()));
    }

    // 5. Compute β over canonical(o).
    let op_value = serde_json::to_value(&grant.o)?;
    let beta = binding_for_op(domain, &r_bytes, &op_value);

    // 6. Verify WebAuthn assertion against credential's public key.
    if let Some(ref a_cred_id) = grant.assertion.credential_id {
        if a_cred_id != &grant.credential_id {
            return Err(AppError::Unauthorized(
                "assertion.credential_id != grant.credential_id".into(),
            ));
        }
    }
    verify_assertion(
        &grant.assertion,
        &entry.x,
        &entry.y,
        origin,
        rp_id,
        &beta,
        AssertionKind::Get,
    )?;

    // 7. Decode user_key + credential_id raw bytes.
    let credential_id_bytes = STANDARD
        .decode(&grant.credential_id)
        .map_err(|_| AppError::BadRequest("credential_id not base64".into()))?;
    let user_key = STANDARD
        .decode(&grant.user_key)
        .map_err(|_| AppError::BadRequest("user_key not base64".into()))?;
    if user_key.len() != 32 {
        return Err(AppError::BadRequest("user_key must be 32 bytes".into()));
    }

    Ok(ValidatedGrant {
        op: grant.o.clone(),
        credential_id_bytes,
        user_key,
        r_bytes,
    })
}
