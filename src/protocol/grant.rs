//! `Grant` validation pipeline.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::binding::{binding_for_op, DOMAIN_SETUP, DOMAIN_STANDARD};
use crate::error::{AppError, Result};
use crate::passkey::webauthn::{verify_assertion, AssertionData};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{
    as_enroll_credential, check_now, ActType, Operation,
};

/// Grant submitted to `POST /grant` (or to `/approve/{id}/confirm`).
///
/// Matches the SUDP paper §5.5 wire shape `G := (o, r, cid_{c*}, W*, σ*, opt)`
/// — `wrapping_key` is `W*` (= `W_c` for the acting credential), derived on
/// the client from `userKey` and shipped over the confidential TLS leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Operation contract.
    pub o: Operation,
    /// Server-issued challenge (base64, 16+ bytes).
    pub r: String,
    /// Acting credential id (base64).
    pub credential_id: String,
    /// `W*` — wrapping key for the acting credential (base64, 32B raw).
    pub wrapping_key: String,
    /// WebAuthn assertion.
    pub assertion: AssertionData,
    /// TLS-bound side payload — sealed bytes that depend on `W*` and so
    /// cannot be hashed into β at the moment the WebAuthn assertion is
    /// generated. Channel integrity is provided by TLS. Currently only used
    /// by `Act::Enroll` (initial setup).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_payload: Option<SetupPayload>,
    /// Optional rotation payload (`W*_next` for write/rotate/enroll/revoke).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt: Option<serde_json::Value>,
}

/// Side payload for `Act::Enroll`. Carried out-of-band of the canonical op so
/// that β = SHA-256(domain ‖ 0x00 ‖ r ‖ SHA-256(canonical(o))) can be
/// pre-computed before the PRF-bearing WebAuthn `.get()` runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPayload {
    /// Base64 of `K̂_c = Wrap_{W_c}(K)` — the wrapped state-encryption key.
    /// AAD is sudp's `WrapBinding ‖ cid ‖ ver_be`.
    pub wrapped_key: String,
    /// Base64 of `C = Enc_K(canonical(ProtectedState); DS_seal ‖ ver_be)`.
    pub ciphertext: String,
}

/// Output of `validate_grant` — what the act dispatcher uses.
pub struct ValidatedGrant {
    pub op: Operation,
    /// Acting credential id (raw bytes).
    pub credential_id_bytes: Vec<u8>,
    /// 32-byte wrapping key `W*` (zeroized on drop).
    pub wrapping_key: Vec<u8>,
    /// `r` consumed (raw bytes).
    pub r_bytes: Vec<u8>,
}

impl Drop for ValidatedGrant {
    fn drop(&mut self) {
        self.wrapping_key.zeroize();
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
    check_now(&grant.o.valid)?;

    // 3. Resolve credential public key:
    //    - first-time Enroll (target empty): pubkey comes from the op body
    //      (no enrolled credential to look up yet), DOMAIN_SETUP.
    //    - add-passkey Enroll (target == "passkeys"): signed by an EXISTING
    //      acting credential — the new credential's pubkey rides in
    //      scope.new and only gets installed on the approve path. Use the
    //      standard lookup + DOMAIN_STANDARD to match what the frontend's
    //      addPasskey actually signs with.
    //    - everything else: standard lookup.
    let (entry, domain) = match &grant.o.act.kind {
        ActType::Enroll if grant.o.act.target == "passkeys" => {
            let entry = credential_lookup(&grant.credential_id)
                .ok_or_else(|| AppError::Unauthorized("unknown credential".into()))?;
            (entry, DOMAIN_STANDARD)
        }
        ActType::Enroll => {
            let credential = as_enroll_credential(&grant.o)?;
            if credential.credential_id != grant.credential_id {
                return Err(AppError::BadRequest(
                    "grant.credential_id != enroll.credential.credential_id".into(),
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
    )?;

    // 7. Decode wrapping_key + credential_id raw bytes.
    let credential_id_bytes = STANDARD
        .decode(&grant.credential_id)
        .map_err(|_| AppError::BadRequest("credential_id not base64".into()))?;
    let wrapping_key = STANDARD
        .decode(&grant.wrapping_key)
        .map_err(|_| AppError::BadRequest("wrapping_key not base64".into()))?;
    if wrapping_key.len() != 32 {
        return Err(AppError::BadRequest("wrapping_key must be 32 bytes".into()));
    }

    Ok(ValidatedGrant {
        op: grant.o.clone(),
        credential_id_bytes,
        wrapping_key,
        r_bytes,
    })
}
