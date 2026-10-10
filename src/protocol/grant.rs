//! `Grant` validation pipeline.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::crypto::binding::{binding_for_op, DOMAIN_STANDARD};
use crate::error::{AppError, Result};
use crate::passkey::webauthn::{verify_assertion, AssertionData};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{check_now, decode_credential_id, Operation};

/// Grant deposited by the console for an op (contract 8.5, design D6):
/// `{o, r, credential_id, k_enc, k_ct, assertion | batch}`.
///
/// The secret is the vault's 64-byte K bundle, HPKE-sealed to THIS device's
/// admitted enc key with `info = grant_seal_info(op_id)` (contract 1.7); the
/// backend carrying it never sees K. No custody secret (UIK root, `W_c`, a
/// plaintext wrapping key) ever travels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Operation contract.
    pub o: Operation,
    /// Server-issued challenge (base64, 16+ bytes).
    pub r: String,
    /// Acting credential id (base64url).
    pub credential_id: String,
    /// HPKE encapped key of the sealed K bundle (base64url-no-pad).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_enc: Option<String>,
    /// HPKE ciphertext + tag of the sealed K bundle (base64url-no-pad).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_ct: Option<String>,
    /// WebAuthn assertion. Present on every PLAIN grant (challenge = β).
    /// ABSENT on a batch grant — the shared proof rides in `batch` instead,
    /// and a batch grant carrying a top-level assertion is rejected outright
    /// (an old daemon would verify it against β, fail, and march
    /// `fail_count` to auto-reject; see design/batch-approve.md §Wire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<AssertionData>,
    /// Batch-approve proof (design/batch-approve.md): ONE assertion whose
    /// challenge is SHA-256(tag ‖ MerkleRoot(β_1..β_N)) over the ops named in
    /// `op_ids` (leaf order). Deposited once per op row; the daemon rebuilds
    /// the root from its OWN stored ops and verifies via
    /// `validate_batch_grant`. Mutually exclusive with `assertion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchProof>,
}

/// The shared batch proof carried by each of a batch's grant rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProof {
    /// The batch's op ids in LEAF ORDER (= the exact ordered set the user's
    /// gesture signed). 2..=32 entries, no duplicates, must contain the op
    /// this grant is deposited on.
    pub op_ids: Vec<String>,
    /// The one WebAuthn assertion over the domain-tagged Merkle root.
    pub assertion: AssertionData,
}

/// Output of `validate_grant` — what the act dispatcher uses. The K bundle is
/// opened separately ([`crate::server::handlers::approve`]), after the assertion
/// verified.
pub struct ValidatedGrant {
    pub op: Operation,
    /// Acting credential id (raw bytes).
    pub credential_id_bytes: Vec<u8>,
    /// `r` consumed (raw bytes).
    pub r_bytes: Vec<u8>,
}

/// Validate a PLAIN grant (challenge = the op's own β). The challenge `r` is
/// consumed (single-use). Rejects batch-shaped grants outright — the batch
/// arm goes through [`validate_batch_grant`] with a caller-computed challenge.
///
/// `credential_lookup` returns the credential's public key entry or `None` if
/// unknown (the caller resolves it from the approver member's ledger).
pub fn validate_grant(
    grant: &Grant,
    challenge_store: &mut crate::passkey::challenge::ChallengeStore,
    origin: &str,
    rp_id: &str,
    credential_lookup: impl FnOnce(&str) -> Option<PasskeyEntry>,
) -> Result<ValidatedGrant> {
    if grant.batch.is_some() {
        return Err(AppError::BadRequest(
            "batch grant not accepted on this path".into(),
        ));
    }
    let assertion = grant
        .assertion
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("grant carries no assertion".into()))?;

    // Validity window.
    check_now(&grant.o.valid)?;

    let entry = credential_lookup(&grant.credential_id).ok_or_else(|| {
        AppError::Unauthorized(
            "this passkey isn't admitted in the ledger of any member of this vault".into(),
        )
    })?;
    let domain = DOMAIN_STANDARD;

    // Decode r and compute β over canonical(o) (strict float-rejecting
    // encoder) — the plain arm's expected challenge.
    let r_bytes = STANDARD
        .decode(&grant.r)
        .map_err(|_| AppError::BadRequest("r not base64".into()))?;
    if r_bytes.len() < 16 {
        return Err(AppError::BadRequest("r too short".into()));
    }
    let op_value = serde_json::to_value(&grant.o)?;
    let beta = binding_for_op(domain, &r_bytes, &op_value)?;

    validate_grant_core(
        grant,
        assertion,
        &entry,
        &beta,
        challenge_store,
        origin,
        rp_id,
    )
}

/// Validate a BATCH grant (design/batch-approve.md). The caller (the approve
/// handler) has already rebuilt the Merkle root from the daemon's OWN stored
/// ops and derived `expected_challenge` = SHA-256(tag ‖ root); this arm
/// resolves the credential (standard lookup only — batches are Use-only, so
/// no Enroll special cases) and runs the same shared core as the plain arm:
/// ONE validator, different challenge source, sudp untouched.
pub fn validate_batch_grant(
    grant: &Grant,
    expected_challenge: &[u8; 32],
    challenge_store: &mut crate::passkey::challenge::ChallengeStore,
    origin: &str,
    rp_id: &str,
    credential_lookup: impl FnOnce(&str) -> Option<PasskeyEntry>,
) -> Result<ValidatedGrant> {
    let batch = grant
        .batch
        .as_ref()
        .ok_or_else(|| AppError::BatchVerify("grant carries no batch proof".into()))?;
    if grant.assertion.is_some() {
        return Err(AppError::BatchVerify(
            "batch grant must not carry a top-level assertion".into(),
        ));
    }
    // Expired window and unknown credential stay TERMINAL (per-op parity:
    // the same grant would die the same way on the plain path, and neither
    // is recoverable by a per-op retry with the same material).
    check_now(&grant.o.valid)?;
    let entry = credential_lookup(&grant.credential_id).ok_or_else(|| {
        AppError::Unauthorized(
            "this passkey isn't admitted in the ledger of any member of this vault".into(),
        )
    })?;

    // EVERY core failure on a batch grant — challenge peek, credential-id
    // mismatch, ASSERTION/ROOT verification, malformed r/wk — must surface
    // as `batch_verify_failed` (design §Daemon verify 7): the relay client
    // recovers by re-registering the op, and a tampered or cross-language-
    // divergent root must never re-open Rev 1's mass-reject through the
    // 401/400 seam.
    validate_grant_core(
        grant,
        &batch.assertion,
        &entry,
        expected_challenge,
        challenge_store,
        origin,
        rp_id,
    )
    .map_err(|e| match e {
        AppError::Unauthorized(msg) | AppError::BadRequest(msg) => AppError::BatchVerify(msg),
        other => other,
    })
}

/// Shared validation tail for both arms: challenge peek → assertion verify
/// against `expected_challenge` → challenge consume. Every check here runs
/// identically for plain and batch grants.
fn validate_grant_core(
    grant: &Grant,
    assertion: &AssertionData,
    entry: &PasskeyEntry,
    expected_challenge: &[u8; 32],
    challenge_store: &mut crate::passkey::challenge::ChallengeStore,
    origin: &str,
    rp_id: &str,
) -> Result<ValidatedGrant> {
    // 1. Gate on r (must be issued by us and unexpired) but do NOT consume it
    //    yet — a cheap peek. Consuming here (before the signature is verified)
    //    would let anyone who learned the op's `r` burn a live op's single-use
    //    challenge with a bogus grant, breaking the real approval. The challenge
    //    is consumed only after the WebAuthn signature checks out (step 8).
    if !challenge_store.peek(&grant.r) {
        return Err(AppError::Unauthorized(
            "invalid or expired challenge `r`".into(),
        ));
    }
    let r_bytes = STANDARD
        .decode(&grant.r)
        .map_err(|_| AppError::BadRequest("r not base64".into()))?;
    if r_bytes.len() < 16 {
        return Err(AppError::BadRequest("r too short".into()));
    }

    // 6. Verify WebAuthn assertion against credential's public key.
    if let Some(ref a_cred_id) = assertion.credential_id {
        if a_cred_id != &grant.credential_id {
            return Err(AppError::Unauthorized(
                "assertion.credential_id != grant.credential_id".into(),
            ));
        }
    }
    verify_assertion(
        assertion,
        &entry.x,
        &entry.y,
        origin,
        rp_id,
        expected_challenge,
    )?;

    // 7. The credential id's raw bytes (the K bundle is opened by the caller).
    let credential_id_bytes = decode_credential_id(&grant.credential_id)?;

    // 8. Grant fully validated (signature + all fields) — NOW consume the
    //    single-use challenge, so a valid grant can't be replayed and a bogus
    //    one never got this far to burn it.
    challenge_store.consume(&grant.r);

    Ok(ValidatedGrant {
        op: grant.o.clone(),
        credential_id_bytes,
        r_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::challenge::ChallengeStore;
    use crate::protocol::operation::{Act, ActType, Bind, Valid};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    fn use_op() -> Operation {
        Operation {
            act: Act {
                kind: ActType::Use,
                target: "github".into(),
                scope: serde_json::json!({ "method": "GET", "host": "api.github.com", "path": "/user" }),
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    fn dummy_entry() -> PasskeyEntry {
        PasskeyEntry {
            x: B64.encode([1u8; 32]),
            y: B64.encode([2u8; 32]),
            device_name: "test".into(),
            created_at: 0,
        }
    }

    fn batch_grant(r: &str) -> Grant {
        Grant {
            o: use_op(),
            r: r.into(),
            credential_id: B64.encode([7u8; 16]),
            k_enc: None,
            k_ct: None,
            assertion: None,
            batch: Some(BatchProof {
                op_ids: vec!["a".into(), "b".into()],
                assertion: AssertionData {
                    credential_id: None,
                    authenticator_data: B64.encode([0u8; 37]),
                    client_data_json: B64.encode(b"{}"),
                    signature: B64.encode([0u8; 8]),
                },
            }),
        }
    }

    /// The load-bearing §7 guarantee: a batch grant whose assertion does NOT
    /// verify against the expected (root-derived) challenge must surface as
    /// `batch_verify_failed` (recoverable), never as the 401/400 the plain
    /// path would emit — that seam was Rev 1's mass-reject.
    #[test]
    fn batch_assertion_failure_is_batch_verify_failed() {
        let mut chs = ChallengeStore::new();
        let r = chs.issue("127.0.0.1".parse().unwrap()).unwrap();
        let grant = batch_grant(&r);
        let err = validate_batch_grant(
            &grant,
            &[0x42u8; 32],
            &mut chs,
            "http://localhost",
            "localhost",
            |_| Some(dummy_entry()),
        );
        let err = match err {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(
            matches!(err, AppError::BatchVerify(_)),
            "wrong-root/bad-assertion must be recoverable, got: {}",
            err
        );
        let (code, _) = err.code();
        assert_eq!(code.as_str(), "batch_verify_failed");
        assert_eq!(code.status(), 409);
        // The single-use challenge must SURVIVE a failed batch verify (peek
        // only; consume happens after a successful verify) so the per-op
        // retry after re-register can still redeem it.
        assert!(
            chs.peek(&r),
            "r must not be consumed by a failed batch verify"
        );
    }

    /// A batch-shaped grant on the PLAIN path fails closed.
    #[test]
    fn plain_path_rejects_batch_grants() {
        let mut chs = ChallengeStore::new();
        let r = chs.issue("127.0.0.1".parse().unwrap()).unwrap();
        let grant = batch_grant(&r);
        let err = validate_grant(&grant, &mut chs, "http://localhost", "localhost", |_| {
            Some(dummy_entry())
        });
        let err = match err {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    /// A batch grant carrying a top-level assertion is rejected before any
    /// crypto (an old daemon would verify it against β and burn fail_count).
    #[test]
    fn batch_with_top_level_assertion_rejected() {
        let mut chs = ChallengeStore::new();
        let r = chs.issue("127.0.0.1".parse().unwrap()).unwrap();
        let mut grant = batch_grant(&r);
        grant.assertion = grant.batch.as_ref().map(|b| b.assertion.clone());
        let err = validate_batch_grant(
            &grant,
            &[0x42u8; 32],
            &mut chs,
            "http://localhost",
            "localhost",
            |_| Some(dummy_entry()),
        );
        let err = match err {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(matches!(err, AppError::BatchVerify(_)));
    }
}
