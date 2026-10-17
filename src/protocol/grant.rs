//! `Grant` validation pipeline.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::binding::{binding_for_op, DOMAIN_SETUP, DOMAIN_STANDARD};
use crate::error::{AppError, Result};
use crate::passkey::webauthn::{verify_assertion, AssertionData, RelyingParty};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{
    as_enroll_credential, check_now, decode_credential_id, ActType, Operation,
};

/// Grant submitted to `POST /grant` (or to `/approve/{id}/confirm`).
///
/// Matches the SUDP paper §5.5 wire shape `G := (o, r, cid_{c*}, W*, σ*, opt)`.
/// Retired unlock-secret fields remain in the wire type only so the approval
/// handler can recognize and refuse them with `wk_refused_v2`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Operation contract.
    pub o: Operation,
    /// Server-issued challenge (base64, 16+ bytes).
    pub r: String,
    /// Acting credential id (base64).
    pub credential_id: String,
    /// Retired plaintext `W*` wrapping key. Deserialized only so the approval
    /// handler can refuse it with `wk_refused_v2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapping_key: Option<String>,
    /// Retired HPKE-sealed `W*` encapped key. Paired with `wk_ct` and retained
    /// only so the approval handler can refuse it with `wk_refused_v2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wk_enc: Option<String>,
    /// HPKE-sealed `W*` ciphertext + tag (base64url-no-pad). Paired with `wk_enc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wk_ct: Option<String>,
    /// HPKE-sealed VAULT KEY encapped key (base64url-no-pad). Paired with `k_ct`.
    /// An admin approving ANOTHER member's op on a team vault delivers the
    /// vault's key (opened in the browser through the admin's own membership
    /// entry), never their own UIK root: the root is the person's identity in
    /// every vault, so it must not reach someone else's machine. Sealed to the
    /// daemon's `sc_pk` with `info = grant_k_seal_info(op_id)`, aad empty.
    /// Plaintext: the 32-byte `K` (generation 0) or the 64-byte key bundle
    /// `id_seed ‖ content`. Mutually exclusive with `wrapping_key` / `wk_*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_enc: Option<String>,
    /// HPKE-sealed vault key ciphertext + tag (base64url-no-pad). Paired with `k_enc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_ct: Option<String>,
    /// Grant v3 (contract C3): the approver's identity (`us_…`). Paired with
    /// `id_sig`. Required on every grant the daemon applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Grant v3: Ed25519 signature by `id`'s UIK over
    /// [`crate::identity::grant_id_input`] (this op's β, the raw credential id,
    /// the K seal hash and the daemon's `sc_pk`), base64url-no-pad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_sig: Option<String>,
    /// The vault key opened from `k_enc`/`k_ct` by the approve handler. Never
    /// on the wire (not deserialized, not serialized).
    #[serde(skip)]
    pub vault_key: Option<DeliveredVaultKey>,
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

/// The vault key material a `k_*` grant delivered (zeroized on drop; its
/// bytes never print).
#[derive(Clone)]
pub struct DeliveredVaultKey(zeroize::Zeroizing<Vec<u8>>);

impl DeliveredVaultKey {
    /// Adopt opened key material: the 32-byte `K` or the 64-byte bundle.
    pub fn new(material: Vec<u8>) -> Result<Self> {
        let material = zeroize::Zeroizing::new(material);
        if material.len() != 32 && material.len() != 64 {
            return Err(AppError::BadRequest(
                "a delivered vault key must be 32 or 64 bytes".into(),
            ));
        }
        Ok(Self(material))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for DeliveredVaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveredVaultKey(..)")
    }
}

/// How a grant delivers what opens the vault. A grant carries EXACTLY ONE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryForm {
    /// Retired plaintext `wrapping_key`, recognized for explicit refusal.
    Plain,
    /// `wk_enc`/`wk_ct`: the approver's own unlock secret, HPKE-sealed
    /// (`W_c` on a v1 keyset, the approver's UIK root on a v2 keyset).
    SealedSecret,
    /// `k_enc`/`k_ct`: the vault key an admin delivers, HPKE-sealed.
    SealedVaultKey,
}

/// The one delivery form `grant` carries, as it arrived on the wire (before
/// the handler opens a seal). Exactly one of `wrapping_key`, the `wk_*` pair
/// or the `k_*` pair (a half pair counts as its form, and is refused when
/// opened); both or neither is malformed.
pub fn delivery_form(grant: &Grant) -> Result<DeliveryForm> {
    let forms = [
        (grant.wrapping_key.is_some(), DeliveryForm::Plain),
        (
            grant.wk_enc.is_some() || grant.wk_ct.is_some(),
            DeliveryForm::SealedSecret,
        ),
        (
            grant.k_enc.is_some() || grant.k_ct.is_some(),
            DeliveryForm::SealedVaultKey,
        ),
    ];
    let mut present = forms.iter().filter(|(p, _)| *p).map(|(_, f)| *f);
    match (present.next(), present.next()) {
        (Some(f), None) => Ok(f),
        _ => Err(AppError::BadRequest(
            "a grant carries exactly one of wrapping_key, wk_enc/wk_ct or k_enc/k_ct".into(),
        )),
    }
}

/// What a validated grant delivered, as the read seams consume it.
#[derive(Clone, Copy)]
pub enum GrantKey<'a> {
    /// The approver's own unlock secret: `W_c` (v1 keyset) or their UIK root
    /// (v2 keyset). Opens `K` through the acting credential's keyset entry.
    Custody(&'a [u8]),
    /// The vault key material itself (a grant v3 `k_*` delivery): `K` or the
    /// 64-byte bundle (v2 keyset), the 32-byte `K` (v1 keyset).
    VaultKey(&'a [u8]),
}

/// Which [`GrantKey`] a [`ValidatedGrant`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Custody,
    VaultKey,
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
    /// The delivered secret (zeroized on drop), read per `delivery`: the
    /// 32-byte custody secret `W*` (W_c or UIK root), or the vault key
    /// material (32 or 64 bytes) an admin delivered.
    pub secret: Vec<u8>,
    /// What `secret` is.
    pub delivery: Delivery,
    /// `r` consumed (raw bytes).
    pub r_bytes: Vec<u8>,
}

impl ValidatedGrant {
    /// The delivered secret as the read seams take it.
    pub fn key(&self) -> GrantKey<'_> {
        match self.delivery {
            Delivery::Custody => GrantKey::Custody(&self.secret),
            Delivery::VaultKey => GrantKey::VaultKey(&self.secret),
        }
    }

    /// The approver's custody secret (`W_c` / UIK root), for the paths that
    /// need the passkey's own secret (whole-blob open, add-passkey, KCV
    /// backfill). A delivered vault key is not one: refused.
    pub fn custody_secret(&self) -> Result<&[u8]> {
        match self.delivery {
            Delivery::Custody => Ok(&self.secret),
            Delivery::VaultKey => Err(AppError::BadRequest(
                "this act needs the approver's own passkey secret, not a delivered vault key"
                    .into(),
            )),
        }
    }
}

impl Drop for ValidatedGrant {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Validate a PLAIN grant (challenge = the op's own β). The challenge `r` is
/// consumed (single-use). Rejects batch-shaped grants outright — the batch
/// arm goes through [`validate_batch_grant`] with a caller-computed challenge.
///
/// `credential_lookup` returns the credential's public key entry or `None` if
/// unknown. For `setup`, the credential is taken from the operation body
/// instead of the lookup.
pub fn validate_grant(
    grant: &Grant,
    challenge_store: &mut crate::passkey::challenge::ChallengeStore,
    rp: &RelyingParty,
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

    // Resolve credential public key:
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

    validate_grant_core(grant, assertion, &entry, &beta, challenge_store, rp)
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
    rp: &RelyingParty,
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
    let entry = credential_lookup(&grant.credential_id)
        .ok_or_else(|| AppError::Unauthorized("unknown credential".into()))?;

    // EVERY core failure on a batch grant — challenge peek, credential-id
    // mismatch, ASSERTION/ROOT verification, malformed r/delivery must surface
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
        rp,
    )
    .map_err(|e| match e {
        AppError::Unauthorized(msg) | AppError::BadRequest(msg) => AppError::BatchVerify(msg),
        other => other,
    })
}

/// Shared validation tail for both arms: challenge peek, assertion verify
/// against `expected_challenge`, vault-key extraction, challenge consume.
/// Every check here runs identically for plain and batch grants.
fn validate_grant_core(
    grant: &Grant,
    assertion: &AssertionData,
    entry: &PasskeyEntry,
    expected_challenge: &[u8; 32],
    challenge_store: &mut crate::passkey::challenge::ChallengeStore,
    rp: &RelyingParty,
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
    verify_assertion(assertion, &entry.x, &entry.y, rp, expected_challenge)?;

    // 7. Take the vault key already opened by the approve handler and decode
    // the credential id. Unlock-secret delivery was refused before validation.
    let credential_id_bytes = decode_credential_id(&grant.credential_id)?;
    let (secret, delivery) = match (grant.wrapping_key.as_deref(), grant.vault_key.as_ref()) {
        (None, Some(k)) => (k.as_bytes().to_vec(), Delivery::VaultKey),
        (Some(_), Some(_)) => {
            return Err(AppError::BadRequest(
                "grant carries both a wrapping key and a vault key".into(),
            ))
        }
        (Some(_), None) => {
            return Err(AppError::BadRequest(
                "grant carries a wrapping key instead of a vault key".into(),
            ))
        }
        (None, None) => {
            return Err(AppError::BadRequest(
                "grant carries no vault key (and no opened seal)".into(),
            ))
        }
    };

    // 8. Grant fully validated (signature + all fields) — NOW consume the
    //    single-use challenge, so a valid grant can't be replayed and a bogus
    //    one never got this far to burn it.
    challenge_store.consume(&grant.r);

    Ok(ValidatedGrant {
        op: grant.o.clone(),
        credential_id_bytes,
        secret,
        delivery,
        r_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::challenge::ChallengeStore;
    use crate::protocol::operation::{Act, Bind, Valid};
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
            wrapping_key: Some(B64.encode([9u8; 32])),
            wk_enc: None,
            wk_ct: None,
            k_enc: None,
            k_ct: None,
            id: None,
            id_sig: None,
            vault_key: None,
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
            setup_payload: None,
            opt: None,
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
            &RelyingParty::exact("http://localhost", "localhost"),
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

    /// A grant delivers in exactly one form: the plaintext wrapping key, the
    /// sealed secret (`wk_*`) or the sealed vault key (`k_*`). Both or neither
    /// is malformed; a half pair counts as its form (and fails when opened).
    #[test]
    fn exactly_one_delivery_form() {
        let mut g = batch_grant("r");
        assert_eq!(delivery_form(&g).unwrap(), DeliveryForm::Plain);
        g.wrapping_key = None;
        assert!(delivery_form(&g).is_err(), "neither");
        g.wk_enc = Some("e".into());
        g.wk_ct = Some("c".into());
        assert_eq!(delivery_form(&g).unwrap(), DeliveryForm::SealedSecret);
        g.k_enc = Some("e".into());
        g.k_ct = Some("c".into());
        assert!(delivery_form(&g).is_err(), "wk_* and k_*");
        g.wk_enc = None;
        g.wk_ct = None;
        assert_eq!(delivery_form(&g).unwrap(), DeliveryForm::SealedVaultKey);
        g.k_ct = None;
        assert_eq!(delivery_form(&g).unwrap(), DeliveryForm::SealedVaultKey);
        g.wrapping_key = Some(B64.encode([9u8; 32]));
        assert!(delivery_form(&g).is_err(), "wrapping_key and k_*");
        // The opened vault key is never on the wire.
        let mut g = batch_grant("r");
        g.wrapping_key = None;
        g.vault_key = Some(DeliveredVaultKey::new(vec![1u8; 32]).unwrap());
        let wire = serde_json::to_value(&g).unwrap();
        assert!(wire.get("vault_key").is_none());
        let mut injected = wire.clone();
        injected["vault_key"] = serde_json::json!("AAAA");
        let back: Grant = serde_json::from_value(injected).unwrap();
        assert!(back.vault_key.is_none());
        assert!(!format!("{:?}", g).contains("[1, 1"));
        assert!(DeliveredVaultKey::new(vec![1u8; 48]).is_err());
        assert!(DeliveredVaultKey::new(vec![1u8; 64]).is_ok());
    }

    /// A batch-shaped grant on the PLAIN path fails closed.
    #[test]
    fn plain_path_rejects_batch_grants() {
        let mut chs = ChallengeStore::new();
        let r = chs.issue("127.0.0.1".parse().unwrap()).unwrap();
        let grant = batch_grant(&r);
        let err = validate_grant(
            &grant,
            &mut chs,
            &RelyingParty::exact("http://localhost", "localhost"),
            |_| Some(dummy_entry()),
        );
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
            &RelyingParty::exact("http://localhost", "localhost"),
            |_| Some(dummy_entry()),
        );
        let err = match err {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(matches!(err, AppError::BatchVerify(_)));
    }
}
