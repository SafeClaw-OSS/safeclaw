//! `Operation` — re-export of [`sudp::Operation`] plus deployment-side
//! helpers that pull SafeClaw-specific payloads out of `act.scope`.
//!
//! SafeClaw maps its business actions onto the SUDP vocabulary
//! (paper §5.4, §5.6):
//!
//! | SafeClaw action      | sudp::ActType  | scope shape                                   |
//! |----------------------|----------------|-----------------------------------------------|
//! | Reveal stored secret | `Export`       | `{requester}` (target carries the key)        |
//! | Broker call          | `Use`          | `{requester, method, host, path, …}`          |
//! | Lifecycle / writes   | `Custom(…)`    | `{requester, …}` per acts.toml                |
//!
//! Every op the daemon mints carries `act.scope.requester = {device, member}`
//! (contract 1.6), so `act.scope` is always an object.
//!
//! `Operation`, `Act`, `ActType`, `Bind`, `Valid`, `RecipientPk` all come
//! straight from sudp — no wrapper types here.

pub use sudp::{Act, ActType, Bind, Operation, RecipientPk, Valid};

use crate::error::{AppError, Result};

/// SafeClaw-side validity check that reads the system clock and applies a
/// 5-minute `iat` skew tolerance. Thin adapter over `sudp::Valid::check`.
pub fn check_now(valid: &Valid) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    valid.check(now, 300).map_err(|e| match e {
        sudp::Error::OperationExpired => AppError::BadRequest("operation expired".into()),
        sudp::Error::OperationIatSkew => AppError::BadRequest("iat in future".into()),
        other => AppError::Internal(format!("validity check: {}", other)),
    })
}

// ─── Export (a.k.a. Reveal) payload extraction ─────────────────────────────

/// Extract the export target path from an `ActType::Export` Operation.
///
/// The key lives in `act.target`; the scope carries only the requester.
///
/// **Note:** the SUDP standard `execute_export` requires a non-`None`
/// `bind.recipient` for KEM-sealed delivery; SafeClaw currently uses an
/// out-of-band TLS-trusted reveal path (`bind.recipient = None`), pending the
/// SUDP "TLS-trusted export" extension (see `project_sudp_tls_export.md`).
pub fn as_export_path(op: &Operation) -> Result<&str> {
    if op.act.kind != ActType::Export {
        return Err(AppError::BadRequest(format!(
            "expected ActType::Export, got {:?}",
            op.act.kind
        )));
    }
    Ok(&op.act.target)
}

// ─── Discriminator helper ──────────────────────────────────────────────────

/// Stable short label for logs / responses (`"enroll"` / `"write"` / `"export"`
/// / `"use"` / `"custom:<name>"`).
pub fn discriminator(act: &Act) -> String {
    match &act.kind {
        ActType::Use => "use".into(),
        ActType::Export => "export".into(),
        ActType::Write => "write".into(),
        ActType::Rotate => "rotate".into(),
        ActType::Enroll => "enroll".into(),
        ActType::Revoke => "revoke".into(),
        ActType::Custom(s) => format!("custom:{}", s),
        _ => "unknown".into(),
    }
}

// ─── Requester binding (trust-reset contract 1.6) ──────────────────────────

/// Who minted an op: `act.scope.requester = {device: dv_, member: us_}`. β
/// already covers `act.scope`, so the approver's signature binds it; the grant
/// is sealed to `device`'s admitted enc key and the daemon refuses an op whose
/// requester device is not itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRequester {
    /// The minting device's `dv_` id.
    pub device: String,
    /// The minting device's person, `us_`.
    pub member: String,
}

/// Extract the requester from an `act.scope` value. Strict: `scope` must be an
/// object whose `requester` is an object with exactly the string fields
/// `device` (a well-formed `dv_` id) and `member` (a well-formed `us_` id).
/// Anything else is `None` (an op without a requester is not bound to anyone).
pub fn scope_requester(scope: &serde_json::Value) -> Option<OpRequester> {
    use crate::identity::{parse_id, IdKind};
    let req = scope.as_object()?.get("requester")?.as_object()?;
    if req.len() != 2 {
        return None;
    }
    let device = req.get("device")?.as_str()?;
    let member = req.get("member")?.as_str()?;
    if parse_id(device) != Some(IdKind::Device) || parse_id(member) != Some(IdKind::User) {
        return None;
    }
    Some(OpRequester {
        device: device.to_string(),
        member: member.to_string(),
    })
}

/// [`scope_requester`] of an op's act.
pub fn op_requester(act: &Act) -> Option<OpRequester> {
    scope_requester(&act.scope)
}

/// The daemon's gate: is this op bound to `device_id` (its own `dv_`)?
pub fn op_bound_to_device(act: &Act, device_id: &str) -> bool {
    op_requester(act).is_some_and(|r| r.device == device_id)
}

/// Stamp `act.scope.requester = {device, member}` on an op the daemon mints
/// (contract 1.6). The scope becomes an object (a null scope — an Export's —
/// becomes `{}` first); any requester the caller supplied is REPLACED, so a
/// local CLI or agent can't mint an op bound to another device. Refuses a
/// non-object, non-null scope and ids that are not well-formed.
pub fn stamp_requester(act: &mut Act, requester: &OpRequester) -> Result<()> {
    use crate::identity::{parse_id, IdKind};
    if parse_id(&requester.device) != Some(IdKind::Device)
        || parse_id(&requester.member) != Some(IdKind::User)
    {
        return Err(AppError::Internal(
            "requester ids are not well-formed".into(),
        ));
    }
    if act.scope.is_null() {
        act.scope = serde_json::Value::Object(Default::default());
    }
    let obj = act
        .scope
        .as_object_mut()
        .ok_or_else(|| AppError::BadRequest("act.scope must be an object".into()))?;
    obj.insert(
        "requester".into(),
        serde_json::json!({ "device": requester.device, "member": requester.member }),
    );
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

/// Decode a WebAuthn `credentialId` from its on-wire base64url-no-pad string.
///
/// `credential_id` is the one sudp field that crosses the WebAuthn boundary
/// (W3C spec mandates base64url here) and appears in pro-backend URL paths.
/// All emitters agree on URL_SAFE_NO_PAD: the daemon's metadata.rs, the
/// pro-backend's `parseAttestation`, and the frontend's `toBase64url`. Other
/// sudp fields (signatures, public keys, prf_salt, ciphertext, wrapping_key,
/// …) stay strict-STANDARD.
pub fn decode_credential_id(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AppError::BadRequest("credential_id: not valid base64url-no-pad".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act(scope: serde_json::Value) -> Act {
        Act {
            kind: ActType::Export,
            target: "K".into(),
            scope,
        }
    }

    fn me() -> OpRequester {
        OpRequester {
            device: crate::identity::derive_id(crate::identity::IdKind::Device, &[1; 32]),
            member: crate::identity::derive_id(crate::identity::IdKind::User, &[2; 32]),
        }
    }

    #[test]
    fn stamp_requester_binds_the_op_to_this_device() {
        // An Export's null scope becomes an object carrying the requester.
        let mut a = act(serde_json::Value::Null);
        stamp_requester(&mut a, &me()).unwrap();
        assert_eq!(op_requester(&a), Some(me()));
        assert!(op_bound_to_device(&a, &me().device));
        assert!(!op_bound_to_device(&a, "dv_other"));
        // A caller-supplied requester is replaced, other scope fields kept.
        let other = OpRequester {
            device: crate::identity::derive_id(crate::identity::IdKind::Device, &[9; 32]),
            member: me().member,
        };
        let mut a = act(serde_json::json!({
            "method": "GET",
            "requester": { "device": other.device, "member": other.member },
        }));
        stamp_requester(&mut a, &me()).unwrap();
        assert_eq!(op_requester(&a), Some(me()));
        assert_eq!(a.scope["method"], "GET");
        // A non-object scope is refused; malformed ids are refused.
        assert!(stamp_requester(&mut act(serde_json::json!("x")), &me()).is_err());
        let bad = OpRequester {
            device: "dev_x".into(),
            member: me().member,
        };
        assert!(stamp_requester(&mut act(serde_json::Value::Null), &bad).is_err());
    }
}
