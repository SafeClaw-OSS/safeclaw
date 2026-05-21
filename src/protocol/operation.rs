//! `Operation` — re-export of [`sudp::Operation`] plus deployment-side
//! helpers that pull SafeClaw-specific payloads out of `act.scope`.
//!
//! SafeClaw maps its business actions onto the SUDP vocabulary
//! (paper §5.4, §5.6):
//!
//! | SafeClaw action      | sudp::ActType  | scope shape                                   |
//! |----------------------|----------------|-----------------------------------------------|
//! | First-time vault     | `Enroll`       | `{public_key_x, public_key_y, prf_salt, …}`   |
//! | Edit vault contents  | `Write`        | `{body, wrapped_dek, prf_salt_next}`          |
//! | Reveal stored secret | `Export`       | empty (target carries the dotted path)        |
//! | Future: broker call  | `Use`          | `{method, path, headers, body, upstream}`     |
//!
//! `Operation`, `Act`, `ActType`, `Bind`, `Valid`, `RecipientPk` all come
//! straight from sudp — no wrapper types here.

use serde::{Deserialize, Serialize};

pub use sudp::{Act, ActType, Bind, Operation, RecipientPk, Valid};

use crate::error::{AppError, Result};

/// SafeClaw-side validity check that reads the system clock and applies a
/// 5-minute `iat` skew tolerance. Equivalent to sudp's
/// `Operation::check_validity(now, 300)`, exposed against `&Valid` because
/// some call sites have the `Valid` in hand without the full `Operation`.
pub fn check_now(valid: &Valid) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if valid.iat > now + 300 {
        return Err(AppError::BadRequest("iat in future".into()));
    }
    if let Some(exp) = valid.exp {
        if exp < now {
            return Err(AppError::BadRequest("operation expired".into()));
        }
    }
    Ok(())
}

// ─── Enroll (a.k.a. Setup) payload extraction ──────────────────────────────

/// New credential payload — used in `ActType::Enroll` scope.
///
/// Wire shape: `act.scope = { public_key_x, public_key_y, prf_salt, device_name }`
/// and `act.target = credential_id` (base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCredential {
    /// Base64-encoded credential ID (sourced from `act.target`).
    pub credential_id: String,
    /// Base64 P-256 X coordinate (32B raw).
    pub public_key_x: String,
    /// Base64 P-256 Y coordinate (32B raw).
    pub public_key_y: String,
    /// Base64 prf_salt (32B raw) — used to derive KEK.
    pub prf_salt: String,
    #[serde(default)]
    pub device_name: String,
}

/// Extract `NewCredential` from an `ActType::Enroll` Operation. Returns a
/// `BadRequest` if `act.kind != Enroll` or any required field is missing.
pub fn as_enroll_credential(op: &Operation) -> Result<NewCredential> {
    if op.act.kind != ActType::Enroll {
        return Err(AppError::BadRequest(format!(
            "expected ActType::Enroll, got {:?}",
            op.act.kind
        )));
    }
    let scope = &op.act.scope;
    Ok(NewCredential {
        credential_id: op.act.target.clone(),
        public_key_x: scope_string(scope, "public_key_x")?,
        public_key_y: scope_string(scope, "public_key_y")?,
        prf_salt: scope_string(scope, "prf_salt")?,
        device_name: scope
            .get("device_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default(),
    })
}

// ─── Write payload extraction ──────────────────────────────────────────────

/// Write patch — for v0 this is a full replace. Lives in `act.scope` for
/// an `ActType::Write` Operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritePatch {
    /// Base64 of new sealed body (XChaCha20-Poly1305 of canonical KV under DEK).
    pub body: String,
    /// Base64 of new wrapped DEK (XChaCha20-Poly1305 under KEK derived from
    /// `user_key` + `prf_salt_next`).
    pub wrapped_dek: String,
    /// Base64 of next prf_salt (32B raw).
    pub prf_salt_next: String,
}

/// Extract `WritePatch` from an `ActType::Write` Operation.
pub fn as_write_patch(op: &Operation) -> Result<WritePatch> {
    if op.act.kind != ActType::Write {
        return Err(AppError::BadRequest(format!(
            "expected ActType::Write, got {:?}",
            op.act.kind
        )));
    }
    let scope = &op.act.scope;
    Ok(WritePatch {
        body: scope_string(scope, "body")?,
        wrapped_dek: scope_string(scope, "wrapped_dek")?,
        prf_salt_next: scope_string(scope, "prf_salt_next")?,
    })
}

// ─── Export (a.k.a. Reveal) payload extraction ─────────────────────────────

/// Extract the export target path from an `ActType::Export` Operation.
///
/// The dotted path (e.g. `env.api_key`) lives in `act.target`; scope is empty.
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

// ─── helpers ───────────────────────────────────────────────────────────────

fn scope_string(scope: &serde_json::Value, field: &str) -> Result<String> {
    scope
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::BadRequest(format!("act.scope.{} missing or not a string", field)))
}
