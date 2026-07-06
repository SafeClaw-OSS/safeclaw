//! `POST /v/{vid}/export/{key}` — the agent-surface Export door, shut.
//!
//! Raw-secret export hands the agent custody of the plaintext — the opposite
//! shape of the phantom broker (inject-toward-upstream, never reveal). It has no
//! upstream, so it doesn't fit the phantom model, and forcing it back in would
//! reopen the raw-exfil hole. The human path is the op-plane Export ceremony
//! (`sc secret get` → passkey "Reveal <key>"); only this agent door is closed.

use axum::{http::StatusCode, Json};
use serde_json::Value;

use crate::error::{AppError, Result};

/// `/export/{key}` is DISABLED on the agent surface.
pub async fn disabled() -> Result<(StatusCode, Json<Value>)> {
    Err(AppError::Forbidden(
        "raw secret export is disabled on the agent surface — reveal a secret with a passkey via `sc secret get`; put a phantom (see `sc status`) where the credential goes for brokered calls".into(),
    ))
}
