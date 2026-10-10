//! Broker (Use) op-plane resolve.
//!
//! Under the phantom-only model the op plane never forwards: the resident proxy
//! serves live traffic. An approved Use op is always `authorize_only` — the
//! approve handler resolves the connection's primary secret with the verified
//! grant's K and stashes it in the session cache so the agent's *retried* request
//! (through the proxy) fast-paths. This module holds that one resolve.

use crate::error::{AppError, Result};
use crate::protocol::Operation;

/// Resolve a Use operation's primary secret WITHOUT forwarding: fold the vault
/// with the grant's verified K bundle and resolve `op.act.target`, returning
/// the bytes for the caller to stash so the agent's retried request can
/// consume them.
pub async fn resolve_use_primary(
    op: &Operation,
    k: &[u8],
    state: &crate::state::AppState,
    vault_id: &str,
) -> Result<Vec<u8>> {
    let view = crate::server::handlers::metadata::open_view_with_state_key(state, vault_id, k)?;
    view.resolve_value_async(&op.act.target)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!("secret '{}' not found in vault", op.act.target))
        })
}
