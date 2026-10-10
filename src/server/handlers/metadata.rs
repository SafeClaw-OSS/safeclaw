//! Vault-scoped read-only endpoints.
//!
//! - `GET  /v/{vid}/passkeys` — the passkeys that can approve for this vault:
//!   the own person's ledger-admitted passkeys (public metadata only), for a
//!   vault on a verified member record.
//! - `POST /v/{vid}/sync`     — on-demand cloud sync (`sc sync`).
//!
//! Plus the per-item read seams every grant / unlock / refresh folds through.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use sudp::primitives::StdPrimitives;

use crate::error::{AppError, Result};
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;
use crate::storage::item::VaultKeys;
use crate::storage::plaintext::VaultPlaintextView;

#[derive(Debug, Serialize)]
pub struct PasskeyMeta {
    pub credential_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

/// `GET /v/{vid}/passkeys`. `vault_exists` = this daemon holds the vault on a
/// verified member record (`record: false` with a store but no record = a vault
/// the console hasn't upgraded yet). The passkeys are the own person's live,
/// ledger-admitted passkeys: any of them can approve for any vault the person
/// is a member of.
pub async fn passkeys(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;
    let per_item_path = state.vaults.per_item_path(&vault_id)?;
    let Some(pv) = crate::storage::sealed_vault::read_per_item(&per_item_path)? else {
        return Ok(Json(json!({ "vault_exists": false, "passkeys": [] })));
    };
    let metas: Vec<PasskeyMeta> = state
        .trust
        .own_ledger()
        .map(|l| {
            l.passkeys()
                .map(|p| PasskeyMeta {
                    credential_id: p.cid().to_string(),
                    device_name: p.label().to_string(),
                    created_at: 0,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({
        "vault_exists": true,
        "record": pv.record.is_some(),
        "passkeys": metas,
    })))
}

/// `POST /v/{vid}/sync` — on-demand cloud pull + complete-pending-connect
/// (backs `sc sync`). No passkey: it only advances already-sealed state (the
/// pull is DIK-signed; the connect re-seal uses the retained K and
/// no-ops if the vault is locked). The vault id is validated; the rest is
/// handled inside `sync::sync_vault_now`.
pub async fn sync_now(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Json<Value> {
    if let Err(e) = validate_vault_id(&vault_id) {
        return Json(json!({ "ok": false, "error": e.to_string() }));
    }
    match crate::sync::sync_vault_now(&state, &vault_id).await {
        Ok(out) => {
            let c = &out.connects;
            Json(json!({
                "ok": true,
                "pulled": out.pulled,
                "connects": {
                    "completed": c.completed,
                    "failed": c.failed.iter()
                        .map(|(conn, reason)| json!({ "conn": conn, "reason": reason }))
                        .collect::<Vec<_>>(),
                    "unreached": c.unreached.iter()
                        .map(|(conn, host)| json!({ "conn": conn, "host": host }))
                        .collect::<Vec<_>>(),
                },
            }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

/// Fold a per-item vault with a K bundle (no grant, no passkey). The held
/// member record is re-verified first ([`crate::trust::check_held_record`]: the
/// own ledger's pin, this person, the fold, the latch), so a record edited on
/// disk can't steer owner config or agent records. `Err` also if K no longer
/// matches the record's commitment (the vault was re-keyed): callers treat it
/// as "lock + unlock".
pub fn decrypt_vault_view_peritem_with_key(
    trust: &crate::trust::TrustCache,
    k: &[u8],
    vault: &crate::storage::sealed_vault::PerItemVault,
    vault_id: &str,
) -> Result<VaultPlaintextView> {
    let record = vault
        .record
        .as_ref()
        .ok_or_else(|| AppError::Conflict(crate::storage::sealed_vault::NO_RECORD.into()))?;
    crate::trust::check_held_record(trust, vault_id, record)
        .map_err(|e| AppError::Forbidden(e.to_string()))?;
    vault.fold_view::<StdPrimitives>(VaultKeys::from_material(k), vault_id)
}

/// Open the CURRENT vault view with a K bundle the daemon holds (a grant's
/// verified K, or the retained K of an unlocked vault). The ONE per-item read
/// seam: grants, unlock, local writes and refreshes all fold through here.
pub fn open_view_with_state_key(
    state: &AppState,
    vault_id: &str,
    k: &[u8],
) -> Result<VaultPlaintextView> {
    let path = state.vaults.per_item_path(vault_id)?;
    let pv = crate::storage::sealed_vault::read_per_item(&path)?
        .ok_or_else(|| AppError::Conflict(crate::storage::sealed_vault::NO_RECORD.into()))?;
    decrypt_vault_view_peritem_with_key(&state.trust, k, &pv, vault_id)
}
