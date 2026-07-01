//! Cloud sealed-blob sync (Slice 3).
//!
//! The daemon is a thin pull/push client over the pro-backend's blind blob
//! store (`/v/{vid}/blob`, Supabase Storage behind it). On startup it pulls
//! the active vault's `SealedState` blob and writes it to the local
//! `vault.dat`, so a freshly-paired device can serve a vault that was sealed
//! in the browser. Cloud is the source of truth (1Password model); the pull
//! is version-gated (`?since=<local>`) so an already-current local copy is
//! left untouched and a web edit shows up on the next daemon (re)start.
//!
//! The cloud never decrypts: the blob is passkey-sealed (W_c is not in it).
//! Auth is the daemon's device-key (`~/.safeclaw/device-key`, a `sc_device_`
//! token), distinct from the agent→daemon broker api-key.
//!
//! Best-effort by design: any failure logs and leaves local state untouched
//! — a local-only daemon (no `cloud_backend` configured) just skips this and
//! serves whatever `vault.dat` is on disk. See [[project_slice3_design]].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::cli::active;
use crate::state::AppState;
use crate::storage::sealed_vault::{self, SealedVault};

/// Outcome of a single blob `pull`. The cloud envelope's clear-text `status`
/// field (`"live"` | `"deleted"`) is the lifecycle channel; this enum is its
/// daemon-side projection so callers can branch on it without re-parsing JSON.
///
/// - `Unchanged` — local copy is already current (or the cloud has no blob row
///   at all: an HTTP 404 keeps its long-standing meaning of "never sealed").
/// - `Updated(version)` — a newer, `status:"live"` blob was pulled and written
///   to `vault.dat`; `version` is the cloud-stamped revision now on disk.
/// - `Deleted` — the cloud row is a tombstone (`status:"deleted"`). This is the
///   ONLY signal that destroys local vault state (see `drop_local_vault`); a
///   live-but-undecryptable blob is deliberately NOT a delete (docs/SYNC.md §4
///   case 3 — log only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    Unchanged,
    Updated(u64),
    Deleted,
}

/// Read the persisted device-key (`~/.safeclaw/device-key`, written by
/// `sc login`). Returns None when the device hasn't been paired.
pub fn device_key() -> Option<String> {
    let home = dirs::home_dir()?;
    let raw = std::fs::read_to_string(home.join(".safeclaw").join("device-key")).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Sidecar next to a vault's `vault.dat` recording the last-pulled blob
/// version, so `?since=` can short-circuit an unchanged cloud copy.
fn version_sidecar(state_dir: &Path, vault: &str) -> PathBuf {
    state_dir.join("vaults").join(vault).join(".blob_version")
}

fn read_local_version(state_dir: &Path, vault: &str) -> u64 {
    std::fs::read_to_string(version_sidecar(state_dir, vault))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Pull the active vault's sealed blob from the cloud and write `vault.dat`
/// if the cloud copy is newer than the local one. Never returns Err — a
/// failed or unconfigured sync must not stop the daemon from serving.
pub async fn pull_on_start(state_dir: &Path) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("cloud sync: no CLI config ({}); skipping pull", e);
            return;
        }
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        tracing::debug!("cloud sync: no cloud_backend configured; local-only daemon");
        return;
    };
    let Some(dk) = device_key() else {
        tracing::debug!("cloud sync: no device-key (unpaired); skipping pull");
        return;
    };
    // All vaults this device knows (active ∪ known_vaults) are kept online —
    // the agent addresses any of them by vid, no "switch vault" needed (1P
    // model). See [[project_vault_agent_architecture_2026_06_25]].
    let ids = synced_vault_ids(&cfg);
    if ids.is_empty() {
        tracing::debug!("cloud sync: no vaults to pull");
        return;
    }
    for vault in &ids {
        match pull(state_dir, cloud, vault, &dk).await {
            Ok(PullOutcome::Updated(version)) => tracing::info!(vault = %vault, version, "cloud sync: pulled vault.dat from cloud"),
            Ok(PullOutcome::Unchanged) => tracing::debug!(vault = %vault, "cloud sync: local vault.dat already current"),
            Ok(PullOutcome::Deleted) => {
                // The vault was deleted (tombstoned) cloud-side while this device
                // was offline. Drop the local copy on startup so we never serve a
                // retired vault. No AppState yet at this point (pre-serve), so the
                // disk + CLI-config side is dropped here; the in-memory K/audit
                // handle don't exist yet (daemon boots Locked, audit opens lazily).
                drop_local_vault_disk(state_dir, vault);
                tracing::info!(vault = %vault, "cloud sync: vault deleted upstream; dropped local state");
            }
            Err(e) => tracing::warn!(vault = %vault, "cloud sync pull failed (serving local state): {}", e),
        }
        // PER-ITEM: pull content rows too (pre-serve, no cache to refresh yet —
        // the first unlock folds them). Best-effort; a 404 / non-per-item vault
        // is a no-op.
        match pull_items(state_dir, cloud, vault, &dk).await {
            Ok(n) if n > 0 => tracing::info!(vault = %vault, adopted = n, "cloud sync: pulled item rows"),
            Ok(_) => {}
            Err(e) => tracing::debug!(vault = %vault, "cloud sync: per-item pull failed: {}", e),
        }
    }
}

/// One-shot, on-demand sync of `vault_id`, backing `POST /v/{vid}/sync`
/// (`sc sync`): pull the latest blob from the cloud (if any), refresh the
/// in-memory cache, and complete any pending OAuth connect
/// (`<conn>_oauth_pending` → exchange → `<conn>_refresh_token`). Returns
/// `Ok(true)` when a newer blob was pulled. Never needs a passkey — it only
/// moves already-sealed state forward: the pull is device-key-authed, and the
/// connect re-seal uses the retained `K` from a prior unlock (no-ops if locked).
pub async fn sync_vault_now(state: &Arc<AppState>, vault_id: &str) -> Result<bool, String> {
    let cfg = active::load().map_err(|_| {
        "not set up yet — run `sc login` to pair this daemon with the cloud".to_string()
    })?;
    // `sc sync` only makes sense for a cloud-paired daemon. Distinguish the two
    // not-logged-in shapes so the message guides the user (mainstream: gcloud /
    // gh both point you at the login command rather than printing a raw error).
    let cloud = cfg
        .cloud_backend
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "local-only daemon (no cloud backend) — nothing to sync from the cloud; \
             run `sc login` to pair"
                .to_string()
        })?;
    let dk = device_key().ok_or_else(|| {
        "this daemon isn't paired with the cloud — run `sc login` first".to_string()
    })?;
    let pulled = match pull(&state.config.state_dir, cloud, vault_id, &dk).await? {
        PullOutcome::Updated(_version) => {
            refresh_after_pull(state, vault_id);
            true
        }
        PullOutcome::Unchanged => false,
        PullOutcome::Deleted => {
            // The vault was deleted (tombstoned) cloud-side. Drop all local
            // state — disk, retained K, audit handle, CLI config — under the
            // per-vault write lock (this runs at serving time via POST
            // /v/{vid}/sync, so it must not race a concurrent approve write) and
            // return without the connect step (there is nothing left to act on).
            drop_local_vault_locked(state, vault_id).await;
            tracing::info!(vault = %vault_id, "cloud sync: vault deleted upstream; dropped local state");
            return Ok(false);
        }
    };
    // PER-ITEM: also pull content item rows (keyset lifecycle rides `/blob`
    // above; content rides `/items`). Best-effort — a 404 (endpoint not live) or
    // a not-yet-per-item vault is a no-op. On adoption, refresh the cache from
    // the folded item view so the new rows are served without a re-unlock.
    if let Some(cloud2) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) {
        if let Some(dk2) = device_key() {
            match pull_items(&state.config.state_dir, cloud2, vault_id, &dk2).await {
                Ok(n) if n > 0 => {
                    refresh_after_item_pull(state, vault_id);
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(vault = %vault_id, "per-item pull failed: {}", e),
            }
        }
    }
    // Complete a pending connect even when the blob was unchanged — the pending
    // item may have synced earlier (background watcher) but never been processed.
    crate::auth::connect::process_vault_connects(state, vault_id).await;
    Ok(pulled)
}

/// After a per-item pull adopted new rows, refresh the in-memory cache for an
/// UNLOCKED vault by folding the per-item store with the retained `K` — no
/// passkey. Locked vault (no K) → no-op (the next unlock folds the new rows). A
/// rotated `K` that can't unseal → log + leave the cache (graceful).
fn refresh_after_item_pull(state: &Arc<AppState>, vault: &str) {
    let Some(k) = state.cloned_state_key(vault) else {
        return;
    };
    let Some(pv) = read_per_item_store(&state.config.state_dir, vault) else {
        return;
    };
    match crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(&k, &pv, vault) {
        Ok(view) => {
            let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
            state.unlock_vault(vault.to_string(), cache, k);
            tracing::info!(vault = %vault, "per-item pull: cache refreshed from item rows");
        }
        Err(_) => {
            tracing::warn!(
                vault = %vault,
                "per-item pull: retained K can't unseal a row (rotated K?); lock+unlock to see new state"
            );
        }
    }
}

/// Vault ids this device keeps synced: the active vault plus every vault in
/// `known_vaults` (added by `sc vault use` / `sc vault create`), deduped. The
/// agent reaches any of them by vid; `sc vault use` is only the CLI default.
fn synced_vault_ids(cfg: &crate::cli::active::CliConfig) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    if let Some(v) = cfg.vault.as_deref().filter(|s| !s.is_empty()) {
        ids.push(v.to_string());
    }
    for kv in &cfg.known_vaults {
        if !kv.vault.is_empty() && !ids.iter().any(|x| x == &kv.vault) {
            ids.push(kv.vault.clone());
        }
    }
    ids
}

/// Spawn one `watch_loop` per synced vault (active ∪ known_vaults), so every
/// vault is kept live, not just the active one. Gated like the rest of sync —
/// no-op for a local-only/unpaired daemon. Vaults added after start are picked
/// up on the next daemon (re)start.
pub fn spawn_watchers(state: Arc<AppState>) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(cloud) = cfg.cloud_backend.clone().filter(|s| !s.is_empty()) else {
        tracing::debug!("cloud sync watch: no cloud_backend; not started (local-only daemon)");
        return;
    };
    let Some(dk) = device_key() else {
        tracing::debug!("cloud sync watch: no device-key (unpaired); not started");
        return;
    };
    let cloud = cloud.trim_end_matches('/').to_string();
    for vault in synced_vault_ids(&cfg) {
        tokio::spawn(watch_loop(state.clone(), vault, cloud.clone(), dk.clone()));
    }
}

/// Pull the vault's sealed blob (version-gated by the `.blob_version` sidecar).
/// On a newer live blob, writes `vault.dat` and returns `Updated(version)`.
/// Returns `Unchanged` when local is already current OR the cloud has no row
/// (HTTP 404 — "never sealed", unchanged meaning preserved). Returns `Deleted`
/// when the envelope's `status` is `"deleted"` (tombstone) — the caller drops
/// local state; nothing is written to disk on this branch.
async fn pull(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<PullOutcome, String> {
    let local_ver = read_local_version(state_dir, vault);
    let url = format!(
        "{}/v/{}/blob?since={}",
        cloud.trim_end_matches('/'),
        vault,
        local_ver
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;

    match resp.status().as_u16() {
        200 => {}
        // 404 = no blob row at all (never sealed). UNCHANGED meaning is kept
        // EXACTLY as before — a tombstone is a 200 with status:"deleted", never
        // a 404, so a delete can no longer masquerade as "nothing sealed yet".
        404 => return Ok(PullOutcome::Unchanged),
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("cloud blob GET HTTP {}", other)),
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse blob response: {}", e))?;

    Ok(classify_pull_body(state_dir, vault, &body)?)
}

/// Parse a 200 blob-GET body into a `PullOutcome` and, for a live update,
/// persist the blob to `vault.dat`. Factored out of `pull` so the watch loop
/// (which reads its own long-poll body) and the unit tests share one classifier.
///
/// Branch order (status wins over content):
/// 1. `status == "deleted"` → `Deleted` (tombstone; never touch disk here).
/// 2. `{ unchanged: true }` → `Unchanged` (cheap freshness probe).
/// 3. a `blob` present (status absent or `"live"`) → persist, `Updated`.
fn classify_pull_body(
    state_dir: &Path,
    vault: &str,
    body: &serde_json::Value,
) -> Result<PullOutcome, String> {
    // Tombstone: an explicit deleted status is the ONLY drop trigger. Checked
    // before `unchanged`/`blob` so a tombstone is never mistaken for content.
    if body.get("status").and_then(|v| v.as_str()) == Some("deleted") {
        return Ok(PullOutcome::Deleted);
    }

    // `{ unchanged: true }` — the cheap freshness probe said local is current.
    if body
        .get("unchanged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(PullOutcome::Unchanged);
    }

    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let blob = body
        .get("blob")
        .ok_or_else(|| "blob missing in cloud response".to_string())?;

    persist_blob(state_dir, vault, blob, version)?;
    Ok(PullOutcome::Updated(version))
}

/// Validate a pulled blob as a `SealedVault`, write it to `vault.dat`
/// atomically, and record the version sidecar. Shared by the start-time pull
/// and the runtime watch loop. Validates BEFORE touching disk — never persist
/// garbage over a working vault.dat.
fn persist_blob(
    state_dir: &Path,
    vault: &str,
    blob: &serde_json::Value,
    version: u64,
) -> Result<(), String> {
    let sealed: SealedVault = serde_json::from_value(blob.clone())
        .map_err(|e| format!("cloud blob is not a valid SealedState: {}", e))?;
    let vault_path = state_dir.join("vaults").join(vault).join("vault.dat");
    sealed_vault::write_atomic(&vault_path, &sealed)
        .map_err(|e| format!("write vault.dat: {}", e))?;
    if let Err(e) = std::fs::write(version_sidecar(state_dir, vault), version.to_string()) {
        tracing::warn!(vault = %vault, "cloud sync: wrote vault.dat but failed to record version: {}", e);
    }
    Ok(())
}

/// Remove the on-disk footprint of a vault: `vault.dat` and the `.blob_version`
/// sidecar. Best-effort and idempotent (missing files are not an error). Used by
/// both the in-process drop path and the pre-serve startup drop. Deliberately
/// narrow — it removes ONLY the two sync-owned files, not the whole vault dir
/// (the audit `.db` is closed/removed by the registry's `forget`, and we keep the
/// directory shell so a re-pair to the same id, were one to happen, isn't
/// confused by a half-present tree).
fn drop_local_vault_disk(state_dir: &Path, vault: &str) {
    let vault_dir = state_dir.join("vaults").join(vault);
    let vault_path = vault_dir.join("vault.dat");
    if let Err(e) = std::fs::remove_file(&vault_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(vault = %vault, "cloud sync: failed to remove vault.dat on delete: {}", e);
        }
    }
    let sidecar = version_sidecar(state_dir, vault);
    if let Err(e) = std::fs::remove_file(&sidecar) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(vault = %vault, "cloud sync: failed to remove .blob_version on delete: {}", e);
        }
    }
}

/// Drop ALL local state for a vault that was deleted (tombstoned) cloud-side.
/// This is the sole code path that destroys local vault state, and it is only
/// reached on an explicit `status:"deleted"` tombstone (never on a decrypt
/// failure — see docs/SYNC.md §4 case 3). Order matters:
///  1. `lock_vault` — transition to Locked, which DROPS the `Unlocked` variant
///     and thereby zeroizes the retained state key `K` (`Zeroizing<Vec<u8>>`)
///     and the whole secrets cache. Done first so K is gone before we touch the
///     ciphertext it protected.
///  2. remove `vault.dat` + `.blob_version` from disk.
///  3. close/forget the per-vault audit SQLite handle (the registry reopens
///     lazily if ever asked again; on a tombstone it won't be).
///  4. forget the vault from the CLI `known_vaults` config so the next daemon
///     start doesn't re-add a watcher for the dead id.
/// The caller is responsible for stopping this vault's `watch_loop` (it returns
/// from the loop after calling us). Best-effort throughout — a failure in any
/// step logs and proceeds; nothing here may stop the daemon from serving.
fn drop_local_vault(state: &Arc<AppState>, vault: &str) {
    // 1. Zeroize retained K + cache by transitioning to Locked.
    state.lock_vault(vault);
    // 2. Disk.
    drop_local_vault_disk(&state.config.state_dir, vault);
    // 3. Audit handle (closes the SQLite connection; idempotent).
    state.audits.forget(vault);
    // 4. CLI config — drop from known_vaults / clear active if it was active.
    match active::forget_vault(vault) {
        Ok(true) => {}
        Ok(false) => {}
        Err(e) => tracing::warn!(vault = %vault, "cloud sync: failed to forget vault from CLI config: {}", e),
    }
}

/// Async wrapper that acquires the per-vault write lock, then drops all local
/// state. EVERY runtime drop (while the daemon is serving, with concurrent
/// approve.rs / connect writers) MUST go through this so the destroy can't race
/// a concurrent `vault.dat` write — `write_atomic`'s tmp+rename could otherwise
/// land AFTER `remove_file` and re-create a live file for a tombstoned id. The
/// ONLY lock-free drop is `pull_on_start`'s (pre-serve: no AppState, no
/// concurrent writers yet), which uses `drop_local_vault_disk` directly.
async fn drop_local_vault_locked(state: &Arc<AppState>, vault: &str) {
    let lock = {
        let mut locks = state.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _guard = lock.lock().await;
    drop_local_vault(state, vault);
}

/// After a runtime pull wrote a new `vault.dat`, refresh the in-memory cache
/// for an UNLOCKED vault using the retained state key `K` — no passkey. If the
/// vault is Locked (no retained `K`), nothing is cached to refresh; the next
/// unlock reads the new file. If the new ciphertext was sealed under a ROTATED
/// `K`, `K` can't open it — leave the cache and log (graceful: lock+unlock to
/// see new state), mirroring the post-write refresh path.
fn refresh_after_pull(state: &Arc<AppState>, vault: &str) {
    let Some(k) = state.cloned_state_key(vault) else {
        return; // Locked — no retained K
    };
    let vault_path = state.config.state_dir.join("vaults").join(vault).join("vault.dat");
    let sealed = match sealed_vault::read(&vault_path) {
        Ok(Some(v)) => v,
        _ => return,
    };
    match crate::server::handlers::metadata::decrypt_vault_view_with_key(&k, &sealed) {
        Ok(view) => {
            let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
            state.unlock_vault(vault.to_string(), cache, k);
            tracing::info!(vault = %vault, "cloud sync: cache refreshed after pull (no re-unlock)");
        }
        Err(_) => {
            tracing::warn!(
                vault = %vault,
                "cloud sync: retained key can't open pulled ciphertext (rotated K?); lock+unlock to see new state"
            );
        }
    }
}

/// Push the local `vault.dat` (sealed blob) back up to the cloud so OTHER
/// devices' daemons pull it. Used after a daemon-side mutation the browser
/// didn't make — notably an OAuth connect's exchange: Google authorization
/// codes are SINGLE-USE, so only one daemon can redeem a pending connect; the
/// resulting refresh_token must propagate to every device via the cloud blob
/// (otherwise other daemons forever sync only the stale `*_oauth_pending`).
///
/// **Cloud-blind preserved:** the pushed blob is ciphertext (passkey-sealed,
/// `W_c` not in it) — the cloud stores it blind, never decrypts. Best-effort:
/// a local-only/unpaired daemon or any network error just logs; the
/// refresh_token is already durable in the local `vault.dat` either way.
pub async fn push_blob_best_effort(state: &Arc<AppState>, vault_id: &str) {
    let Ok(cfg) = active::load() else { return };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return; // local-only daemon — nothing to push to
    };
    let Some(dk) = device_key() else {
        return; // unpaired — no device-key to authenticate the push
    };
    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let url = format!("{}/v/{}/blob", cloud.trim_end_matches('/'), vault_id);

    // Optimistic-concurrency push. Each attempt re-reads the local vault.dat
    // (it may have been re-sealed by the conflict-recovery step below) and PUTs
    // it with `base_version` = the version we believe the cloud row is at. A
    // `409 {conflict, version}` means another writer won the race: we pull the
    // newer blob (persisted under the SAME K — one-K-per-id), re-apply our
    // daemon-side mutation on the fresh state (the OAuth re-seal), then retry
    // with the cloud's new version as the next base. Bounded to MAX_CAS_RETRIES;
    // after the bound we give up (best-effort — the local vault.dat is durable).
    const MAX_CAS_RETRIES: u32 = 3;
    for attempt in 0..=MAX_CAS_RETRIES {
        // Build the request body in an inner scope so `sealed` (a `SealedVault`,
        // not `Send`) is dropped BEFORE any later `.await` — keeping this future
        // `Send` for `tokio::spawn`. Re-read each attempt: a prior 409's recovery
        // re-sealed vault.dat. base_version = the version we last recorded for
        // this row (opts into server-side CAS; legacy v1.0.22 omits it → LWW).
        let body = {
            let sealed = match sealed_vault::read(&vault_path) {
                Ok(Some(v)) => v,
                _ => return,
            };
            let blob = match serde_json::to_value(&sealed) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(vault = %vault_id, "push-back: serialize failed: {}", e);
                    return;
                }
            };
            let base_version = read_local_version(&state.config.state_dir, vault_id);
            serde_json::json!({ "blob": blob, "base_version": base_version })
        };
        let resp = match client
            .put(&url)
            .bearer_auth(&dk)
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(vault = %vault_id, "push-back: PUT failed: {}", e);
                return;
            }
        };

        let status = resp.status();
        if status.as_u16() == 409 {
            // Drop the response (and its borrow of the connection) before any
            // await below, so this future stays `Send` for `tokio::spawn`.
            drop(resp);
            if attempt == MAX_CAS_RETRIES {
                tracing::warn!(
                    vault = %vault_id,
                    "push-back: gave up after {} CAS retries (local vault.dat is durable)",
                    MAX_CAS_RETRIES
                );
                return;
            }
            tracing::info!(vault = %vault_id, attempt, "push-back: 409 conflict; pulling newer blob and re-applying");
            // Cloud moved on: pull the winner under the same K, re-apply our
            // mutation, then loop to retry with the fresh base_version. Factored
            // into its own fn so no non-`Send` request-build local can leak
            // across its awaits (keeps `push_blob_best_effort` spawnable).
            if !recover_after_conflict(state, cloud, vault_id, &dk).await {
                return; // give up (deleted, or pull error) — already logged
            }
            continue;
        }

        if !status.is_success() {
            tracing::warn!(vault = %vault_id, "push-back: cloud rejected (HTTP {})", status);
            return;
        }

        // Record the version the cloud assigned, so our OWN watcher doesn't treat
        // the blob we just pushed as a newer remote change and re-pull it.
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            if let Some(version) = body.get("version").and_then(|v| v.as_u64()) {
                let _ = std::fs::write(
                    version_sidecar(&state.config.state_dir, vault_id),
                    version.to_string(),
                );
            }
        }
        tracing::info!(vault = %vault_id, "push-back: pushed refreshed sealed blob to cloud");
        return;
    }
}

/// One CAS-conflict recovery step for `push_blob_best_effort`: pull the winning
/// blob (persisted under the SAME K — one-K-per-id), then re-apply the
/// daemon-side mutation (the pending OAuth connect re-seal) on the fresh state.
/// Returns `true` to retry the PUT, `false` to give up (a tombstone showed up
/// mid-push → local state dropped, or the pull errored). Kept separate so its
/// await scopes are clean and the caller's future stays `Send`.
async fn recover_after_conflict(
    state: &Arc<AppState>,
    cloud: &str,
    vault_id: &str,
    dk: &str,
) -> bool {
    // Pull the winning blob and persist it under the same K. This writes
    // vault.dat AND updates the .blob_version sidecar to the cloud's new
    // version, which becomes our next `base_version`.
    match pull(&state.config.state_dir, cloud, vault_id, dk).await {
        Ok(PullOutcome::Updated(_)) | Ok(PullOutcome::Unchanged) => {}
        Ok(PullOutcome::Deleted) => {
            // Deleted out from under us mid-push — stop and drop local state
            // (under the write lock; we're serving) and never resurrect a
            // tombstoned vault.
            drop_local_vault_locked(state, vault_id).await;
            tracing::info!(vault = %vault_id, "push-back: vault deleted upstream during conflict; dropped local state");
            return false;
        }
        Err(e) => {
            tracing::warn!(vault = %vault_id, "push-back: conflict-recovery pull failed: {}", e);
            return false;
        }
    }
    // Re-apply our daemon-side mutation (the pending OAuth connect) on top of the
    // freshly-pulled state and re-seal vault.dat. Uses the retained K (no
    // passkey); no-ops if locked or nothing pending.
    //
    // We call `apply_pending_connects` (the push-FREE inner step), NOT the public
    // `process_vault_connects` (which would spawn another `push_blob_best_effort`
    // and form an async-recursion cycle the compiler can't prove `Send`). We are
    // already inside the push loop: the very next iteration re-reads the re-sealed
    // vault.dat and re-PUTs, so the fan-out is covered without the recursive edge.
    crate::auth::connect::apply_pending_connects(state, vault_id).await;
    true
}

/// Fetch the account-level agent-key hash-set (`/api/vault/agents/hashes`,
/// device-key authed). Returns None on any failure (caller keeps the prior
/// set). The hashes are sha256(token) hex — the broker validates a presented
/// key by re-hashing and checking membership; the cloud never sees plaintext.
async fn fetch_agent_key_hashes(
    client: &reqwest::Client,
    cloud: &str,
    device_key: &str,
) -> Option<std::collections::HashSet<String>> {
    let url = format!("{}/api/vault/agents/hashes", cloud.trim_end_matches('/'));
    let resp = client.get(&url).bearer_auth(device_key).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let keys = body.get("keys")?.as_array()?;
    Some(
        keys.iter()
            .filter_map(|k| k.get("hash").and_then(|h| h.as_str()).map(|s| s.to_string()))
            .collect(),
    )
}

/// One-shot refresh of the broker's agent-key hash-set. Best-effort + gated
/// like the blob sync (no-op for a local-only/unpaired daemon). Call once
/// before serving so the broker accepts account agent-keys from the start.
pub async fn sync_agent_keys_once(state: &Arc<AppState>) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else {
        return;
    };
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(15)).build() {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Some(hashes) = fetch_agent_key_hashes(&client, cloud, &dk).await {
        let n = hashes.len();
        state.set_agent_key_hashes(hashes);
        tracing::debug!(count = n, "synced agent-key hash-set");
    }
}

/// Periodically refresh the agent-key hash-set so a dashboard revoke / a newly
/// added agent takes effect within ~30s on this daemon. Detached, best-effort.
pub async fn sync_agent_keys_loop(state: Arc<AppState>) {
    loop {
        sync_agent_keys_once(&state).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

// ── Audit shipper (de-daemon, DE_DAEMON.md §4) ──────────────────────────────
// Local-first outbox: the daemon already writes every op to its per-vault
// `audit.db` synchronously (offline-safe). This loop is the DELIVERY half — it
// pushes terminal Use-op rows (synced=0) to the cloud `audit_events` table so
// the console can show activity WITHOUT a cloud daemon. Best-effort + gated
// exactly like blob sync: a local-only / unpaired daemon never ships. The
// backend UPSERTs on the daemon-minted `event_id`, so at-least-once delivery
// (ship, then crash before marking) is idempotent.

/// Max rows shipped per vault per backend round-trip. Bounds request size; a
/// larger backlog drains across successive batches within one sweep.
const AUDIT_SHIP_BATCH: u32 = 200;

/// One audit event in the cloud-ingest wire shape. The backend stamps
/// `vault_id` (from the URL path) and `account_id` (from the authenticated
/// device-key) — the daemon never asserts ownership in the body. Secret values,
/// query strings, and request/response bodies are NEVER included (audit.rs only
/// ever records method / sanitized path / status / timestamps).
#[derive(serde::Serialize)]
struct AuditEventWire {
    event_id: String, // daemon-minted op id; the backend's UPSERT key
    ts: i64,          // event time (unix secs): decided_at, else created_at
    decision: String, // allowed | approved | denied | rejected | expired
    op_id: String,    // approval linkage (= event_id for Use ops)
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>, // "METHOD path", e.g. "POST /v1/chat/completions"
}

fn event_from_row(row: &crate::audit::ApprovalRow) -> AuditEventWire {
    let action = match (&row.method, &row.path) {
        (Some(m), Some(p)) => Some(format!("{} {}", m, p)),
        (Some(m), None) => Some(m.clone()),
        (None, Some(p)) => Some(p.clone()),
        (None, None) => None,
    };
    AuditEventWire {
        event_id: row.id.clone(),
        ts: row.decided_at.unwrap_or(row.created_at),
        decision: row.status.clone(),
        op_id: row.id.clone(),
        service: row.service.clone(),
        action,
    }
}

/// Periodically ship each synced vault's unshipped audit rows to the cloud.
/// Detached + best-effort: any failure backs off to the next tick and never
/// affects serving.
pub async fn ship_audit_loop(state: Arc<AppState>) {
    loop {
        ship_audit_once(&state).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// One sweep across all synced vaults (active ∪ known_vaults).
pub async fn ship_audit_once(state: &Arc<AppState>) {
    let Ok(cfg) = active::load() else {
        return;
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return; // local-only daemon — nowhere to ship
    };
    let Some(dk) = device_key() else {
        return; // unpaired — no device-key to authenticate the ingest
    };
    let cloud = cloud.trim_end_matches('/');
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    for vault in synced_vault_ids(&cfg) {
        ship_vault_audit(state, &client, cloud, &dk, &vault).await;
    }
}

async fn ship_vault_audit(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    cloud: &str,
    device_key: &str,
    vault: &str,
) {
    // `for_vault` only opens DBs for vaults that exist on disk; a known-but-not-
    // yet-served vault just yields NotFound and is skipped this tick.
    let store = match state.audits.for_vault(vault) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Opportunistic retention: prune local rows past the vault's window so the
    // outbox + audit.db don't grow unbounded. Cloud-side TTL is separate (§4).
    if let Some(days) = state.audit_retention_days(vault) {
        if let Some(cutoff) = retention_cutoff(days) {
            let _ = store.prune_older_than(cutoff);
        }
    }

    // Drain the backlog in batches; stop on the first error (retry next tick)
    // or when a short page signals the queue is empty.
    loop {
        let rows = match store.list_unsynced(AUDIT_SHIP_BATCH) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(vault = %vault, "audit ship: list_unsynced failed: {}", e);
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        let events: Vec<AuditEventWire> = rows.iter().map(event_from_row).collect();
        let url = format!("{}/v/{}/audit", cloud, vault);
        let resp = client
            .post(&url)
            .bearer_auth(device_key)
            .json(&serde_json::json!({ "events": events }))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
                let n = ids.len();
                if let Err(e) = store.mark_synced(&ids) {
                    tracing::warn!(vault = %vault, "audit ship: mark_synced failed: {}", e);
                    return; // avoid re-shipping the same batch in a tight loop
                }
                tracing::debug!(vault = %vault, count = n, "audit shipped");
                if (n as u32) < AUDIT_SHIP_BATCH {
                    return; // drained
                }
            }
            Ok(r) => {
                tracing::debug!(
                    vault = %vault, status = %r.status(),
                    "audit ship: backend rejected batch; retrying next tick"
                );
                return;
            }
            Err(e) => {
                tracing::debug!(vault = %vault, "audit ship: unreachable backend: {}", e);
                return;
            }
        }
    }
}

/// Unix-seconds cutoff for `days` of retention, or None on a clock error.
fn retention_cutoff(days: u32) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(now - (days as i64) * 86_400)
}

/// Long-lived background sync watcher. Long-polls the cloud blob-version
/// endpoint (`/v/{vid}/blob/wait?since=<local>`, server holds ~25s and
/// responds the instant the version bumps); on a change, pulls the new sealed
/// blob into `vault.dat` (under the per-vault write lock, serialized against
/// approve's writes) and refreshes the unlocked cache with the retained `K`.
/// Best-effort + detached: a local-only/unpaired/offline daemon just no-ops or
/// backs off, and any failure here NEVER affects serving. See
/// [[project_realtime_sync_v1_decision]].
pub async fn watch_loop(state: Arc<AppState>, vault: String, cloud: String, dk: String) {
    let state_dir = state.config.state_dir.clone();
    // Read-timeout MUST exceed the server's long-poll hold (~25s) plus slack.
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(40)).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cloud sync watch: client init failed: {}", e);
            return;
        }
    };
    tracing::info!(vault = %vault, "cloud sync watch loop started");

    let mut backoff = Duration::from_secs(2);
    loop {
        let local_ver = read_local_version(&state_dir, &vault);
        let url = format!("{}/v/{}/blob/wait?since={}", cloud, vault, local_ver);
        match client.get(&url).bearer_auth(&dk).send().await {
            Ok(resp) => match resp.status().as_u16() {
                200 => {
                    backoff = Duration::from_secs(2);
                    let body: serde_json::Value = match resp.json().await {
                        Ok(b) => b,
                        Err(_) => {
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                    };
                    // Tombstone: the vault was deleted cloud-side. Drop ALL local
                    // state (zeroize K, remove vault.dat + sidecar, close audit,
                    // forget from CLI config) and STOP this watcher — there is no
                    // vault left to watch. This is the fix for "web delete →
                    // daemon no-op". Only an explicit tombstone reaches here; a
                    // live-but-undecryptable blob is log-only (refresh_after_pull).
                    if body.get("status").and_then(|v| v.as_str()) == Some("deleted") {
                        // Drop under the per-vault write lock so the destroy can't
                        // race a concurrent approve.rs / connect write to vault.dat.
                        drop_local_vault_locked(&state, &vault).await;
                        tracing::info!(vault = %vault, "cloud sync: vault deleted upstream; dropped local state");
                        return;
                    }
                    if body.get("unchanged").and_then(|v| v.as_bool()).unwrap_or(false) {
                        // Long-poll window elapsed with no change — re-poll.
                        continue;
                    }
                    let Some(blob) = body.get("blob") else { continue };
                    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
                    // Serialize against approve.rs's vault.dat writes.
                    let lock = {
                        let mut locks = state.vault_write_locks.lock().unwrap();
                        Arc::clone(
                            locks
                                .entry(vault.clone())
                                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
                        )
                    };
                    {
                        let _guard = lock.lock().await;
                        if let Err(e) = persist_blob(&state_dir, &vault, blob, version) {
                            tracing::warn!(vault = %vault, "cloud sync watch: persist failed: {}", e);
                            continue;
                        }
                        refresh_after_pull(&state, &vault);
                    }
                    // A freshly-pulled blob may carry a passkey-sealed
                    // `<conn>_oauth_pending` from a browser "Connect" — complete
                    // the OAuth code→token exchange and persist the refresh_token
                    // (CONNECTIONS_AND_AUTH.md §4a). Best-effort; acquires the
                    // per-vault write lock itself, so it runs AFTER the guard
                    // above drops (the lock is not reentrant).
                    crate::auth::connect::process_vault_connects(&state, &vault).await;
                    // PER-ITEM: a keyset/blob change often coincides with content
                    // changes; opportunistically pull item rows and refresh the
                    // cache from the folded item view. Best-effort.
                    match pull_items(&state_dir, &cloud, &vault, &dk).await {
                        Ok(n) if n > 0 => refresh_after_item_pull(&state, &vault),
                        Ok(_) => {}
                        Err(e) => tracing::debug!(vault = %vault, "cloud sync watch: per-item pull failed: {}", e),
                    }
                    tracing::info!(vault = %vault, version, "cloud sync watch: applied pulled blob");
                }
                404 => {
                    // No blob in the cloud yet — gentle retry.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                401 | 403 => {
                    tracing::warn!(vault = %vault, "cloud sync watch: auth rejected (HTTP {}); stopping", resp.status());
                    return;
                }
                _ => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            },
            Err(_) => {
                // Transient (timeout/offline). The 40s read-timeout exceeds the
                // 25s server hold, so a clean long-poll return shouldn't error here.
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM SYNC  (PER_ITEM_SYNC.md §4/§5 / build contract §4 priority 3)
//
// The whole-blob `pull`/`push_blob_best_effort`/`watch_loop` above stay for the
// KEYSET lifecycle (the `/blob` row is now keyset-only, §7). The functions here
// are the CONTENT sync: the daemon holds N sealed item rows in
// `vault.per-item.json` and pulls/pushes them against the backend `/items`
// endpoints (contract §3):
//
//   GET  /v/{vid}/items?since=<seq> → { items:[{item_id,version,seq,ct}], seq }
//   PUT  /v/{vid}/items/{item_id}   { base_version?, version, ct } → CAS
//                                   → 200 {version,seq} | 409 {currentVersion}
//   GET  /v/{vid}/items/wait?since=<seq> (daemon long-poll)
//   DELETE /v/{vid}/items/{item_id}?gc_version=<v> (tombstone GC)
//
// PULL adopts server truth (§5): a newer version replaces the local row, a
// tombstone is stored (fold_view drops it), the cursor advances to max(seq).
// PUSH is per-item CAS (§4); 409 → reconcile — re-apply on the fresh item if the
// edit is independent, else write a conflict-copy (never last-writer-wins).
//
// Backing HTTP is only exercised once the backend `/items` endpoints are live;
// until then these are wired but a 404 leaves the local per-item store as the
// authoritative content (stubbed[]).
// ─────────────────────────────────────────────────────────────────────────

use crate::storage::sealed_vault::{self as pv_store, PerItemVault};

/// One row of a `/items` pull.
#[derive(Debug, Clone, serde::Deserialize)]
struct ItemRow {
    item_id: String,
    version: u64,
    #[allow(dead_code)]
    seq: u64,
    /// base64url-nopad of `suite‖nonce‖ct‖tag`.
    ct: String,
}

/// Load the per-item store for a vault, or `None` if it doesn't exist yet.
fn read_per_item_store(state_dir: &Path, vault: &str) -> Option<PerItemVault> {
    let path = state_dir.join("vaults").join(vault).join("vault.per-item.json");
    pv_store::read_per_item(&path).ok().flatten()
}

fn write_per_item_store(state_dir: &Path, vault: &str, pv: &PerItemVault) -> Result<(), String> {
    let path = state_dir.join("vaults").join(vault).join("vault.per-item.json");
    pv_store::write_per_item_atomic(&path, pv).map_err(|e| format!("write per-item store: {}", e))
}

/// Adopt a batch of pulled item rows into the local store (server-authoritative,
/// §5): a strictly-newer `version` replaces the local row; the cursor advances
/// to the max `seq` seen. Tombstones are stored like any other row — `fold_view`
/// drops them at read time, and a later GC hard-deletes them. Returns the number
/// of rows adopted.
fn adopt_item_rows(pv: &mut PerItemVault, rows: &[ItemRow], max_seq: u64) -> Result<usize, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut adopted = 0usize;
    for row in rows {
        // Only adopt a strictly-newer version (server is authoritative, but a
        // stale replay must not clobber a fresher local row we already pushed).
        let keep = pv
            .get_item(&row.item_id)
            .map(|s| row.version > s.version)
            .unwrap_or(true);
        if !keep {
            continue;
        }
        let ct = URL_SAFE_NO_PAD
            .decode(row.ct.as_bytes())
            .map_err(|e| format!("item ct not base64url: {}", e))?;
        pv.put_raw(row.item_id.clone(), row.version, ct);
        adopted += 1;
    }
    if max_seq > pv.items_seq {
        pv.items_seq = max_seq;
    }
    Ok(adopted)
}

/// Pull item rows changed since the local `.items_seq` cursor and adopt them.
/// Best-effort: a 404 (endpoint not live yet) or a missing local store is a
/// no-op. Returns the number of rows adopted.
pub async fn pull_items(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<usize, String> {
    let Some(mut pv) = read_per_item_store(state_dir, vault) else {
        return Ok(0); // no per-item store yet (vault not enrolled per-item)
    };
    let url = format!(
        "{}/v/{}/items?since={}",
        cloud.trim_end_matches('/'),
        vault,
        pv.items_seq
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(0), // /items not live yet — no-op (stubbed[])
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("items GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse items response: {}", e))?;
    let rows: Vec<ItemRow> = body
        .get("items")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse items array: {}", e))?
        .unwrap_or_default();
    let max_seq = body.get("seq").and_then(|v| v.as_u64()).unwrap_or(pv.items_seq);
    let adopted = adopt_item_rows(&mut pv, &rows, max_seq)?;
    if adopted > 0 || max_seq > 0 {
        write_per_item_store(state_dir, vault, &pv)?;
    }
    Ok(adopted)
}

/// Push a single item to the cloud with per-item CAS (§4). `base_version` is the
/// version the writer last read (absent → create). On `200` returns the cloud-
/// stamped `{version, seq}`; on `409` returns the conflict's `currentVersion` so
/// the caller can reconcile (re-apply on fresh, or conflict-copy — NEVER LWW).
///
/// `PushOutcome::EndpointMissing` (a 404) means the backend `/items` route isn't
/// live yet — the caller treats it as a no-op (stubbed[]).
pub enum PushOutcome {
    Ok { version: u64, seq: u64 },
    Conflict { current_version: u64 },
    EndpointMissing,
}

pub async fn push_item(
    cloud: &str,
    vault: &str,
    device_key: &str,
    item_id: &str,
    base_version: Option<u64>,
    version: u64,
    ct_b64: &str,
) -> Result<PushOutcome, String> {
    let url = format!(
        "{}/v/{}/items/{}",
        cloud.trim_end_matches('/'),
        vault,
        item_id
    );
    // CREATE omits base_version entirely (sending 0 → 409); only include it on
    // update (contract "BACKEND WIRE": a CREATE omits base_version).
    let mut body = serde_json::json!({ "version": version, "ct": ct_b64 });
    if let Some(bv) = base_version {
        body["base_version"] = serde_json::json!(bv);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .put(&url)
        .bearer_auth(device_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {
            let b: serde_json::Value = resp.json().await.map_err(|e| format!("parse put: {}", e))?;
            Ok(PushOutcome::Ok {
                version: b.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
                seq: b.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        }
        409 => {
            let b: serde_json::Value = resp.json().await.unwrap_or_default();
            let current = b
                .get("currentVersion")
                .and_then(|v| v.as_u64())
                .unwrap_or(version);
            Ok(PushOutcome::Conflict { current_version: current })
        }
        404 => Ok(PushOutcome::EndpointMissing),
        other => Err(format!("item PUT HTTP {}", other)),
    }
}

/// Hard-delete a tombstone row that has fully propagated (GC, §6): DELETE
/// `/items/{id}?gc_version=<v>`. Idempotent; only removes the exact version the
/// caller saw so it never drops a newer row that replaced the tombstone.
pub async fn gc_item(
    cloud: &str,
    vault: &str,
    device_key: &str,
    item_id: &str,
    gc_version: u64,
) -> Result<(), String> {
    let url = format!(
        "{}/v/{}/items/{}?gc_version={}",
        cloud.trim_end_matches('/'),
        vault,
        item_id,
        gc_version
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .delete(&url)
        .bearer_auth(device_key)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    if resp.status().is_success() || resp.status().as_u16() == 404 {
        Ok(())
    } else {
        Err(format!("item GC DELETE HTTP {}", resp.status()))
    }
}

/// Push every LOCAL item whose version is ahead of what the cloud last confirmed
/// (tracked by the per-item store's own rows). Each row is pushed with CAS; a
/// 409 is reconciled per §4:
///   - independent edit (the cloud's newer row is a DIFFERENT logical item, i.e.
///     our push targeted a row the cloud doesn't have or has at a lower version)
///     → adopt the cloud row and retry with the fresh base;
///   - genuine same-item conflict (both wrote the same id) → leave theirs, write
///     OURS as a conflict-copy (deterministic id via `conflict_copy_id`, so a
///     retry can't spawn a second) — needs `K`, so it runs only for an UNLOCKED
///     vault; a locked vault defers the conflict-copy to the next unlock.
///
/// NOTE: the full conflict-copy branch requires K + the item's (ns,name), which
/// we recover by unsealing the local row. Where the vault is locked, the row is
/// left ahead and retried next unlock (documented in stubbed[]).
pub async fn push_items_best_effort(state: &Arc<AppState>, vault_id: &str) {
    let Ok(cfg) = active::load() else { return };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else { return };
    let cloud = cloud.trim_end_matches('/');
    let state_dir = &state.config.state_dir;

    let Some(pv) = read_per_item_store(state_dir, vault_id) else {
        return;
    };
    // Snapshot (id, version, ct_b64) so we don't hold the store across awaits.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let rows: Vec<(String, u64, String)> = pv
        .items
        .iter()
        .map(|(id, s)| (id.clone(), s.version, URL_SAFE_NO_PAD.encode(&s.ct)))
        .collect();

    for (id, version, ct_b64) in rows {
        // base_version = version-1 for an update; a version-1 row is a create.
        let base_version = if version > 1 { Some(version - 1) } else { None };
        match push_item(cloud, vault_id, &dk, &id, base_version, version, &ct_b64).await {
            Ok(PushOutcome::Ok { .. }) => {}
            Ok(PushOutcome::EndpointMissing) => return, // /items not live — stop (stubbed[])
            Ok(PushOutcome::Conflict { current_version }) => {
                // Pull the current rows (adopt server truth) so a subsequent
                // resolve/retry sees the winner. The conflict-copy branch (a
                // genuine same-item conflict) requires K + (ns,name); it runs at
                // unlock time via `reconcile_conflicts_after_pull`. Here we only
                // adopt + log so we never last-writer-wins.
                tracing::info!(
                    vault = %vault_id, item = %id, current_version,
                    "per-item push: 409 conflict; adopting server row (conflict-copy deferred to unlock)"
                );
                let _ = pull_items(state_dir, cloud, vault_id, &dk).await;
                return;
            }
            Err(e) => {
                tracing::warn!(vault = %vault_id, item = %id, "per-item push failed: {}", e);
                return;
            }
        }
    }
    tracing::debug!(vault = %vault_id, "per-item push: all local items pushed");
}

#[cfg(test)]
mod peritem_tests {
    use super::*;
    use crate::storage::item::ItemNs;
    use crate::storage::sealed_vault::PerItemVault;
    use sudp::primitives::StdPrimitives;

    fn empty_pv() -> PerItemVault {
        PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap()
    }

    /// Adopt replaces a strictly-newer version and advances the cursor; a stale
    /// (<= local) version is ignored (no clobber of a fresher local push).
    #[test]
    fn adopt_replaces_newer_and_advances_cursor() {
        let k = [0x42u8; 32];
        let vid = "v";
        let mut pv = empty_pv();
        // Local row at version 2.
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                &k, vid, ItemNs::Secret, "A", 2,
                &crate::storage::item::ItemPayload::secret_live("A", "local"),
            )
            .unwrap();

        // A stale row (version 1) must NOT replace it.
        let stale = ItemRow { item_id: id.clone(), version: 1, seq: 5, ct: "AAAA".into() };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&stale), 5).unwrap();
        assert_eq!(n, 0, "stale version ignored");
        assert_eq!(pv.get_item(&id).unwrap().version, 2);
        assert_eq!(pv.items_seq, 5, "cursor still advances to max seq");

        // A newer row (version 3) replaces it (raw ct adopted verbatim).
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let newer_ct = URL_SAFE_NO_PAD.encode([1u8, 2, 3, 4]);
        let newer = ItemRow { item_id: id.clone(), version: 3, seq: 9, ct: newer_ct };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&newer), 9).unwrap();
        assert_eq!(n, 1);
        assert_eq!(pv.get_item(&id).unwrap().version, 3);
        assert_eq!(pv.get_item(&id).unwrap().ct, vec![1u8, 2, 3, 4]);
        assert_eq!(pv.items_seq, 9);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// The browser assembles the blob client-side; this guards that the exact
    /// shape it produces (compact JSON, registry value field order
    /// `x`/`y`/`device_name`, standard-base64 byte fields, registry key =
    /// std-b64(credential_id)) deserializes into a SealedVault and survives a
    /// write_atomic → read round-trip. Values are a real vault.dat sample.
    /// If the frontend's `setupEnvVault` assembly and this ever drift, this
    /// fails before the e2e does. Mirrors lib/vault-grant.ts setupEnvVault.
    #[test]
    fn frontend_assembled_blob_parses_and_roundtrips() {
        let cid = "UNwLi9p8ykq/YcbW/mk7loMRg8NyDZ021BoA8L2MOBZo//Cdi6Gqh1rhIvT8FHsiq6CsubhU";
        // Compact, exactly as the browser serializes (JSON.stringify):
        let blob = serde_json::json!({
            "version": 1,
            "registry": {
                cid: { "x": "72laEiwOtkMX5s7o280rWZk2zAfVG64gtsXAbBS46c4=",
                       "y": "B56KGrJOCOvfT3hR36M4sXimg8dlmLfhK8g+Kf2R66c=",
                       "device_name": "Mac · sunny-panda" }
            },
            "credentials": [
                { "credential_id": cid,
                  "prf_salt": "9gZJFej46o71aNu7955eqwygNwrptzCyg3D40FNQxPI=",
                  "wrapped_key": "OjModKRUWfStXREA8a+5WE06boSM2WhUl2e34x6+PzeWXupr0ulv13OdSwSkbXBRG5FEIbh9VVaKk9ESpuZfKcZbCosHJj7y" }
            ],
            "ciphertext": "fQslPsTIWQLbmWNoD/rJfXlwsaU2RvY5N2U3EqJf6FYWUugz9CSjRlXyc0/M7mc3"
        });

        // 1. Parses into the daemon's SealedVault (the pull path).
        let sealed: SealedVault =
            serde_json::from_value(blob).expect("frontend blob must parse as SealedVault");
        assert_eq!(sealed.credentials.len(), 1);
        assert_eq!(sealed.registry.len(), 1);

        // 2. write_atomic → read round-trips byte-for-field (what pull does).
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        sealed_vault::write_atomic(&path, &sealed).unwrap();
        let back = sealed_vault::read(&path).unwrap().unwrap();
        assert_eq!(back.credentials[0].credential_id, sealed.credentials[0].credential_id);
        assert_eq!(back.ciphertext, sealed.ciphertext);
    }

    /// A tombstone (`status:"deleted"`) classifies as `Deleted` and writes
    /// NOTHING to disk — the drop is the caller's job, never a side effect of
    /// parsing. Status wins even if a (stale) `blob`/`version` is also present.
    #[test]
    fn deleted_status_classifies_as_deleted_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let body = serde_json::json!({
            "status": "deleted",
            "version": 1782722939030u64,
            // A defensive case: even with a blob present, deleted must win.
            "blob": { "garbage": true }
        });
        let outcome = classify_pull_body(dir.path(), "v-del", &body).unwrap();
        assert_eq!(outcome, PullOutcome::Deleted);
        // No vault.dat or sidecar created by the classifier.
        assert!(!dir.path().join("vaults").join("v-del").join("vault.dat").exists());
        assert!(!version_sidecar(dir.path(), "v-del").exists());
    }

    /// `{ unchanged: true }` (no status, or status:"live") classifies as
    /// `Unchanged` and writes nothing.
    #[test]
    fn unchanged_body_classifies_as_unchanged() {
        let dir = tempdir().unwrap();
        let body = serde_json::json!({ "unchanged": true });
        assert_eq!(
            classify_pull_body(dir.path(), "v-unch", &body).unwrap(),
            PullOutcome::Unchanged
        );
        let body_live = serde_json::json!({ "status": "live", "unchanged": true });
        assert_eq!(
            classify_pull_body(dir.path(), "v-unch", &body_live).unwrap(),
            PullOutcome::Unchanged
        );
    }

    /// A live blob (status absent → treated live, backward-compatible with the
    /// v1.0.22 cloud that never sends `status`) persists `vault.dat` + the
    /// version sidecar and classifies as `Updated(version)`.
    #[test]
    fn live_blob_persists_and_classifies_as_updated() {
        let cid = "UNwLi9p8ykq/YcbW/mk7loMRg8NyDZ021BoA8L2MOBZo//Cdi6Gqh1rhIvT8FHsiq6CsubhU";
        let blob = serde_json::json!({
            "version": 1,
            "registry": {
                cid: { "x": "72laEiwOtkMX5s7o280rWZk2zAfVG64gtsXAbBS46c4=",
                       "y": "B56KGrJOCOvfT3hR36M4sXimg8dlmLfhK8g+Kf2R66c=",
                       "device_name": "Mac · sunny-panda" }
            },
            "credentials": [
                { "credential_id": cid,
                  "prf_salt": "9gZJFej46o71aNu7955eqwygNwrptzCyg3D40FNQxPI=",
                  "wrapped_key": "OjModKRUWfStXREA8a+5WE06boSM2WhUl2e34x6+PzeWXupr0ulv13OdSwSkbXBRG5FEIbh9VVaKk9ESpuZfKcZbCosHJj7y" }
            ],
            "ciphertext": "fQslPsTIWQLbmWNoD/rJfXlwsaU2RvY5N2U3EqJf6FYWUugz9CSjRlXyc0/M7mc3"
        });
        let dir = tempdir().unwrap();
        let body = serde_json::json!({ "version": 42u64, "blob": blob });
        let outcome = classify_pull_body(dir.path(), "v-live", &body).unwrap();
        assert_eq!(outcome, PullOutcome::Updated(42));
        assert!(dir.path().join("vaults").join("v-live").join("vault.dat").exists());
        assert_eq!(read_local_version(dir.path(), "v-live"), 42);
    }

    /// `forget_vault` removes a known vault by vid alone and is idempotent.
    /// (Drives the cloud-sync delete path's CLI-config cleanup.) Runs against a
    /// temp HOME so the developer's real `~/.safeclaw/config.toml` is untouched.
    #[test]
    fn forget_vault_by_vid_is_idempotent() {
        use crate::cli::active::{self, CliConfig, KnownVault};
        let home = tempdir().unwrap();
        // active.rs resolves config via dirs::home_dir() → $HOME.
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());

        let cfg = CliConfig {
            daemon: Some("http://localhost:1".into()),
            vault: Some("vid-A".into()),
            known_vaults: vec![
                KnownVault { daemon: "http://localhost:1".into(), vault: "vid-A".into() },
                KnownVault { daemon: "http://localhost:1".into(), vault: "vid-B".into() },
            ],
            ..Default::default()
        };
        active::save(&cfg).unwrap();

        // Remove the ACTIVE vault by vid: dropped from known_vaults AND cleared active.
        assert_eq!(active::forget_vault("vid-A"), Ok(true));
        let after = active::load().unwrap();
        assert!(after.vault.is_none());
        assert!(after.daemon.is_none());
        assert_eq!(after.known_vaults.len(), 1);
        assert_eq!(after.known_vaults[0].vault, "vid-B");

        // Idempotent: forgetting it again is a no-op (Ok(false)).
        assert_eq!(active::forget_vault("vid-A"), Ok(false));
        // A non-active known vault: removed, active untouched.
        assert_eq!(active::forget_vault("vid-B"), Ok(true));
        assert!(active::load().unwrap().known_vaults.is_empty());

        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
