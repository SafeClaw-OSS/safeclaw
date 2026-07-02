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
        // PER-ITEM: pull the KEYSET (the passkey-wrap layer, now on `/keys`)
        // BEFORE the content rows, so the folded view later sees a fresh K-wrap
        // layer. Best-effort; a 404 / non-per-item vault is a no-op.
        match pull_keys(state_dir, cloud, vault, &dk).await {
            Ok(n) if n > 0 => tracing::info!(vault = %vault, adopted = n, "cloud sync: pulled keyset rows"),
            Ok(_) => {}
            Err(e) => tracing::debug!(vault = %vault, "cloud sync: keyset pull failed: {}", e),
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
    // PER-ITEM: pull the KEYSET (`/keys`), then the content item rows (`/items`).
    // The keyset now rides `/keys` (NOT the whole-blob `/blob`, which is a
    // keyset-lifecycle marker only); pull it FIRST so the item fold below sees a
    // fresh K-wrap layer. Best-effort — a 404 (endpoint not live) or a
    // not-yet-per-item vault is a no-op. On item adoption, refresh the cache from
    // the folded item view so the new rows are served without a re-unlock.
    if let Some(cloud2) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) {
        if let Some(dk2) = device_key() {
            match pull_keys(&state.config.state_dir, cloud2, vault_id, &dk2).await {
                Ok(n) if n > 0 => tracing::info!(vault = %vault_id, adopted = n, "keyset pull: adopted rows"),
                Ok(_) => {}
                Err(e) => tracing::debug!(vault = %vault_id, "keyset pull failed: {}", e),
            }
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

    // PER-ITEM: a per-item vault's `/blob` row is now a keyset-lifecycle marker
    // ONLY — the browser writes `{ lifecycle: "per-item-v3", version }` with NO
    // `blob` field (setupEnvVault). The keyset itself rides `/keys`
    // (`pull_keys`), not the whole-blob path. So a live 200 body with no `blob`
    // (and not a tombstone — handled above) is NOT an error and must NOT be
    // persisted to `vault.dat`: treat it as `Unchanged`. (A legacy whole-blob
    // vault still sends a `blob`; that path is unchanged below.)
    let Some(blob) = body.get("blob") else {
        return Ok(PullOutcome::Unchanged);
    };
    // PER-ITEM: `putBlob` wraps the lifecycle marker, so it arrives as
    // `{ blob: { lifecycle: "per-item-v3", version } }` — the marker DOES sit
    // under `blob` (the no-`blob` case above only covers a bare row). It is NOT a
    // whole SealedState: the keyset rides `/keys`, content rides `/items`. Never
    // persist it as vault.dat — treat as Unchanged so `sc sync` doesn't choke
    // trying to parse a lifecycle marker as a SealedState (missing `registry`).
    if blob.get("lifecycle").is_some() {
        return Ok(PullOutcome::Unchanged);
    }

    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
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
                    // Persist the whole-blob body to vault.dat ONLY when it's a real
                    // SealedState. A per-item vault's /blob is a lifecycle marker
                    // ({lifecycle, version}), NOT a SealedState — so skip persist for
                    // it (this was the bug that spammed "not a valid SealedState")
                    // and, crucially, DON'T `continue`: fall through to the per-item
                    // keyset/item pulls below, since the content lives in /keys +
                    // /items, not the blob. A persist error on a real blob is now
                    // logged but also doesn't starve the per-item pulls.
                    if let Some(blob) = body.get("blob").filter(|b| b.get("lifecycle").is_none()) {
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
                        let _guard = lock.lock().await;
                        if let Err(e) = persist_blob(&state_dir, &vault, blob, version) {
                            tracing::warn!(vault = %vault, "cloud sync watch: persist failed: {}", e);
                        } else {
                            refresh_after_pull(&state, &vault);
                        }
                    }
                    // A freshly-pulled blob may carry a passkey-sealed
                    // `<conn>_oauth_pending` from a browser "Connect" — complete
                    // the OAuth code→token exchange and persist the refresh_token
                    // (CONNECTIONS_AND_AUTH.md §4a). Best-effort; acquires the
                    // per-vault write lock itself, so it runs AFTER the guard
                    // above drops (the lock is not reentrant).
                    crate::auth::connect::process_vault_connects(&state, &vault).await;
                    // PER-ITEM: a keyset/blob change often coincides with content
                    // changes; pull the KEYSET (`/keys`) FIRST so the item fold
                    // sees a fresh K-wrap layer, then pull item rows and refresh
                    // the cache from the folded item view. Best-effort.
                    match pull_keys(&state_dir, &cloud, &vault, &dk).await {
                        Ok(n) if n > 0 => tracing::info!(vault = %vault, adopted = n, "cloud sync watch: pulled keyset rows"),
                        Ok(_) => {}
                        Err(e) => tracing::debug!(vault = %vault, "cloud sync watch: keyset pull failed: {}", e),
                    }
                    match pull_items(&state_dir, &cloud, &vault, &dk).await {
                        Ok(n) if n > 0 => refresh_after_item_pull(&state, &vault),
                        Ok(_) => {}
                        Err(e) => tracing::debug!(vault = %vault, "cloud sync watch: per-item pull failed: {}", e),
                    }
                    tracing::debug!(vault = %vault, "cloud sync watch: poll processed (blob + per-item)");
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

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM KEYSET SYNC  (the passkey-wrap layer now rides `/keys`, §7)
//
// The keyset (registry pubkeys + per-cred `prf_salt`/`wrapped_key` = what GIVES
// you `K`) USED to ride the whole-blob `/blob` row. The frontend now writes it
// to `/keys` instead (ONE `vault_keys` row per credential, cid-keyed), so the
// daemon must sync it via `/keys` too, byte-compatible with the frontend:
//
//   GET /v/{vid}/keys?since=<seq> → { keys:[{cid,version,seq,data}], seq }
//   PUT /v/{vid}/keys/{cid}       { base_version?, version, data } → CAS
//                                 → 200 {version,seq} | 409 {currentVersion}
//
// `data = { x, y, device_name, x25519_pub?, prf_salt, wrapped_key }`. Encodings
// (verified against lib/vault-grant.ts + lib/safeclaw-crypto.ts):
//   - cid (row PK)              = base64url-nopad  (WebAuthn credential id)
//   - x / y                     = STANDARD base64  (kept verbatim as strings)
//   - prf_salt / wrapped_key    = STANDARD base64  (leniently decoded to bytes)
//   - x25519_pub                = base64url        (NOT stored — no sudp field)
//   - device_name               = plain string
// The daemon decodes data fields with the LENIENT `decode_keys_data_field`
// (mirrors the frontend's `fromBase64`: accept std OR url, padded or not) so the
// std-base64 fields never break unwrap of `K`.
//
// The keyset must be pulled BEFORE the items each sync cycle so the view is
// folded against a fresh `K`-wrap layer.
// ─────────────────────────────────────────────────────────────────────────

/// One row of a `/keys` pull. `data` is the cloud-VISIBLE keyset material (it is
/// what gives you `K`, so it can't be sealed under `K`).
#[derive(Debug, Clone, serde::Deserialize)]
struct KeyRow {
    cid: String,
    version: u64,
    #[allow(dead_code)]
    seq: u64,
    data: KeyRowData,
}

/// The `data` blob of a `/keys` row — mirrors the frontend `VaultKeyData`.
#[derive(Debug, Clone, serde::Deserialize)]
struct KeyRowData {
    x: String,
    y: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    x25519_pub: Option<String>,
    prf_salt: String,
    wrapped_key: String,
}

/// Pull keyset rows changed since the local `.keyset_seq` cursor and adopt them
/// into the keyset (registry + credentials), keyed by cid. Server-authoritative
/// like `pull_items`: a row whose `version` is `<=` the version we already hold
/// for that cid is skipped (we track the highest adopted version per cid via the
/// pulled `version`, since the daemon keeps no on-disk per-cred version — the
/// cursor advance + a fresh full pull on `keyset_seq=0` keep us convergent). The
/// cursor advances to the response max `seq`; the store is persisted.
///
/// If no local `PerItemVault` exists yet, an EMPTY one is created first (a
/// device that pulls keys before its first enroll/seed still lands a keyset).
///
/// Best-effort: a 404 (endpoint not live yet) is a no-op. Returns the number of
/// rows adopted.
pub async fn pull_keys(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<usize, String> {
    // Create an empty per-item store on demand so a device that pulls keys
    // before it has ever seeded items still ends up with a keyset on disk.
    let mut pv = read_per_item_store(state_dir, vault).unwrap_or_else(empty_keyset_store);

    let url = format!(
        "{}/v/{}/keys?since={}",
        cloud.trim_end_matches('/'),
        vault,
        pv.keyset_seq
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
        404 => return Ok(0), // /keys not live yet — no-op
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("keys GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse keys response: {}", e))?;
    let rows: Vec<KeyRow> = body
        .get("keys")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse keys array: {}", e))?
        .unwrap_or_default();
    let max_seq = body.get("seq").and_then(|v| v.as_u64()).unwrap_or(pv.keyset_seq);
    let adopted = adopt_key_rows(&mut pv, &rows)?;
    if max_seq > pv.keyset_seq {
        pv.keyset_seq = max_seq;
    }
    // Persist even a zero-adopt pull so the advanced cursor sticks.
    write_per_item_store(state_dir, vault, &pv)?;
    Ok(adopted)
}

/// A fresh, EMPTY per-item store with an empty keyset — the on-demand target for
/// `pull_keys` on a device that has no `vault.per-item.json` yet. It has NO
/// credentials and NO items; `pull_keys` fills the keyset from the cloud rows.
fn empty_keyset_store() -> PerItemVault {
    use sudp::state::{Registry, CURRENT_VERSION};
    PerItemVault {
        keyset: pv_store::Keyset {
            version: CURRENT_VERSION,
            registry: Registry::new(),
            credentials: Vec::new(),
            keyset_version: 0,
        },
        items: std::collections::BTreeMap::new(),
        items_seq: 0,
        keyset_seq: 0,
    }
}

/// Adopt a batch of pulled `/keys` rows into the keyset. A row whose `version`
/// is `<=` the highest we've already adopted for that cid IN THIS BATCH is
/// skipped (guards a stale replay within one response); across pulls, the
/// `keyset_seq` cursor gates re-delivery. Each adopted row upserts the registry
/// pubkey + the `SealedCredential`. Returns the count adopted.
fn adopt_key_rows(pv: &mut PerItemVault, rows: &[KeyRow]) -> Result<usize, String> {
    // Track the max version seen per cid in this batch so an out-of-order pair
    // (same cid, v3 then v2) adopts only the newer.
    let mut seen: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    let mut adopted = 0usize;
    // Sort by version so a lower version can't overwrite a higher one when both
    // appear in the same page (the cloud SHOULD send at most one row per cid,
    // but defend in depth).
    let mut ordered: Vec<&KeyRow> = rows.iter().collect();
    ordered.sort_by_key(|r| r.version);
    for row in ordered {
        if let Some(&v) = seen.get(row.cid.as_str()) {
            if row.version <= v {
                continue;
            }
        }
        pv.upsert_key_row(
            &row.cid,
            &row.data.x,
            &row.data.y,
            &row.data.device_name,
            &row.data.prf_salt,
            &row.data.wrapped_key,
        )
        .map_err(|e| format!("adopt key row {}: {}", row.cid, e))?;
        seen.insert(row.cid.as_str(), row.version);
        adopted += 1;
    }
    Ok(adopted)
}

/// Push the daemon's keyset credentials ahead of the cloud after a daemon-side
/// mutation of the acting credential (a Write rotates its `prf_salt`/`wrapped_key`
/// via `replace_after_write`; a connect re-seals through the same `K`). Mirrors
/// `push_items_best_effort`'s 409/adopt handling — NEVER clobber: on a 409 we
/// adopt the cloud's rows (via `pull_keys`) and stop rather than force-overwrite.
///
/// The daemon keeps no on-disk per-cred version, so we CAS with `base_version` =
/// the row's current cloud version derived from `keyset_seq`-tracked pulls. In
/// practice we PUT as an UPDATE (`base_version = <last pulled>`), falling back to
/// a CREATE (base_version omitted) only when the row is unknown cloud-side. Since
/// we can't cheaply know the cloud version per cid without a pull, we first
/// `pull_keys` to refresh, read the freshest local keyset, and PUT each credential
/// at `version = pulled+1` with `base_version = pulled` — a 409 means someone
/// else moved it, so we re-pull and stop (best-effort; local keyset is durable).
pub async fn push_keys_best_effort(state: &Arc<AppState>, vault_id: &str) {
    let Ok(cfg) = active::load() else { return };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else { return };
    let cloud = cloud.trim_end_matches('/');
    let state_dir = &state.config.state_dir;

    // Refresh from the cloud first so our `base_version` is current (never
    // clobber a newer cloud keyset). Best-effort — a 404/offline just means we
    // push against version 0 (create) which the backend rejects with 409 if the
    // row exists, and we re-pull.
    let cloud_versions = match fetch_key_versions(cloud, vault_id, &dk).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(vault = %vault_id, "keyset push: version probe failed: {}", e);
            return;
        }
    };

    let Some(pv) = read_per_item_store(state_dir, vault_id) else {
        return;
    };

    // Snapshot the credentials (cid_b64, keyData) so we don't hold the store
    // across awaits. Build each row's `data` byte-compatible with the frontend.
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let mut rows: Vec<(String, serde_json::Value)> = Vec::new();
    for cred in &pv.keyset.credentials {
        let cid_b64 = URL_SAFE_NO_PAD.encode(&cred.credential_id);
        // Pull the registry pubkey for x/y/device_name; keep x/y verbatim (they
        // are already the strings the frontend wrote — std-base64).
        let pk = match pv.keyset.registry.get::<sudp::passkey::WebAuthn>(&cred.credential_id) {
            Ok(Some(pk)) => pk,
            _ => continue, // no registry entry — can't form a complete row
        };
        let data = serde_json::json!({
            "x": pk.x,
            "y": pk.y,
            "device_name": pk.device_name,
            // Encode wrap material as STANDARD base64 to match the frontend
            // (`toBase64`); its `fromBase64` accepts either, but match for
            // cleanliness. NEVER url here for these two.
            "prf_salt": STANDARD.encode(&cred.prf_salt),
            "wrapped_key": STANDARD.encode(&cred.wrapped_key),
        });
        rows.push((cid_b64, data));
    }

    for (cid_b64, data) in rows {
        let cloud_ver = cloud_versions.get(&cid_b64).copied();
        let (base_version, version) = match cloud_ver {
            Some(v) => (Some(v), v + 1),         // UPDATE: CAS against cloud's version
            None => (None, 1),                   // CREATE: omit base_version
        };
        match push_key(cloud, vault_id, &dk, &cid_b64, base_version, version, &data).await {
            Ok(PushOutcome::Ok { .. }) => {}
            Ok(PushOutcome::EndpointMissing) => return, // /keys not live — stop
            Ok(PushOutcome::Conflict { current_version }) => {
                // Someone moved this row cloud-side: adopt server truth (pull) and
                // stop — NEVER last-writer-wins on the keyset (it gives you K).
                tracing::info!(
                    vault = %vault_id, cid = %cid_b64, current_version,
                    "keyset push: 409 conflict; adopting cloud keyset row (no clobber)"
                );
                let _ = pull_keys(state_dir, cloud, vault_id, &dk).await;
                return;
            }
            Err(e) => {
                tracing::warn!(vault = %vault_id, cid = %cid_b64, "keyset push failed: {}", e);
                return;
            }
        }
    }
    tracing::debug!(vault = %vault_id, "keyset push: all local credentials pushed");
}

/// Probe the cloud for the current `{cid → version}` of every keyset row, so
/// `push_keys_best_effort` can CAS with the right `base_version`. Returns an
/// empty map on a 404 (endpoint not live) so a first push becomes a CREATE.
async fn fetch_key_versions(
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<std::collections::HashMap<String, u64>, String> {
    let url = format!("{}/v/{}/keys?since=0", cloud.trim_end_matches('/'), vault);
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
        404 => return Ok(std::collections::HashMap::new()),
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("keys GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse keys response: {}", e))?;
    let rows: Vec<KeyRow> = body
        .get("keys")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse keys array: {}", e))?
        .unwrap_or_default();
    Ok(rows.into_iter().map(|r| (r.cid, r.version)).collect())
}

/// PUT one keyset row with CAS (§7). Mirrors `push_item`: a CREATE omits
/// `base_version` (sending 0 → 409); an UPDATE includes it. On `200` returns the
/// cloud-stamped `{version, seq}`; `409` → `Conflict{current_version}`; a `404`
/// (endpoint not live) → `EndpointMissing`.
async fn push_key(
    cloud: &str,
    vault: &str,
    device_key: &str,
    cid: &str,
    base_version: Option<u64>,
    version: u64,
    data: &serde_json::Value,
) -> Result<PushOutcome, String> {
    let url = format!("{}/v/{}/keys/{}", cloud.trim_end_matches('/'), vault, cid);
    let mut body = serde_json::json!({ "version": version, "data": data });
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
        other => Err(format!("key PUT HTTP {}", other)),
    }
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

    /// A `/keys` row `data` JSON shaped EXACTLY as the frontend writes it
    /// (`lib/vault-grant.ts` addPasskey / setupEnvVault via `toBase64`): x/y/
    /// prf_salt/wrapped_key are STANDARD base64 (with `+`/`/`/`=`), x25519_pub is
    /// base64url, cid is base64url-nopad. Adopting it must upsert the keyset with
    /// the correctly-DECODED prf_salt/wrapped_key + a registry pubkey entry —
    /// proving the LENIENT decoder handles the frontend's mixed encodings so the
    /// daemon can still unwrap K.
    #[test]
    fn keys_row_roundtrips_frontend_std_base64_data() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        use sudp::passkey::WebAuthn;

        // Raw bytes the frontend would have encoded.
        let cred_id_raw: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        let prf_salt_raw: Vec<u8> = (0u8..32).collect();
        // Pick wrap bytes whose STANDARD base64 contains `+` AND `/` (so a strict
        // base64url decoder would REJECT them → the exact break this guards).
        let wrapped_key_raw: Vec<u8> = vec![
            0xFB, 0xFF, 0xBF, 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B,
            0x30, 0xD3, 0x8F, 0x41, 0x14, 0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9B,
        ];
        let x_raw: Vec<u8> = vec![0xAAu8; 32];
        let y_raw: Vec<u8> = vec![0xBBu8; 32];
        let x25519_raw: Vec<u8> = vec![0xCCu8; 32];

        // cid = base64url-nopad; data fields = STANDARD base64 (x/y/prf_salt/
        // wrapped_key), x25519_pub = base64url (matches the frontend exactly).
        let cid_b64 = URL_SAFE_NO_PAD.encode(&cred_id_raw);
        let x_std = STANDARD.encode(&x_raw);
        let wrapped_std = STANDARD.encode(&wrapped_key_raw);
        assert!(
            wrapped_std.contains('+') || wrapped_std.contains('/'),
            "test fixture must exercise std-base64-only chars"
        );
        let data = serde_json::json!({
            "x": x_std,
            "y": STANDARD.encode(&y_raw),
            "device_name": "Mac · sunny-panda",
            "x25519_pub": URL_SAFE_NO_PAD.encode(&x25519_raw),
            "prf_salt": STANDARD.encode(&prf_salt_raw),
            "wrapped_key": wrapped_std,
        });
        let row_json = serde_json::json!({
            "cid": cid_b64,
            "version": 1u64,
            "seq": 7u64,
            "data": data,
        });
        let row: KeyRow = serde_json::from_value(row_json).unwrap();

        // Adopt into a fresh empty keyset store (the on-demand pull_keys target).
        let mut pv = empty_keyset_store();
        let n = adopt_key_rows(&mut pv, std::slice::from_ref(&row)).unwrap();
        assert_eq!(n, 1);

        // 1. The SealedCredential has the correctly-DECODED prf_salt + wrapped_key.
        let cred = pv
            .keyset
            .credentials
            .iter()
            .find(|c| c.credential_id == cred_id_raw)
            .expect("credential adopted");
        assert_eq!(cred.prf_salt, prf_salt_raw, "prf_salt lenient-decoded");
        assert_eq!(cred.wrapped_key, wrapped_key_raw, "wrapped_key lenient-decoded");

        // 2. The registry has the pubkey entry (x/y kept verbatim as the frontend
        //    strings; sudp stores WebAuthnPublicKey.x/y as-is).
        let pk = pv
            .keyset
            .registry
            .get::<WebAuthn>(&cred_id_raw)
            .unwrap()
            .expect("registry pubkey adopted");
        assert_eq!(pk.x, x_std, "x kept verbatim (std-base64 string)");
        assert_eq!(pk.device_name, "Mac · sunny-panda");

        // 3. Idempotent re-adopt of the SAME row (version 1) doesn't duplicate
        //    the credential.
        let _ = adopt_key_rows(&mut pv, std::slice::from_ref(&row)).unwrap();
        assert_eq!(
            pv.keyset.credentials.iter().filter(|c| c.credential_id == cred_id_raw).count(),
            1,
            "no duplicate credential on re-adopt"
        );

        // 4. Serialize the store and confirm the SealedCredential round-trips
        //    through sudp's STANDARD `wire::b64bytes` codec (byte-stable on disk).
        let bytes = serde_json::to_vec(&pv).unwrap();
        let back: PerItemVault = serde_json::from_slice(&bytes).unwrap();
        let back_cred = back
            .keyset
            .credentials
            .iter()
            .find(|c| c.credential_id == cred_id_raw)
            .unwrap();
        assert_eq!(back_cred.wrapped_key, wrapped_key_raw);
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

    /// PER-ITEM: a per-item vault's `/blob` GET now returns a keyset-lifecycle
    /// marker with NO `blob` field (`{ lifecycle:"per-item-v3", version }`). The
    /// classifier must treat it as `Unchanged` (the keyset rides `/keys` now) and
    /// write NOTHING to `vault.dat` — NOT error, NOT persist.
    #[test]
    fn lifecycle_only_body_classifies_as_unchanged_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let body = serde_json::json!({ "lifecycle": "per-item-v3", "version": 1u64 });
        assert_eq!(
            classify_pull_body(dir.path(), "v-life", &body).unwrap(),
            PullOutcome::Unchanged
        );
        // No vault.dat written — a lifecycle marker is not content.
        assert!(!dir.path().join("vaults").join("v-life").join("vault.dat").exists());
        assert!(!version_sidecar(dir.path(), "v-life").exists());
        // Even a bare `{}` (no blob, no status, no unchanged) is Unchanged, not
        // an error (the old code returned Err "blob missing").
        assert_eq!(
            classify_pull_body(dir.path(), "v-empty", &serde_json::json!({})).unwrap(),
            PullOutcome::Unchanged
        );
        // THE REAL WIRE SHAPE: `putBlob` wraps the marker, and handleBlobGet
        // returns `{ blob: { lifecycle, version }, version, status:"live" }`. The
        // marker sits UNDER `blob`, so this must be Unchanged (not parsed as a
        // SealedState). This is the shape `sc sync` actually receives — the case
        // the top-level-`lifecycle` body above never exercised.
        let wrapped = serde_json::json!({
            "blob": { "lifecycle": "per-item-v3", "version": 1u64 },
            "version": 1u64,
            "status": "live"
        });
        assert_eq!(
            classify_pull_body(dir.path(), "v-wrap", &wrapped).unwrap(),
            PullOutcome::Unchanged
        );
        assert!(!dir.path().join("vaults").join("v-wrap").join("vault.dat").exists());
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
