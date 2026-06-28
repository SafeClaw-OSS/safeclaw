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
            Ok(Some(version)) => tracing::info!(vault = %vault, version, "cloud sync: pulled vault.dat from cloud"),
            Ok(None) => tracing::debug!(vault = %vault, "cloud sync: local vault.dat already current"),
            Err(e) => tracing::warn!(vault = %vault, "cloud sync pull failed (serving local state): {}", e),
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
        Some(_version) => {
            refresh_after_pull(state, vault_id);
            true
        }
        None => false,
    };
    // Complete a pending connect even when the blob was unchanged — the pending
    // item may have synced earlier (background watcher) but never been processed.
    crate::auth::connect::process_vault_connects(state, vault_id).await;
    Ok(pulled)
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

/// Returns `Ok(Some(version))` when a newer blob was written, `Ok(None)` when
/// local was already current (or the cloud has no blob yet).
async fn pull(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<Option<u64>, String> {
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
        404 => return Ok(None), // no blob in the cloud yet (not sealed on web)
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("cloud blob GET HTTP {}", other)),
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse blob response: {}", e))?;

    // `{ unchanged: true }` — the cheap freshness probe said local is current.
    if body
        .get("unchanged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let blob = body
        .get("blob")
        .ok_or_else(|| "blob missing in cloud response".to_string())?;

    persist_blob(state_dir, vault, blob, version)?;
    Ok(Some(version))
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
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let url = format!("{}/v/{}/blob", cloud.trim_end_matches('/'), vault_id);
    let resp = match client
        .put(&url)
        .bearer_auth(dk)
        .json(&serde_json::json!({ "blob": blob }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "push-back: PUT failed: {}", e);
            return;
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(vault = %vault_id, "push-back: cloud rejected (HTTP {})", resp.status());
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
}
