//! OAuth CONNECT completion on the daemon (CONNECTION_SCHEMA.md §5).
//!
//! The browser drives Google consent with the **public Desktop client + PKCE**
//! and seals `{ service, config, code, verifier }` into `aux.connecting[<id>]`
//! (CONNECTION_SCHEMA.md §2). To stay **cloud-blind**, the code is relayed to the
//! daemon *through the sealed vault* (the cloud only ever stores ciphertext) —
//! never through the backend. This module is the daemon side of that handshake:
//!
//! 1. with the vault **open** (retained `K` from an unlocked session), read every
//!    in-flight connect from `aux.connecting`;
//! 2. for each, resolve the connection's *service* → its provider
//!    (client_id / secret / token_url + the fixed redirect_uri, all from the
//!    public Desktop literal) and exchange the code at `token_url`;
//! 3. WRITE the durable refresh_token at the §3 address `[<conn>:]<ROLE>` and
//!    **MOVE** the entry from `aux.connecting` into `aux.connections`; re-seal the
//!    body under the same `K` and persist `vault.dat`.
//!
//! **No approval op.** This is the completion of a *user-initiated*,
//! passkey-sealed, Google-authenticated connect; the daemon holds `K` while
//! unlocked and re-seals directly. Approval-ops gate *agent* requests, not the
//! daemon's own connect-completion. An agent cannot forge a Google login plus a
//! passkey-sealed code.
//!
//! **Multi-connection.** `connection_id` is independent of `service_id`: each
//! `connecting`/`connections` entry names its `service` explicitly, so two Gmail
//! accounts (`gmail`, `gmail-work`) connect side-by-side. The refresh_token
//! address is bare for the default (`conn == service`) and `<conn>:<ROLE>` for a
//! named one (see [`secret_address`]).
//!
//! **Best-effort, never fatal.** Anything that goes wrong logs and is skipped; a
//! malformed/unresolvable pending or an exchange failure (e.g. an expired code)
//! leaves the `connecting` entry in place so the user can retry within the code
//! TTL (~10 min). It never panics the daemon and never blocks serving.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};
use sudp::state::ProtectedState;

use crate::auth::oauth2::{ExchangedTokens, OAuthStyle};
use crate::state::AppState;
use crate::storage::plaintext::{secret_address, Connecting, Connection};

/// The OAuth client/endpoint a pending connect resolves to before exchange, plus
/// the service's secret role (so we know where to write the result).
#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub style: OAuthStyle,
    /// The OAuth client's fixed redirect_uri (provider config), echoed at the
    /// token call so it matches the browser's consent request.
    pub redirect_uri: String,
    /// The service's mainstream secret role, e.g. `GMAIL_REFRESH_TOKEN` — the base
    /// name the refresh_token is written under (namespaced per `conn`).
    pub secret_role: String,
}

/// Resolve the exchange config for a connection's **service** from the
/// registry. `None` when the service is unknown, isn't oauth2, or is missing a
/// token_url / client_id / secret role (e.g. a provider literal we can't load).
pub fn resolve_exchange_config(
    services: &crate::service::ServiceRegistry,
    service: &str,
) -> Option<ExchangeConfig> {
    let svc = services.get(service)?;
    let oauth = svc.oauth2.as_ref()?;
    let resolved = services.resolve_oauth_config(oauth);
    let token_url = resolved.token_url?;
    let client_id = resolved.client_id?;
    let secret_role = oauth.refresh_token.clone();
    let style = services.provider_oauth_style(&oauth.provider);
    Some(ExchangeConfig {
        token_url,
        client_id,
        client_secret: resolved.client_secret,
        style,
        redirect_uri: resolved.redirect_uri,
        secret_role,
    })
}

/// Read a `connection_id → T` map out of `m.aux[<key>]`. Empty when the key is
/// absent or doesn't parse (forward-compat: a newer schema we can't read yields
/// no entries — never an error).
fn aux_map<T: DeserializeOwned>(m: &ProtectedState, key: &str) -> BTreeMap<String, T> {
    m.aux
        .get(key)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Write a `connection_id → T` map back into `m.aux[<key>]`, dropping the key
/// entirely when the map is empty (matching the `skip_serializing_if` shape the
/// rest of the aux schema round-trips with). Leaves all other aux fields intact.
fn set_aux_map<T: Serialize>(m: &mut ProtectedState, key: &str, map: BTreeMap<String, T>) {
    if !m.aux.is_object() {
        // A v3 vault's aux is always an object; tolerate a malformed one by
        // starting fresh rather than panicking.
        m.aux = serde_json::json!({});
    }
    let obj = m.aux.as_object_mut().expect("aux normalized to object");
    if map.is_empty() {
        obj.remove(key);
    } else if let Ok(v) = serde_json::to_value(&map) {
        obj.insert(key.to_string(), v);
    }
}

/// Apply one successful exchange to the open `ProtectedState`: write the durable
/// refresh_token at the §3 address (`secret_address(conn, service, role)`,
/// overwriting any prior one — a re-connect supersedes) and **MOVE** the entry
/// from `aux.connecting` into `aux.connections` (no partial/duplicate record).
/// `hosts` carries any exact FQDNs pinned at connect for a wildcard service.
/// Pure state transition (no I/O) so it's unit-testable against a mocked
/// `ProtectedState`.
pub fn apply_exchange_result(
    m: &mut ProtectedState,
    conn: &str,
    service: &str,
    hosts: Option<Vec<String>>,
    role: &str,
    tokens: &ExchangedTokens,
) {
    if let Some(rt) = &tokens.refresh_token {
        m.put_secret(secret_address(conn, service, role), rt.as_bytes().to_vec());
    }
    // MOVE: drop from `connecting`, add to `connections` (name carried over).
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    let name = connecting.remove(conn).and_then(|c| c.name);
    set_aux_map(m, "connecting", connecting);

    let mut connections = aux_map::<Connection>(m, "connections");
    connections.insert(
        conn.to_string(),
        // Service-backed: secrets derive from the service def, never stored here.
        Connection { name, service: Some(service.to_string()), hosts, secrets: None },
    );
    set_aux_map(m, "connections", connections);
}

/// Collect the in-flight connects worth exchanging from `aux.connecting`. Pure
/// (no network) for testability.
///
/// A connect that already carries a terminal `error` (its code was
/// `invalid_grant` — expired/used) is DONE, not pending: it stays in
/// `connecting` only so the console can render "reconnect". Re-exchanging it is
/// futile AND harmful — the re-mark re-pushes the entry, which the cloud-sync
/// watcher sees as a change and re-processes, forming a self-perpetuating retry
/// storm against the token endpoint. So skip error'd entries; only a fresh
/// connect (no `error`) or a transient failure (never stamped one) is retried.
fn collect_pending(m: &ProtectedState) -> Vec<(String, Connecting)> {
    aux_map::<Connecting>(m, "connecting")
        .into_iter()
        .filter(|(_, c)| c.oauth2.error.is_none())
        .collect()
}

/// Drive the connecting→refresh→move state machine over an open `ProtectedState`,
/// given an async `exchange` closure (injected so tests can avoid real network
/// calls). Mutates `m` in place; returns the number of connects that completed (a
/// refresh_token was written). On a per-connect failure it logs and **leaves the
/// `connecting` entry in place** (the user retries within the code TTL) — it never
/// aborts the whole batch.
///
/// Returns `(completed, failed)`: `completed` = connects that got a refresh_token
/// (MOVEd to `connections`); `failed` = connects whose code was TERMINALLY
/// rejected (`invalid_grant`) — those get an `error` stamped on their `connecting`
/// entry so the console can render "reconnect". Transient errors bump neither (the
/// next sync retries). The caller persists + pushes whenever either is non-zero.
///
/// `exchange(conn, cfg, connecting)` performs the code→token call and returns the
/// tokens (or an error string to log + skip).
pub async fn run_pending<F, Fut>(
    services: &crate::service::ServiceRegistry,
    m: &mut ProtectedState,
    mut exchange: F,
) -> (usize, usize)
where
    F: FnMut(String, ExchangeConfig, Connecting) -> Fut,
    Fut: std::future::Future<Output = Result<ExchangedTokens, String>>,
{
    let pending = collect_pending(m);
    let mut completed = 0usize;
    let mut failed = 0usize;
    for (conn, p) in pending {
        let Some(cfg) = resolve_exchange_config(services, &p.service) else {
            tracing::warn!(
                conn = %conn,
                service = %p.service,
                "oauth connect: no oauth2 exchange config for the connection's service \
                 (unknown/non-oauth2 service or missing provider creds); leaving connecting"
            );
            continue;
        };
        // Capture what the post-exchange MOVE needs before `p` is consumed.
        let service = p.service.clone();
        let hosts = p.hosts.clone();
        let role = cfg.secret_role.clone();
        match exchange(conn.clone(), cfg, p).await {
            Ok(tokens) => {
                if tokens.refresh_token.is_none() {
                    // No durable credential came back (consent without offline
                    // access). Leave connecting so the user can redo consent.
                    tracing::warn!(
                        conn = %conn,
                        "oauth connect: exchange returned no refresh_token; leaving connecting"
                    );
                    continue;
                }
                apply_exchange_result(m, &conn, &service, hosts, &role, &tokens);
                completed += 1;
                tracing::info!(
                    conn = %conn,
                    "oauth connect: refresh_token persisted; moved to connections"
                );
            }
            Err(e) => {
                if e.contains("invalid_grant") {
                    // Terminal: the code expired or was already used. Stamp the
                    // connecting entry so the console shows "failed — reconnect"
                    // instead of a perpetual "connecting". Only a fresh consent
                    // (new code) recovers — it overwrites this entry (clearing
                    // the error).
                    mark_connecting_failed(m, &conn, "authorization expired or already used");
                    failed += 1;
                    tracing::warn!(conn = %conn, "oauth connect: invalid_grant (code expired/used) — marked failed");
                } else {
                    // Transient (network / provider 5xx) — leave connecting + retry
                    // on the next sync.
                    tracing::warn!(conn = %conn, "oauth connect: exchange failed (transient), will retry: {}", e);
                }
            }
        }
    }
    (completed, failed)
}

/// Stamp a terminal `error` on one `connecting` entry (leaving code/code_verifier
/// so the console still knows which connection it is). No-op if the entry is gone.
fn mark_connecting_failed(m: &mut ProtectedState, conn: &str, reason: &str) {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    if let Some(entry) = connecting.get_mut(conn) {
        entry.oauth2.error = Some(reason.to_string());
    }
    set_aux_map(m, "connecting", connecting);
}

/// Process all in-flight connects (`aux.connecting`) for one vault: open the body
/// with the retained `K`, exchange each pending code, write the refresh_tokens,
/// MOVE each entry to `aux.connections`, re-seal under the same `K`, and persist
/// `vault.dat`.
///
/// Best-effort end-to-end:
/// - Locked vault (no retained `K`) → skip (the next unlock re-runs this).
/// - No pending connects → no-op (no disk write).
/// - A retained `K` that can't open the body (rotated `K`) → log + skip.
/// - Per-connect failures are handled by [`run_pending`] (leave + retry).
///
/// Holds the per-vault write lock for the open→mutate→re-seal→write cycle so it
/// serializes against approve.rs's writes and the cloud-sync pull (same lock).
/// Never panics; any error logs and returns.
pub async fn process_vault_connects(state: &Arc<AppState>, vault_id: &str) {
    // Apply any pending connects (open → exchange → re-seal → persist). On a
    // completion, fan the re-sealed blob out to OTHER devices via the cloud.
    if apply_pending_connects(state, vault_id).await {
        // A fresh connect landed → clear any stale needs-reauth flag for this
        // vault (a still-dead token re-marks on the next /use).
        state.oauth_clear_reauth_vault(vault_id);
        // Propagate to OTHER devices: push the re-sealed blob back to the cloud.
        // A Google authorization code is single-use, so only THIS daemon could
        // redeem the pending connect — every other device's daemon must PULL the
        // resulting refresh_token rather than re-exchange (which fails
        // `invalid_grant`). Cloud-blind preserved: the pushed blob is ciphertext.
        // Detached + best-effort, after the write lock drops (push only reads
        // vault.dat + HTTP).
        let state = state.clone();
        let vid = vault_id.to_string();
        tokio::spawn(async move {
            // Keyset lifecycle rides the whole-blob push (the `/blob` marker) AND
            // the per-cred wrap material rides `/keys`; content (the new
            // refresh-token secret + connection MOVE) rides the per-item push.
            crate::sync::push_blob_best_effort(&state, &vid).await;
            crate::sync::push_keys_best_effort(&state, &vid).await;
            crate::sync::push_items_best_effort(&state, &vid).await;
        });
    }
}

/// Apply pending connects WITHOUT the cloud push-back. Returns `true` iff at
/// least one connect completed (and thus `vault.dat` was re-sealed). The push
/// fan-out lives in the public `process_vault_connects` wrapper, NOT here — that
/// split is load-bearing: the cloud-sync CAS-conflict recovery
/// (`sync::recover_after_conflict`) calls this inner fn to re-apply its mutation
/// on a freshly-pulled blob; routing it through the push-spawning wrapper would
/// form an async-recursion cycle (push → recover → process → push) the compiler
/// can't prove `Send`. Keeping the push out of the recursive edge breaks it.
pub(crate) async fn apply_pending_connects(state: &Arc<AppState>, vault_id: &str) -> bool {
    let Some(k) = state.cloned_state_key(vault_id) else {
        return false; // Locked — no retained K; next unlock retries.
    };

    let lock = {
        let mut locks = state.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _guard = lock.lock().await;

    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat");
    // Open the vault body from whichever store backs it. A daemon-side
    // Enroll/Write vault has a whole-blob vault.dat; a WEB-enrolled vault has
    // ONLY the per-item store (vault.per-item.json) — for that we fold the item
    // rows into a view and rebuild the ProtectedState M the connect machine runs
    // on (inverse of VaultPlaintextView::from_protected_state).
    let vault_dat = match crate::storage::sealed_vault::read(&vault_path) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: read vault.dat failed: {}", e);
            None
        }
    };
    let mut m = if let Some(vault) = &vault_dat {
        match crate::server::handlers::metadata::open_protected_state_with_key(&k, vault) {
            Ok(m) => m,
            Err(_) => return false, // rotated K — lock+unlock retries
        }
    } else {
        let Ok(pi_path) = state.vaults.per_item_path(vault_id) else {
            return false;
        };
        let Ok(Some(pv)) = crate::storage::sealed_vault::read_per_item(&pi_path) else {
            return false; // neither vault.dat nor a per-item store — nothing to do
        };
        let view = match crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(
            &k, &pv, vault_id,
        ) {
            Ok(v) => v,
            Err(_) => return false, // rotated K
        };
        match build_m_from_view(&view) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(vault = %vault_id, "oauth connect: rebuild M from per-item failed: {}", e);
                return false;
            }
        }
    };

    // Cheap pre-check: nothing to do if there are no in-flight connects.
    if collect_pending(&m).is_empty() {
        return false;
    }

    let services = &state.services;
    let (completed, failed) = run_pending(services, &mut m, |_conn, cfg, p| async move {
        crate::auth::oauth2::exchange_code(
            &cfg.token_url,
            &cfg.client_id,
            cfg.client_secret.as_deref(),
            &p.oauth2.code,
            &p.oauth2.code_verifier,
            &cfg.redirect_uri,
            cfg.style,
        )
        .await
    })
    .await;

    if completed == 0 && failed == 0 {
        // Nothing changed (all left pending / transient) — don't rewrite or push.
        return false;
    }
    // A terminal failure (invalid_grant) with no completion still MUTATED the
    // state (stamped `error` on the connecting entry) — fall through so it's
    // persisted + pushed, surfacing "reconnect" in the console.

    // Post-connect view: the new refresh_token secret + connecting→connections
    // MOVE, folded from the mutated M.
    let view = match crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: view rebuild failed: {}", e);
            return false;
        }
    };

    // Persist. If a whole-blob vault.dat backs this vault, re-seal + write it so
    // the legacy path stays authoritative. EITHER way, write the change to the
    // per-item store (the content that syncs via /items) — for a web-enrolled
    // per-item vault this is the ONLY durable write. Per-item upserts are
    // version-bumped for CAS, so a concurrent browser edit to a DIFFERENT item
    // never collides (contract §4).
    if let Some(mut vault) = vault_dat {
        if let Err(e) =
            crate::server::handlers::metadata::reseal_body_with_key(&k, &mut vault, &m)
        {
            tracing::warn!(vault = %vault_id, "oauth connect: re-seal failed: {}", e);
            return false;
        }
        if let Err(e) = crate::storage::sealed_vault::write_atomic(&vault_path, &vault) {
            tracing::warn!(vault = %vault_id, "oauth connect: write vault.dat failed: {}", e);
            return false;
        }
        reconcile_per_item_after_connect(state, vault_id, Some(&vault), &view, &k);
    } else {
        reconcile_per_item_after_connect(state, vault_id, None, &view, &k);
    }
    tracing::info!(vault = %vault_id, connects = completed, failed, "oauth connect: processed");

    // Refresh the in-memory cache so /use sees the new refresh_token without a
    // manual lock/unlock. Best-effort.
    let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
    state.unlock_vault(vault_id.to_string(), cache, k);

    true
}

/// Rebuild a [`ProtectedState`] `M` from a folded per-item view — the inverse of
/// [`VaultPlaintextView::from_protected_state`]. Lets the connect state machine
/// (which reads/writes `M`'s aux + secrets) run against a web-enrolled per-item
/// vault that has no whole-blob `vault.dat`.
fn build_m_from_view(
    view: &crate::storage::plaintext::VaultPlaintextView,
) -> Result<ProtectedState, String> {
    let mut m = ProtectedState::new();
    m.aux = serde_json::to_value(&view.aux)
        .map_err(|e| format!("aux to json: {}", e))?;
    for (name, bytes) in &view.native_secrets {
        m.put_secret(name.clone(), bytes.clone());
    }
    Ok(m)
}

/// Apply the post-connect state (new refresh-token secret + connecting→
/// connections MOVE) to the local per-item store as version-bumped item
/// upserts/tombstones, then persist it. Best-effort; logs and returns on any
/// error (the whole-blob vault.dat already holds the durable state).
fn reconcile_per_item_after_connect(
    state: &Arc<AppState>,
    vault_id: &str,
    vault: Option<&crate::storage::SealedVault>,
    view: &crate::storage::plaintext::VaultPlaintextView,
    k: &[u8],
) {
    use crate::storage::sealed_vault::{Keyset, PerItemVault};
    let Ok(path) = state.vaults.per_item_path(vault_id) else {
        return;
    };
    // Reuse the existing per-item store if present (so versions/cursors are
    // preserved); otherwise bootstrap one from the whole-blob keyset. A
    // web-enrolled per-item vault ALWAYS has a store, so `vault` is `None` there
    // and the bootstrap branch is only reached on the vault.dat path.
    let mut pv = match crate::storage::sealed_vault::read_per_item(&path) {
        Ok(Some(pv)) => pv,
        _ => {
            let Some(vault) = vault else { return };
            PerItemVault {
                keyset: Keyset {
                    version: vault.version,
                    registry: vault.registry.clone(),
                    credentials: vault.credentials.clone(),
                    keyset_version: 0,
                },
                items: std::collections::BTreeMap::new(),
                items_seq: 0,
                keyset_seq: 0,
            }
        }
    };
    match pv.reconcile_from_view::<sudp::primitives::StdPrimitives>(k, vault_id, view) {
        Ok(changed) => {
            if changed.is_empty() {
                return;
            }
            if let Err(e) =
                crate::storage::sealed_vault::write_per_item_atomic(&path, &pv)
            {
                tracing::warn!(vault = %vault_id, "per-item connect reconcile write failed: {}", e);
                return;
            }
            tracing::info!(
                vault = %vault_id,
                changed = changed.len(),
                "per-item store updated after connect (refresh-token + connection MOVE)"
            );
        }
        Err(e) => {
            tracing::warn!(vault = %vault_id, "per-item connect reconcile failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ProtectedState` whose `aux.connecting` carries one in-flight connect.
    /// The rest of the aux is a minimal valid v3 shell (only `connecting` matters
    /// to these functions).
    fn with_connecting(conn: &str, service: &str, code: &str) -> ProtectedState {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({
            "version": 3,
            "stores": {},
            "store_order": [],
            "connecting": {
                conn: { "service": service, "oauth2": { "code": code, "code_verifier": "verif-xyz" } }
            }
        });
        m
    }

    fn tokens(rt: Option<&str>) -> ExchangedTokens {
        ExchangedTokens {
            refresh_token: rt.map(|s| s.to_string()),
            access_token: "at-123".to_string(),
            expires_at: 9_999_999_999,
        }
    }

    /// The compiled-in defaults include the gmail service + the google provider
    /// literal, so resolve_exchange_config finds a real config.
    fn gmail_registry() -> crate::service::ServiceRegistry {
        crate::service::ServiceRegistry::load()
    }


    #[test]
    fn collect_pending_reads_aux_connecting() {
        let m = with_connecting("gmail", "gmail", "code-AUX");
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "gmail");
        assert_eq!(got[0].1.service, "gmail");
        assert_eq!(got[0].1.oauth2.code, "code-AUX");
    }

    #[test]
    fn collect_pending_empty_when_none() {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({ "version": 3, "stores": {}, "store_order": [] });
        assert!(collect_pending(&m).is_empty());
    }

    #[test]
    fn collect_pending_skips_terminally_failed() {
        // A connect whose code was invalid_grant carries a terminal `error`.
        // It must NOT be re-collected (else we re-exchange a dead code every
        // sync tick + re-push it, forming a retry storm). It stays in the aux so
        // the console can show "reconnect" — just isn't retried.
        let mut m = with_connecting("gmail", "gmail", "code-DEAD");
        m.aux["connecting"]["gmail"]["oauth2"]["error"] =
            serde_json::json!("authorization expired or already used");
        assert!(
            collect_pending(&m).is_empty(),
            "an error-stamped connect must not be treated as pending"
        );
    }

    #[test]
    fn apply_exchange_default_writes_bare_and_moves() {
        // Default connection: conn == service → bare refresh_token name.
        let mut m = with_connecting("gmail", "gmail", "code-AUX");
        apply_exchange_result(
            &mut m,
            "gmail",
            "gmail",
            None,
            "GMAIL_REFRESH_TOKEN",
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
        assert!(
            aux_map::<Connecting>(&m, "connecting").is_empty(),
            "connecting entry must be dropped after exchange"
        );
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(conns.get("gmail").and_then(|c| c.service.as_deref()), Some("gmail"));
    }

    #[test]
    fn apply_exchange_named_writes_prefixed_address() {
        // Named connection: conn != service → `<conn>:<ROLE>` address.
        let mut m = with_connecting("gmail-work", "gmail", "code-AUX");
        apply_exchange_result(
            &mut m,
            "gmail-work",
            "gmail",
            None,
            "GMAIL_REFRESH_TOKEN",
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("gmail-work:GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
        assert!(m.secrets.get("GMAIL_REFRESH_TOKEN").is_none(), "named conn must not write the bare name");
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(conns.get("gmail-work").and_then(|c| c.service.as_deref()), Some("gmail"));
    }

    #[test]
    fn apply_exchange_carries_pinned_hosts_into_connection() {
        let mut m = with_connecting("acme-forge", "acme", "code-AUX");
        apply_exchange_result(
            &mut m,
            "acme-forge",
            "acme",
            Some(vec!["tenant.acme.dev".to_string()]),
            "ACME_TOKEN",
            &tokens(Some("rt-NEW")),
        );
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns.get("acme-forge").and_then(|c| c.hosts.clone()),
            Some(vec!["tenant.acme.dev".to_string()]),
        );
    }

    #[test]
    fn apply_exchange_overwrites_existing_refresh_token() {
        let mut m = with_connecting("gmail", "gmail", "code-A");
        m.put_secret("GMAIL_REFRESH_TOKEN", b"rt-OLD".to_vec());
        apply_exchange_result(
            &mut m,
            "gmail",
            "gmail",
            None,
            "GMAIL_REFRESH_TOKEN",
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
    }

    #[tokio::test]
    async fn run_pending_success_moves_and_writes() {
        let services = gmail_registry();
        let role = services.service_env_key("gmail").expect("gmail has a secret role");
        let mut m = with_connecting("gmail", "gmail", "code-AUX");

        let mut seen = None;
        let (n, _) = run_pending(&services, &mut m, |conn, cfg, p| {
            seen = Some((conn.clone(), cfg.token_url.clone(), cfg.redirect_uri.clone(), p.oauth2.code.clone()));
            async move { Ok(tokens(Some("rt-NEW"))) }
        })
        .await;

        assert_eq!(n, 1);
        assert!(aux_map::<Connecting>(&m, "connecting").is_empty(), "connecting cleared");
        assert_eq!(
            aux_map::<Connection>(&m, "connections").get("gmail").and_then(|c| c.service.clone()),
            Some("gmail".to_string()),
        );
        assert_eq!(m.secret(&role).unwrap(), b"rt-NEW");
        let (conn, token_url, redirect_uri, code) = seen.expect("exchange called");
        assert_eq!(conn, "gmail");
        assert_eq!(code, "code-AUX");
        assert!(
            token_url.starts_with("https://oauth2.googleapis.com/token"),
            "token_url must come from the google provider literal, got {token_url}"
        );
        assert!(
            redirect_uri.starts_with("http://127.0.0.1"),
            "redirect_uri must come from the provider/loopback default, got {redirect_uri}"
        );
    }

    #[tokio::test]
    async fn run_pending_failure_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-EXPIRED");

        let (n, _) = run_pending(&services, &mut m, |_conn, _cfg, _p| async move {
            Err("oauth2 code-exchange returned HTTP 400 — invalid_grant".to_string())
        })
        .await;

        assert_eq!(n, 0, "a failed exchange completes nothing");
        assert!(
            aux_map::<Connecting>(&m, "connecting").contains_key("gmail"),
            "connecting must survive a failed exchange (user retries within TTL)"
        );
        assert!(aux_map::<Connection>(&m, "connections").is_empty());
    }

    #[tokio::test]
    async fn run_pending_no_refresh_token_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-A");

        let (n, _) = run_pending(&services, &mut m, |_conn, _cfg, _p| async move {
            Ok(tokens(None)) // consent without offline access → no refresh_token
        })
        .await;

        assert_eq!(n, 0);
        assert!(
            aux_map::<Connecting>(&m, "connecting").contains_key("gmail"),
            "no durable token ⇒ leave connecting"
        );
    }

    #[tokio::test]
    async fn run_pending_unknown_service_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("whatever", "nosuchservice", "code-A");

        let mut called = false;
        let (n, _) = run_pending(&services, &mut m, |_conn, _cfg, _p| {
            called = true;
            async move { Ok(tokens(Some("rt"))) }
        })
        .await;

        assert_eq!(n, 0);
        assert!(!called, "exchange must not run when no config resolves");
        assert!(aux_map::<Connecting>(&m, "connecting").contains_key("whatever"));
    }

    #[test]
    fn resolve_exchange_config_for_gmail_uses_public_desktop_client() {
        let services = gmail_registry();
        let cfg = resolve_exchange_config(&services, "gmail")
            .expect("gmail resolves to an oauth2 exchange config");
        assert!(cfg.token_url.starts_with("https://oauth2.googleapis.com/token"));
        assert!(
            cfg.client_id.ends_with(".apps.googleusercontent.com"),
            "client_id must be the google provider literal"
        );
        // The public Desktop client ships a (non-confidential) secret.
        assert!(cfg.client_secret.is_some());
        assert!(matches!(cfg.style, OAuthStyle::Form));
        assert!(cfg.redirect_uri.starts_with("http://127.0.0.1"));
        assert!(!cfg.secret_role.is_empty(), "gmail service declares a secret role");
    }

    #[test]
    fn resolve_exchange_config_none_for_unknown() {
        let services = gmail_registry();
        assert!(resolve_exchange_config(&services, "nosuchservice").is_none());
    }
}
