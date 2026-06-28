//! OAuth CONNECT completion on the daemon (CONNECTIONS_AND_AUTH.md §4a).
//!
//! The browser drives Google consent with the **public Desktop client + PKCE**
//! and seals `{code, verifier, redirect_uri}` into the vault as a transient
//! item `<connection_id>_oauth_pending`. To stay **cloud-blind**, the code is
//! relayed to the daemon *through the sealed vault* (the cloud only ever stores
//! ciphertext) — never through the backend. This module is the daemon side of
//! that handshake:
//!
//! 1. with the vault **open** (retained `K` from an unlocked session), read
//!    every pending handshake — the explicit `aux.connections[*].oauth_pending`
//!    records (the v3 form) plus, for backward-compat, any legacy flat
//!    `<conn>_oauth_pending` native-secret;
//! 2. for each, resolve the service's provider (client_id/secret/token_url
//!    from the public Desktop literal) and exchange the code at `token_url`;
//! 3. WRITE `<connection_id>_refresh_token` and CLEAR the pending from both
//!    places it could live (the `aux.connections` record and the legacy flat
//!    item); re-seal the body under the same `K` and persist `vault.dat`.
//!
//! **No approval op.** This is the completion of a *user-initiated*,
//! passkey-sealed, Google-authenticated connect; the daemon holds `K` while
//! unlocked and re-seals directly. Approval-ops gate *agent* requests, not the
//! daemon's own connect-completion. An agent cannot forge a Google login plus a
//! passkey-sealed code.
//!
//! **Default connection only.** `connection_id == service_id` here (the general
//! `connection_id` addressing / `:` namespacing is a separate slice), so
//! `gmail_oauth_pending` → service `gmail` → `gmail_refresh_token` (matching the
//! recipe's `secret`).
//!
//! **Best-effort, never fatal.** Anything that goes wrong logs and is skipped;
//! a malformed/unresolvable pending or an exchange failure (e.g. an expired
//! code) leaves the pending item in place so the user can retry within the code
//! TTL (~10 min). It never panics the daemon and never blocks serving.

use std::collections::BTreeMap;
use std::sync::Arc;

use sudp::state::ProtectedState;

use crate::auth::oauth2::{ExchangedTokens, OAuthStyle};
use crate::state::AppState;
use crate::storage::plaintext::{Connection, OAuthPending};

/// Suffix of the *legacy* flat `<conn>_oauth_pending` native-secret. Still
/// honored for backward-compat — vaults sealed before `aux.connections`, or a
/// frontend that hasn't migrated — but new connects use the explicit
/// `aux.connections[conn].oauth_pending` form (see [`collect_pending`]).
const PENDING_SUFFIX: &str = "_oauth_pending";
/// Suffix of the durable item the connect writes back.
const REFRESH_SUFFIX: &str = "_refresh_token";

/// The OAuth client/endpoint a pending connect resolves to before exchange.
/// (= the public Desktop client for Google, from the provider literal.)
#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub style: OAuthStyle,
}

/// Map a `<conn>_oauth_pending` item key to its connection id (== service id,
/// default connection). Returns `None` for keys that don't carry the suffix.
fn conn_from_pending_key(key: &str) -> Option<&str> {
    key.strip_suffix(PENDING_SUFFIX).filter(|c| !c.is_empty())
}

/// Resolve the exchange config for a connection (default: `conn == service_id`)
/// from the service registry. `None` when the service is unknown, isn't oauth2,
/// or is missing a token_url/client_id (e.g. a provider literal we can't load).
pub fn resolve_exchange_config(
    services: &crate::service::ServiceRegistry,
    conn: &str,
) -> Option<ExchangeConfig> {
    let svc = services.get(conn)?;
    let auth = svc.upstream.first().and_then(|u| u.auth.as_ref())?;
    if !services.auth_is_oauth2(auth) {
        return None;
    }
    let resolved = services.resolve_oauth_config(auth);
    let token_url = resolved.token_url?;
    let client_id = resolved.client_id?;
    let style = match auth.oauth_style.as_deref() {
        Some("json") => OAuthStyle::Json,
        _ => OAuthStyle::Form,
    };
    Some(ExchangeConfig {
        token_url,
        client_id,
        client_secret: resolved.client_secret,
        style,
    })
}

/// Read the `aux.connections` map from an open state. Empty when the key is
/// absent or the sub-value doesn't parse (forward-compat: a newer schema we
/// can't read just yields no pending here — never an error).
fn aux_connections(m: &ProtectedState) -> BTreeMap<String, Connection> {
    m.aux
        .get("connections")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Write `connections` back into `m.aux`, dropping the `connections` key
/// entirely when the map is empty (matching the `skip_serializing_if` shape
/// the rest of the aux schema round-trips with). Leaves all other aux fields
/// untouched.
fn set_aux_connections(m: &mut ProtectedState, conns: BTreeMap<String, Connection>) {
    if !m.aux.is_object() {
        // A v3 vault's aux is always an object; tolerate a malformed one by
        // starting fresh rather than panicking.
        m.aux = serde_json::json!({});
    }
    let obj = m.aux.as_object_mut().expect("aux normalized to object");
    if conns.is_empty() {
        obj.remove("connections");
    } else if let Ok(v) = serde_json::to_value(&conns) {
        obj.insert("connections".to_string(), v);
    }
}

/// Apply one successful exchange to the open `ProtectedState`: write the durable
/// `<conn>_refresh_token` (overwriting any prior one — a re-connect supersedes)
/// and CLEAR the consumed pending from BOTH places it can live: the
/// `aux.connections[conn]` record (dropped when it's left empty) and the legacy
/// flat `<conn>_oauth_pending` native-secret. Pure state transition (no I/O) so
/// it's unit-testable against a mocked `ProtectedState`.
pub fn apply_exchange_result(m: &mut ProtectedState, conn: &str, tokens: &ExchangedTokens) {
    if let Some(rt) = &tokens.refresh_token {
        m.put_target(format!("{}{}", conn, REFRESH_SUFFIX), rt.as_bytes().to_vec());
    }
    // Legacy flat pending (harmless no-op if it isn't there).
    m.remove_target(&format!("{}{}", conn, PENDING_SUFFIX));
    // Explicit aux pending: clear the field and drop the record if now empty.
    let mut conns = aux_connections(m);
    if conns.contains_key(conn) {
        if let Some(c) = conns.get_mut(conn) {
            c.oauth_pending = None;
        }
        if conns.get(conn).is_some_and(Connection::is_empty) {
            conns.remove(conn);
        }
        set_aux_connections(m, conns);
    }
}

/// Collect every pending OAuth-connect handshake in an open `ProtectedState`,
/// from BOTH sources: the explicit `aux.connections[*].oauth_pending` (the v3
/// form) and the legacy flat `<conn>_oauth_pending` native-secret. De-duped by
/// connection id — the explicit aux form wins when a conn appears in both (e.g.
/// a re-connect that migrated to aux while a stale flat item lingers). Malformed
/// legacy payloads are logged and skipped (a stale one is harmless ciphertext).
/// Pure (no network) for testability.
fn collect_pending(m: &ProtectedState) -> Vec<(String, OAuthPending)> {
    let mut out: Vec<(String, OAuthPending)> = Vec::new();

    // 1. Explicit aux.connections — the canonical v3 form.
    for (conn, c) in aux_connections(m) {
        if let Some(p) = c.oauth_pending {
            out.push((conn, p));
        }
    }

    // 2. Legacy flat `<conn>_oauth_pending` targets, skipping conns already
    //    covered by the aux form.
    for (key, val) in m.targets.iter() {
        let Some(conn) = conn_from_pending_key(key) else {
            continue;
        };
        if out.iter().any(|(c, _)| c == conn) {
            continue;
        }
        match serde_json::from_slice::<OAuthPending>(val.as_bytes()) {
            Ok(p) => out.push((conn.to_string(), p)),
            Err(e) => {
                tracing::warn!(
                    item = %key,
                    "oauth connect: malformed legacy pending payload, skipping: {}", e
                );
            }
        }
    }
    out
}

/// Drive the pending→refresh→delete state machine over an open
/// `ProtectedState`, given an async `exchange` closure (injected so tests can
/// avoid real network calls). Mutates `m` in place; returns the number of
/// connects that completed (a refresh_token was written). On a per-connect
/// failure it logs and **leaves the pending in place** (the user retries within
/// the code TTL) — it never aborts the whole batch.
///
/// `exchange(conn, cfg, pending)` performs the code→token call and returns the
/// tokens (or an error string to log + skip).
pub async fn run_pending<F, Fut>(
    services: &crate::service::ServiceRegistry,
    m: &mut ProtectedState,
    mut exchange: F,
) -> usize
where
    F: FnMut(String, ExchangeConfig, OAuthPending) -> Fut,
    Fut: std::future::Future<Output = Result<ExchangedTokens, String>>,
{
    let pending = collect_pending(m);
    let mut completed = 0usize;
    for (conn, p) in pending {
        let Some(cfg) = resolve_exchange_config(services, &conn) else {
            tracing::warn!(
                conn = %conn,
                "oauth connect: no oauth2 exchange config for connection (unknown/ \
                 non-oauth2 service or missing provider creds); leaving pending"
            );
            continue;
        };
        match exchange(conn.clone(), cfg, p).await {
            Ok(tokens) => {
                if tokens.refresh_token.is_none() {
                    // No durable credential came back (consent without
                    // offline access). Nothing to persist; leave pending so
                    // the user can redo the consent with offline access.
                    tracing::warn!(
                        conn = %conn,
                        "oauth connect: exchange returned no refresh_token; leaving pending"
                    );
                    continue;
                }
                apply_exchange_result(m, &conn, &tokens);
                completed += 1;
                tracing::info!(conn = %conn, "oauth connect: refresh_token persisted");
            }
            Err(e) => {
                // `invalid_grant` ⇒ the code is expired/consumed; leave the
                // pending so a fresh connect can replace it. Other errors are
                // transient (network/provider) — also leave + retry.
                tracing::warn!(conn = %conn, "oauth connect: exchange failed, leaving pending: {}", e);
            }
        }
    }
    completed
}

/// Process all `*_oauth_pending` items for one vault: open the body with the
/// retained `K`, exchange each pending code, write the refresh_tokens, delete
/// the pending items, re-seal under the same `K`, and persist `vault.dat`.
///
/// Best-effort end-to-end:
/// - Locked vault (no retained `K`) → skip (the next unlock re-runs this).
/// - No pending items → no-op (no disk write).
/// - A retained `K` that can't open the body (rotated `K`) → log + skip.
/// - Per-connect failures are handled by [`run_pending`] (leave + retry).
///
/// Holds the per-vault write lock for the open→mutate→re-seal→write cycle so it
/// serializes against approve.rs's writes and the cloud-sync pull (same lock).
/// Never panics; any error logs and returns.
pub async fn process_vault_connects(state: &Arc<AppState>, vault_id: &str) {
    let Some(k) = state.cloned_state_key(vault_id) else {
        return; // Locked — no retained K; next unlock retries.
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
    let mut vault = match crate::storage::sealed_vault::read(&vault_path) {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: read vault.dat failed: {}", e);
            return;
        }
    };

    let mut m = match crate::server::handlers::metadata::open_protected_state_with_key(&k, &vault) {
        Ok(m) => m,
        Err(_) => {
            // Retained K can't open (rotated) — graceful skip, lock+unlock retries.
            return;
        }
    };

    // Cheap pre-check: nothing to do if there are no pending handshakes at all
    // (checks both the aux.connections form and the legacy flat targets).
    if collect_pending(&m).is_empty() {
        return;
    }

    let services = &state.services;
    let completed = run_pending(services, &mut m, |_conn, cfg, p| async move {
        crate::auth::oauth2::exchange_code(
            &cfg.token_url,
            &cfg.client_id,
            cfg.client_secret.as_deref(),
            &p.code,
            &p.verifier,
            &p.redirect_uri,
            cfg.style,
        )
        .await
    })
    .await;

    if completed == 0 {
        // Nothing persisted (all failed/left pending) — don't rewrite the blob.
        return;
    }

    // Re-seal the mutated body under the same K (registry/credentials/wrapped_key
    // untouched) and persist. No approval op — direct daemon re-seal (§4a).
    if let Err(e) =
        crate::server::handlers::metadata::reseal_body_with_key(&k, &mut vault, &m)
    {
        tracing::warn!(vault = %vault_id, "oauth connect: re-seal failed: {}", e);
        return;
    }
    if let Err(e) = crate::storage::sealed_vault::write_atomic(&vault_path, &vault) {
        tracing::warn!(vault = %vault_id, "oauth connect: write vault.dat failed: {}", e);
        return;
    }
    tracing::info!(
        vault = %vault_id,
        connects = completed,
        "oauth connect: completed; refreshed vault.dat (direct re-seal, no approval op)"
    );

    // Refresh the in-memory cache so the newly written refresh_token (and any
    // allow-level fast-path) reflects the post-connect state without a manual
    // lock/unlock. Best-effort: a decrypt failure just leaves the cache as-is.
    if let Ok(view) =
        crate::server::handlers::metadata::decrypt_vault_view_with_key(&k, &vault)
    {
        let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
        state.unlock_vault(vault_id.to_string(), cache, k);
    }

    // Propagate to OTHER devices: push the re-sealed blob back to the cloud.
    // A Google authorization code is single-use, so only THIS daemon could
    // redeem the pending connect — every other device's daemon must PULL the
    // resulting refresh_token rather than re-exchange (which fails
    // `invalid_grant`). Cloud-blind preserved: the pushed blob is ciphertext.
    // Detached + best-effort, after the write lock drops (push only reads
    // vault.dat + does HTTP).
    {
        let state = state.clone();
        let vid = vault_id.to_string();
        tokio::spawn(async move {
            crate::sync::push_blob_best_effort(&state, &vid).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_json(code: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "code": code,
            "verifier": "verif-xyz",
            "redirect_uri": "http://127.0.0.1:8765/callback",
        }))
        .unwrap()
    }

    fn tokens(rt: Option<&str>) -> ExchangedTokens {
        ExchangedTokens {
            refresh_token: rt.map(|s| s.to_string()),
            access_token: "at-123".to_string(),
            expires_at: 9_999_999_999,
        }
    }

    #[test]
    fn conn_from_pending_key_strips_suffix() {
        assert_eq!(conn_from_pending_key("gmail_oauth_pending"), Some("gmail"));
        assert_eq!(conn_from_pending_key("gmail_refresh_token"), None);
        assert_eq!(conn_from_pending_key("_oauth_pending"), None); // empty conn
        assert_eq!(conn_from_pending_key("plain"), None);
    }

    #[test]
    fn collect_pending_parses_and_skips_malformed() {
        let mut m = ProtectedState::new();
        m.put_target("gmail_oauth_pending", pending_json("code-A"));
        m.put_target("gdrive_oauth_pending", b"{not json".to_vec());
        m.put_target("unrelated_key", b"value".to_vec());

        let got = collect_pending(&m);
        assert_eq!(got.len(), 1, "malformed pending must be skipped");
        assert_eq!(got[0].0, "gmail");
        assert_eq!(got[0].1.code, "code-A");
    }

    // ── aux.connections path (the v3 explicit form) ─────────────────────────

    /// Build a ProtectedState whose `aux.connections` carries one connection
    /// with an `oauth_pending`. The rest of the aux is a minimal valid v3 shell
    /// (only the `connections` sub-value matters to these functions).
    fn with_aux_pending(conn: &str, code: &str) -> ProtectedState {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({
            "version": 3,
            "stores": {},
            "store_order": [],
            "connections": {
                conn: { "oauth_pending": {
                    "code": code,
                    "verifier": "verif-xyz",
                    "redirect_uri": "http://127.0.0.1:8765/callback",
                }}
            }
        });
        m
    }

    #[test]
    fn collect_pending_reads_aux_connections() {
        let m = with_aux_pending("gmail", "code-AUX");
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "gmail");
        assert_eq!(got[0].1.code, "code-AUX");
    }

    #[test]
    fn collect_pending_aux_wins_over_legacy_duplicate() {
        // Same conn in BOTH the aux record and a stale legacy flat target →
        // exactly one entry, carrying the aux code.
        let mut m = with_aux_pending("gmail", "code-AUX");
        m.put_target("gmail_oauth_pending", pending_json("code-LEGACY"));
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1, "a conn in both sources must de-dupe");
        assert_eq!(got[0].1.code, "code-AUX", "the aux form wins");
    }

    #[test]
    fn collect_pending_unions_aux_and_distinct_legacy() {
        // Distinct conns from each source both surface.
        let mut m = with_aux_pending("gmail", "code-AUX");
        m.put_target("gdrive_oauth_pending", pending_json("code-DRIVE"));
        let mut got = collect_pending(&m);
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "gdrive");
        assert_eq!(got[1].0, "gmail");
    }

    #[test]
    fn apply_exchange_result_clears_aux_pending_and_drops_record() {
        let mut m = with_aux_pending("gmail", "code-AUX");
        apply_exchange_result(&mut m, "gmail", &tokens(Some("rt-NEW")));
        assert_eq!(m.target("gmail_refresh_token").unwrap(), b"rt-NEW");
        assert!(
            aux_connections(&m).is_empty(),
            "an emptied connection record must be dropped from aux"
        );
    }

    #[test]
    fn apply_exchange_result_clears_both_aux_and_legacy_for_conn() {
        let mut m = with_aux_pending("gmail", "code-AUX");
        m.put_target("gmail_oauth_pending", pending_json("code-LEGACY"));
        apply_exchange_result(&mut m, "gmail", &tokens(Some("rt-NEW")));
        assert!(
            m.targets.get("gmail_oauth_pending").is_none(),
            "legacy flat pending must be cleared"
        );
        assert!(aux_connections(&m).is_empty(), "aux pending must be cleared");
        assert_eq!(m.target("gmail_refresh_token").unwrap(), b"rt-NEW");
    }

    #[tokio::test]
    async fn run_pending_success_from_aux_mutates_aux() {
        let services = gmail_registry();
        let mut m = with_aux_pending("gmail", "code-AUX");

        let n = run_pending(&services, &mut m, |conn, _cfg, p| {
            assert_eq!(conn, "gmail");
            assert_eq!(p.code, "code-AUX");
            async move { Ok(tokens(Some("rt-NEW"))) }
        })
        .await;

        assert_eq!(n, 1);
        assert!(
            aux_connections(&m).is_empty(),
            "aux pending cleared after a successful exchange"
        );
        assert_eq!(m.target("gmail_refresh_token").unwrap(), b"rt-NEW");
    }

    #[tokio::test]
    async fn run_pending_failure_leaves_aux_pending() {
        let services = gmail_registry();
        let mut m = with_aux_pending("gmail", "code-EXPIRED");

        let n = run_pending(&services, &mut m, |_conn, _cfg, _p| async move {
            Err("oauth2 code-exchange returned HTTP 400 — invalid_grant".to_string())
        })
        .await;

        assert_eq!(n, 0);
        assert!(
            aux_connections(&m).get("gmail").and_then(|c| c.oauth_pending.as_ref()).is_some(),
            "aux pending must survive a failed exchange (user retries within TTL)"
        );
        assert!(m.targets.get("gmail_refresh_token").is_none());
    }

    #[test]
    fn apply_exchange_result_writes_refresh_and_deletes_pending() {
        let mut m = ProtectedState::new();
        m.put_target("gmail_oauth_pending", pending_json("code-A"));
        apply_exchange_result(&mut m, "gmail", &tokens(Some("rt-NEW")));

        assert!(
            m.targets.get("gmail_oauth_pending").is_none(),
            "pending must be deleted after exchange"
        );
        assert_eq!(
            m.target("gmail_refresh_token").unwrap(),
            b"rt-NEW",
            "refresh_token must be written under <conn>_refresh_token"
        );
    }

    #[test]
    fn apply_exchange_result_overwrites_existing_refresh_token() {
        let mut m = ProtectedState::new();
        m.put_target("gmail_refresh_token", b"rt-OLD".to_vec());
        m.put_target("gmail_oauth_pending", pending_json("code-A"));
        apply_exchange_result(&mut m, "gmail", &tokens(Some("rt-NEW")));
        assert_eq!(m.target("gmail_refresh_token").unwrap(), b"rt-NEW");
    }

    // ── run_pending state machine, with a mocked exchange (no network) ──────

    fn gmail_registry() -> crate::service::ServiceRegistry {
        // The compiled-in defaults include the gmail service + the google
        // provider literal, so resolve_exchange_config finds a real config.
        crate::service::ServiceRegistry::load()
    }

    #[tokio::test]
    async fn run_pending_success_completes_and_mutates() {
        let services = gmail_registry();
        let mut m = ProtectedState::new();
        m.put_target("gmail_oauth_pending", pending_json("code-A"));

        let mut seen_grant = None;
        let n = run_pending(&services, &mut m, |conn, cfg, p| {
            seen_grant = Some((conn.clone(), cfg.token_url.clone(), p.code.clone()));
            async move { Ok(tokens(Some("rt-NEW"))) }
        })
        .await;

        assert_eq!(n, 1);
        assert!(m.targets.get("gmail_oauth_pending").is_none());
        assert_eq!(m.target("gmail_refresh_token").unwrap(), b"rt-NEW");
        let (conn, token_url, code) = seen_grant.expect("exchange called");
        assert_eq!(conn, "gmail");
        assert_eq!(code, "code-A");
        assert!(
            token_url.starts_with("https://oauth2.googleapis.com/token"),
            "token_url must come from the google provider literal, got {token_url}"
        );
    }

    #[tokio::test]
    async fn run_pending_failure_leaves_pending() {
        let services = gmail_registry();
        let mut m = ProtectedState::new();
        m.put_target("gmail_oauth_pending", pending_json("code-EXPIRED"));

        let n = run_pending(&services, &mut m, |_conn, _cfg, _p| async move {
            Err("oauth2 code-exchange returned HTTP 400 — invalid_grant".to_string())
        })
        .await;

        assert_eq!(n, 0, "a failed exchange completes nothing");
        assert!(
            m.targets.get("gmail_oauth_pending").is_some(),
            "pending must survive a failed exchange (user retries within TTL)"
        );
        assert!(
            m.targets.get("gmail_refresh_token").is_none(),
            "no refresh_token on a failed exchange"
        );
    }

    #[tokio::test]
    async fn run_pending_no_refresh_token_leaves_pending() {
        let services = gmail_registry();
        let mut m = ProtectedState::new();
        m.put_target("gmail_oauth_pending", pending_json("code-A"));

        let n = run_pending(&services, &mut m, |_conn, _cfg, _p| async move {
            Ok(tokens(None)) // consent without offline access → no refresh_token
        })
        .await;

        assert_eq!(n, 0);
        assert!(
            m.targets.get("gmail_oauth_pending").is_some(),
            "no durable token ⇒ leave pending"
        );
    }

    #[tokio::test]
    async fn run_pending_unknown_service_leaves_pending() {
        let services = gmail_registry();
        let mut m = ProtectedState::new();
        m.put_target("nosuchservice_oauth_pending", pending_json("code-A"));

        let mut called = false;
        let n = run_pending(&services, &mut m, |_conn, _cfg, _p| {
            called = true;
            async move { Ok(tokens(Some("rt"))) }
        })
        .await;

        assert_eq!(n, 0);
        assert!(!called, "exchange must not run when no config resolves");
        assert!(m.targets.get("nosuchservice_oauth_pending").is_some());
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
    }

    #[test]
    fn resolve_exchange_config_none_for_unknown() {
        let services = gmail_registry();
        assert!(resolve_exchange_config(&services, "nosuchservice").is_none());
    }
}
