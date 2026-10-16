//! The 23294 **API face** — a read-only responder living on the proxy listener.
//!
//! The proxy port serves two RFC 7230 §5.3 request-line forms
//! (CREDENTIAL_BROKER.md §14): CONNECT / absolute-form = the credential proxy
//! (MITM / blind-tunnel);
//! **origin-form** (`GET /v/{vid}/registry`) = discovery + op-poll, self-answered
//! here so the agent needs ONE port. A self-authority absolute-form request (the
//! agent wrongly routed discovery through its own proxy) is the loop-guard case,
//! also handled here. Everything is a plain READ:
//! - `/health`, `/ca` — unauthenticated (liveness / public CA cert).
//! - `/v/{vid}/registry`, `/op/{id}` — the agent's AIK proof in the Bearer slot (§8),
//!   admitted by the account ledger (§15 W3).
//!
//! Writes / ceremony never appear here — they stay on the control port (23293),
//! passkey-gated and invisible to the agent. The read projections come from the
//! SAME functions the control plane serves (`registry::vault_registry_value`,
//! `approve::op_poll_value`, `health::health_value`), so the two ports can't
//! drift; agent admission is `principal_ledger::authorize_agent`, the same rule
//! the proxy applies. Both shared surfaces are
//! `Value`/`&str`-typed, so this module never touches axum's `http` types.

use std::sync::Arc;

use hudsucker::hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use hudsucker::Body;
use serde_json::{json, Value};

use crate::error::ScCode;
use crate::state::AppState;

/// Is `req` addressed to us (the API face) rather than a proxied upstream? True
/// for origin-form (no authority — a direct `GET /path` to this port) and for
/// the self-authority loop-guard (absolute-form whose host:port is our own
/// loopback proxy). Any other authority is a real proxy target → false.
pub fn is_api_face(req: &Request<Body>, proxy_port: u16) -> bool {
    match req.uri().host() {
        None => true,
        Some(h) => is_self_authority(h, req.uri().port_u16(), proxy_port),
    }
}

fn is_self_authority(host: &str, port: Option<u16>, proxy_port: u16) -> bool {
    let loopback = matches!(host, "127.0.0.1" | "::1" | "localhost");
    // Require the EXACT proxy port: `127.0.0.1:<other>` is a real localhost
    // upstream the agent is proxying to, not a loop back into us.
    loopback && port == Some(proxy_port)
}

/// Self-answer an API-face request. GET-only; unknown paths → 404. Every
/// projection is a synchronous read; the only await is the debounced hash
/// refresh on an auth miss.
pub async fn respond(state: &Arc<AppState>, req: &Request<Body>) -> Response<Body> {
    if req.method() != Method::GET {
        return problem(ScCode::MethodNotAllowed, "GET only");
    }
    let path = req.uri().path().to_string();
    // The exact origin-form target on the wire (path + any query) — the hop-A PoP
    // binds THIS string (`apiface:<pq>`), so the shim signs the same request-line
    // target it sends and a token can't be lifted to another api-face path.
    let pq = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str().to_string())
        .unwrap_or_else(|| path.clone());

    // ── Unauthenticated: liveness + public CA ────────────────────────────────
    if path == "/health" {
        return json(
            StatusCode::OK,
            &crate::server::handlers::health::health_value(state),
        );
    }
    if path == "/ca" {
        return ca_pem(state);
    }

    // ── Bearer-gated reads (§8) ──────────────────────────────────────────────
    if let Some(op_id) = path.strip_prefix("/op/") {
        let caller = match require_agent(state, req.headers(), &pq).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        // Op-agent binding (team §C1): an agent-created op is pollable only by
        // the agent that triggered it — a different (still valid) agent gets the
        // same shape as an unknown op, so this face leaks nothing about other
        // agents' pending work. Ops with no agent stamp (ceremonies) stay
        // reachable by any valid agent, matching today's user-surface semantics.
        // `caller` is the resolved attribution (hop-A `ag_` or legacy key prefix),
        // the SAME id the proxy path stamped on the op at creation — so the two
        // faces compare like-for-like across the dual-auth window.
        {
            let bound = state
                .approvals
                .lock()
                .unwrap()
                .get(op_id)
                .and_then(|r| r.agent_prefix.clone());
            if let Some(expected) = bound {
                if caller != expected {
                    return problem(ScCode::NotFound, "Not found");
                }
            }
        }
        // Same E1 gate as the control plane: an Export value is released only
        // with its waiter secret, so the two faces stay byte-identical.
        let waiter = req
            .headers()
            .get(crate::server::handlers::approve::WAITER_HEADER)
            .and_then(|v| v.to_str().ok());
        return match crate::server::handlers::approve::op_poll_value(state, op_id, waiter) {
            Ok(v) => op_poll_response(&v),
            Err(e) => app_err(e),
        };
    }
    // GET /vaults — the agent's vault index (team §A/§7.7): every vault this
    // daemon holds, with lock state and a per-vault connection summary the
    // caller's reach mask has already been applied to. EXISTS ONLY ON THIS
    // AUTHED AGENT FACE — the control plane deliberately never exposes a
    // vault index (see registry.rs's no-vault_id note). The vid in each entry
    // is the address the agent puts on the wire (proxy auth / URL); item
    // names stay bare and resolve inside the chosen vault.
    if path == "/vaults" {
        let agent = match require_agent(state, req.headers(), &pq).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let mut vaults: Vec<Value> = Vec::new();
        let ids = state.vaults.list().unwrap_or_default();
        let mut catalogued: std::collections::HashSet<String> = crate::cli::active::known_vaults()
            .into_iter()
            .map(|v| v.vault)
            .collect();
        if let Ok(cfg) = crate::cli::active::load() {
            if let Some(active) = cfg.vault.filter(|v| !v.is_empty()) {
                catalogued.insert(active);
            }
        }
        for vid in ids {
            if state.is_vault_revoked(&vid) || !catalogued.contains(&vid) {
                continue;
            }
            let locked = state.is_vault_locked(&vid);
            let mut conns: Vec<Value> = Vec::new();
            if !locked {
                let snapshot = state.connections_snapshot(&vid);
                let candidates: Vec<String> = snapshot.iter().map(|(id, _)| id.clone()).collect();
                let allowed = state.agent_allowed_connections(&vid, &agent, &candidates);
                let allow: Option<std::collections::HashSet<String>> =
                    allowed.map(|w| w.into_iter().collect());
                for (id, conn) in snapshot {
                    let masked = allow.as_ref().map(|a| !a.contains(&id)).unwrap_or(false);
                    let mut row = json!({ "id": id, "service": conn.service });
                    if masked {
                        row["locked"] = Value::Bool(true);
                    }
                    conns.push(row);
                }
                conns.sort_by(|a, b| {
                    a["id"]
                        .as_str()
                        .unwrap_or("")
                        .cmp(b["id"].as_str().unwrap_or(""))
                });
            }
            vaults.push(json!({
                "vid": vid,
                "locked": locked,
                "vault_key_changed": state.is_vault_key_changed(&vid),
                "vault_key_changed_message": state.is_vault_key_changed(&vid)
                    .then_some(crate::error::VAULT_KEY_CHANGED_MSG),
                "connections": conns,
            }));
        }
        return json(StatusCode::OK, &json!({ "vaults": vaults }));
    }
    if let Some(vid) = path
        .strip_prefix("/v/")
        .and_then(|r| r.strip_suffix("/registry"))
    {
        let agent = match require_agent(state, req.headers(), &pq).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let q = crate::server::handlers::registry::RegistryQuery::from_query_str(
            req.uri().query().unwrap_or(""),
        );
        // Agent surface: annotate reach-masked connections as locked stubs, keyed
        // by the resolved attribution (hop-A `ag_` or legacy key prefix).
        return match crate::server::handlers::registry::vault_registry_value(
            state,
            vid,
            &q,
            Some(agent.as_str()),
        ) {
            Ok(v) => json(StatusCode::OK, &v),
            Err(e) => app_err(e),
        };
    }

    problem(ScCode::NotFound, "Not found")
}

/// Gate an api-face request and resolve the caller's attribution (§8, §15 W3).
/// The agent proves its AIK with a `scpop1…` token in the Bearer slot (the `sc`
/// transport holds the AIK and mints it, keeping the key out of the child env),
/// verified against the request-line target (`apiface:<pq>`, account-scoped
/// `vault=""`). Then the one admission rule ([`crate::principal_ledger::authorize_agent`]):
/// this device serves, the ledger admits the `ag_`, and some unlocked vault
/// lists it. An api key alone is no longer an agent credential. Returns the
/// `ag_` (the same attribution the proxy stamps). `Err` carries the ready refusal.
async fn require_agent(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    pq: &str,
) -> Result<String, Response<Body>> {
    use crate::principal_ledger::AgentRefusal;
    let verified = bearer_token(headers).and_then(|tok| {
        crate::agent_pop::verify_agent_proxy_pop(
            &tok,
            "",
            &crate::agent_pop::apiface_target(pq),
            crate::util::now_unix(),
            crate::agent_pop::DEFAULT_MAX_SKEW_SECS,
        )
    });
    let vault = pq
        .strip_prefix("/v/")
        .and_then(|rest| rest.split('/').next())
        .filter(|vid| !vid.is_empty());
    match crate::principal_ledger::authorize_agent(state, verified.as_deref(), vault).await {
        Ok(ag) => Ok(ag),
        Err(AgentRefusal::Device(e)) => {
            let (code, msg) = e.code();
            Err(problem(code, &msg))
        }
        Err(AgentRefusal::Gone(error)) => {
            let (code, message) = error.code();
            Err(problem(code, &message))
        }
        Err(AgentRefusal::NoIdentity) => Err(problem(
            ScCode::Unauthorized,
            crate::principal_ledger::NO_AGENT_IDENTITY_MSG,
        )),
        Err(AgentRefusal::NotAdmitted) => Err(problem(
            ScCode::AgentNotAdmitted,
            crate::error::AGENT_NOT_ADMITTED_MSG,
        )),
        Err(AgentRefusal::Locked) => {
            Err(problem(ScCode::VaultLocked, crate::error::VAULT_LOCKED_MSG))
        }
        // Verified and admitted, but NOT turned on anywhere yet: distinct from a
        // bad credential — the fix is a Console authorize (Agent access page).
        Err(AgentRefusal::NotAuthorized) => Err(problem(
            ScCode::AgentNotAuthorized,
            "this agent is not turned on for any vault yet. Ask the user to turn it \
             on in a vault's Agent access page in the SafeClaw console",
        )),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.to_string())
}

/// `GET /ca` — the resident CA PEM (public cert; the agent trusts it ADDITIVELY
/// for its self-construct client, mitmproxy `mitm.it`-style). Unauthenticated:
/// a public certificate, and served over plain localhost HTTP so there's no
/// chicken-and-egg. Read from THIS daemon's state dir (where `ca::load_or_generate`
/// wrote it).
fn ca_pem(state: &AppState) -> Response<Body> {
    let path = state.config.state_dir.join("ca.pem");
    match std::fs::read(&path) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-pem-file")
            .body(Body::from(bytes))
            .unwrap_or_else(|_| plain_500()),
        Err(e) => {
            tracing::warn!("api_face: read {} failed: {}", path.display(), e);
            problem(ScCode::CaUnavailable, "resident CA unreadable")
        }
    }
}

fn app_err(e: crate::error::AppError) -> Response<Body> {
    let (code, detail) = e.code();
    problem(code, &detail)
}

/// RFC 9457 rendering for this face — the SAME `problem_body` row the control
/// plane emits, so both ports map an error identically.
fn problem(code: ScCode, detail: &str) -> Response<Body> {
    let status = StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&crate::error::problem_body(code, detail))
        .unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/problem+json")
        .header("x-safeclaw-error", code.as_str())
        .body(Body::from(body))
        .unwrap_or_else(|_| plain_500())
}

/// `/op/{id}` poll response — the shared `op_poll_value` body PLUS the same
/// `Retry-After` pacing hint the control-plane poll sets on a pending op, so the
/// agent (which polls THIS API face at the absolute poll_url, §9) keeps the
/// standard cadence and the two faces stay byte-for-byte identical.
fn op_poll_response(v: &Value) -> Response<Body> {
    let pending = v.get("status").and_then(|s| s.as_str()) == Some("pending");
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json");
    if pending {
        b = b.header(
            header::RETRY_AFTER,
            crate::approval::store::POLL_INTERVAL_HINT_SECS.to_string(),
        );
    }
    b.body(Body::from(body)).unwrap_or_else(|_| plain_500())
}

fn json(status: StatusCode, v: &Value) -> Response<Body> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| plain_500())
}

fn plain_500() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from("{}"))
        .expect("static response builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_authority_requires_exact_proxy_port() {
        assert!(is_self_authority("127.0.0.1", Some(23294), 23294));
        assert!(is_self_authority("localhost", Some(23294), 23294));
        assert!(is_self_authority("::1", Some(23294), 23294));
        // A different port is a real localhost upstream, not a loop.
        assert!(!is_self_authority("127.0.0.1", Some(3000), 23294));
        // A missing port is not our exact authority either.
        assert!(!is_self_authority("127.0.0.1", None, 23294));
        // A non-loopback host is always a proxy target.
        assert!(!is_self_authority("api.github.com", Some(23294), 23294));
    }

    #[test]
    fn origin_form_is_api_face_absolute_upstream_is_not() {
        // Origin-form (no authority) → the API face.
        let origin = Request::builder()
            .uri("/v/abc/registry")
            .body(Body::empty())
            .unwrap();
        assert!(is_api_face(&origin, 23294));

        // Absolute-form to a real upstream → NOT the API face (a proxy request).
        let upstream = Request::builder()
            .uri("http://api.github.com/x")
            .body(Body::empty())
            .unwrap();
        assert!(!is_api_face(&upstream, 23294));

        // Absolute-form looped back at our own authority → the API face (guard).
        let loop_back = Request::builder()
            .uri("http://127.0.0.1:23294/health")
            .body(Body::empty())
            .unwrap();
        assert!(is_api_face(&loop_back, 23294));
    }

    /// §15 W3: an agent is served only while the account ledger admits its
    /// `ag_` AND some vault lists it. A revoked agent is refused with
    /// `agent_not_admitted` though a vault still lists it; a not-admitted device
    /// refuses every agent; an api key alone is no agent credential.
    #[tokio::test]
    async fn the_ledger_admits_agents_and_a_revoked_agent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            state_dir: dir.path().to_path_buf(),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            relying_party: crate::passkey::webauthn::RelyingParty::exact(
                "http://localhost",
                "localhost",
            ),
            admin_key: None,
            relay_url: None,
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        let state = Arc::new(AppState::new(cfg));
        let id = crate::identity::SigningIdentity::from_seed(&[9u8; 32]);
        let ag = crate::identity::derive_id(crate::identity::IdKind::Agent, &id.public_bytes());
        let signer = crate::agent_pop::AgentProxyPopSigner::new(id, ag.clone());
        let headers = |pq: &str| {
            let tok = signer.token(
                "",
                &crate::agent_pop::apiface_target(pq),
                crate::util::now_unix(),
            );
            let mut h = HeaderMap::new();
            h.insert(
                header::AUTHORIZATION,
                format!("Bearer {tok}").parse().unwrap(),
            );
            h
        };
        let code = |r: &Response<Body>| {
            r.headers()
                .get("x-safeclaw-error")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        // The vault lists the agent.
        let mut cache = crate::state::SecretsCache::default();
        cache.agents.insert(ag.clone(), Default::default());
        // Admitted by the ledger (a parked device holds no K) and listed: served.
        state.open_ledger_for_tests(&[&ag]);
        state.unlock_vault(
            "v1".into(),
            cache,
            zeroize::Zeroizing::new(vec![0x42u8; 32]),
        );
        assert_eq!(
            require_agent(&state, &headers("/vaults"), "/vaults")
                .await
                .unwrap(),
            ag
        );

        // Revoked in the ledger (the latest fold no longer admits it): refused
        // with agent_not_admitted, though the vault still lists it. The on-miss
        // re-pull finds no pairing in this test and changes nothing.
        state.open_ledger_for_tests(&[]);
        *state.ledger_sync.lock().await = Some(std::time::Instant::now());
        let r = require_agent(&state, &headers("/vaults"), "/vaults")
            .await
            .unwrap_err();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(code(&r).as_deref(), Some("agent_not_admitted"));

        // No verified agent identity (an api key): refused, never looked up.
        state.open_ledger_for_tests(&[&ag]);
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer sc_agent_k9".parse().unwrap());
        let r = require_agent(&state, &h, "/vaults").await.unwrap_err();
        assert_eq!(code(&r).as_deref(), Some("unauthorized"));

        // A named revoked vault is explicit and wins over its locked state or
        // vault-level agent table.
        state.open_ledger_for_tests(&[&ag]);
        state.mark_vault_closing("v1", crate::vault_runtime::TombstoneReason::Removed);
        let pq = "/v/v1/registry";
        let r = require_agent(&state, &headers(pq), pq).await.unwrap_err();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(code(&r).as_deref(), Some("vault_access_revoked"));
        state.restore_vault("v1");

        // This device not admitted: every agent refused with device_not_admitted.
        state.set_ledger(crate::principal_ledger::LedgerGate::default());
        let r = require_agent(&state, &headers("/vaults"), "/vaults")
            .await
            .unwrap_err();
        assert_eq!(code(&r).as_deref(), Some("device_not_admitted"));
        assert!(state.is_vault_locked("v1"), "parking evicts K");
    }
}
