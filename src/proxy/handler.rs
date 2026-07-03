//! The resident proxy's request handler: the whole brokered pipeline.
//!
//! One `BrokerHandler` is cloned per TCP connection. On a CONNECT it captures
//! the vault id from `Proxy-Authorization` and decides MITM-vs-blind-tunnel by
//! whether the destination host is anchored by any unlocked vault's connection.
//! For each intercepted inner request it: finds phantoms, resolves them to ONE
//! connection, enforces the host anchor, evaluates policy, substitutes the real
//! credential at egress, strips the agent's own/proxy auth, and forwards. A
//! request with no phantom is forwarded untouched — the phantom is the only
//! injection trigger.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use http_body_util::BodyExt;
use hudsucker::hyper::{header, HeaderMap, Method, Request, Response, StatusCode, Uri};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use serde_json::json;

use crate::proxy::resolver::{self, Phantom};
use crate::state::{AppState, UnlockedVaults};

/// The probe host the daemon self-answers so `sc status` can prove liveness
/// *through* the proxy (env vars present but proxy dead ⇒ `routed:false`).
const PROBE_HOST: &str = "sc.probe";

/// Bodies larger than this (or non-text) pass through unscanned — phantoms live
/// in headers / URL / Basic-auth in practice, never a multi-MiB upload.
const MAX_BODY_SCAN: u64 = 1024 * 1024;

/// The default validity window for a captive-portal op if policy gives no ttl.
const DEFAULT_ASK_TTL: u64 = 300;

/// What `handle_response` needs to write the terminal audit row after the
/// upstream answers a forwarded (allow) request.
#[derive(Clone)]
pub struct AuditPending {
    pub vault_id: String,
    pub service: String,
    pub method: String,
    pub path: String,
}

#[derive(Clone)]
pub struct BrokerHandler {
    pub state: Arc<AppState>,
    /// Vault id captured from the CONNECT's `Proxy-Authorization`, inherited by
    /// every inner-request clone of this handler.
    pub vid: Option<String>,
    /// Set on the allow/forward path; consumed by `handle_response`.
    pub pending: Option<AuditPending>,
}

impl BrokerHandler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state, vid: None, pending: None }
    }
}

impl HttpHandler for BrokerHandler {
    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        // The vid rides the CONNECT's Proxy-Authorization userinfo; capture it
        // here so inner-request clones inherit it (read-only).
        self.vid = vid_from_proxy_auth(req);
        match req.uri().host() {
            Some(h) => self.state.host_in_any_unlocked_union(h),
            None => false,
        }
    }

    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        // The CONNECT itself is forwarded unchanged (vid already captured in
        // should_intercept, which runs inside process_connect).
        if req.method() == Method::CONNECT {
            return req.into();
        }

        // Liveness probe — answered directly, never forwarded.
        if req.uri().host() == Some(PROBE_HOST) {
            return probe_response().into();
        }

        self.pipeline(ctx, req).await
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if let Some(p) = self.pending.take() {
            write_forward_audit(&self.state, &p, res.status().as_u16());
        }
        res
    }
}

impl BrokerHandler {
    async fn pipeline(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let is_https = req.uri().scheme_str() == Some("https");
        let dest_host = match req.uri().host() {
            Some(h) => h.to_ascii_lowercase(),
            None => return req.into(), // origin-form / no authority: not ours
        };
        let ip = ctx.client_addr.ip();

        let (parts, body) = req.into_parts();
        // `orig_body` is the un-scanned streaming body; `body_bytes` is the
        // buffered copy when we scan. Exactly one is live past the scan below,
        // so both consumers `take()` from the Option.
        let mut orig_body = Some(body);
        let method = parts.method.as_str().to_string();
        let path = parts.uri.path().to_string();
        let pq = parts
            .uri
            .path_and_query()
            .map(|x| x.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        // ── gather phantom-bearing scan sites ────────────────────────────────
        let mut phantoms: Vec<Phantom> = Vec::new();
        merge_phantoms(&mut phantoms, resolver::collect_phantoms(&pq));
        for value in parts.headers.values() {
            if let Ok(s) = value.to_str() {
                merge_phantoms(&mut phantoms, resolver::collect_phantoms(s));
            }
        }
        // Authorization: Basic <b64> — decode before matching.
        if let Some(decoded) = basic_auth_decoded(&parts.headers) {
            merge_phantoms(&mut phantoms, resolver::collect_phantoms(&decoded));
        }

        // Decide whether to buffer the body for scanning (bounded + text-ish).
        let scan_body = body_is_text(&parts.headers)
            && content_length(&parts.headers).map(|n| n <= MAX_BODY_SCAN).unwrap_or(false);

        let mut body_bytes: Option<Vec<u8>> = None;
        if scan_body {
            match orig_body.take().expect("body present before scan").collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes().to_vec();
                    if let Ok(s) = std::str::from_utf8(&bytes) {
                        merge_phantoms(&mut phantoms, resolver::collect_phantoms(s));
                    }
                    body_bytes = Some(bytes);
                }
                Err(e) => {
                    tracing::warn!("proxy: body collect failed: {}", e);
                    return err_response(
                        StatusCode::BAD_GATEWAY,
                        "upstream_body",
                        "failed to read request body",
                    )
                    .into();
                }
            }
        }

        // No phantom anywhere → forward untouched (rebuild body if we buffered).
        if phantoms.is_empty() {
            let body = body_bytes
                .map(Body::from)
                .unwrap_or_else(|| orig_body.take().unwrap_or_else(Body::empty));
            return Request::from_parts(parts, body).into();
        }

        // A phantom over plain HTTP can't be TLS-substituted — refuse.
        if !is_https {
            return err_response(
                StatusCode::BAD_REQUEST,
                "phantom_plain_http",
                "a phantom requires HTTPS (the proxy only substitutes inside TLS)",
            )
            .into();
        }

        // ── one connection per request ───────────────────────────────────────
        let mut conns: Vec<&str> = phantoms.iter().map(|p| p.conn.as_str()).collect();
        conns.sort_unstable();
        conns.dedup();
        if conns.len() != 1 {
            return err_response(
                StatusCode::BAD_REQUEST,
                "multi_connection",
                &format!(
                    "one connection per request — this request names {}",
                    conns.join(", ")
                ),
            )
            .into();
        }
        let conn = conns[0].to_string();

        // ── bind the vault ───────────────────────────────────────────────────
        let vault_id = match self.vid.clone() {
            Some(v) => v,
            None => match self.state.unlocked_vault() {
                UnlockedVaults::One(v) => v,
                UnlockedVaults::None => {
                    return err_response(
                        StatusCode::FORBIDDEN,
                        "no_vault",
                        "no vault is unlocked — run `sc up`",
                    )
                    .into()
                }
                UnlockedVaults::Many => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        "ambiguous_vault",
                        "multiple vaults unlocked — run 'sc run' so SafeClaw knows which (the vault id rides the proxy address)",
                    )
                    .into()
                }
            },
        };
        if self.state.is_vault_locked(&vault_id) {
            return err_response(
                StatusCode::from_u16(423).unwrap(),
                "vault_locked",
                "vault is locked — run `sc up`",
            )
            .into();
        }

        // ── resolve the connection ───────────────────────────────────────────
        let Some(conn_rec) = self.state.connection_snapshot(&vault_id, &conn) else {
            return err_response(
                StatusCode::BAD_REQUEST,
                "unknown_connection",
                &format!("unknown connection '{}'", conn),
            )
            .into();
        };
        let def = conn_rec.service.as_deref().and_then(|s| {
            self.state
                .services
                .get(s)
                .cloned()
                .or_else(|| self.state.custom_service(&vault_id, s))
        });
        let is_oauth = def.as_ref().and_then(|d| d.oauth2.as_ref()).is_some();
        // The service id policy/mint use; for a raw connection there is none so
        // the conn id stands in (registry lookups miss → global default floor).
        let service_id = conn_rec.service.clone().unwrap_or_else(|| conn.clone());
        let resolved_hosts = self
            .state
            .resolved_hosts_for(&vault_id, &conn)
            .unwrap_or_default();

        // ── host anchor (exact FQDN, with the private/metadata floor beneath) ─
        if !crate::core::host::host_allowed(&dest_host, &resolved_hosts) {
            if !crate::service::validate::host_egress_allowed(&dest_host) {
                return err_response(
                    StatusCode::FORBIDDEN,
                    "host_forbidden",
                    &format!("destination '{}' is not a permitted egress target", dest_host),
                )
                .into();
            }
            return self.widen_deny(&vault_id, &conn, &dest_host, ip).await;
        }

        // ── policy ───────────────────────────────────────────────────────────
        let body_for_policy = body_bytes.as_deref().and_then(|b| std::str::from_utf8(b).ok());
        let decision = self.state.evaluate_request_policy(
            &vault_id,
            &conn,
            &service_id,
            &method,
            &path,
            &dest_host,
            body_for_policy,
        );
        let (level, rule_id, ttl) = match decision {
            Some(d) => d,
            None => {
                return err_response(
                    StatusCode::from_u16(423).unwrap(),
                    "vault_locked",
                    "vault is locked — run `sc up`",
                )
                .into()
            }
        };

        use crate::core::policy::AccessLevel;
        if level == AccessLevel::Deny {
            write_forward_audit(
                &self.state,
                &AuditPending {
                    vault_id: vault_id.clone(),
                    service: service_id.clone(),
                    method: method.clone(),
                    path: path.clone(),
                },
                0,
            );
            return err_response(
                StatusCode::FORBIDDEN,
                "policy_denied",
                "this request is denied by policy",
            )
            .into();
        }

        // The credential bytes come from the session cache (the proxy has no
        // grant to open the vault). Allow / Ask read it; AskAlways burns it
        // single-use. A miss on Ask/AskAlways (or an unexpected miss on Allow)
        // falls through to the captive portal.
        let (primary, secrets_map) = if level == AccessLevel::AskAlways {
            (self.state.cache_take(&vault_id, &conn), None)
        } else {
            (
                self.state.cache_lookup(&vault_id, &conn),
                self.state.cache_lookup_secrets(&vault_id, &conn),
            )
        };

        let values = match self
            .resolve_values(&vault_id, &conn, &service_id, is_oauth, &phantoms, primary, secrets_map)
            .await
        {
            Ok(v) => v,
            Err(ResolveErr::NeedsApproval) => {
                return self
                    .captive_portal(&vault_id, &conn, &service_id, &dest_host, &method, &path, level, rule_id, ttl, ip)
                    .await
            }
            Err(ResolveErr::Ambiguous) => {
                let roles = phantom_role_hint(&conn, def.as_ref());
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "ambiguous_phantom",
                    &format!(
                        "'{}' exposes several secrets — use a role phantom: {}",
                        conn, roles
                    ),
                )
                .into();
            }
            Err(ResolveErr::Exposes(role)) => {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "exposes_unsupported",
                    &format!("connection '{}' role '{}' is not yet mintable", conn, role),
                )
                .into();
            }
            Err(ResolveErr::Mint(msg)) => {
                return err_response(StatusCode::BAD_GATEWAY, "oauth_mint", &msg).into();
            }
            Err(ResolveErr::NotUtf8) => {
                return err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "secret_encoding",
                    "resolved credential is not valid UTF-8",
                )
                .into();
            }
        };

        // ── substitute everywhere + strip shadowing auth, then forward ───────
        let mut parts = parts;
        // URL: rebuild the absolute URI with the substituted path+query. The
        // authority (host[:port]) is preserved from the MITM'd request.
        let (new_pq, _) = resolver::substitute(&pq, |ph| values.get(&ph.raw).cloned());
        if new_pq != pq {
            let authority = parts
                .uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| dest_host.clone());
            if let Ok(u) = format!("https://{}{}", authority, new_pq).parse::<Uri>() {
                parts.uri = u;
            }
        }

        // Headers: substitute values, decode/re-encode Basic, strip proxy/agent
        // auth, drop hop-by-hop; content-length is dropped only if we rewrote
        // the body (hyper re-derives it from the sized body).
        let body_rewritten = body_bytes.is_some();
        let new_headers = rewrite_headers(&parts.headers, &values, body_rewritten);
        parts.headers = new_headers;

        // Body: substitute if we buffered it.
        let out_body = match body_bytes {
            Some(bytes) => match std::str::from_utf8(&bytes) {
                Ok(s) => {
                    let (ns, _) = resolver::substitute(s, |ph| values.get(&ph.raw).cloned());
                    Body::from(ns.into_bytes())
                }
                Err(_) => Body::from(bytes),
            },
            None => orig_body.take().unwrap_or_else(Body::empty),
        };

        self.pending = Some(AuditPending {
            vault_id,
            service: service_id,
            method,
            path,
        });
        Request::from_parts(parts, out_body).into()
    }

    /// Resolve every phantom to its credential string. Errors distinguish
    /// "needs a passkey" (→ portal) from hard misuse (→ 4xx).
    #[allow(clippy::too_many_arguments)]
    async fn resolve_values(
        &self,
        vault_id: &str,
        conn: &str,
        service_id: &str,
        is_oauth: bool,
        phantoms: &[Phantom],
        primary: Option<Vec<u8>>,
        secrets_map: Option<HashMap<String, Vec<u8>>>,
    ) -> Result<HashMap<String, String>, ResolveErr> {
        let mut out = HashMap::new();
        for ph in phantoms {
            let bytes: Vec<u8> = if is_oauth
                && ph.role.as_deref().map(|r| r == "access").unwrap_or(true)
            {
                // The oauth ACCESS phantom: mint from the refresh token (primary).
                let refresh = primary.clone().ok_or(ResolveErr::NeedsApproval)?;
                crate::server::broker_flow::resolve_auth_value(
                    &self.state, vault_id, conn, service_id, &refresh,
                )
                .await
                .map_err(|e| match e {
                    crate::error::AppError::Unauthorized(m) => ResolveErr::Mint(m),
                    other => ResolveErr::Mint(format!("{:?}", other)),
                })?
            } else if is_oauth {
                // A minted-derived `exposes` value (e.g. codex account_id) — the
                // mint doesn't surface these yet.
                return Err(ResolveErr::Exposes(ph.role.clone().unwrap_or_default()));
            } else {
                match &ph.role {
                    Some(r) => secrets_map
                        .as_ref()
                        .and_then(|m| {
                            m.iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case(r))
                                .map(|(_, v)| v.clone())
                        })
                        .ok_or(ResolveErr::NeedsApproval)?,
                    None => match &secrets_map {
                        Some(m) if m.len() > 1 => return Err(ResolveErr::Ambiguous),
                        Some(m) if m.len() == 1 => m.values().next().cloned().unwrap(),
                        _ => primary.clone().ok_or(ResolveErr::NeedsApproval)?,
                    },
                }
            };
            let s = String::from_utf8(bytes).map_err(|_| ResolveErr::NotUtf8)?;
            out.insert(ph.raw.clone(), s);
        }
        Ok(out)
    }

    /// Build + register the captive-portal (ask) op and return the 401 that
    /// surfaces the approve link through a dumb tool's error output.
    #[allow(clippy::too_many_arguments)]
    async fn captive_portal(
        &self,
        vault_id: &str,
        conn: &str,
        service_id: &str,
        host: &str,
        method: &str,
        path: &str,
        level: crate::core::policy::AccessLevel,
        rule_id: Option<String>,
        ttl: Option<u64>,
        ip: IpAddr,
    ) -> RequestOrResponse {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let now = now_secs();
        let ttl_secs = ttl.unwrap_or(DEFAULT_ASK_TTL);

        let role = self
            .state
            .services
            .service_env_key(service_id)
            .unwrap_or_else(|| service_id.to_string());
        let target = crate::storage::plaintext::secret_address(conn, service_id, &role);

        let scope = json!({
            "connection_id": conn,
            "service": service_id,
            "host": host,
            "method": method,
            "path": path,
            "authorize_only": true,
        });
        let op = Operation {
            act: Act { kind: ActType::Use, target, scope },
            bind: Bind { redeemer: vault_id.to_string(), recipient: None },
            valid: Valid::single_use(now, Some(now + ttl_secs)),
        };
        let pc = crate::approval::PolicyContext {
            level,
            rule_id,
            ttl_seconds: ttl_secs,
            host: Some(host.to_string()),
        };

        match crate::server::broker_flow::register_pending_use(
            &self.state,
            vault_id,
            op,
            Some(pc),
            ip,
        ) {
            Ok((op_id, _r, expires_at)) => {
                let approve_url = crate::cli::active::grant_url(&op_id);
                let body = format!(
                    "SafeClaw approval needed to use this credential.\n\
                     Approve with your passkey:\n  {}\n\
                     Then re-run the same command.\n\n\
                     {}\n",
                    approve_url,
                    json!({
                        "status": "pending",
                        "op_id": op_id,
                        "approve_url": approve_url,
                        "poll_url": format!("/op/{}", op_id),
                        "expires_at": expires_at,
                    })
                );
                let mut b = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("x-safeclaw-approve-url", approve_url.as_str())
                    .header("x-safeclaw-op-id", op_id.as_str())
                    .header(header::LOCATION, format!("/op/{}", op_id));
                let interval = crate::approval::store::POLL_INTERVAL_HINT_SECS;
                b = b.header(header::RETRY_AFTER, interval.to_string());
                b.body(Body::from(body))
                    .unwrap_or_else(|_| plain(StatusCode::UNAUTHORIZED, "approval required"))
                    .into()
            }
            Err(e) => err_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_register",
                &format!("could not register approval: {:?}", e),
            )
            .into(),
        }
    }

    /// Host-anchor miss to a public host → DENY + a one-tap widen op (component
    /// C). The 403 body carries the approve link labeled as a permanent grant.
    async fn widen_deny(
        &self,
        vault_id: &str,
        conn: &str,
        host: &str,
        ip: IpAddr,
    ) -> RequestOrResponse {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let now = now_secs();
        let scope = json!({
            "connection_id": conn,
            "host": host,
            "etld1": etld1(host),
        });
        let op = Operation {
            act: Act { kind: ActType::Custom("widen-host".into()), target: String::new(), scope },
            bind: Bind { redeemer: vault_id.to_string(), recipient: None },
            valid: Valid::single_use(now, Some(now + 900)),
        };
        let approve_line = match crate::server::broker_flow::register_pending_use(
            &self.state,
            vault_id,
            op,
            None,
            ip,
        ) {
            Ok((op_id, _r, _exp)) => {
                let approve_url = crate::cli::active::grant_url(&op_id);
                let body = format!(
                    "SafeClaw: connection '{}' is not anchored to '{}'.\n\
                     Approve adding this host as a PERMANENT grant (passkey):\n  {}\n\
                     Then re-run the same command.\n",
                    conn, host, approve_url
                );
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("x-safeclaw-approve-url", approve_url.as_str())
                    .header("x-safeclaw-op-id", op_id.as_str())
                    .header("x-safeclaw-error", "host_not_anchored")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| plain(StatusCode::FORBIDDEN, "host not anchored"))
                    .into();
            }
            Err(e) => format!("(could not open a widen request: {:?})", e),
        };
        err_response(
            StatusCode::FORBIDDEN,
            "host_not_anchored",
            &format!(
                "connection '{}' is not anchored to '{}' {}",
                conn, host, approve_line
            ),
        )
        .into()
    }
}

/// Resolution failure taxonomy — decides portal vs 4xx vs 5xx.
enum ResolveErr {
    /// The credential isn't in the session cache — needs a passkey (→ portal).
    NeedsApproval,
    /// Bare `__sc__conn__` on a connection exposing several secrets.
    Ambiguous,
    /// An oauth2 `exposes` role the mint doesn't surface yet.
    Exposes(String),
    /// The oauth mint failed / the refresh token is dead.
    Mint(String),
    /// The resolved bytes aren't valid UTF-8.
    NotUtf8,
}

// ── free helpers ─────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn merge_phantoms(acc: &mut Vec<Phantom>, more: Vec<Phantom>) {
    for p in more {
        if !acc.iter().any(|x| x.raw == p.raw) {
            acc.push(p);
        }
    }
}

/// Read the vault id from a CONNECT's `Proxy-Authorization: Basic base64("<vid>:")`.
fn vid_from_proxy_auth(req: &Request<Body>) -> Option<String> {
    let h = req.headers().get(header::PROXY_AUTHORIZATION)?;
    let s = h.to_str().ok()?;
    let b64 = s
        .strip_prefix("Basic ")
        .or_else(|| s.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let vid = text.split(':').next()?.trim();
    if vid.is_empty() {
        None
    } else {
        Some(vid.to_string())
    }
}

/// Decode `Authorization: Basic <b64>` to `user:pass`, if present.
fn basic_auth_decoded(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = v
        .strip_prefix("Basic ")
        .or_else(|| v.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn body_is_text(headers: &HeaderMap) -> bool {
    match headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.contains("json")
                || ct.starts_with("text/")
                || ct.contains("x-www-form-urlencoded")
                || ct.contains("xml")
        }
        None => false,
    }
}

/// Rebuild the header map: substitute phantom values, decode/re-encode Basic,
/// strip Proxy-Authorization + any agent Authorization the injected cred
/// replaces, drop hop-by-hop, and drop content-length when the body was rewritten.
fn rewrite_headers(
    headers: &HeaderMap,
    values: &HashMap<String, String>,
    body_rewritten: bool,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if lname == "proxy-authorization" || crate::server::broker_flow::is_hop_by_hop(&lname) {
            continue;
        }
        if body_rewritten && lname == "content-length" {
            continue;
        }
        let Ok(vs) = value.to_str() else {
            out.insert(name.clone(), value.clone());
            continue;
        };
        if lname == "authorization" {
            // Basic → decode, substitute, re-encode; else substitute raw. If no
            // phantom was in it, the agent's own auth is stripped (the injected
            // credential elsewhere is the real one; agents can't shadow it).
            if let Some(rest) = vs.strip_prefix("Basic ").or_else(|| vs.strip_prefix("basic ")) {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        let (new_text, any) =
                            resolver::substitute(&text, |ph| values.get(&ph.raw).cloned());
                        if any {
                            let enc = base64::engine::general_purpose::STANDARD
                                .encode(new_text.as_bytes());
                            if let Ok(hv) =
                                header::HeaderValue::from_str(&format!("Basic {}", enc))
                            {
                                out.insert(header::AUTHORIZATION, hv);
                            }
                            continue;
                        }
                    }
                }
                // Basic with no phantom → strip.
                continue;
            }
            let (new_v, any) = resolver::substitute(vs, |ph| values.get(&ph.raw).cloned());
            if any {
                if let Ok(hv) = header::HeaderValue::from_str(&new_v) {
                    out.insert(header::AUTHORIZATION, hv);
                }
            }
            // No phantom in Authorization → strip (don't forward the agent's own).
            continue;
        }
        // Any other header: substitute in place (no-op if it has no phantom).
        // `append` preserves legitimately repeated headers (e.g. Cookie).
        let (new_v, _) = resolver::substitute(vs, |ph| values.get(&ph.raw).cloned());
        match header::HeaderValue::from_str(&new_v) {
            Ok(hv) => {
                out.append(name.clone(), hv);
            }
            Err(_) => {
                out.append(name.clone(), value.clone());
            }
        }
    }
    out
}

/// A human hint listing a connection's role phantoms (for the ambiguous case).
fn phantom_role_hint(conn: &str, def: Option<&crate::service::ServiceDef>) -> String {
    match def {
        Some(d) => crate::core::host::phantoms_for(conn, d)
            .into_values()
            .collect::<Vec<_>>()
            .join(", "),
        None => crate::core::host::short_phantom(conn),
    }
}

/// Naive eTLD+1 (display only): the last two dot-labels of `host`.
fn etld1(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

fn probe_response() -> Response<Body> {
    let body = json!({ "safeclaw": env!("CARGO_PKG_VERSION"), "proxy": true }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| plain(StatusCode::OK, "ok"))
}

fn plain(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .expect("static response builds")
}

/// A plain-text 4xx/5xx with a machine-readable `x-safeclaw-error` token.
fn err_response(status: StatusCode, code: &str, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-safeclaw-error", code)
        .body(Body::from(format!("{}\n", msg)))
        .unwrap_or_else(|_| plain(status, msg))
}

/// Best-effort terminal audit row for a forwarded (or denied) request. Denies
/// pass `upstream_status = 0`.
fn write_forward_audit(state: &AppState, p: &AuditPending, upstream_status: u16) {
    let Ok(store) = state.audits.for_vault(&p.vault_id) else {
        return;
    };
    let now = now_secs() as i64;
    let status = if upstream_status == 0 {
        crate::audit::STATUS_DENIED
    } else {
        crate::audit::STATUS_ALLOWED
    };
    let row = crate::audit::ApprovalRow {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: now,
        decided_at: Some(now),
        expires_at: now,
        status: status.into(),
        act_kind: "use".into(),
        service: Some(p.service.clone()),
        method: Some(p.method.clone()),
        path: Some(p.path.clone()),
        target: None,
        reason: None,
        credential_id: None,
        upstream_status: if upstream_status == 0 {
            None
        } else {
            Some(upstream_status as i64)
        },
    };
    if let Err(e) = store.insert(&row) {
        tracing::warn!(vault = %p.vault_id, "proxy audit insert failed: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn vid_from_proxy_auth_decodes_userinfo() {
        let req = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b"vault-abc:")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(vid_from_proxy_auth(&req), Some("vault-abc".to_string()));
    }

    #[test]
    fn vid_absent_or_empty_is_none() {
        let none = Request::builder()
            .uri("api.github.com:443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(vid_from_proxy_auth(&none), None);
        // Empty vid (`:` only) is not a routing hint.
        let empty = Request::builder()
            .uri("api.github.com:443")
            .header(header::PROXY_AUTHORIZATION, format!("Basic {}", b64(b":")))
            .body(Body::empty())
            .unwrap();
        assert_eq!(vid_from_proxy_auth(&empty), None);
    }

    #[test]
    fn probe_answers_200_json() {
        let r = probe_response();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn basic_auth_decode_roundtrip() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"x:secret")).parse().unwrap(),
        );
        assert_eq!(basic_auth_decoded(&h).as_deref(), Some("x:secret"));
    }

    #[test]
    fn etld1_takes_last_two_labels() {
        assert_eq!(etld1("foo.bar.github.com"), "github.com");
        assert_eq!(etld1("api.stripe.com"), "stripe.com");
        assert_eq!(etld1("localhost"), "localhost");
    }

    #[test]
    fn rewrite_headers_strips_proxy_auth_and_injects_basic() {
        let mut values = HashMap::new();
        values.insert("__sc__github__".to_string(), "ghp_REAL".to_string());
        let mut h = HeaderMap::new();
        h.insert(header::PROXY_AUTHORIZATION, "Basic Zm9vOg==".parse().unwrap());
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"x:__sc__github__")).parse().unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert!(out.get(header::PROXY_AUTHORIZATION).is_none(), "proxy auth stripped");
        let auth = out.get(header::AUTHORIZATION).unwrap().to_str().unwrap();
        let enc = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(enc).unwrap();
        assert_eq!(decoded, b"x:ghp_REAL", "phantom substituted inside Basic");
    }

    #[test]
    fn rewrite_headers_strips_shadowing_agent_bearer() {
        // The phantom lives elsewhere; the agent's own Authorization must not
        // ride along (it would shadow the injected credential).
        let values: HashMap<String, String> = HashMap::new();
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer agents-own-token".parse().unwrap());
        let out = rewrite_headers(&h, &values, false);
        assert!(out.get(header::AUTHORIZATION).is_none());
    }

    #[test]
    fn rewrite_headers_substitutes_bearer_phantom() {
        let mut values = HashMap::new();
        values.insert("__sc__stripe_key__".to_string(), "sk_live_X".to_string());
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer __sc__stripe_key__".parse().unwrap());
        let out = rewrite_headers(&h, &values, false);
        assert_eq!(
            out.get(header::AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer sk_live_X"
        );
    }

    #[test]
    fn rewrite_headers_drops_content_length_when_body_rewritten() {
        let values: HashMap<String, String> = HashMap::new();
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, "42".parse().unwrap());
        h.insert("x-custom", "keep-me".parse().unwrap());
        let out = rewrite_headers(&h, &values, true);
        assert!(out.get(header::CONTENT_LENGTH).is_none());
        assert_eq!(out.get("x-custom").unwrap(), "keep-me");
    }
}
