# Agent-surface redesign — LOCKED decisions (2026-07-05)

Follows the shipped schema rework (commits `ab08fc3`…`5f9b7e6` on `feat/broker-phantom`
+ `2b20e66` on `feat/broker-phantom-fe`). Build this on the SAME branches, then fold
into canon (`CREDENTIAL_BROKER.md` / `CONNECTION_SCHEMA.md`) + delete this file, then
merge → e2e. Every point is settled with the user via a constraint-first derivation —
do NOT re-litigate. Method that produced these: [[feedback_design_constraints_first]].

---

## 1. Opt-in, NOT a mandatory proxy
Normal traffic goes DIRECT and untouched. Only credential traffic — a request the agent
DELIBERATELY writes a phantom into — is routed through the proxy (via `sc run --`, or a
per-request `--proxy $SAFECLAW_PROXY_URL`). We do NOT require a global `HTTPS_PROXY`.
Why (hard architectural reasons): (a) a credential broker must not sit in the critical
path of non-credential traffic — a dead daemon must degrade ONLY vault features, not all
egress; (b) child-scoping is the positioning pillar (not "全机器流量"); (c) the agent is
smart enough to opt in — writing a phantom IS the opt-in signal (dumb tools need a blanket
proxy; agents don't). Failure mode is safe: a phantom sent unrouted reaches the upstream as
a literal string → clean 401, never a leak.

## 2. Single port, dual-face (the 0x5AFE port serves both)
`PROXY_PORT` (23294) is the agent's ONLY port. One listener, dispatched by RFC 7230 §5.3
request-line form:
- **proxy face** — `CONNECT host:443` or absolute-form `GET http://host/…` → MITM /
  blind-tunnel (existing behavior). Loop guard: an absolute-form request whose authority ==
  self is treated as a direct request (answer, never forward) — standard Squid/Privoxy move.
- **API face** — origin-form `GET /v/{vid}/registry`, `GET /op/{id}`, `GET /health` →
  self-answer a READ-ONLY subset. This is what the agent hits directly for discovery/poll.
`CONTROL_PORT` (23295) keeps every WRITE/ceremony route (op create/approve/reject, passkey,
pending-passkey, events, approvals, secret-keys, usage, sync, admin, pubkey, skill.md, the
static `/registry`) — CLI + human only, invisible to the agent. Precedent: Privoxy/Squid
serve a management page + proxy on one port. hudsucker hook: origin-form currently lands in
`handle_request`'s `uri().host()==None → forward` branch (which fails) — route it to the API
responder instead. Security bonus: the agent-reachable API face is an explicit read-only
whitelist; writes stay passkey-gated on 23295.

## 3. Discovery + op-poll are a plain DIRECT GET (never through the proxy)
Discovery carries no phantom → it doesn't need the proxy. Routing it through the proxy
(an earlier idea) taxed the agent's single most reliable primitive ("GET a URL, parse
JSON") with proxy ceremony — rejected. So:
`GET $SAFECLAW_DAEMON_URL/v/$SAFECLAW_VAULT_ID/registry` and `…/op/{id}` — plain, direct,
to the 23294 API face. This is consistent with opt-in (no phantom ⇒ no proxy).

## 4. Env vars — `sc env` emits all, agent copies VERBATIM (zero assembly)
```
SAFECLAW_DAEMON_URL=http://127.0.0.1:23294               # API face: GET $DAEMON_URL/v/$VAULT_ID/registry, /op/<id>
SAFECLAW_VAULT_ID=<vid>                                  # discovery path param + the proxy-auth username
SAFECLAW_API_KEY=<key>                                   # agent identity — Bearer on the API face; §8
SAFECLAW_PROXY_URL=http://<vid>:<key>@127.0.0.1:23294    # proxy face: vid=user, api-key=password (Proxy-Auth); §8
```
Four vars (was three) — the api-key is the agent's auth to BOTH faces (§8), so it rides the
API-face `Authorization: Bearer` AND the proxy-face `Proxy-Authorization` password. It
appears in `API_KEY` + inside `PROXY_URL` (like vid appears in `VAULT_ID` + `PROXY_URL`);
single source = config's paired key, `sc env` derives atomically.
Two channels carry `(vid, key)` two different ways — this is the load-bearing distinction
(don't conflate a REQUEST url with a PROXY url):

| channel | what it is | vid | key | fetch-safe because |
|---|---|---|---|---|
| **API face** (discovery, op-poll) | a normal request TO the daemon (`fetch($DAEMON_URL/v/$VAULT_ID/registry)`) | URL **path** | `Authorization: Bearer` **header** | the request URL (`DAEMON_URL`) is userinfo-free |
| **proxy face** (credential traffic) | a request THROUGH the daemon as a proxy | proxy-userinfo **username** | proxy-userinfo **password** | a PROXY url is not a request url — userinfo is the standard proxy-auth channel |

Hard constraints that force this shape (four single-purpose vars, zero assembly):
- **`fetch()` throws on a REQUEST url with credentials** (WHATWG) → `DAEMON_URL` must be
  userinfo-free → it can't also be the proxy URL. Key rides a `Bearer` header, vid rides the
  path.
- **an HTTPS proxied request is a `CONNECT`** → its only auth channel is `Proxy-Authorization`,
  which the client derives from the PROXY url's userinfo → `PROXY_URL` carries `<vid>:<key>@`.
  This rule does NOT hit the fetch restriction (it's a proxy url, not a request url), and the
  SHIPPED design already carries the vid here (`<vid>:@`, empty pw) across tools — the key
  just fills the empty password slot (same mechanism, no new risk).
- daemon side: API face reads `Bearer <key>` + the path vid; proxy face decodes
  `Proxy-Authorization: Basic base64("<vid>:<key>")` → vid (route) + key (verify, §8). No
  request url ever carries credentials.
Soft principle: every agent-facing value is copied verbatim, never assembled (assembly =
silent-error surface, same rule as "copy the phantom, never build it"). vid appears in
`VAULT_ID` + inside `PROXY_URL`, but the single source is `config.toml` and `sc env` derives
atomically (AWS's `ACCESS_KEY_ID`/`SECRET`/`REGION` model). `sc env` emits the port as
`PROXY_PORT` (23294) — the agent's DAEMON_URL is the API face, NOT config's control root.
`$SAFECLAW_VAULT_URL` (the combined URL) is RETIRED; **`$SAFECLAW_API_KEY` STAYS** (§8 — it's
the agent's auth, not vestigial). `sc env` emits these four — NOT a global `HTTPS_PROXY`
(that would route everything = the blast-radius model we rejected); `sc run` still sets
`HTTPS_PROXY`+CA vars for the CHILD.

## 5. Vault selection — snapshot binding; `sc` and agent stay consistent via env-pin precedence
- **Binding = SNAPSHOT, not live.** The agent pins its vault at env-materialization; the
  human's `sc vault use` changes the durable DEFAULT (`config.toml`) → affects future
  launches + fresh-shell CLI, NOT a running agent. Divergence is LEGITIMATE (stability >
  auto-follow), matching env-at-exec (`AWS_PROFILE`) + the canonical "agent⊥vault". **Do NOT
  live-resolve the vault from config in the proxy/discovery paths** — that would rebuild the
  rug-pull.
- **`resolve_active` precedence (REVISES [[project_vault_selection_env_model]]'s "must NOT
  read env"):** `--vault flag  >  $SAFECLAW_VAULT_ID / $SAFECLAW_DAEMON_URL (env pin)  >
  config.toml`. Mainstream (env overrides file: `AWS_PROFILE`, `kubectl`). This is the ONE
  choke point every `sc` command routes through → up/status/run/git-credential/env all honor
  the agent's pin, so the agent's shelled-out `sc` calls match its own HTTP. The old "must
  NOT read env" was combined-URL-era + protected `sc vault use`; the clean 3-var selector +
  the agent-consistency principle make env>config correct. Human ergonomics preserved: fresh
  shell (no env) → config → `sc vault use` works; pinned shell → its pin, switch via re-eval
  or `--vault` (identical to exported `AWS_PROFILE`).
- **Single-vault auto-select:** a daemon with exactly one vault → `resolve_active` defaults
  to it (no `sc vault use`, nothing in the install prompt). Divergence can't even occur in
  the common single-vault case.
- **`sc status` visibility** (build it now, testable at e2e): show config's default vault vs
  the current shell's pinned vault, and flag a mismatch ("shell pinned to A; default is B;
  `eval \"$(sc env)\"` to move this shell").

## 6. Install / bootstrap — vault identity enters ONCE, via the pairing token
Steady state is generic (3 vars from `sc env`; agent reads `$SAFECLAW_VAULT_ID`, never
hardcodes). The vault identity is public routing info (not a secret). It enters at bootstrap:
- **local single vault** → `sc vault create` / web-enroll already wrote it to config →
  nothing in the prompt.
- **local multi vault** → `sc vault use <id>`.
- **remote / connect-a-new-agent** → the console issues a **vault-scoped pair token** (bound
  to THAT vault); redeeming writes `(daemon, vault)` to config. The prompt carries only the
  token — the raw vault id never appears. (Same "key-out-of-prompt" slot as
  [[project_install_prompt_onboarding_redesign]].)

## 7. Egress floor — just mainstream SSRF hygiene, no name special-cases
`host_is_blocked_name` over-reaches (blocks all `.internal` + special-cases
`metadata.google.internal`). Mainstream forward proxies do NEITHER. Reduce to the standard:
- **block literal private/loopback/link-local/multicast/unspecified IP ranges** (`127/8`,
  `10/8`, `172.16/12`, `192.168/16`, `169.254/16` — the metadata IP falls in this range, so
  it's covered without naming it — `::1`, `fc00::/7`, …). This is `host_is_blocked_ip`; keep.
- **block the RFC-6761 loopback names** `localhost` / `*.localhost`.
- **allow every other name**, including `*.internal` and `metadata.google.internal`. A
  credential only reaches a host a HUMAN deliberately anchored (curated-service PR / `sc
  connect` behind a passkey), and we don't resolve DNS at egress — so there's no default-
  reachable SSRF to name-block against. No `safeclaw.internal` reservation (§9: no magic host).

## 8. The api-key IS the agent's auth — MOVE the check onto the live proxy (fixes a real hole)
NOT vestigial. The trust boundary is NOT "localhost" — a machine runs many agents/processes,
any of which could send a phantom. The api-key is the AGENT's identity (agent ≡ api-key,
account-level — [[project_vault_agent_architecture]]); it scopes + revokes per-agent access.
**The real bug:** the phantom-only pivot moved the broker to the proxy but LEFT the api-key
check on the dead `/export` stub — so the live proxy currently authenticates NOBODY; any
localhost process with the public vid can use an unlocked vault's allow-level creds. Fix —
**move the check onto both faces, don't delete it:**
- **proxy face:** carry the key in the Proxy-Auth PASSWORD slot —
  `Proxy-Authorization: Basic base64("<vid>:<api-key>")` (today it's `<vid>:`, empty pw). The
  proxy verifies `sha256(key) ∈ agent_key_hashes` BEFORE substituting any phantom; miss → 407.
- **API face (discovery/op):** `Authorization: Bearer <api-key>`; same check.
- Keep `$SAFECLAW_API_KEY`; `$SAFECLAW_PROXY_URL` embeds it in the password. **Revert the
  skill's "local daemon needs no api-key"** (that was my error).
- "localhost-only justifies it" still holds: the key needn't be a strong network secret
  (loopback surface); a same-user process that reads the agent's env can steal it — out of
  scope, same as any env-var secret. The key's job is per-agent identity / scoping /
  revocation, not perfect same-user isolation.

## 9. Simplifications the opt-in decision unlocks (delete, don't build)
- **Retire ALL routing-detection.** In opt-in the agent routes every vault request EXPLICITLY
  → the "phantom sent unrouted" state is unreachable → detection is dead code. Delete
  `is_routed`, the through-proxy liveness probe (`PROBE_HOST`/`probe_response`/`PROBE_URL`/the
  `probe_via` routing use), and the §8 `sc status` routing block (`https_proxy` raw value +
  `ca_trust` introspection, and the `raw_https_proxy`/`ca_trust_vars`/`proxy_reachable`
  helpers). `sc status` keeps: daemon liveness via a DIRECT `GET $DAEMON_URL/health`, the
  three vars, and the connections projection.
- **No magic host at all** (probe retired) → `.internal` is purely §7's over-reach fix.
- **`poll_url` absolute.** The captive-portal 401 currently returns a RELATIVE `poll_url`
  (`/op/<id>`) — emitted while proxying e.g. a gmail request, it resolves against gmail's
  domain. Make it absolute: `$SAFECLAW_DAEMON_URL/op/<id>` (the 23294 API face).

## 10. Open / implementation notes (resolve during build, not design forks)
- **CA trust for the self-construct case (gmail via the agent's own HTTP client).** A request
  the agent proxies to a MITM'd host gets our resident-CA leaf → the client must trust our
  CA. `sc run` sets the CA vars for a child; for the agent's OWN client, confirm the path
  (either the agent runs the request under `sc run`, or its client trusts `ca.pem`). Do NOT
  emit a global `SSL_CERT_FILE` from `sc env` that would REPLACE the system bundle for
  non-MITM'd hosts — prefer additive (`NODE_EXTRA_CA_CERTS`) or `sc run` scoping.
- **Local api-key source (§8).** `agent_key_hashes` empty ⇒ reject everything (paired-cloud
  model). A local/unpaired daemon must accept a locally-issued key (via `sc agent add`) so
  the e2e agent can authenticate; confirm the daemon seeds its own hash set locally, not only
  from cloud sync.
- **Stale local `config.toml`** on the dev box has `daemon = …:23294` (pre-swap) — a fresh
  enroll writes the correct control root; not a code bug.
- The registry/op projections currently live as axum handlers on 23295 — refactor the
  read-only ones into shared functions the 23294 API face can call (given state + vid).

---

## Build order (post-compact, one pass on `feat/broker-phantom` + `-fe`)
core: (a) proxy 23294 API face — dispatch origin-form → read-only `/v/{vid}/registry`,
`/op/{id}`, `/health`; loop guard; share the projections. (b) retire routing-detection
(is_routed / probe / §8 routing block + helpers) → `sc status` = direct health + 3 vars +
connections. (c) `sc env` → emit `SAFECLAW_DAEMON_URL` + `SAFECLAW_VAULT_ID` +
`SAFECLAW_PROXY_URL` (drop VAULT_URL/API_KEY, no global HTTPS_PROXY). (d) `resolve_active` →
`--vault > env pin > config`; single-vault auto-select; `sc status` pin-vs-config mismatch.
(e) MOVE the api-key check onto the proxy (Proxy-Auth password) + the API face (Bearer);
ensure a local/unpaired daemon has a working local api-key source. (f) egress floor =
mainstream IP ranges + localhost names only (drop the `.internal`/metadata name blocks). (g)
`poll_url` absolute. Then: skill (opt-in; discover = direct GET to `$DAEMON_URL`; use = phantom via
`sc run` / `--proxy $PROXY_URL`; drop routing-preflight prose), console/backend (vault-scoped
pair token; `sc env` 3-var; any `$SAFECLAW_VAULT_URL` references), tests, `cargo build`/`test`
/console `tsc`, fold into canon + delete this file, then merge → e2e.
