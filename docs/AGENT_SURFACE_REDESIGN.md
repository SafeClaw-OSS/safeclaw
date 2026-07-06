# Agent-surface redesign — LOCKED decisions (2026-07-05)

Follows the shipped schema rework (commits `ab08fc3`…`5f9b7e6` on `feat/broker-phantom`
+ `2b20e66` on `feat/broker-phantom-fe`). Build this on the SAME branches, then fold
into canon (`CREDENTIAL_BROKER.md` / `CONNECTION_SCHEMA.md`) + delete this file, then
merge → e2e. Every point is settled with the user via a constraint-first derivation —
do NOT re-litigate. Method that produced these: [[feedback_design_constraints_first]].

---

## BUILD STATUS (2026-07-06)

**SHIPPED on `feat/broker-phantom`** (`6244ca1`→`8a39bb7`; `cargo build` + `cargo test --lib`
196 green): §2 dual-face proxy (`src/proxy/api_face.rs` origin-form → registry/op/health/ca,
loop guard, shared `*_value` projections; verified against hudsucker 0.24.1 `serve_stream`
authority-injection so it can't misfire on MITM'd inner traffic) · §3 direct-GET discovery ·
§4 `sc env` = `DAEMON_URL`+`VAULT_ID` (no key, `VAULT_URL` retired) · §5 `resolve_active`
env-pin = `VAULT_ID` only + single-vault auto-select + `sc status` pin-vs-config · §7 egress
mainstream IP floor (dropped `.internal`/metadata NAME blocks) · §8 proxy verifies the agent
key (`Proxy-Auth` password → `check_token` in `pipeline` BEFORE substitution; keyless
`unlocked_vault` fallback removed; `sc run` threads the key) · §9 all routing-detection
deleted (probe/`is_routed`/helpers) + absolute `poll_url`. **Skill** rewritten (`static/safeclaw-skill.md`).
**Console/backend** (`-fe` + backend `dev`): `VAULT_URL`→`DAEMON_URL`+`VAULT_ID` prose only.

**DEFERRED to morning discussion (§6/§11 key-pre-baking):** the install prompt still uses
`sc agent add` (blind-capture) for the agent key + keeps the pair-token for device pairing.
Pre-baking the key INTO the prompt REVERSES a deliberate security decision in the backend
(`vault-routes.mjs` L393-401: key kept out of the chat transcript) and interacts with device
pairing — a "反复点" the user asked to defer. The e2e WORKS without it: the agent gets
`DAEMON_URL`+`VAULT_ID` from `sc env` and `API_KEY` from `sc agent add` (hash cloud-synced),
and `sc run` derives `PROXY_URL` from `VAULT_ID`+`API_KEY`. Discuss the transcript-security
tradeoff + device-pairing-token fate, then build.

**Adversarial review** (6-dim workflow) run before handoff; findings triaged in memory.

---

## DESIGN WAVE 2026-07-06 — authoritative mental model + atomic-env (POST-E2E cleanup; local build unaffected)

Discussion-derived, self-consistency-reviewed. This SUPERSEDES the port/env framing scattered
below and REVISES §5's implementation (same direction, cleaner). All of it is a **post-e2e
cleanup** — the current local build is correct (everything defaults to `127.0.0.1`, so nothing
splits); build this after the user's e2e.

### A. The authoritative mental model — three planes, and WHO is the client
| plane | port | the CLIENT is | auth | for |
|---|---|---|---|---|
| **data (proxy)** | :23294 | the **agent's runtime** (its HTTP client + `sc run`-launched children) | agent-key | discovery (`/v/{vid}/registry`, `/op`, `/health`, `/ca`) + broker credentials |
| **control** | :23295 | the **`sc` CLI** (human directly, or agent via a shelled `sc up`) | passkey / localhost | unlock, connect, approve, status |
| **account** | cloud :443 | the **`sc` CLI** (`login`/`logout`, `agent add/ls/rm`) | device-key (pair-token bootstraps it) | pair devices, mint agent-keys, hash registry, blob sync, op-relay |

One-liner that ends the confusion: **the agent's own traffic touches ONLY the proxy port (:23294);
`sc` is a control/account tool that talks to :23295 + the cloud and is NEVER a client of the proxy
port; `sc run` doesn't *use* the proxy, it *launches a child* onto it.** When an agent "runs sc",
that is the `sc` CLI acting on the control/account plane — not the agent's data flow. `sc status` /
`sc git-credential` discovery hits the CONTROL port's `/registry` (:23295); the AGENT's discovery
hits the proxy port's API face (:23294) — same projection, two ports, two audiences.

### B. Two ports STAY (reframed) — data/control-plane separation
The split is the classic data-plane/control-plane pattern (Envoy admin vs data, etcd client vs peer,
DBs). Reframe from "the proxy MUST be loopback" (too absolute) to: **two independently-exposable
planes; the proxy DEFAULTS to loopback as a safe default, not a permanent law.** Independent exposure
(expose the proxy to an agent fleet without exposing admin, or vice-versa) *requires* independent
listeners → two ports. Exposing the proxy remotely is a valid FUTURE capability, gated on: (1) TLS on
the client→proxy leg, (2) the api-key hardened to a network-grade secret (rotation/rate-limit/lockout),
(3) the remote daemon being the USER's own infra (a vendor-run proxy would see the substituted
credential → breaks cloud-blind). The account plane (cloud) is ALREADY the authed remote surface for
account ops; "expose :23295" is a narrower remote-manage-this-daemon need.

### C. Atomic env — atoms are truth, `_url`s are DERIVED, agent stays at `_url`
- **Atoms (source of truth):** `DAEMON_HOST` (scheme+host) · `PROXY_PORT` · `CONTROL_PORT` · `VAULT_ID`,
  plus the agent's `API_KEY` (identity, not a routing atom — routing ⊥ principal). Device config holds
  the atom DEFAULTS (`http://127.0.0.1` / `23294` / `23295`); user may hand-edit + restart (no
  convenience tooling — manual is fine for the advanced case).
- **`_url`s are NEVER stored — always derived from atoms.** Device-side this is LIVE (`sc` derives on
  every run, so a hand-edited atom takes effect on restart → "self-consistent playability"). The
  agent's env is a mint-time SNAPSHOT (the minter derived it from the atoms once); changing atoms
  means re-minting the agent env.
- **Two SSOTs at two levels, bridged ONCE at mint — the agent never treats `sc` as its source.**
  The DEVICE SSOT is config atoms (used by the daemon's bind + the human's `sc`). The AGENT SSOT is the
  agent's OWN `.env`: the minter projects the device atoms into ready `_url`s and writes them there ONCE
  (mint time). At runtime the agent reads its `.env` for its own HTTP — it does NOT re-derive from atoms
  and does NOT call `sc` to learn its own vars. A `sc` the agent shells INHERITS that same `.env`
  (env-first, §5), so the agent's HTTP and its shelled `sc` share ONE SSOT automatically — the split
  can't arise from cross-derivation. So assembly (atoms → `_url`) happens at the **mint dimension**, off
  the agent's reasoning (assembly = silent-error surface). **Agent required surface =
  `DAEMON_URL` + `VAULT_ID` + `API_KEY` (3)**, all read from its `.env`; `PROXY_URL` demoted to optional
  (`sc run` derives it). Sub-choice: the `.env` carries `DAEMON_URL` only and `sc` derives control from
  its host (3 vars, control-port defaulted — recommended), OR carries an explicit control endpoint too
  (zero runtime derivation, handles a custom remote control port) — the agent's mental surface is 3
  either way (it ignores the control var).

### D. THE self-consistency invariant (the crux — must be encoded)
**Proxy and control ALWAYS derive from the SAME daemon host.** Concretely: when an agent shells `sc`,
`resolve_active` derives the control root from the **agent's own `DAEMON_URL` host** (+ `CONTROL_PORT`),
NOT from device config. So an agent's proxy face and its shelled-`sc` control face are the same daemon
by construction → they **cannot split**. Worst case is a stale snapshot (agent points at an old daemon)
= a clean, uniform failure (both faces fail together), never half-working. This REVISES §5's
implementation: `resolve_active` reads `DAEMON_URL`'s host (not only `VAULT_ID`), and
`proxy_url_for_vault` takes a host instead of hardcoding `127.0.0.1` — same env-first direction, no
split. (If code ever lets `sc` take the host from config while the agent uses its env `DAEMON_URL`, the
split returns — this is the one invariant to hold.)

**Scoped boundary (not a problem now):** `DAEMON_URL` carries scheme+host+`PROXY_PORT` but NOT
`CONTROL_PORT`, so `sc` supplies the control port from the default constant — correct for local +
remote-with-default-ports. A remote daemon on a NON-default control port would add `CONTROL_PORT` to
the agent env; doesn't exist yet.

### E. Settled sub-decisions
- **CA:** `ca.pem` (public cert) is distributable — the `/ca` endpoint serves it (done); `ca.key`
  (private) never leaves (loopback + `chmod 600`). Remote = copy the PUBLIC cert (safe). Local-first,
  remote via manual public-cert copy; security-first — no private-key exposure ever.
- **Account plane = device axis (`login`/`logout`) + agent axis (`agent *`), both account-level,
  device-key authed.** Add a `sc device` group with `login`/`logout` as aliases (symmetry with `agent`).
  Key minting is inherently a backend op (shared hash registry + device-key auth) — NEVER on the
  daemon's localhost ports.
- **`known_vaults` → its own file** (like `~/.ssh/known_hosts`: append-growing, harmless to delete),
  separate from the active-selection/account config.
- **CA path override + remote `sc run`:** `sc run`'s proxy is already env-overridable
  (`$SAFECLAW_PROXY_URL`); make the CA path overridable too, so a hand-configured remote daemon works
  (default local, remote via manual config). run/env are local-by-DEFAULT, not local-by-necessity.

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
- **API face** — origin-form `GET /v/{vid}/registry`, `GET /op/{id}`, `GET /health`,
  `GET /ca` → self-answer a READ-ONLY subset (discovery/poll + fetch the resident CA, §10).
  `/health` + `/ca` are unauthenticated (liveness / public cert); `/registry` + `/op` require
  the Bearer key (§8).
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

## 4. The agent's four env vars — delivered by its install prompt (§11), copied VERBATIM
```
SAFECLAW_DAEMON_URL=http://127.0.0.1:23294               # API face: GET $DAEMON_URL/v/$VAULT_ID/registry, /op/<id>
SAFECLAW_VAULT_ID=<vid>                                  # discovery path param + the proxy-auth username
SAFECLAW_API_KEY=<key>                                   # agent identity — Bearer on the API face; §8
SAFECLAW_PROXY_URL=http://<vid>:<key>@127.0.0.1:23294    # proxy face: vid=user, api-key=password (Proxy-Auth); §8
```
Four vars — the api-key is the agent's auth to BOTH faces (§8), riding the API-face
`Authorization: Bearer` AND the proxy-face `Proxy-Authorization` password. **These four are
the AGENT's config, delivered by its install prompt (§11) — NOT by `sc env`** (that is the
device/human's tool). Whoever mints the connection (console / local CLI) knows the vid + the
new key + the daemon address, so it pre-assembles all four; the agent copies each verbatim
(incl. `PROXY_URL`, so the agent never does userinfo surgery).
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
silent-error surface, same rule as "copy the phantom, never build it") — hence the prompt
pre-bakes `PROXY_URL` rather than making the agent splice userinfo. The port is `PROXY_PORT`
(23294): the agent's `DAEMON_URL` is the API face, not the control root. `$SAFECLAW_VAULT_URL`
(the combined URL) is RETIRED; **`$SAFECLAW_API_KEY` STAYS** (§8). The agent never sets a
global `HTTPS_PROXY` (that would route everything = the rejected blast-radius model); `sc run`
sets `HTTPS_PROXY`+CA on the CHILD from the agent's own `PROXY_URL`.

## 5. Vault selection — snapshot binding; `sc` and agent stay consistent via env-pin precedence
- **Binding = SNAPSHOT, not live.** The agent's vault is fixed by its env (from its install
  prompt, §6/§11); the human's `sc vault use` changes the DEVICE's durable default
  (`config.toml`) → affects the human's shell + future connections, NOT a running agent. Divergence is LEGITIMATE (stability >
  auto-follow), matching env-at-exec (`AWS_PROFILE`) + the canonical "agent⊥vault". **Do NOT
  live-resolve the vault from config in the proxy/discovery paths** — that would rebuild the
  rug-pull.
- **`resolve_active` precedence (REVISES [[project_vault_selection_env_model]]'s "must NOT
  read env"):** the env pin overrides only the **VAULT** — `vault = --vault flag >
  $SAFECLAW_VAULT_ID (env pin) > config.vault`; the **daemon CONTROL root ALWAYS comes from
  config.toml**, never from env. Why the asymmetry (a real port trap): `$SAFECLAW_DAEMON_URL`
  is the agent's API face (`:23294`, read-only), but shelled control/ceremony (`sc up` / `op` /
  `approve` / `unlock`) lives ONLY on the control root (`:23295`) — feeding DAEMON_URL in as the
  `daemon` would send `sc up` to the read-only face and silently fail. So the two worlds stay
  separate: the agent's OWN http uses its env `DAEMON_URL` (`:23294`); the agent's shelled `sc`
  control uses config's control root (`:23295`); the **VAULT_ID pin is the only bridge**, making
  shelled `sc` target the SAME vault as the agent's http. Mainstream (env overrides file for the
  VARYING axis — `AWS_PROFILE`, `kubectl` — while the server address stays in the config file).
  This is the ONE choke point every `sc` command routes through → up/status/run/git-credential/env
  all honor the agent's vault pin. The old "must NOT read env" was combined-URL-era + protected
  `sc vault use`; the clean selector + agent-consistency make env>config correct for the vault
  axis. Human ergonomics preserved: fresh shell (no env) → config → `sc vault use` works; pinned
  shell → its VAULT_ID pin, switch via re-eval or `--vault` (identical to exported `AWS_PROFILE`).
- **Single-vault auto-select:** a daemon with exactly one vault → `resolve_active` defaults
  to it (no `sc vault use`, nothing in the install prompt). Divergence can't even occur in
  the common single-vault case.
- **`sc status` visibility** (build it now, testable at e2e): show config's default vault vs
  the current shell's pinned vault, and flag a mismatch ("shell pinned to A; default is B;
  `eval \"$(sc env)\"` to move this shell").

## 6. Install / bootstrap — the prompt IS the agent's config (all four vars, key included)
The install prompt is the agent's self-contained config source (§4 / §11), generated per
agent×vault connection. Whoever mints it (the console for a remote vault, local `sc` for
self-host) knows the daemon URL + the vault id + a freshly-minted per-agent key, so it emits
the four ready-to-paste vars (`SAFECLAW_DAEMON_URL` / `VAULT_ID` / `API_KEY` / `PROXY_URL`).
The agent sets them in its OWN env/config and holds them — **the agent manages its own key**
([[project_vault_agent_architecture]]). Per-agent by construction: a second agent gets its own
prompt → its own key → `sc agent rm` revokes just that one. The key IS in the prompt (the
intuitive place — it's per-agent, not device state); it's account-level, so treat a leaked
prompt like a leaked key (revoke + re-issue). This RETIRES the earlier vault-scoped pair-token
idea — the prompt carries the four vars directly, simpler. `config.toml` (the device/human's
active vault + catalog) is a SEPARATE source, unaffected; `sc env` bridges it for the human's
own shell, not the agent.

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
- **Where the check lives (build — the infra ALREADY exists, this is just wiring):** the auth
  primitives are done — `AppState.agent_key_hashes` is a BLOB-EXTERNAL in-memory set (works while
  the vault is locked → no deadlock), populated by `sync_agent_keys_once` (pre-serve) + the 30s
  `sync_agent_keys_loop` off the `.pro` `/api/vault/agents/hashes` endpoint, and `api_key::check` /
  `check_token` are reusable. So: **API face reuses `api_key::check` (Bearer) AS-IS**; **proxy face**
  adds a Proxy-Auth Basic decoder (extract the password beside the vid in `vid_from_proxy_auth`)
  feeding the same `check_token`. The check runs in `handler.rs::pipeline` **before**
  `resolve_values`/substitution — NOT in `should_intercept` (returns bool, can't 407). The keyless
  `unlocked_vault()` fallback (pipeline, `vid==None`) is the exact hole → must NOT broker without a
  verified key. **Absent** Proxy-Auth → BLIND-TUNNEL (non-participating: the phantom reaches
  upstream literally → clean 401, preserves §1 blast-radius); **present-but-wrong** key → 407.
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
  connections projection, and the pin-vs-config vault view (§5).
- **No magic host at all** (probe retired) → `.internal` is purely §7's over-reach fix.
- **`poll_url` absolute.** The captive-portal 401 currently returns a RELATIVE `poll_url`
  (`/op/<id>`) — emitted while proxying e.g. a gmail request, it resolves against gmail's
  domain. Make it absolute: `$SAFECLAW_DAEMON_URL/op/<id>` (the 23294 API face).

## 11. Who owns the key: the AGENT, not the device — the prompt delivers it, `sc env` never emits it
The entity model settles this. **Routing (which daemon + vault) and principal (which agent =
the key) are ORTHOGONAL, with different owners.** The key is per-agent (agent ≡ api-key,
account-level revoke/audit — [[project_vault_agent_architecture]]), so it is the AGENT's:
delivered by the AGENT's install prompt (§6), held in the agent's own env/config. It is NOT
device state.
- **`sc env` does NOT emit the key** (nor a key-bearing `PROXY_URL`). `sc env` / `config.toml`
  are the DEVICE/human's config (the human's active vault + catalog). Baking a per-agent key
  into a device-level `sc env` would collapse every agent on the device to ONE key — losing
  per-agent revocation/audit. (This corrects an earlier draft of this section that proposed
  local key-persistence + `sc env` emitting it — that conflated device and agent ownership.)
- **The install prompt pre-bakes all four vars** (§4), incl. `PROXY_URL` with the key already
  in the userinfo — the minter (console / local `sc`) knows vid+key+daemon, so the agent
  copies verbatim, zero assembly. Blind-capture is dropped: the key IS in the prompt (the
  intuitive, per-agent place). Minting registers the key's hash so the daemon accepts it
  (cloud-synced, or locally seeded — §10).
- **`sc run` / `sc status`, shelled by the agent, read the agent's OWN env** (via §5's env-pin
  precedence): `sc run` propagates the agent's `PROXY_URL`+CA to the child; it never owns or
  persists the key. The human's own control-plane `sc` (op / approve / passkey) needs no key.

Setup chain, end to end:
```
mint a connection (console for a remote vault / local `sc` for self-host)
  → prompt = the 4 pre-baked vars incl the per-agent key   [+ register the key's hash → daemon accepts it]
  → agent pastes them into its own env/config, holds them (agent manages its own key)
  → daemon: verify key ∈ agent_key_hashes (§8) + route by vid + policy   →  discover + use
config.toml (device/human) is a SEPARATE source; `sc env` bridges it for the human's shell only.
```

## 10. Open / implementation notes (resolve during build, not design forks)
- **CA trust for self-construct (gmail via the agent's own HTTP client) — RESOLVED via `/ca`.**
  A request the agent proxies to a MITM'd host gets our resident-CA leaf → the client must
  trust our CA. The CA is DEVICE-local (per-daemon `ca.pem`), so it can't ride the
  (possibly remote-minted) prompt. Resolution: the API face serves `GET $DAEMON_URL/ca` (the
  resident CA PEM — a public cert, unauthenticated, like mitmproxy's `mitm.it`); the agent
  fetches it and trusts it ADDITIVELY in its self-construct client (never replace the system
  bundle). Dumb tools keep using `sc run` (which sets the CA vars). `/ca` added to §2.
- **Key-hash timing (VERIFIED against code — NOT a blocker).** `agent_key_hashes` is in-memory /
  blob-external, so the check works with the vault locked (agent can auth → see `locked:true` →
  `sc up`; no deadlock). The plumbing exists: `.pro` `/api/vault/agents/hashes` +
  `sync_agent_keys_once` (pre-serve) + a 30s `sync_agent_keys_loop`. A cloud-paired daemon accepts
  account keys from startup; a key minted AFTER startup lands within ≤30s, and human-paced e2e
  (add → copy prompt → paste → run) absorbs that window. OPTIONAL hardening (not required for e2e):
  re-sync on a 407 miss so a just-minted key skips the wait.
- **The agent must DURABLY hold its four vars** (from the prompt) in its own config, not a
  transient shell — `sc env` can't re-supply them (device-only, no key). The install prompt
  must say so.
- **SaaS-proxy / cloud-blindness** is a separate deployment concern (out of scope for the
  local e2e): the MITM proxy must stay LOCAL even for a hosted vault — a remote proxy would
  see the substituted real credential. The e2e is local self-host, so daemon + proxy + CA are
  all on the device.
- **No unpaired-daemon key source needed (was a worry, now MOOT).** There is no unpaired daemon
  in the model: the broker plane needs agent-key management (lives in the backend), so a daemon is
  either cloud-paired (`.pro` or a self-hosted backend → the sync path above) or has the broker
  plane OFF (`state.rs`: "an unpaired/local-only daemon has no broker plane to gate"). The e2e
  daemon is cloud-paired via `sc login`, so `sc agent add` → backend → sync just works — no
  local-only key-seed path to build.
- **Stale local `config.toml`** on the dev box has `daemon = …:23294` (pre-swap) — a fresh
  enroll writes the correct control root; not a code bug.
- The registry/op projections currently live as axum handlers on 23295 — refactor the
  read-only ones into shared functions the 23294 API face can call (given state + vid).

---

## Build order (post-compact, one pass on `feat/broker-phantom` + `-fe`)
core: (a) proxy 23294 API face — dispatch origin-form → read-only `/v/{vid}/registry`,
`/op/{id}`, `/health`, `/ca` (resident CA PEM); loop guard; share the projections. (b) retire routing-detection
(is_routed / probe / §8 routing block + helpers) → `sc status` = direct health + connections
+ the pin-vs-config vault view. (c) `sc env` = DEVICE/human config only — emit
`SAFECLAW_DAEMON_URL` + `SAFECLAW_VAULT_ID` for the human's shell, NO key, no global
`HTTPS_PROXY`; retire `$SAFECLAW_VAULT_URL`. The AGENT's four vars (incl `PROXY_URL`=`<vid>:<key>@`)
are minted into its install prompt (§6/§11), NOT emitted by `sc env`. (d) `resolve_active` →
`--vault > env pin > config`; single-vault auto-select; `sc status` pin-vs-config mismatch.
(e) MOVE the api-key check onto the proxy (Proxy-Auth password) + the API face (Bearer); a
local/unpaired daemon must accept a locally-issued key. (f) egress floor = mainstream IP
ranges + localhost names only (drop the `.internal`/metadata name blocks). (g) `poll_url`
absolute. Then: skill (opt-in; discover = direct `GET $DAEMON_URL/v/$VAULT_ID/registry` +
Bearer; use = phantom via `sc run` / `--proxy $PROXY_URL`; drop routing-preflight; REVERT
'local needs no api-key'), console/backend (the connect-agent install prompt emits the 4
pre-baked vars incl the per-agent key + registers its hash; drop the pair-token; `sc env`
device-only), tests, `cargo build`/`test`/console `tsc`, fold into canon + delete, then merge → e2e.
