# Streaming / Transparent-Proxy Approval ("captive portal for secret-use")

> **⚠️ PARTIALLY SUPERSEDED (2026-07-03 phantom-only pivot).** The `/stream` endpoint this doc anchors on is retired; the captive-portal approval mechanism itself (reject-before-forward + SSE link → passkey → retry) SURVIVES and moves onto the proxy path unchanged. Canon = [CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md); toml rules = [SERVICES.md](./SERVICES.md) v4.

Status: **implemented** on `feat/stream-ask-approval` (2026-06-29), 207 lib
tests green; awaiting rebase onto `main` after the connection/sync work lands,
then merge. Companion to [GIT_INTEGRATION.md](./GIT_INTEGRATION.md) and
[PROTOCOL.md](./PROTOCOL.md). Implemented symbols: `stream.rs`
(`stream_approval_required`), `use_broker::register_pending_use` (shared core),
`broker::resolve_use_primary` (resolve-without-forward), `approve.rs`
`authorize_only` branch, `state::cache_take` (single-use), and the relaxed
streaming validator. Recipes: `services/integration/{cratesio,npm}`.

## 1. Problem

A SafeClaw `Use` (delegated, non-extracting secret use) is exposed two ways
today:

- **`/v/{vid}/use/{service}/…`** — for **SafeClaw-aware** clients (the agent):
  structured request → policy eval → if `ask`, a passkey approval ceremony
  (`202 Accepted` + `op_id` + poll, plus an SSE `pending` event) → broker
  injects the credential and forwards → structured (cacheable) response.
- **`/v/{vid}/stream/{service}/…`** — for **SafeClaw-unaware tools** (git, and
  by extension cargo/npm): the tool's raw upstream protocol is proxied verbatim,
  bidirectional, unbuffered (`DefaultBodyLimit::disable()`); the broker strips
  the agent key, injects the real upstream credential, streams to the upstream.

The gap: the streaming path **bypasses the approval ceremony** and is therefore
**gated to `allow`-policy services only** (`stream.rs`: "streaming requires an
allow-policy service"). So any high-consequence streamed operation —
**`cargo publish` / `npm publish` (irreversible), `git push` to a protected
branch** — cannot be `ask`-gated. We want a passkey per such operation without
breaking the unaware tool.

Two hard constraints (from the product owner) shaped the whole design:

1. **No user-precondition.** Users never proactively do something *before* an
   action. Approval must surface **in-flight**, as a link the user merely
   reacts to.
2. **No agent pre-flight probe.** Only the vault knows the live policy (and its
   TTL); and many streams the agent cannot control or inject a token into. So
   approval must be **triggered by real traffic**, not by the agent guessing
   ahead of time.

## 2. The mainstream pattern this maps to

This is a solved shape in industry. One logical operation, two client
contracts (aware ↔ unaware) = **control plane / data plane separation sharing a
single authorization core**:

| Concern | Mainstream pattern | Spec anchor | Our surface |
|---|---|---|---|
| aware client, async approval | Long-Running Operation (202 + op resource + poll/watch) | RFC 7240 `Prefer: respond-async`; Google AIP-151 | `/use/` (control plane) |
| unaware tool, transparent proxy + authz | forward-auth / external authorization reverse proxy | Envoy `ext_authz`, NGINX `auth_request`, Cloudflare Access | `/stream/` (data plane) |
| "intercepted → here's where to get authorized" | Captive Portal API | RFC 8908 / 8910 | reject + approve link |
| unify the two | control/data-plane split over one policy core | service mesh (Istio/Envoy xDS), API gateway | shared **Use core** |

Design rules that follow:

- `/use/` and `/stream/` are **not two verbs**; they are the **two planes** of
  the same `Use` semantics. Two URLs is correct (two genuine client contracts +
  two path grammars), but they must **not** carry independent policy logic.
- **The data plane never decides policy itself** — it calls back into the shared
  authz core on every request (exactly how Envoy's data plane always defers to
  `ext_authz`). This is what structurally prevents the allow-only regression
  from ever recurring.
- `/use/stream/` (nesting transport under the verb) is rejected: paths name
  resources/planes, not buffering strategy.
- Naming note: the data-plane prefix's defining trait is *transparent
  passthrough*, not merely streaming; `/proxy/` would communicate intent better
  than `/stream/`. Minor — the load-bearing decision is "data plane defers to
  the shared core," not the URL string.

## 3. Architecture

```
                 ┌─────────────────────────────────────────────┐
   agent ───────►│ /use/   (control plane: LRO / 202+poll+SSE)  │─┐
 (aware)         └─────────────────────────────────────────────┘ │
                 ┌─────────────────────────────────────────────┐ │   ┌──────────────┐
 git/cargo ─────►│ /stream/ (data plane: transparent proxy)     │─┼──►│  Use core    │
 (unaware tool)  └─────────────────────────────────────────────┘ │   │ (shared)     │
                                                                  │   │ • policy eval│
                                                                  └──►│ • approval   │
                                                                      │   + SSE      │
                                                                      │ • secret     │
                                                                      │   resolve/   │
                                                                      │   inject     │
                                                                      │ • audit      │
                                                                      └──────────────┘
```

Both planes are thin transport adapters over one **Use core**. The core owns
policy, the approval ceremony, SSE emission, credential resolution/injection,
and audit. The planes differ only in their I/O envelope:

- control plane (aware): `202 + op_id + poll_url` and a structured/cacheable
  response.
- data plane (unaware): raw passthrough; on `ask`, a **captive-portal
  challenge** instead (see §4).

## 4. The captive-portal approval flow (data plane, `ask` policy)

```
agent runs `git push` / `cargo publish`  (normal work, NO pre-probe)
        │ first real brokered request hits /stream/
Use core│ evaluate LIVE policy → ask
        │ ① reject BEFORE forwarding upstream  → zero upstream side-effect
        │ ② emit SSE `pending` (op_summary + approval_id → approve link)
        │ ② (backup) return an upstream-shaped error body carrying the link
agent ◄─┘ learns the link (SSE primary; tool stderr secondary)
agent ── surface link to user
user ── taps passkey at the link
Use core ── record fresh server-side authorization (= cache-on-approve, §5)
        ── emit SSE `approved` (same approval_id)
agent ── (on `approved`) RE-RUN the identical command
Use core ── authorization on record → forward → inject real upstream credential → stream
        ▼
     upstream (crates.io / npm / github)   — tool never saw the real credential
```

**Why reject-then-retry is safe:** the core rejects *before* forwarding
upstream, so the blocked attempt has **no upstream effect** — the retry is never
a double-publish. The retry is cheap (trigger requests are small —
`git info/refs`, registry index GETs; cargo's local build is cached).

**Trigger = the first real request**, whatever it is. We do not depend on a
protocol-defined preflight existing (many have one — git `GET /info/refs`,
docker/S3 `POST …/uploads/`, libcurl `Expect: 100-continue` — but it is not
universal). Treating "whatever comes first" as the trigger generalizes to any
streamed protocol.

### 4.1 Link delivery — two channels, by audience

| Audience | Authoritative channel | Other channel |
|---|---|---|
| **agent** | **SSE** `/v/{vid}/events` — tool-independent, structured; also delivers the `approved`/`rejected` resolution signal so the agent knows when to retry (no polling, no scraping tool output) | the tool's in-band error echo → **ignore / dedupe by `approval_id`** |
| **human, no agent watching SSE** | **in-band** (the tool prints it) | — |

Both references carry the **same `approval_id`** → same approve URL. They are two
notifications of **one** approval, never two. The agent keys everything by
`approval_id`: one id → one prompt → one passkey → one retry. No double-surface,
no confusion — by construction, each consumer has a single authoritative source.

### 4.2 In-band reachability per tool (the secondary channel)

| Tool | Does the tool print the server error body? |
|---|---|
| **cargo** | **Yes, reliably** — registry API errors are `{"errors":[{"detail":"…"}]}`; cargo prints `detail`. Put the link there. |
| **npm** | **Yes, generally** — npm surfaces the registry error message/body. |
| **git** | **Not via plain HTTP error body** (version-dependent; often only `fatal: … returned error: 403`). The reliable git channel for a URL is the **sideband `remote:` line** (how GitHub prints "Create a pull request: https://…"), which requires entering the pack phase = the *hold* path (§4.3). |

This is exactly why **SSE is the load-bearing channel** for the agent: it does
not depend on the tool relaying anything.

### 4.3 Resume: reject-fast + retry (baseline); hold-and-resume (optional)

- **Baseline = reject-fast + retry.** Universal; works for any tool/protocol.
- **Optional per-protocol optimization = hold-and-resume.** Where the transport
  tolerates being held open (git sideband keepalive: stream
  `remote: waiting for SafeClaw approval <link>` while parked), forward on
  approval without a retry. Not the baseline — holding a connection for a human
  risks client timeout (the original reason `/stream/` was allow-only).

## 5. Authorization state = server-side (Model B), not a client-carried token

After the passkey approval, the broker records a **server-side** authorization
keyed by `(agent-key, vault, service, op-signature)`, single-use or short-TTL
**decided by the vault's policy**. The agent injects **nothing** (fixes "agent
can't control the stream"); the TTL is owned by the vault (fixes "only the vault
knows expiry").

- `op-signature` binds at the **logical** level: `service + method + path-pattern`
  — **not** a body hash (the body streams; and the human approves "publish to
  crates.io", a logical op, not specific tarball bytes).
- This is **the existing `/use/` Ask-cache semantics extended to streaming.**
  Today `/use/` on `ask` → approve → forward + cache for TTL → identical requests
  within TTL pass without re-prompting. Streaming reuses the same cache: the
  data plane already gates on "is the credential resident in cache?"; the approve
  handler already writes the cache per policy TTL. So **Model B ≈ the existing
  cache-on-approve** — no separate store to build.
- **`ask-always` = single-use.** For an irreversible op (publish), reusing a
  cached grant within a TTL window would violate "passkey every time". So the
  stream path *consumes* the entry for `ask-always` (`AppState::cache_take` —
  lookup-and-remove), and only *reuses* it within the TTL for plain `ask`
  (`cache_lookup`). The grant carries a bounded window (300s) so the user has
  time to re-run after tapping; `ask-always` then burns it on the first stream.
  (As-built the window also caps `ask`; a future hardening could read the per-rule
  TTL for `ask`.)

## 6. What is NOT a new primitive

No new SUDP concept. Still `Operation` / `Grant` / challenge `r` / redeem /
Ask-cache. The only genuinely new mechanic is **deriving the `Operation` from
real traffic** — which the broker already does for buffered `/use/` (it compiles
`method`/`path`/`headers` into `op.scope`). The streaming variant compiles from
the request line + headers only; the body stays on the wire.

## 7. Change list

Existing (reuse, do not rebuild): `/stream/` transport + credential injection;
`/use/` approval ceremony; SSE channel + endpoint + `ApprovalEvent` + emitters +
web consumer; cache-on-approve; recipe / connection / template injection.

Done (this branch; "no new endpoints, no new crypto" held):

1. ✅ **Data plane defers to the core on `ask`.** `stream.rs` replaces the
   allow-only hard reject with a policy match; on an `ask`/`ask-always` miss,
   `stream_approval_required` compiles a body-less `Use` op (`scope.authorize_only`),
   registers it via the shared `use_broker::register_pending_use` (which emits the
   `pending` SSE), and rejects-before-forward with the approve link (body +
   `x-safeclaw-approve-url`/`x-safeclaw-op-id` headers).
2. ✅ **Approve = authorize-without-forwarding for streaming ops.** `approve.rs`
   Use arm branches on `scope.authorize_only`: resolves the secret via the new
   `broker::resolve_use_primary` (no forward) and `cache_insert`s it for the
   window; `execute_use_forward` runs only for buffered ops.
3. ⏳ **Agent SSE consumer + skill instruction.** Channel exists and emits; the
   agent-side subscription + skill wording live in the *skill* repo (not this
   crate) — follow-up. (Optional `sc` tail helper too.)
4. ✅ **Recipes.** `services/integration/{cratesio,npm}` — `[[upstream]]
   stream=true` + `policy.levels = ask-always` + `[setup]`. The load-time
   validator (`service/validate.rs`) was relaxed to permit ask/ask-always for
   streaming (was allow-only).
5. ⏳ **(Polish) per-tool in-band error shaping.** Generic text body for now;
   cargo-`detail` / npm / git-sideband shaping is a follow-up (SSE covers the
   agent, so not a dependency).

Caveat (cargo): routing `cargo publish` through an alternative registry needs the
broker to also serve the registry `config.json`/index handshake (cargo reads the
`api` endpoint first). `npm publish --registry …` is a pure passthrough and needs
none. Tracked in the cratesio recipe's `[setup]` NOTE.

## 8. Decisions (resolved by the owner, 2026-06-29)

1. ✅ SSE-primary / in-band-secondary layering — confirmed.
2. ✅ `op-signature` bind granularity = `service + method + path-pattern` — confirmed.
3. ✅ hold-and-resume only for git (sideband); reject + retry everywhere else — confirmed.
4. ✅ Keep `/stream/` — **no** rename to `/proxy/` (owner vetoed). Core rule stands:
   the data plane defers to the shared authz core.
```
