# SSE Sync Push — daemon↔backend event stream (v2, 2026-07-14)

One SSE stream per daemon replaces the per-vault pair of 25s HTTP long-polls as the
*wake* transport. Long-poll stays as the fallback and for old daemons. Events are
**hints, not data** — the daemon reacts by running its existing pull paths, guarded
by its existing monotonic cursors, so duplicated / stale / echoed events are no-ops
by construction. The daemon NEVER talks to Supabase directly (single-egress
principle unchanged); events originate in the backend process at its own write
sites — pushing a wake costs zero Supabase calls.

v2 incorporates the adversarial design review (7 lenses + write-site enumeration).
Changes from v1 are marked ★.

## Why

Idle daemon today (post 2026-07-13 fixes): 2 long-polls × ~25s reconnect ≈ 6.9k
conns/day/vault ≈ 13-15k Supabase reads/day/daemon. After this change: idle reads
collapse to the 300s reconcile + ~15-min stream reconnect reconciles (★ Railway
hard-caps any HTTP request at 15 min even with heartbeats, and cuts it at 5 idle
min — heartbeats cover the latter, reconnect-with-hello covers the former; see
docs.railway.com/guides/sse-vs-websockets). Expected: ~4.5-6k reads/day/daemon v1
(~-60%), ~1.5-2k after v1.1 (agent-hash/op_relay eventing).

## Wire protocol

```
GET {cloud}/api/vault/sync/stream?vids=<vid1>,<vid2>,...
Authorization: Bearer <device sc_ key>

200 OK
Content-Type: text/event-stream
Cache-Control: no-cache, no-transform
X-Accel-Buffering: no

event: hello
data: {"vaults":{"<vid>":{"version":N,"status":"live|deleted"}, ...}}

event: vault
data: {"vid":"...","version":N,"status":"live|deleted"}

event: items
data: {"vid":"...","seq":N}          (seq optional — absent means "just pull")

event: keys                          (★ new: today NOTHING wakes on vault_keys
data: {"vid":"..."}                   writes; they ride other wakes / reconcile.
                                      This event is a strict improvement.)

: ka                                 (comment heartbeat, every 20s)
```

- ★ `vids` validation: max 32 entries, each must match the route vid shape
  `^[0-9a-f-]{1,64}$`; violations → 400. Tier gating ≡ whatever the existing
  `/v/{vid}/blob/wait` auth path accepts (mirror it exactly; do not invent a new
  policy).
- Connect sequence is **verify → register → snapshot** with ★ error discipline:
  (1) ownership query — ★ `vaults.select('id,version,status').in('id', vids)
  .eq('user_id', account)` (the column is `user_id`, NOT account_id) — a Supabase
  error here or in (3) fails the WHOLE connect with 503 (never "zero owned vids");
  (2) register owned vids; (3) snapshot re-query → `hello`. Requested vids missing
  from `hello` are NOT registered; the daemon keeps those vaults in long-poll
  fallback. Soft-deleted rows ARE included (status:"deleted").
- Events carry only metadata (vid/version/seq/status). Secret content always flows
  through the existing pull + unseal paths.
- Version skew: old backend → 404 → daemon disables SSE for 10 min then retries.
  Old daemons never call the route. Backend ships first.

## Backend (safeclaw-pro-backend)

- New route in vault-routes.mjs: `GET /api/vault/sync/stream`.
- Registry: `Map<vid, Set<conn>>` where conn = {res, accountId, keyId, openedAt}.
  ★ Per-connection lifecycle with guards on EVERY path: reserve the account slot
  before the queries and release it on every exit (including a client disconnect
  that fires mid-query); any `res.write` error → full teardown (deregister,
  clearInterval, destroy). Caps: MAX_STREAMS_PER_ACCOUNT=8 — ★ on overflow EVICT
  the OLDEST stream of that account (close it) rather than rejecting the new one
  (post-suspend ghost connections must not lock the account out);
  MAX_STREAMS_GLOBAL=500 → 429.
- ★ Key revocation severs live streams: `revokeApiKey` closes every stream opened
  with that key (track keyId per conn). Natural upper bound regardless: the 15-min
  Railway cap forces re-auth on every reconnect.
- ★ Deploy drain: on SIGTERM close all SSE connections (daemons reconnect to the
  new instance ≤ their backoff) before the process exits.
- Heartbeat: per-conn `setInterval(20s)` writing `:ka\n\n` (also satisfies
  Railway's 5-min idle rule). Stream EOF at the 15-min cap is NORMAL — daemons
  treat it as reconnect-not-error.
- `sseEmit(vid, kind, payload)` — serialize once, write to registered conns,
  called AFTER the DB write succeeds. ★ Emit sites (from exhaustive enumeration —
  these are ALL sync-relevant mutation sites of vaults/vault_items/vault_keys):
  | site | event |
  |---|---|
  | vault-routes.mjs:939 handleDeleteVault (tombstone) | vault |
  | vault-routes.mjs:1415 handleBlobPut (version bump) | vault |
  | vault-routes.mjs:1460 handleBlobDelete (tombstone) | vault |
  | admin-vault-cleanup.mjs:242 bulkDeleteVaults (tombstone) | vault |
  | vault-routes.mjs:1704 handleItemPut (RPC vault_item_put) | items |
  | vault-routes.mjs:1841 handleKeyPut (RPC vault_key_put) | keys |
  | vault-routes.mjs:1870 handleKeyDelete | keys |
  NOT evented (by design): handleItemGc:1783 (tombstone GC the caller already
  saw, no seq bump), handleRenameVault:895 (label only, invisible to daemons
  today), handleCreateVault:857 (daemon picks up new vaults on restart),
  admin-demo-cleanup hard-delete via auth-user FK cascade (demo-only; vanished
  row → hello omits vid → fallback long-poll owns it). pg_cron touches none of
  the three tables (verified).
- At the vault/items sites also `wakeNow` the existing long-poll waiters —
  fallback and old daemons get faster wakes for free (keys have no waiter today).
- Node server is bare node:http/https, no compression middleware. ★ Verify in
  soak (not just by reading docs) that no server-level timeout
  (requestTimeout/headersTimeout/keepAliveTimeout) kills a held stream on our
  Node version.

## Core (safeclaw crate, new module src/sync_stream.rs + surgical edits to sync.rs)

**★ Shared blob-body handler (was v1's biggest gap):** the design routes vault
events and SSE-mode reconciles through "the existing blob pull + persist" — but no
safe callable unit exists: `classify_pull_body` persists WITHOUT the vault write
lock (sc-sync parity), while watch_loop's blob-200 arm persists WITH it. Factor
watch_loop's blob-200-arm body handling (tombstone → drop_local_vault_locked +
stop; persist-under-lock; marker → record_blob_version; then unconditional
`pull_and_process`; persist-failure → no cursor advance + backoff signal) into a
helper used by BOTH shapes. The SSE path fetches with a plain 15s-client
`GET /v/{vid}/blob?since=<cursor>` (never holding the lock across the network
call) and feeds the body to that helper.

**Dispatcher task** (spawned by `spawn_watchers`, which knows the vault set):
- Owns the SSE connection. ★ Client is REBUILT on every (re)connect via a new
  `egress_proxy::client_streaming()` (proxy config applied fresh — preserves the
  proxy hot-reload contract; no total `.timeout()`, which would kill the stream).
  Connect budget: 10s to response headers, hello expected within 5s more.
- Liveness: `tokio::time::timeout(45s, next_chunk)` — heartbeats reset it; expiry
  / EOF / error = stream dead. Parser operates on a BYTE buffer (records split on
  blank line; `event:`/`data:` fields; `:` comments ignored; tolerate \r\n; a
  UTF-8 sequence or record split across chunks must reassemble).
- ★★ **Rotation is routine, not failure:** a stream that dies after having been
  healthy (post-hello) for >60s is a ROTATION (Railway's 15-min cap): reconnect
  IMMEDIATELY with no backoff sleep and do NOT flip health to Down — vault tasks
  must not churn select! shapes or fire fallback long-polls every 15 min. Flip
  Down only if that immediate re-dial fails to reach hello within ~5s (one
  attempt); backoff applies to failed connects only. Rotation reconnects log at
  debug (one info line at most) — never warn/error, or the overnight-soak
  "clean logs" criterion dies. The unconditional hello reconcile is what makes
  the zero-churn rotation window safe (it covers writes landing in the gap).
- ★ Per-vault delivery is a merged **pending-wake cell, not a queue**:
  `Mutex<Pending { vault: Option<(version,status)>, items: bool, keys: bool,
  mode: Mode }>` + `Notify` per vault. No bounded-queue head-of-line blocking,
  burst coalescing falls out for free, and a tombstone payload can't be dropped.
  Take-then-process on the task side (re-check the cell after arming
  `notified()` — the standard missed-wakeup pattern).
  ★★ The cell's vault slot merges **MONOTONICALLY**: keep the HIGHER version,
  and status "deleted" is sticky for the cell's lifetime (items/keys flags are
  already monotone). Emits from concurrent backend write handlers are not
  serialized with commit order, and a stale hello can arrive after a fresher
  pre-hello event — latest-wins would regress the cell across the cursor
  boundary; monotone merge makes both harmless (mirrors cursors-only-advance).
  ★★ Events received BEFORE hello merge into cells exactly like any other
  event — hello is only the connect-budget sentinel, the mode-setter, and the
  per-vault reconcile trigger, never a gate on event processing (backend
  registers vids before its snapshot query, so an event can legitimately hit
  the wire first).
- ★ Per-vault mode: the cell's `mode` field (Sse / Fallback) is set by the
  dispatcher — Fallback for vids absent from hello or when the stream is down
  (plus a global `watch<StreamHealth>` so fallback tasks notice recovery early).
  A vault task that exited (tombstone) leaves its cell dropped; the dispatcher
  prunes the vid from its set and from `?vids` on the next reconnect.
- ★ Backoff/flap discipline: reconnect backoff 2s→60s doubling **resets only
  after the stream has stayed healthy ≥60s** (NOT at hello — a middlebox that
  kills streams right after hello must decay to 60s retries, not hot-loop
  hello+reconcile). Add ±20% jitter. 404 → sleep 600s (old backend). 401/403 →
  park 600s (mirrors long-poll AUTH_RETRY). 429 (cap hit) → park 300s.
  ★★ Never-healthy escalation: after 5 consecutive attempts that never reach
  healthy-≥60s, park 600s between tries (a middlebox that always kills the
  stream post-hello must cost ~144 attempts/day, not 1440 — each failed attempt
  also burns 2 backend snapshot queries).
- On (re)connect, hello rows are merged into the cells as vault events + items
  and keys flags set → every vault runs one cursor-gated reconcile round.
  (Re)connect ≡ reconcile; at ~15-min forced reconnects this costs ~96
  reconcile rounds/day/daemon — cursor-gated, mostly `{unchanged}` probes.

**watch_loop third shape** (sync.rs:988-1265; both existing shapes stay intact):
each round picks its shape from the cell's mode:
- Sse: `select! { _ = notified => …, _ = sleep_until(next_reconcile) => …,
  _ = health_rx.changed() => continue }`
- Fallback: the existing long-poll select! (unchanged) + a health_rx arm to flip
  back early.

Event handling reuses today's paths 1:1 via the shared helper:
- Pending vault (version,status): status=="deleted" → the helper's tombstone
  branch (drop + task exit — blob channel semantics preserved: the SSE vault
  event IS the lifecycle authority in Sse mode). version > cursor → blob GET +
  helper. Else no-op.
- Pending items/keys flag → `pull_and_process` (pull_keys runs first inside it,
  as today).
- ★ Reconcile deadline is INDEPENDENT of event traffic: keep
  `last_reconcile: Instant`; run the reconcile block (blob `?since` probe via the
  helper + `pull_and_process`) whenever 300s have elapsed, even under steady
  events — under long-poll the loop-top read WAS the implicit reconcile; the SSE
  shape must not lose the out-of-band bound (pg_cron-class writes, missed emits).
- ★ Pull-failure bounded retry: long-poll gets free re-delivery (an unadvanced
  cursor makes the server answer instantly on the re-armed hold); SSE consumes
  the event once. If the blob GET or a sub-pull errors in Sse mode, retry with
  the existing 2s→60s backoff (bounded, cursor-gated) instead of waiting 300s.
- ★ Cursors are read from disk at use time (read_local_version /
  read_per_item_store per event), never cached across parks — the existing
  loop-top discipline.
- Suspend: the wall-vs-mono check runs per round in both shapes (a Sse round =
  wake-to-wake); on detect → `pull_and_process("resume")` (no per-task client to
  rebuild in Sse shape; the dispatcher's own 45s gap detection reconnects the
  stream ≤45s after resume).
- Echo self-wakes (daemon's own push → emit → event back): bounded to at most
  one redundant cursor-gated pull per push, never a loop (after the pull the
  cursor equals the server version).

**Invariants preserved (do not touch):** one task per vault; `pull_and_process`
serial inside it; `vault_write_locks` held only across persist/drop, never across
network calls or `process_vault_connects`; cursors only advance; 401/403 parking;
consec-err client rebuild (long-poll shape); agent-hash 30s loop and op_relay 2s
short-poll untouched in v1.

**Config:** `sync_stream = "auto" | "off"` in config.toml (optional key, absent =
auto) + `SAFECLAW_SYNC_STREAM` env override. "off" → never connect, pure long-poll.
★★ Runtime semantics stated honestly: the switch is read at every (re)connect, so
flipping to "off" bites on the next reconnect (≤15 min under the Railway cap);
restart the daemon for immediate effect. Env var is the robust override (an old
binary's config save may drop the unknown key).

★★ **Backend follow-up in the same change (separate commit):** with `wakeNow`
wired at every write site, the per-connection Supabase Realtime channel inside
`makeChangeWaiter` is redundant — every mutation of these tables flows through
this process (verified: pg_cron touches none), so drop the Realtime subscription
from the waiters entirely (~14k channel joins/day/daemon gone). Worst case for a
missed in-process wake is the existing ~25s deadline answer + reconnect fresh
read — the same bound the system already lives with. Rolling-deploy dual-instance
writes lose cross-instance wakes for the overlap window; same 25s bound applies.

## v1.1 — op_relay + agent-hash eventing (2026-07-14 evening, user-approved)

Two new event kinds on the SAME stream, same hints-not-data semantics, each
with its poll kept as fallback:

```
event: agent_hashes   data: {}                              (api_keys changed for this account)
event: op             data: {"vid":"...","op_id":"...","status":"approved|rejected"}
```

**Backend:**
- `sseEmitAccount(accountId, kind, payload)` — the registry already stores
  accountId per conn; fan out to every stream of the account.
- `agent_hashes` emits at exactly the three sites that already invalidate
  agentHashCache (generateApiKey / revokeApiKey / renameApiKey in vault.mjs) —
  cache-invalidation and eventing stay symmetric by construction.
- `op` emits at every op_relay write that flips grant_status
  (deposit→approved, reject; enumerate ALL `.from('op_relay')` writes and
  classify — register INSERTs are NOT evented, the daemon that registered is
  the one polling).

**Core:**
- Dispatcher routes `agent_hashes` → a daemon-global Notify; `op` → a
  registry `Map<op_id, Notify>` that relay clients register into (unknown
  op_id = ignored, forward-compatible).
- ★ Resync-on-reconnect: after every apply_hello, fire the agent-hash notify
  — the dominant loss cause for an event IS a disconnect, and the reconnect
  it forces becomes the recovery. With Railway's ≤15-min rotation this makes
  the platform itself a ≤15-min revocation backstop.
- agent-hash loop cadence is MODE-DEPENDENT: stream healthy → 600s poll
  (pure belt-and-suspenders under the rotation resync; the number that goes
  in the security docs is "revocation: instant, worst case 10 min"); stream
  down / sync_stream=off → today's 30s unchanged (degraded environments keep
  the poll as their only propagation path). Add-key latency is independent
  of all this: refresh_agent_keys_on_miss already refetches on first sight
  of an unknown key.
- Relay client: the 2s `POLL_INTERVAL` sleep becomes `timeout(interval,
  notified)` — event-driven when streamed (interval stretches to 15s as a
  safety net), 2s legacy cadence when the stream is down. Poll count for an
  approval ceremony drops from ~30/min to ~4/min idle + instant completion.

**★★ Capability gating (post-review):** relaxing a cadence needs PROOF the
event can reach this daemon, and "stream healthy" is strictly weaker than
that — `op` events are delivered per-vid (a vault born after daemon start,
over the 32-vid cap, or hello-rejected never hears them), and a v1-stream
backend emits neither new kind at all (version skew / rollback). hello now
carries `caps:["op","agent_hashes"]`; the daemon keeps the hello-confirmed
vid set + caps in a process-global, cleared on every go_down. Relay uses
15s only for `op_events_for(vid)`; the agent-hash loop uses 600s only for
`agent_hash_events_live()`; anything short of proof keeps legacy cadences.

**★★ Storm floors (post-review):** events accelerate polls, they never
replace pacing — a buggy emitter must be bounded client-side (the 0.9.36
lesson). Relay: ≥1s between polls regardless of event wakes (and note the
old MAX_POLLS count became a wall-clock POLL_BUDGET deadline, so the floor
is what bounds request COUNT now). Agent-hash: ≥2s between fetches,
mirroring refresh_agent_keys_on_miss's debounce. Plus: the agent-hash
loop's armed sleep re-sizes on a health flip (stream_health_edge) instead
of riding a 600s timer across an Up→Down transition; mid-stream hellos
fire the resync notify exactly like connect hellos.

## Non-goals (v1)

No WebSocket / Socket.IO / Centrifugo / NATS / Redis. No multi-instance fan-out
(single Railway instance; long-poll fallback stays correct if that changes). No
dynamic vault subscribe (restart picks up new vaults, as today). No exactly-once —
cursors + idempotent pulls + reconcile ARE the delivery semantics. op_relay +
agent-hash eventing = v1.1.

## Rollout & rollback

Backend merges to dev first (additive). Core builds in wt-sse-core, local binary
dogfood against dev backend (temporarily swap the sc-up-managed daemon), overnight
soak watching logs.all idle rates + `sc logs`, then rc tag (next rc after
v0.9.48-rc.4) for `sc upgrade` e2e. Rollback: `sync_stream=off` (runtime), or
revert — pre-work anchors: backend dev `6995405`, core dev `dc52d57`.
