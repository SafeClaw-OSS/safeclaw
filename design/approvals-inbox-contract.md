# Approvals inbox: implementation contract (appendix to design/approvals-inbox.md Rev 3.1)

The design doc is the SSOT for behaviour and invariants. This file pins the
WIRE between the three components so they can be built in parallel. Field
names are exact. All new fields are optional on read (old peers omit them).

## Versions
- Daemon/CLI release: `0.10.7-rc.1` (bump Cargo.toml in the core repo).
- Console constant `EXPORT_BATCH_MIN = 0.10.7` (batches containing an Export
  need it); `use`-only batches keep the 0.10.6 floor.

## Requester triad (new product requirement, all surfaces)
Every approval row/card shows THREE roles: **user** (the human account that
owns the requesting agent key or device key; in a personal vault this is the
viewer, rendered "you"/"你"), **agent** (label of the agent key whose prefix
the daemon signed into `scope.agent`; absent for CLI ceremonies such as
`sc get` → render "SafeClaw CLI"), **device** (device key label the relay row
was registered with). All three are DISPLAY ONLY (backend-resolved, never used
for signing or default-check).

## 1. Daemon ↔ CLI (local loopback)

### Use op scope (signed, in β) — new keys
- `level`: `"ask"` | `"ask-always"` (from PolicyContext.level at mint)
- `window_s`: integer seconds, present only for `"ask"` (= pc.ttl_seconds)
Apply asserts `scope.level == pc.level` and, when `window_s` present,
`window_s == pc.ttl_seconds`; mismatch → refuse (BadRequest, plain arm;
BatchVerify in batch arm).

### `POST /v/{vid}/op` (Export create) response
`{ op_id, r, expires_at, waiter_secret }` — `waiter_secret` = 32 random bytes,
base64url, returned ONLY here, stored as SHA-256 on the record, never logged,
never in SSE, never sent to the relay.

### `GET /op/{id}` response — new fields
- `superseded_by`: op_id | null (chain head pointer, path-compressed)
- `satisfied_by`: op_id | null (set when this op was resolved because a
  sibling in its intent chain applied)
- `retry_count`: int ≥ 1
- Export `value` is included ONLY when request header
  `x-safeclaw-waiter: <waiter_secret>` matches (constant-time). Otherwise the
  body has status but no `value`, and the plaintext is NOT consumed.
- Liveness: each poll carrying a valid waiter header updates
  `last_waiter_poll`.

### `POST /op/{id}/cancel` (new)
Body `{ "waiter_secret"?: string }`. Requester withdrawal. If the record has a
waiter secret, it is required. Pending → terminal `Rejected{reason:
"withdrawn by requester"}` + audit `cancelled`, relay withdraw with reason
`withdrawn`. Never via `reject_op`.

### CLI
`sc get` (and every `remote_approve` waiter for an op it created) sends the
waiter header on every poll; on Ctrl-C/SIGTERM/timeout calls
`POST /op/{id}/cancel`. A satisfied/`ok` poll without value on an Export →
existing "no value in response" error.

## 2. Daemon → Backend (relay; device key auth)

### `POST /v/{vid}/op/relay/register` body — new fields
- `boot_id`: hex string, random per daemon process (AppState, generated at start)
- `supersedes`: [op_id] — ids this op supersedes (Use chains only); `[]` on
  recovery re-register
- `superseded_by`: op_id | null — this op's current pointer
- `retry_count`: int ≥ 1

### `POST /v/{vid}/op/relay/{op_id}/cancel` body — new fields
- `reason`: `"satisfied"` | `"rejected"` | `"withdrawn"` | `"abandoned"`
- `satisfied_by`: op_id (with reason `satisfied`)
(Existing callers send no reason → backend stores null, behaves as today.)

## 3. Backend storage (op_relay new columns; dev ALTER now, prod at promote)
- `registered_key_id text` (auth.keyId of the registering device key)
- `boot_id text`
- `superseded_by text`
- `retry_count int default 1`
- `cancel_reason text`
- `satisfied_by text`

## 4. Backend behaviour
- Register: first insert stores `registered_key_id`; re-register on an
  existing op_id only by the same `registered_key_id` (else 409
  `op_relay_immutable`); `daemon_pubkey`/vault immutable (already b2fa26d).
  Apply `supersedes`: for each id with the same `registered_key_id` and
  vault, set `superseded_by = op_id` (never un-mark); apply own
  `superseded_by` monotonically. Restart zombies: pending rows of the same
  `registered_key_id` with a different non-null `boot_id` → `cancelled`,
  `cancel_reason = 'daemon_restarted'`.
- Cancel/poll: when the row has `registered_key_id`, the caller's keyId must
  match (null = legacy row, allowed). Cancel stores `cancel_reason`,
  `satisfied_by`.
- Deposit (`POST /api/op/{id}/approve` path, handleOpGrant) on a non-pending
  row → 409 `{ grant_status, cancel_reason, satisfied_by }`.
- Reject only transitions `pending` (status guard).
- P0.b: `ceremonyTierBlocked` on blob PUT/DELETE and item PUT/GC.

### `GET /api/grant/{op_id}` response — new fields
`superseded_by`, `retry_count`, `cancel_reason`, `satisfied_by`,
`vault_kind` ('personal'|'shared'), and
`requester: { user_label, user_is_viewer, agent_id, agent_label, device_name }`
(`user_is_viewer` only computable with a session; else null).

### `GET /api/me/approvals?status=pending` (new; console session only)
Union over every vault the caller can approve on (owned + member).
`{ entries: [ { op_id, vault_id, vault_label, vault_kind, act_kind, service,
method, path, target, created_at, expires_at, daemon_version, retry_count,
requester: { user_label, user_is_viewer, agent_id, agent_label, device_name } } ],
pending_total }` — only live chain heads (`grant_status='pending'`, not
expired, `superseded_by is null`), soonest-expiring first, limit 200.

## 5. Console
- Route `/approvals` (console group), sidebar item "Approvals / 待批准" with
  count badge, account level.
- Bell: account-wide (uses `/api/me/approvals`), preview ≤5, inline Approve
  for `use` only, footer link.
- Rows/cards render from fetched `GET /api/grant/{id}` material via the SAME
  renderer as `/grant/{id}` (extract shared components), plus requester triad.
- Selection, partition, default-check, caps, strip, 600 ms settle: design D3.
- `/grant/{id}`: login line / "N more waiting" banner, superseded copy (still
  approvable), cancelled-reason copy (`satisfied`, `rejected`, `withdrawn`,
  `abandoned`, `daemon_restarted`), requester triad.
- Login redirect validator rejects backslashes.
