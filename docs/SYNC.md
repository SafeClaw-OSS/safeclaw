# Cloud sealed-blob sync — bidirectional (pull + push-back)

> **Status: pull shipped (Slice 3); push-back shipped 2026-06-27 for the
> OAuth-connect case.** This is the single source of truth for how a vault's
> sealed state moves between a device's daemon and the cloud. It supersedes the
> scattered notes in `src/sync.rs`, `CONNECTIONS_AND_AUTH.md` §4a, and the
> session memories.

## 0. The invariant — cloud-blind

The cloud (`pro-backend` + Supabase Storage) stores **one ciphertext blob per
vault** (`<vid>.json`) and **never decrypts it**. The blob is a SUDP
`SealedState`: the protected body is sealed under the per-vault state key `K`,
and `K` is itself wrapped under each passkey's `W_c` (which is derived from a
passkey PRF and never leaves a device). So sync moves **ciphertext only**;
every property below holds without the cloud ever seeing a secret.

## 1. Why sync is bidirectional

A vault is edited from **two kinds of writer**, and either can produce state the
other must see:

- **The browser** (console): seals edits — new API keys, an OAuth
  `<conn>_oauth_pending`, policy changes — and `PUT`s the blob.
- **A device's daemon**: completes work the browser *can't* — most importantly
  an **OAuth connect's code→token exchange**. A Google authorization code is
  **single-use**, so only ONE daemon can redeem a pending connect; the resulting
  `refresh_token` must reach every *other* device. The daemon also re-seals
  after that exchange.

Pull-only is therefore not enough: a daemon-side mutation (the exchange) would
be stranded on whichever daemon happened to do it. Hence **push-back**.

## 2. The wire contract (`/v/{vid}/blob`)

| | Method | Auth | Body / Query | Returns |
|---|---|---|---|---|
| **pull** | `GET /v/{vid}/blob?since=<ver>` | device-key bearer | — | `{blob, version}` or `{unchanged:true}` / 404 |
| **push** | `PUT /v/{vid}/blob` | device-key bearer | `{blob: <SealedState>}` | `{ok, version}` |

- **Versioning = last-writer-wins.** The backend stamps `version = Date.now()`
  on every `PUT` (monotonic-enough; `vault_blobs` table, one row per vault). A
  daemon's `GET ?since=<local>` short-circuits to `{unchanged}` when the cloud
  isn't newer — so "pull right before use" costs one tiny row read.
- **No CAS / no merge.** Concurrent writers are rare (one user, few devices) and
  the blob is atomic; LWW is sufficient. A lost update only re-occurs on the next
  edit. (If multi-writer contention ever matters, add an `If-Match: <version>`
  precondition — out of scope today.)

## 3. Daemon side

`src/sync.rs`:

- **`pull_on_start`** — on boot, pull every synced vault (`active ∪
  known_vaults`) so a freshly-paired device serves the latest sealed state.
- **`spawn_watchers` / `watch_loop`** — one long-poll watcher per synced vault;
  applies a newer blob to `vault.dat`, refreshes the in-memory cache for an
  unlocked vault (`refresh_after_pull`, retained `K`, no passkey), and runs
  `process_vault_connects` (a pulled blob may carry a browser-sealed pending).
- **`sync_vault_now`** (`POST /v/{vid}/sync`, `sc sync`) — force an on-demand
  pull + complete-pending-connect.
- **`push_blob_best_effort`** — read local `vault.dat`, `PUT {blob}`, record the
  returned `version` in the `.blob_version` sidecar so our **own** watcher
  doesn't treat the blob we just pushed as a newer remote change. Best-effort:
  local-only/unpaired daemon or any network error just logs (the change is
  already durable in `vault.dat`).

The `.blob_version` sidecar (next to each `vault.dat`) records the last-synced
version both for `?since=` and to suppress self-pull after a push.

## 4. Push-back trigger (OAuth connect)

`src/auth/connect.rs::process_vault_connects`, after a successful exchange:
re-seal under retained `K` → `write_atomic(vault.dat)` → **spawn detached
`push_blob_best_effort`** (after the per-vault write lock drops; push only reads
`vault.dat` + does HTTP). Net flow for a connect:

```
browser: seal {code,verifier} → PUT blob (cloud: pending, version=t0)
daemon A (unlocked): pull/Write → exchange code → write refresh_token,
                     delete pending → re-seal → PUSH blob (cloud: refreshed, version=t1)
daemon B,C …       : watcher pull (since<t1) → get refreshed blob → refresh_token available
```

**Single-use-code corollary:** other daemons must NOT re-exchange (the code is
spent → `invalid_grant`); they must **pull the result**. Push-back is what makes
that possible without the cloud ever seeing the token.

## 5. What's deferred

- **Push-back for non-connect daemon writes.** Today only the OAuth-connect path
  pushes. If/when the daemon mutates vault state in other ways that other devices
  must see, route them through the same `push_blob_best_effort`.
- **Conflict precondition (`If-Match`).** LWW is fine for now.
- **Per-item / lazy sync.** Whole-blob today; revisit only if blobs grow.
