# Cloud sync — sealed-blob, server-authoritative, lifecycle-aware

> **Single source of truth for how a vault's sealed state moves between a
> device's daemon and the cloud.** Supersedes the scattered notes in
> `src/sync.rs`, `CONNECTIONS_AND_AUTH.md` §4a, and the session memories.
>
> Status tags below: **[SHIPPED]** = live today · **[GAP]** = a known hole this
> redesign closes · **[PROPOSED]** = the target design (not yet built).
>
> **Pre-launch: no migration.** Landing the lifecycle layer = wipe + re-enroll;
> no compat path.

## 0. The invariant — cloud-blind [SHIPPED]

The cloud (`pro-backend` + Supabase Storage) stores **one ciphertext blob per
vault** (`<vid>.json`) and **never decrypts it**. The blob is a SUDP
`SealedState`: the protected body is sealed under the per-vault state key `K`,
and `K` is itself wrapped under each passkey's `W_c` (derived from a passkey PRF,
never leaves a device). Sync moves **ciphertext only**; every property below
holds without the cloud ever seeing a secret.

## 1. The model — copied from 1Password, adapted to one-blob-per-vault

1Password's sync is **server-authoritative**: the server is the single source of
truth, every device is a cache, and clients converge to the server's state. Two
properties we adopt verbatim:

- **Terminal-state, not an operation log.** Sync is "give me the *current state*
  of everything that changed since my last revision" — not a replay of actions.
  Each record carries a monotonic revision; a client at revision `N` pulls the
  latest state of records changed after `N`. (This answers "actions vs state":
  **state**, per a monotonic revision. An oplog/CRDT is a different model;
  1Password doesn't use it and neither do we — overkill for one user / few
  devices.)
- **Deletes are tombstones.** A deletion is a *recorded* event the sync carries,
  so a device that was offline still learns the thing is gone
  ([1Password Support](https://support.1password.com/archive-delete-items/) —
  "tombstones let all devices know an item has been deleted"; user-facing it is
  trash → 30 days → permanent, but the propagation mechanism is a tombstone).

Our adaptation: the cloud is blind, so we don't sync per-item records — we sync
**one sealed blob per vault** plus a small **clear-text envelope** the cloud
*can* author (id, version, status). The envelope is the lifecycle channel; the
blob is the content channel.

**One iron rule that removes a whole class of bugs:** a **vault id has exactly
one `K` for its entire lifetime.** `K` is never rotated under a live id (see §2
for why delete+recreate gets a *new* id instead). So "the daemon holds a `K`
that can't open the cloud blob" is, by construction, impossible — it was the root
of the `rotated K?` divergence (§7).

## 2. Vault lifecycle — three distinct operations

The bug behind "I deleted on the web and the daemon kept the old vault" is that
we conflated *clear the contents* with *destroy the vault*, and reused the id on
recreate. Split them:

| op | id | `K` | items | what devices do |
|---|---|---|---|---|
| **Clear contents** | same | same | emptied | normal content pull (blob now empty); nothing else changes — the agent's `SAFECLAW_VAULT_URL` keeps working |
| **Delete vault** | **retired forever** | gone | gone | pull sees a **tombstone** → drop local `vault.dat`, lock, forget, zeroize `K`; the agent's URL now 404s (re-pair expected) |
| **Create / recreate** | **brand-new id** | fresh | fresh | a new vault to enroll — re-pair, `sc env` again |

**Delete ⇒ new id on recreate (never reuse).** A deleted id is a tombstone and is
**never reissued**. Recreating "the same vault" mints a new id with a new `K`.
This is exactly 1Password (a deleted vault's id is dead; you make a new vault),
and it is *correct* that an agent pointed at the old id can no longer reach the
new vault — that is the intended security boundary, not a regression. If a user
wants to keep the id and the agent wiring, the right operation is **clear
contents**, not delete.

(A future **in-place re-key** — rotate `K` while keeping the id and items, e.g.
on passkey compromise — is the *only* case that needs a `generation` epoch in the
envelope; out of scope now, noted in §9.)

## 3. The blob envelope + wire contract

The cloud row per vault (`vault_blobs`) carries a small clear-text envelope it
authors, plus the opaque blob:

```jsonc
{
  "vid":     "…",          // immutable id
  "version": 1782722939030, // monotonic, cloud-stamped on every PUT [SHIPPED]
  "status":  "live",        // "live" | "deleted" (tombstone)        [PROPOSED]
  "blob":    "<SealedState ciphertext>"   // cloud-blind             [SHIPPED]
}
```

| | Method | Auth | Body / Query | Returns |
|---|---|---|---|---|
| **pull** | `GET /v/{vid}/blob?since=<ver>` | device-key bearer | — | `{blob, version, status}` · `{unchanged:true}` · `{status:"deleted"}` |
| **push** | `PUT /v/{vid}/blob` | device-key bearer | `{blob, base_version}` | `{ok, version}` · `409 {conflict, version}` |
| **delete** | `DELETE /v/{vid}/blob` | device-key bearer | — | `{ok}` (sets `status:"deleted"`, keeps the tombstone) |

Changes from today:
- **Tombstone, not 404.** A deleted vault returns `status:"deleted"` (not a bare
  404). 404 stays "no blob yet / never sealed". **[GAP]** today the daemon reads
  a delete as 404 → "nothing sealed yet" → no-op, so the delete never lands
  (`sync.rs:195`). This is the core fix.
- **Optimistic concurrency.** `PUT` carries `base_version`; the cloud rejects with
  `409` if its version moved on (another writer won the race). The pusher pulls
  the new blob, re-applies its mutation on top, re-seals, retries. **[GAP]** today
  is blind last-writer-wins → a concurrent edit is silently lost.

## 4. Daemon sync state machine [PROPOSED]

`watch_loop` long-polls `?since=<local>`. On each response, exactly one branch:

1. **`unchanged`** → idle.
2. **`status:"deleted"`** (tombstone) → this vault is gone cloud-side. Remove
   local `vault.dat` + `.blob_version`, `lock_vault` (zeroize retained `K`),
   forget it from the synced set, close its audit db. (Fixes "web delete → daemon
   no-op".)
3. **newer `version`, `status:"live"`** → pull the blob; open with retained `K`.
   - opens → apply (current behavior: refresh cache, run `process_vault_connects`).
   - **does NOT open** → with the one-K-per-id rule this should be impossible for
     a live id. If seen, it means a stale local copy of a *retired* id (pre-fix
     churn) → treat as case 2 (drop local), do **not** loop forever on
     `rotated K?`. Log once.

Push (after any daemon-side mutation, e.g. an OAuth exchange): `PUT {blob,
base_version=local}`. On `409`, pull → re-apply → re-seal → retry (bounded).

## 5. Backend responsibilities [PROPOSED]

- Store the envelope: `vid`, monotonic `version`, `status`, `blob`. **[SHIPPED]**
  for `version`+`blob`; **add** `status`.
- `DELETE` sets `status:"deleted"` and **retains the tombstone row** (so offline
  devices still learn of the delete on their next poll). GC the tombstone only
  after a long TTL, never reissue the `vid`.
- **Create/recreate mints a fresh `vid`** (UUID). Never reuse a tombstoned id.
- `PUT` enforces `base_version` (optimistic concurrency) → `409` on stale.
- A separate **clear-contents** path = a normal `PUT` of an empty-items blob
  under the same `vid` (no lifecycle change). This is just an authoring choice in
  the console; the backend needs no special case.

## 6. Frontend responsibilities [PROPOSED]

- **"Delete vault"** → `DELETE /v/{vid}/blob` (tombstone) + drop it from the UI;
  copy must say the id is retired and any paired agent must re-connect.
- **"Clear contents"** → a distinct, less-scary action: seal an empty-items blob
  under the same `vid` and `PUT` (id + agent wiring preserved). Surface both, so
  a user who just wants a clean slate doesn't nuke the id.
- **"Recreate"** → create a brand-new vault (new `vid`); never offer "recreate to
  the same id".
- writeVault stays **stable-`K`** (reuse the wrapped `K`; verified
  `lib/vault-grant.ts` re-opens `wrapped_key` and re-seals under the same
  `stateKey`). Never `freshDek()` on an edit — only on initial enroll.

## 7. What this fixes (the bugs that motivated it)

- **"Deleted on web, daemon unchanged."** Delete is now a tombstone the daemon
  acts on (§4 case 2), not a 404 it ignores.
- **`rotated K?` / stuck "connecting" after delete+recreate.** Recreate mints a
  new id (§2), so a daemon never holds a `K` for a live id it can't open. The old
  id is tombstoned → daemon drops it cleanly.
- **Ghost items (e.g. a stray `github_api_key` in `sc ls`).** These are the
  symptom of two copies of one id diverging under different `K` (id-reuse + no
  tombstone + blind LWW). One-K-per-id + tombstones + `base_version` CAS make a
  divergent local copy impossible, so `sc ls` can never show a mix again.

## 8. Status & rollout

- **[SHIPPED]** cloud-blind blob, monotonic `version`, pull (`watch_loop` +
  `pull_on_start`), push-back (OAuth-connect re-seal), `.blob_version` sidecar,
  `sc sync`.
- **[PROPOSED] this redesign:** `status` tombstone end-to-end, daemon delete-
  propagation, `base_version` CAS, new-id-on-recreate, the clear-vs-delete split.
- **Rollout:** pre-launch, no migration. Land backend envelope + daemon state
  machine + frontend lifecycle together; wipe existing dev vaults and re-enroll.
  Touches the crypto/`K` boundary — `PROTOCOL.md §6` is ground truth; read before
  editing.

## 9. Open decisions

- **DP-S1 — `generation` epoch for in-place re-key.** Needed only if we ever
  rotate `K` while keeping the id + items (passkey compromise). Add a
  `generation` to the envelope; a daemon seeing a higher generation drops its `K`
  and re-unlocks. Not needed for delete (new-id covers it). **Defer until a
  re-key feature is real.**
- **DP-S2 — push-back for non-connect daemon writes.** Today only the OAuth
  exchange pushes. If other daemon-side mutations land, route them through the
  same CAS push.
- **DP-S3 — tombstone GC TTL.** How long the cloud keeps a `deleted` row before
  hard-removing it (long enough that any device polls at least once).
