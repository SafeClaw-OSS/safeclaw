# De-daemon-ization — retire the cloud daemon; one local daemon + a blind cloud

> **Canonical design for fully retiring the cloud-side daemon.** The 2026-06-23
> pivot decided *engine local / control-plane cloud*: every vault lives on the
> user's LOCAL daemon; the cloud (`pro-backend` + Supabase) is blind storage +
> relay + auth/billing. The cloud daemon (the old SaaS-hosted-vault engine) has
> no real vaults and is being retired. Today the backend still PROXIES ~7 paths
> to it — vestiges of the SaaS-hosted model. This doc is the plan to retire all
> of them, one by one, with *how each function works without a cloud daemon*.
>
> Tags: **[SHIPPED]** live today · **[TODO]** to build · **[DECISION]** a choice
> made here. No pure self-host exists — every daemon is cloud-paired; there is no
> unpaired/self-host approval surface to preserve.

## 1. The model

- A **vault** = one passkey-sealed blob on Supabase (SUDP `SealedState`: body
  sealed under `K`; `K` wrapped per-passkey under `W_c`). **[SHIPPED]** (sync layer)
- **Devices** = the user's local daemon(s) **and any UNLOCKED browser tab.** Both
  are devices: each can decrypt the blob (with a passkey), edit it, re-seal,
  upload — the change syncs to every device (pull/push, `base_version` CAS,
  tombstones). **[SHIPPED]** (sync layer)
- **Every vault mutation** (write/delete a secret, add/remove a passkey, connect a
  service, clear, delete) is a **client-side blob-op** by any unlocked device,
  re-sealed + synced. The passkey assertion that decrypts the blob **is** the
  authorization.
- The **cloud** = blind blob storage + op-relay (approval) + an `audit_events`
  table + auth/billing. **No cloud daemon.**
- **Approvals** (an agent `/use` that needs a passkey) = the **op-relay**: the
  local daemon registers the op + polls; the user approves on `safeclaw.pro`; the
  grant is deposited; the daemon applies it. **[SHIPPED]** (`relay/client.rs` +
  backend op-relay)
- **Audit** = append-only **plaintext** rows on Supabase; the daemon ships events
  (local-first outbox); cloud + console read. **[TODO]** (§4)

## 2. The daemon's irreducible roles (what CANNOT move to the browser)

1. **The broker hot-path** — `/v/{vid}/use|stream|export`: inject the real secret
   server-side + forward. The product itself.
2. **OAuth `code→token` exchange** — the confidential `client_secret` + the
   single-use auth code live only in the daemon. The browser deposits
   `{code, verifier}` (K-sealed in the blob); the daemon exchanges + re-seals.
   **[SHIPPED]** (connect flow)
3. It is the process the local **agent** reaches (localhost broker), and the
   **generator of audit events**.

Everything else — vault edits, passkey add/remove, reading
registry/connections/entries — is a blob-op any unlocked device performs.

## 3. Per-function retirement map (the ~7 backend → cloud-daemon proxies)

| backend handler | what it did | replacement (no cloud daemon) | action |
|---|---|---|---|
| `handleAgentUse` `/v/{vid}/use/*` | cloud broker | agent hits its **LOCAL** daemon | **[SHIPPED]** removed (archive branch) |
| `handleAgentRegistry` `/v/{vid}/registry` | proxy registry | agent → local daemon `/registry`; console → **decrypted blob** | **delete** |
| `handleAgentExport` `/v/{vid}/export` | proxy export (daemonProxy) | agent → local daemon `/export` | **delete** |
| `handleAgentPoll` `GET /op/{id}` | proxy op poll | **op-relay** store | **delete** |
| `handleSetup` (enroll `/op/approve`) | proxy enroll approve | enroll = browser seal + blob PUT + `vaults` row (client-side) | **delete** (§6.4 verify) |
| `handleVaultUsage` `/v/{vid}/usage` | proxy usage | `audit_events` table (§4) | **delete** |
| `handleSkillMd` `/skill.md` | fetch daemon (→302 GitHub) | **delete entirely** — backend never serves/redirects the skill (a compromised backend could 302 to a malicious skill); the agent fetches it ONLY from the GitHub-raw single source | **delete** |
| console `/menu` | static catalog | backend serves a static catalog itself (or frontend bundles it) | **delete** [DECISION: appears unused — confirm + delete] |
| console `/pubkey` | daemon HPKE pubkey | arrives via the **op-relay register** payload, **pinned** (§6.2) | **delete** |
| console `/passkeys` `/keys-known` `/pending-passkeys` | proxy vault state | console reads **decrypted blob**; passkey ADD = blob-op (§5) | **delete** |
| console `/op` `/approvals` | proxy op create/list | console mutations are **blob-ops**; pending approvals read from `op_relay` (Realtime) | **delete** |
| `handleConsoleSseStream` `/events` | proxy SSE | console subscribes **Supabase Realtime** (`op_relay` + `vault_blobs`) | **delete** |
| `DAEMON_URL` / `DAEMON_PROXY_URL` / `daemonAdmin` / `daemonProxy` | the proxy plumbing | — | **delete** once all above gone |

**Kept untouched:** op-relay (register/deposit/poll), sealed-blob endpoints
(PUT/GET/DELETE `/v/{vid}/blob`), account/agents/devices/pair-token. **[SHIPPED]**

## 4. Audit / usage

- **Purpose: user-facing activity display. NOT billing** (flat per-seat +
  entitlement token; no per-approval metering — metering would force approvals
  into the cloud hot path, and laptop approvals are localhost-invisible anyway).
- **Store = a PLAINTEXT append-only table `audit_events` on Supabase.**
  Append-only ⇒ no CAS, no conflict (multi-device/multi-agent just `INSERT`).
  The mainstream activity-log pattern; Supabase **Realtime** drives live console
  updates. A sealed blob is *wrong* here: high-frequency multi-writer would mean
  constant CAS conflicts + re-pull churn.
- **Why plaintext (not cloud-blind):** the cloud must SEE it (user decision). The
  disclosure is **activity metadata only — never secret values.** Vault CONTENTS
  stay sealed/cloud-blind. Precedent: 1Password (item contents E2E; access/activity
  log server-visible).
- **Local-first outbox (why `audit.db` stays):** the daemon ALWAYS writes its
  local per-vault `audit.db` first (synchronous, offline-safe), each row with a
  `synced` flag; a background **shipper** pushes `synced=false` rows to Supabase
  best-effort and marks them synced. `audit.db` = durable origin + offline buffer
  + `sc audit` debug. Deleting it would lose offline events + the delivery guarantee.
- **Dedup:** each event carries a daemon-minted `event_id` (UUID); the backend
  **upserts on `event_id`** ⇒ at-least-once shipping is idempotent (ship-then-crash
  re-ships safely).
- **Schema (metadata only — NEVER secret values / request-response bodies):**
  `audit_events(event_id uuid PK, vault_id, account_id, ts /*event time*/,
  inserted_at /*server, canonical order*/, connection_id, service,
  action /*method + sanitized path or rule id*/, decision /*allow|ask|deny*/,
  agent_id, op_id?)`.
- **RLS:** a daemon (device-key) may `INSERT` only for vaults it owns; an account
  (session JWT) may `SELECT` only its own events. Ownership = `resolveAuth` +
  `isOwnedVaultId`.
- **Retention:** a TTL (e.g. 90d) on both the table and the local db.
- **Ordering:** display by event `ts`; canonical order/tiebreak by server
  `inserted_at` (clock skew across devices).
- **v2 (deferred): private audit** — seal each row's payload, console-side decrypt;
  same append-only, rows become ciphertext. Add only if the "cloud sees nothing"
  story ever needs to be that hard.

## 5. Passkey add / remove (the hard part)

- **LIST:** console reads credentials from the **decrypted blob.** No daemon.
- **ADD (same unlocked session):** the unlocked browser has `K` → wraps `K` under
  the new credential's pubkey (HPKE) → adds the `SealedCredential` to the blob →
  re-seals → PUT (sync). The unlock **is** the authorization.
- **ADD (a brand-new device that can't decrypt yet):** the new device drops its
  pubkey into the blob as a `pending` entry; the next time an already-unlocked
  device (browser OR daemon) syncs, it wraps `K` under that pending pubkey +
  finalizes + re-seals.
- 🔴 **SECURITY INVARIANT — wrapping `K` under a new key ALWAYS requires an
  explicit, authenticated user action on an unlocked device:**
  - same-session add → the user's unlock authorizes it;
  - cross-device pending → the user must **explicitly confirm the join** on an
    unlocked device ("a new device wants to join — approve?"). **NEVER auto-wrap a
    pending on sync.** Otherwise a compromised cloud (or anyone who can write the
    blob) injects a pending pubkey → auto-wrap → **full vault takeover.**
  - This gate exists today in `approve.rs` (pending-passkey is an approval op).
    **Preserve it** when moving to the blob-op model.
- **Crypto:** porting "wrap `K` under a new cred" from Rust
  (`pending_passkey.rs` / `approve.rs`) to TS (frontend) is the core build + the
  main correctness risk. Verify byte-for-byte against the Rust path.
- **REMOVE a passkey:** blob-op (drop the `SealedCredential`, re-seal). Removing a
  passkey does **not** rotate `K` (1P model) — a removed device that retained `K`
  could still open an OLD blob copy; revoke is best-effort. (Already the model.)

## 6. Pitfalls & mitigations

- **6.1 Concurrent blob writes** (browser passkey-add ∥ daemon connect): the
  browser blob-op MUST do the CAS retry — on `409`, pull → re-apply its mutation
  onto the newer blob → re-seal → re-PUT — not just throw "reload". **[TODO frontend]**
- **6.2 daemon-pubkey pinning:** the op-relay-delivered daemon pubkey must be
  **account-bound + TOFU-pinned**, else a compromised cloud swaps it → the
  browser seals the `W_c` grant to the attacker → grant interception. Intersects
  `grant.rs:29` (tracked separately). **[TODO]**
- **6.3 audit dedup / RLS / retention:** §4. **[TODO backend]**
- **6.4 enroll fully client-side:** verify new-vault = browser seal + blob PUT +
  `vaults` row, with **no** hidden cloud-daemon dependency, BEFORE deleting
  `handleSetup`. **[TODO verify]**
- **6.5 console pending-approvals + live state:** move from the daemon `/events`
  SSE to **Supabase Realtime** — `op_relay` for pending approvals, `vault_blobs`
  for state changes (a daemon-side connect should reflect live, not on refresh).
  **[TODO frontend]**
- **6.6 console writes never create a daemon op:** confirm which console flows hit
  `/op` and convert them to blob-ops (or op-relay for true approvals). **[TODO verify]**
- **6.7 audit scope (v1):** daemon-generated AGENT activity (Use/approval).
  Console/user edits = optional / out of scope for v1.

## 7. Implementation plan

| layer | work | weight |
|---|---|---|
| **Backend** (前后端) | delete all §3 forwards + `DAEMON_URL`/`DAEMON_PROXY_URL`/`daemonAdmin`/`daemonProxy`; `handleSkillMd` delete; `/menu` static-or-delete; **add `audit_events`** (migration + RLS + retention + the daemon-push endpoint + console query) | mechanical + the audit table |
| **Daemon** (Rust) | the **audit shipper** (local-first outbox → Supabase push, dedup, `synced` flag); single-port + op-page already in **v1.0.24** | the audit shipper = the new daemon work |
| **Frontend** (console) | passkey add/remove + any residual vault ops → **client-side blob-ops** (the `K`-wrap port = the hard part); registry/passkeys/connections from the decrypted blob; pending-approvals + live state via Realtime | **the heavy build** |
| **Infra** (user) | retire the VM daemon services **LAST**; decide VM keep-as-Caddy-shell vs retire | user |

**Sequence:** ① backend pure-deletes (registry/export/pubkey/skill/menu) — zero
risk → ② `audit_events` table + daemon shipper → ③ frontend blob-ops (passkey-add
`K`-wrap crypto) + Realtime → ④ delete the remaining forwards + `DAEMON_URL` → ⑤
infra retire.

## 8. Out of scope / open

- **`grant.rs:29` HPKE** (enroll/unlock `W_c` grant sealing) — separate security
  TODO, but **6.2** (pubkey pinning) intersects it.
- **sealed-audit v2** (private audit) — deferred (§4).
- Related: `docs/SYNC.md` (the blob sync layer this rides on), `docs/PROTOCOL.md`
  (§4.6 proxy port now marked REMOVED), the 2026-06-23 pivot.
