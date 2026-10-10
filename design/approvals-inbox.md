# Approvals inbox: replace duplicates, one page, one gesture

Rev 3.1 (CONVERGED 2026-10-10), after adversarial review rounds 1 to 4 (fable-advisor + independent
red-team; red-team round 2: converged on security). Extends `design/batch-approve.md` Rev 3 (commitment, wire, daemon
verify and recovery rules unchanged unless stated). Implementation may not
start until review converges.

Rev 1 → Rev 2 in one paragraph: supersede is now a DISPLAY state, not an
authority state (a superseded op stays approvable, so no race can lose a
gesture); supersede is driven only by the daemon naming explicit ids, never
by a backend key match; Export never supersedes and is bound to its creating
process before it may batch; the inbox renders every signed field, freezes
its eligible set at first render, and defaults to checking only read-only
requests from the viewer's own agents. A pre-existing relay hole found in
review (P0) was hot-fixed on dev.

## Problem

During one agent session approvals pile up and the surfaces fight the user:
retries accumulate as ×N rows nobody waits on; batch is per card (one card
per path); Export cannot batch; bell batch is two clicks plus a fetch;
`/grant/{id}` is an island (one link per request).

Prior art: agent tools (Claude Code, Codex, VS Code) cut prompt count rather
than batch; wallets batch only with an itemised confirm whose signed bytes
equal the display (ERC-7730, EIP-5792, SPC); GitHub Actions concurrency
groups / Terraform retire an older pending run for the same intent; GitHub
deployment review approves several ticked environments in one click.

## P0. Relay row integrity (pre-existing, hot-fixed on dev b2fa26d)

Found in review (red-team B1, confirmed): op-relay register/cancel/poll and
blob/items reads accepted ANY account key (agent and demo tiers included),
and register upserted on `op_id`. An agent holds the `op_id` of its own
pending op (401 body) before the daemon's async register lands, so it could
register or overwrite the row with its own `daemon_pubkey`; the approver
seals W* to that (never displayed) key; the agent polls the sealed grant,
opens W*, and reads the sealed vault. Full vault compromise from one
legitimate-looking approval.

Hot-fix (dev b2fa26d, prod pending user go): `ceremonyTierBlocked` on
op-relay register/cancel/poll and blob GET/wait + items GET/wait; register
refuses to change an existing row's `daemon_pubkey` or vault.

Still required BEFORE this design ships (blockers for D1 and D2):
- P0.a Bind each relay row to the registering device key id
  (`registered_key_id`); only that key may re-register, cancel, poll or
  supersede it.
- P0.b Tier-gate blob/items WRITE routes.
- P0.c (tracked, priority raised) Pin `daemon_pubkey` to the device record in
  a passkey-signed ledger entry so the console can verify it; threat model
  now includes agent keys, not only a hostile cloud.

## D1. Exact duplicates are replaced in the inbox (Use only)

**Intent key** (daemon-local, never trusted from the wire):

    intent_key = SHA-256( "safeclaw/v1/intent" || JCS({
        redeemer: op.bind.redeemer, recipient: op.bind.recipient,
        act: op.act, level: pc.level, ttl: pc.ttl_seconds }) )

`r`, `valid.*` excluded. `op.act` for Use carries connection_id, service,
host, method, path (query string and port excluded, same as existing grant
keys), agent, scoped, scope_vars, consent; no body, no nonce, so retries of
the same request are byte-identical. PolicyContext level+ttl are included so
ops minted under different policy (single-use op_grant vs 15-min window)
never merge.

**Policy level is signed and shown.** The Use op scope gains
`level: "ask" | "ask-always"` and, for `ask`, `window_s` (integer seconds;
JCS rejects floats). Being in `op.act.scope` they are in β. What the
approval actually authorizes depends on the already-signed `scoped` flag,
and the console renders exactly that:
- `ask-always` → "allows this one request".
- `ask` + `scoped` → "allows this request shape (same bound values) for N
  min" (request-bound op_grant).
- `ask` unscoped → "opens <connection> for <agent> for N min: every
  ask-level request on it, including writes" (connection-keyed cache; this
  is today's semantics, now stated instead of implied).
At apply the daemon asserts the signed `scope.level` equals the record's
PolicyContext level, and `window_s` equals `pc.ttl_seconds` WHEN present
(ask-always omits `window_s` while its record still carries a ttl), and
refuses on mismatch, so what was rendered is what is applied. (They are already in
intent_key through `act`; the explicit pc fields stay for ops whose scope
predates this.) Older daemons omit them; the console treats a missing level
as ask-always for default-check purposes. Agent identity is per key, not per process: every session
sharing one agent.env is one requester (harmless given the rules below).

**Only `use` participates.** Export never supersedes (no requester
attribution; any local process can mint a byte-identical Export, red-team
B2 / advisor F1). Lifecycle singleton for unlock/lock stays as is. All other
kinds never supersede.

**Supersede is a display state, not an authority state.**
- On mint of B with key K, the daemon marks every live op with key K on this
  daemon as `superseded_by = B` (path-compressed: all point at the chain
  head) and B inherits `retry_count = max + 1`. Daemon-side truth.
- A superseded op REMAINS APPROVABLE until its own expiry: `approve_op`
  accepts Pending ops whether or not they are superseded. A grant verifies
  against the op's OWN stored (o, r); WYSIWYS holds because the user signed
  exactly what they saw. This removes every "deposit landed on the old id"
  race (advisor F2/F4, red-team M2).
- Resolution propagates across the chain: when any op with key K applies,
  every other pending op with key K resolves `approved` with
  `satisfied_by = <applied op>` and no value (Use has no value; the agent's
  next replay consumes the applied op's grant). When any op with key K is
  rejected by the user, every pending K op resolves rejected (red-team S4).
  Raw pollers therefore read `ok` for an approval and `rejected` only for a
  user rejection (advisor F5, red-team S1). A satisfied sibling's poll body
  mirrors the applied op's body exactly (today an applied Use returns `ok`
  with `value: null` and agents re-run) plus `satisfied_by`; no new shape.
- Resolution is withdrawn from the relay too: for each resolved sibling the
  daemon calls the requester cancel path with a reason (`satisfied_by=<id>`
  or `rejected`); the backend stores it, the inbox/grant page render it, and
  a deposit on such a row returns 409 with that status. If a grant for an
  already-resolved op still reaches the daemon, the relay client reads local
  status first and, if resolved, ends the poll quietly (no reject, no
  "approved but apply failed" audit row).
- Atomic apply: `approve_op` keeps its cheap pre-lock pending check, then
  re-checks pending + chain state UNDER the per-vault write lock (one chain
  is always one vault, redeemer == vault_id); `store.approve` and sibling
  resolution happen under ONE acquisition of the `approvals` mutex; sibling
  relay withdrawals are spawned after it is released. Two grants for one chain arriving together: the second
  sees the chain resolved and ends quietly (one applied op = one grant).
- Never over-grants: one applied op = one grant, exactly as today. If the
  agent genuinely needed two executions, its second replay mints a fresh op.

**Backend never supersedes by key match** (advisor F3, red-team M3). The
daemon's register body carries `supersedes: [op_ids]` (ids it just marked)
and `boot_id`. The backend sets `superseded_by` on exactly those ids, only if
they were registered by the same `registered_key_id` (P0.a). A
recovery re-register (batch_verify_failed) sends `supersedes: []`. Restart
zombies: the daemon's op store is in-memory and poll tasks spawn only at
mint, so a pre-restart row can never apply. On register, the backend
CANCELS pending rows of the same `registered_key_id` whose `boot_id`
differs, reason `daemon_restarted`; a deposit on them returns 409 and the
grant page says "this request ended when SafeClaw restarted on <device>; ask
your agent to retry".

Register ordering: independent register tasks can land out of order (B's
`supersedes:[A]` before A's own register). Every register and recovery
re-register body also carries the op's current `superseded_by` (if any);
the backend applies pointers monotonically (never un-marks), so the inbox
converges to one head. The inbox may use backend pointers ONLY to collapse
display; never to choose what to sign.

**Surfaces.**
- Inbox/bell list one row per chain head with "attempt N".
- `/grant/{id}` of a superseded op: still approvable (it applies and
  resolves the chain). The page shows "Your agent sent this same request
  again (attempt N). Approving here covers it." No automatic redirect, so a
  backend pointer can never steer the user to a different row.
- `GET /op/{id}` (daemon) for a superseded op keeps `status: pending` plus
  `superseded_by`; after resolution it returns ok/rejected with
  `satisfied_by`. CLIs need no follow logic.
- Backend deposit (`/approve`) on a row that is no longer pending returns
  409 with the current status instead of today's 200 (red-team M1).

## D1-E. Export retries: the creator withdraws its own op

- New daemon endpoint `POST /op/{id}/cancel` (requester withdrawal; for an
  Export it requires the `waiter_secret`). `sc get` (and every
  remote_approve waiter) calls it on SIGINT, SIGTERM and timeout; the daemon
  then withdraws the relay row through the existing `spawn_cancel`.
- Requester withdrawal is recorded as `withdrawn by requester` (audit
  `cancelled`), never through `reject_op` (which reads as a user denial).
- Daemon liveness backstop (kill -9): a pending Export whose create-time
  waiter secret (E1) has not polled for 60 s is withdrawn (`abandoned`);
  `REMOTE_POLL_INTERVAL` stays well under that (≤ 5 s). Only the creating
  `sc get` can wait on an Export (E1): `sc op wait <export id>` without the
  secret sees status only, so a Ctrl-C'd `sc get` is simply re-run.
- Result: dead `sc get` retries leave the inbox without any intent matching.

## D2. Export joins batch, behind E1

E1 (prerequisite, same release): **value delivery bound to the creator.**
`POST /v/{vid}/op` for Export returns a per-op `waiter_secret` (random,
returned only to the creator, never in SSE, never registered to the relay).
`GET /op/{id}` releases an Export value only with that secret
(constant-time compare; returned only in the POST /op response, never
printed or logged); the poll without it sees status only. An old `sc get`
binary cannot be taught new wording: the E1 daemon answers its status-only
poll with `ok` and no `value`; verify `run_get` exits non-zero with its
existing "no value in response" error rather than printing empty (it does
today: secret.rs `ok_or`), and ship sc + daemon from one binary as now. This closes "whoever polls first gets the
plaintext" (red-team B2, M7) regardless of batching.

Then:
- `batch_expected_challenge` accepts `ActType::Use | ActType::Export`;
  binding stays `DOMAIN_STANDARD`; every per-op Export check still runs.
- Version gate per kind: a batch containing Export needs the daemon release
  that ships E1 + D2 (`EXPORT_BATCH_MIN`); the console re-checks on fetched
  material. Older daemons fail it as recoverable `batch_verify_failed`.
- Consent: export rows have NO section select-all, are default unchecked,
  ticked one by one, at most 8 per gesture; the action bar names how many
  plaintexts the gesture hands over.

## D3. One inbox page

Route `/approvals` (account level). One gesture covers one
(`op.bind.redeemer`, `daemon_pubkey`) partition from FETCHED material, never
the backend's vault_id; ≤ 32 ops per gesture, split in on-screen order; the
action bar names each gesture's vault and device ("2 passkey taps:
personal on MacBook Pro, team-infra on dev-vm").

Data: rows recruit from `GET /api/me/approvals` (union of the caller's
approvable vaults: vault_id, daemon_version, retry_count, chain head only).
Every rendered fact and every signed op comes from per-op fetched material,
rendered by the SAME renderer as `/grant/{id}`: method, host, path,
connection, service, agent, device, consent/scope_vars (red-team M5). A row
whose material fails to load has no checkbox.

Selection and signing (replaces Rev 3 WYSIWYS rule 2; the rendered list is
the confirm):
1. The eligible set is frozen at first render. Every row that arrives later
   goes to a "N new requests" strip, unchecked, and joins only on click
   (red-team M4).
2. `op_ids` per gesture = exactly the checked rows of one partition in
   on-screen order. Button label from the checked set ("Approve 5 · 1 passkey
   tap"), never a cloud total.
3. The approve button is disabled for 600 ms after any change to the
   checked set or the visible rows.
4. Default checked ONLY when every condition holds on SIGNED material:
   `use`, method GET/HEAD, signed `level == "ask"` AND signed
   `scoped == true` (request-bound; an unscoped ask opens the whole
   connection, so its method says nothing about the authority), and the op's
   `bind.redeemer` is a personal (non-team) vault of the viewer per the
   console's own vault list. Everything else is default unchecked (writes,
   DELETE, ask-always or missing level, team vaults, export). Backend
   attribution (agent label, `requester_is_viewer`) is display only and
   never makes a row default-checked. Default-check alone never authorizes:
   an explicit tap after the 600 ms settle is always required. Section
   select-all exists for `use` rows only.
5. A row whose op gets superseded while on screen keeps its rendered
   material and check state, gains an "agent sent it again" marker, and the
   gesture signs the op as rendered (still approvable under D1). No in-place
   swap, so nothing changes under the cursor.
6. Rows that leave (resolved elsewhere, expired) animate out and are removed
   from the checked set before signing.
7. Non-batchable kinds render in "Needs its own confirmation" with "Review"
   (opens the grant ceremony in a drawer).
8. Reject: per row and "Reject selected" (no passkey). Reject resolves the
   chain (D1).

## D4. Bell = preview

Account-wide count; dropdown lists up to five chain heads rendered from
fetched material, order FROZEN while open. Inline Approve only for `use`
rows (plain per-op ceremony on the rendered material); other kinds show
"Review". Footer "View all N →" to `/approvals`. The in-bell batch panel is
removed (red-team M6).

## D5. Grant page links into the inbox, stays login-free

- Not signed in: muted line "Signed in? See every pending request and approve
  them in one tap" → `/login?redirect=/approvals%3Ffocus%3D{id}`. Fix the
  login redirect validator to reject backslashes (`/\host` normalizes to a
  protocol-relative URL; red-team nit).
- Signed in with other pending rows: "4 more waiting → Review all" →
  `/approvals?focus={id}` (focused row scrolls into view; pre-checked only if
  it is a default-checked row per D3 rule 4).

## Non-goals (v1)

- "Don't ask again for 15 minutes" at approve time (deferred by user).
- Supersede for Export, write/secret-set and lifecycle kinds.
- Cross-vault single gesture.
- Storm-detection heuristics beyond `retry_count`.

## Security invariants for review

- WYSIWYS per gesture with cross-card selection (D3 1-6): every signed field
  rendered; eligible set frozen; no in-place swap.
- Supersede never adds authority and never moves a signature to another op;
  a superseded op applies only its own (o, r).
- No backend-originated pointer is ever followed for signing.
- Export value reaches only the creating process (E1); never via supersede.
- Relay rows are writable only by their registering device key (P0, P0.a).
- Stated plainly: until P0.c ships, a hostile BACKEND can still substitute
  its own daemon_pubkey in `/api/grant` and read the grant it stores (same
  per-op exposure as today; batch neither worsens nor fixes it). Do not
  describe "the backend never learns W*" as closed before P0.c.
- Per-kind version gate re-checked on fetched material.

## Implementation order (after convergence)

0. P0.a/b backend (+ prod promote of b2fa26d on user go).
1. Daemon: intent index, display-supersede + chain resolution, E1 waiter
   secret, liveness withdraw, CLI cancel-on-exit, batch arm accepts Export,
   register sends supersedes/boot_id; tests + intent_key fixture.
2. Backend: registered_key_id, boot_id, superseded_by, retry_count columns
   (dev ALTER; prod at promote), deposit 409, reject status guard,
   `/api/me/approvals`.
3. Console: inbox page, bell preview, grant page lines, login redirect fix,
   per-kind version gate.
4. fable-advisor final review of the diff.
