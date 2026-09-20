# Batch approve — one passkey gesture, N pending ops

Rev 3 — after adversarial security review rounds 1 and 2 (two independent
reviewers). Rev 1's compat story was wrong, its sibling rule self-destructed,
and it had no WYSIWYS bar; Rev 2's "leave pending on batch-verify failure"
had no transport on the relay path (the grant row is first-deposit-wins and
the poll task exits after one apply). All corrected below. Implementation may
not start until the review converges.

## What

One WebAuthn assertion authorizes N pending ops. The assertion's challenge is
a Merkle root over the N ops' individual bindings (β), so the single signature
commits to exactly that op set — swap, add or drop an op and the root changes.
Security is equivalent to N per-op assertions folded into one gesture: every
op's β is still recomputed daemon-side from the daemon's OWN stored state; the
passkey proves presence once per batch the user saw.

**Scope rule: a batch may contain only `Use` ops (brokered ask-approvals,
DOMAIN_STANDARD).** Enroll, export, revoke, widen-host, secret-set,
vault-delete, vault-lock and every other lifecycle/high-consequence kind keeps
the per-op ceremony and detail page. This is the consent boundary, not an
optimization.

## Commitment

- Leaf_i = SHA-256(0x00 ‖ β_i), node = SHA-256(0x01 ‖ L ‖ R) — RFC-6962 shape,
  odd node PROMOTED (never duplicated — duplication reintroduces the
  CVE-2012-2459 `[a,b] ≡ [a,b,b]` ambiguity). β_i is the op's standard 32-byte
  binding (`crypto/binding.rs::binding_for_op`, DOMAIN_STANDARD), unchanged.
  Leaf input is the RAW 32-byte β, never a hex/base64 rendering.
- Challenge = SHA-256("safeclaw/v1/batch-approve" ‖ root). ASCII tag directly
  concatenated — NO 0x00 separator (deliberately unlike binding.rs β; one test
  vector pins exactly this). The tag diverges from "safeclaw/v1/binding" at
  byte 13, so a batch challenge can never be read as a single-op β or vice
  versa; arm selection is structural (presence of `batch`), never inferred
  from bytes.
- Leaf order = the batch's `op_ids` array order = the exact order the console
  signed. Async completion order must never leak into `op_ids`.
- Bounds: 2 ≤ N ≤ 32, no duplicate ids, all ops same vault, same credential,
  all `Use`/DOMAIN_STANDARD. Console chunks larger groups (one gesture per
  chunk of ≤32). Daemon enforces the same bounds BEFORE loading any records.
- Rust: `rs_merkle` with a custom SHA-256 hasher — its default
  `concat_and_hash` does NOT add the 0x01 node prefix and its odd-node
  behavior must be pinned to promotion; both are overridden explicitly.
  Console: a ~30-line TS mirror. Cross-language test vectors at
  N = 1, 2, 3, 5, 6, 7, 11 (promotion at multiple depths) live in BOTH repos
  and are committed BEFORE any implementation code; the vectors are the
  compatibility guarantee, not the library choice. (N=1 vectors pin the shape
  even though the wire floor is N=2.) At least one vector is END-TO-END:
  β list → root → exact 32 challenge bytes, plus the dedicated
  no-0x00-separator tag pin.

## WYSIWYS — render-source must equal sign-source

The bell's grouped card is built from approvals-list rows whose display fields
(and missing `path`) are cloud-asserted; trusting them recruits a gesture for
ops the user never saw. Therefore:

1. `approvePendingOps` fetches each op's grant material and derives the
   op's display facts (service/connection, method, host, path, bound scope
   summary) from the SAME normalized `o` that feeds `computeBinding`. List
   rows recruit attention; they never feed the signature or the confirm UI.
2. Any op whose derived facts don't match the tapped group's key is dropped
   from the batch and surfaced separately, loudly. Any op that fails the
   scope rule (non-`Use`) is dropped to its per-op page.
3. The confirm state renders the per-op list (method · host · path,
   expandable) from those derived facts. The rendered list IS `op_ids` —
   one gesture covers exactly the rendered ops, count shown =
   `op_ids.length`, never a page-capped or cloud-supplied total. This holds
   PER GESTURE: when a group chunks into multiple gestures of ≤32, each
   confirm renders exactly its own chunk ("gesture 1 of 4 covers these 32");
   no gesture ever covers ops rendered under a different chunk's confirm.
4. No re-fetch loops under one intent: the reject-all drain pattern must NOT
   be copied for approve. One tap, one rendered set, one gesture.
5. The ceremony audit row records the full `op_ids`.

## Wire — the backend stays blind (unchanged)

No new backend endpoint. The console deposits ONE grant per op into the
existing op_relay rows (the backend never inspects grants). A batch grant is
the current per-op grant shape with the per-op assertion replaced by the
shared batch proof:

```
{ o, r, credential_id, wk_enc, wk_ct,          // per-op, as today
  batch: { op_ids: [ ... N ids, leaf order ], assertion } }
```

- Top-level `assertion` is ABSENT in a batch grant, and must never be
  populated with the batch assertion (an old daemon would verify it against β,
  fail, and march `fail_count` to auto-reject).
- `wk_enc`/`wk_ct` stay per-op: independent HPKE encapsulations (fresh
  ephemeral each) with `info = grant_seal_info(op_id)` — one PRF gesture
  yields material for all N with no key/nonce reuse (reviewed, sound).
- The console partitions a visual group by `daemon_pubkey` from the fetched
  grant material: one root, one gesture per daemon. A vault served by two
  daemons gets two gestures — correctness over UX; a cross-daemon root can
  never verify anywhere.

## Version gating — the console never sends batch blind

An old daemon does NOT "fail batch grants closed" at the parser:
`Grant` has no `deny_unknown_fields`, so `batch` is silently ignored, and the
missing top-level `assertion` fails serde in the Json extractor → HTTP 422 →
the relay client's apply-failure path REJECTS the op. Unhandled, a mixed
version turns "user approved N" into "N permanently rejected". Therefore:

- The daemon advertises support: op relay registration (`reg_body`) gains a
  passthrough `daemon_version` field (backend stores/serves it opaquely, like
  `passkeys`; still blind). The console offers "Approve all ×N" ONLY when
  every op in the group carries a version ≥ the release that ships the batch
  arm; otherwise it falls back to per-op ceremonies. Absent field ⇒ no batch.
- The advertised version is relay-asserted and deliberately UNAUTHENTICATED —
  do not "fix" this. Forging it DOWN (or stripping it) only forces per-op
  fallback: UX cost, nothing else. Forging it UP sends batch grants to an old
  daemon, whose apply failure the relay could equally have manufactured by
  answering the poll with a bare 403 — no new capability. Authenticating
  daemon metadata against a blind relay belongs to the sc_pk-pinning
  workstream, not here.
- Backstop (not the mechanism): a batch grant reaching an old daemon still
  cannot approve anything.

## Daemon verify (approve path gains a batch arm)

`validate_grant` is refactored to take the expected challenge as a parameter
(β for the plain arm, tagged root for the batch arm) — ONE validator, no
parallel fork; the WebAuthn seam (`passkey/webauthn.rs::verify_assertion`)
already accepts a caller-supplied 32-byte challenge, so sudp is untouched.

For an incoming grant carrying `batch`:
1. Bounds first (before touching any record): 2 ≤ len ≤ 32, no duplicates,
   `op_id ∈ batch.op_ids`.
2. TARGET row checks (this op only): op exists, pending, unexpired;
   `grant.o` equals the stored op (existing canonical check); and
   **`grant.r` equals the stored record's `r`** — the batch assertion covers
   stored r's, not the wire `r`, so without this equality a relay can shuffle
   r's between rows and burn a sibling's single-use challenge. The plain arm
   gets the SAME equality, required, in the same release: the challenge store
   is daemon-global, so today a relay-swapped `r` on the per-op path still
   verifies (β binds whatever wire `r` the console was fed) while consuming a
   sibling's live challenge.
3. SIBLING lookup (every other id in `op_ids`): the record must EXIST with
   its stored `(o, r)` — ANY status, expiry ignored (raw map access, not the
   expiry-filtered `get`). Rows arrive and apply at independent times; by row
   k the earlier siblings are already Approved/Consumed, and a short-TTL
   sibling may have expired — a signed β is immutable and each sibling's own
   application is separately gated by its own pending check, so only a
   genuinely ABSENT record rejects. Every op must be `Use`; every record the
   same vault; one `credential_id` for the whole batch; DOMAIN_STANDARD
   pinned (an op that would select DOMAIN_SETUP can never enter a batch).
4. Rebuild β_i from the daemon's OWN stored `(o, r)` (never the wire's) in
   `op_ids` order, build the root, derive the tagged challenge, verify
   `batch.assertion` — the same WebAuthn verify as today, different challenge
   source.
5. Verify-once cache — AS BUILT, strictly stronger than specified: the memo
   keys on `(credential_id, op_ids)` and stores only the root DERIVATION (a
   pure function of the daemon's own op store), and the WebAuthn verify is
   NEVER skipped — it runs on every row against the memo'd root, so a stale
   or adversarial entry can only fail a signature, never approve anything.
   The original spec (hit may also skip the verify, keyed with assertion
   bytes) remains sound but is not what shipped. A hit skips ONLY the
   sibling loads and the root rebuild — nothing else: the challenge
   peek→consume, `check_now(o.valid)`, the wk_enc/wk_ct open, the
   `grant.o == stored op` / `grant.r == stored r` equalities and every other
   per-row check run unchanged on every row. Entries are written only after
   a full successful verify (no poisoning path; a malleated signature just
   misses and re-verifies); size is bounded (success-only writes, ≤32 ids
   each, TTL eviction, hard cap on entry count). Honest batches cost O(N)
   total, not O(N²), and stop depending on sibling record retention.
6. Then the existing per-op apply, unchanged (resolve target, store the
   op-grant, consume THIS op's `r` on success). A per-op apply failure
   rejects only that op (truthful reason, per the rc.3 fix), never siblings.
7. Failure semantics — batch-verify failures are RECOVERABLE, never terminal,
   and the recovery has a real transport:
   - Every batch-arm validation failure (bounds, non-`Use` op, missing
     sibling, root mismatch, `r`/`o` equality, assertion failure) returns a
     machine-readable `ScCode` (RFC-9457, existing convention) —
     `batch_verify_failed`. The relay client switches on the CODE, never on
     body text. As built, two failures stay TERMINAL by design (per-op
     parity — the same material dies the same way per-op, and a retry with
     it cannot succeed): an expired validity window and an unknown
     credential.
   - On that code the relay client does NOT `apply_reject`. It RE-REGISTERS
     the op with the relay (the existing register upsert on `op_id` resets
     `grant_status` to `pending` — daemon-authenticated, vault-owned, zero
     backend change; the stale `sealed_grant` is unreachable while pending
     and overwritten by the next deposit) and CONTINUES its poll loop until
     the op's own expiry. The op reappears as pending in the console; per-op
     approve works again. Verified against the deposit handler: deposits are
     first-write-wins on `grant_status = 'pending'`, so without the
     re-register no second deposit could ever land — this step is
     load-bearing, not an optimization.
   - The client memoizes SHA-256 of the FULL grant body bytes and skips
     re-applying a byte-identical redelivery (no spin between failure and
     the re-register taking effect). The memo must hash the whole body, not
     the assertion: a same-set retry has the same root, and a deterministic
     authenticator (RFC 6979 is permitted) can legitimately repeat the
     assertion byte-for-byte — what guarantees an honest retry differs is
     the fresh HPKE ephemeral in `wk_enc`/`wk_ct`, present only in the full
     body. Memoizing assertion bytes would wedge honest retries.
   - `fail_count` increments once per applied bad grant as today;
     `MAX_APPROVE_ATTEMPTS` (10) stays the backstop. "Recoverable" holds
     against honest accidents (daemon restart, expired sibling, version
     skew). Against a MALICIOUS relay it degrades to the reject power the
     relay already has (it can answer any poll with a bare 403); byte-varying
     bad grants march `fail_count` to the 10-cap automatically — bounded,
     and preferable to the unbounded CPU-spin that not counting them would
     open.
   - The console should surface "this request failed verification N times"
     on a re-pending row rather than presenting a clean pending card, so
     tampering reads as suspicious rather than inviting fatigue-taps.
   - Only per-op apply failures AFTER a verified batch reject (truthfully).

Replay: each `r` is single-use as today. The same batch assertion
re-delivered lands on already-resolved ops (no-op). A different op set yields
a different root, so the assertion cannot be re-targeted; permuting `op_ids`
changes the root.

## Console

- `lib/approve-op.ts` grows `approvePendingOps(opIds)`: fetch each op's grant
  material (same normalize), derive display facts + β from the SAME bytes
  (WYSIWYS rules above), partition by daemon_pubkey, chunk ≤32, Merkle root,
  ONE `safePasskeyGet` on the tagged challenge per chunk, seal wk per op,
  deposit N grants (existing `approveOp` per op, now carrying `batch`).
- Bell: a group with N>1 ops (on batch-capable daemons) gets "Approve all
  ×N" opening the rendered confirm list; single rows keep the existing inline
  approve (no batch envelope — the plain per-op path stays canonical for
  N=1).

## Adjacent findings this design depends on (tracked separately, not in scope)

- **Unpinned `sc_pk` (pre-existing, product-wide):** the console seals W*/UIK
  root to the relay-SERVED `daemon_pubkey`; a malicious relay substituting its
  own key captures the unlock material client-side, re-seals, and forwards —
  undetectable. Batch neither worsens nor fixes this (identical exposure to
  today's single-op relay approve), but "the backend never sees W*" is not
  true until sc_pk is authenticated through a channel the cloud cannot forge
  (natural home: passkey-signed device/daemon record, §15 ledger). Own
  workstream, owner-prioritized.
- **Challenge-origin invariant:** a vault credential must never sign a
  `.get()` challenge that was not derived client-side from a tagged
  `safeclaw/v1/*` construction. All current call sites comply (reviewed);
  any future passkey LOGIN flow on the same rpId would hand the cloud
  arbitrary-challenge assertions = forged approvals. Enforce in the
  `safePasskeyGet` wrapper (accept `{tag, payload}`, hash inside) as
  follow-up hardening.
- **Plaintext `wrapping_key` on the relay path:** the loopback approve
  accepts the legacy plaintext W* form regardless of origin; the relay client
  should require `wk_enc`/`wk_ct` for relay-delivered grants. One-line
  hardening, land with the batch release train.

## Non-goals

- No backend/op_relay schema change beyond the opaque `daemon_version`
  passthrough; no new HTTP surface anywhere.
- No subset/inclusion-proof verification (the daemon always rebuilds the full
  root from its own op store); Merkle is used for its shape + future room,
  not partial proofs today.
- No change to multiplicity, r consumption, or per-op apply semantics.
- Does not replace the per-op grant path; batch is an additive arm behind a
  version gate, and N=1 never uses it.
