# Batch approve — one passkey gesture, N pending ops

## What

One WebAuthn assertion authorizes N pending ops. The assertion's challenge is
a Merkle root over the N ops' individual bindings (β), so the single signature
commits to exactly that op set — swap, add or drop an op and the root changes.
Security is equivalent to N per-op assertions folded into one gesture: every
op's β is still recomputed and checked daemon-side; the passkey still proves
presence once per BATCH the user saw.

## Commitment

- Leaf_i = SHA-256(0x00 ‖ β_i), node = SHA-256(0x01 ‖ L ‖ R) — RFC-6962 shape,
  odd node promoted (never duplicated). β_i is the op's standard 32-byte
  binding (`crypto/binding.rs::binding_for_op`, DOMAIN_STANDARD), unchanged.
- Challenge = SHA-256("safeclaw/v1/batch-approve" ‖ root). The domain tag
  guarantees a batch challenge can never be mistaken for (or replayed as) a
  single-op β, and vice versa.
- Leaf order = the batch's `op_ids` array order. The signature covers the
  exact ordered set via the root; no canonical sort needed.
- Rust: `rs_merkle` with a custom SHA-256 hasher pinned to the shape above.
  Console: a ~30-line TS mirror. CROSS-LANGUAGE TEST VECTORS live in both
  repos (same leaves → same root); the vectors are the compatibility
  guarantee, not the library choice.

## Wire — the backend stays blind (unchanged)

No new backend endpoint. The console deposits ONE grant per op into the
existing op_relay rows (the backend never inspects grants). A batch grant is
the current per-op grant shape with the per-op assertion replaced by the
shared batch proof:

```
{ o, r, credential_id, wk_enc, wk_ct,          // per-op, as today
  batch: { op_ids: [ ... N ids, leaf order ], assertion } }
```

`wk_enc`/`wk_ct` stay per-op (they are op-id-bound seals; the PRF→userKey
recovery is op-independent, one gesture yields material for all N).

## Daemon verify (approve path gains a batch arm)

For an incoming grant carrying `batch`:
1. `op_id ∈ batch.op_ids`, op exists, is pending, `grant.o` equals the stored
   op (existing canonical check).
2. For EVERY id in `batch.op_ids`: load the daemon's OWN stored op + r
   (never the wire's) and recompute β_i. Unknown/expired sibling id ⇒ reject
   this grant (the root can't be rebuilt from trusted state).
3. Build the root in `op_ids` order, derive the domain-tagged challenge,
   verify `batch.assertion` against it with the credential — the SAME
   WebAuthn verify as today, different challenge source.
4. Then the existing per-op apply, unchanged (resolve target, store the
   op-grant, consume r on success). Per-op apply failures reject only that op
   (with the truthful reason, per the rc.3 fix), never the siblings.

Replay: each r is single-use as today. The same batch assertion re-delivered
lands on already-resolved ops (no-op). A different op set yields a different
root, so the assertion cannot be re-targeted.

## Console

- `lib/approve-op.ts` grows `approvePendingOps(opIds)`: fetch each op's grant
  material (same normalize), compute β_i (the existing computeBinding),
  Merkle root, ONE `safePasskeyGet` on the tagged challenge, seal wk per op,
  deposit N grants (existing `approveOp` per op, now carrying `batch`).
- Bell: a group with N>1 gets "Approve all ×N" (one gesture); single rows
  keep the existing inline approve (no batch envelope — the plain per-op
  path stays canonical for N=1).

## Non-goals

- No backend/op_relay schema change; no new HTTP surface anywhere.
- No subset/inclusion-proof verification (the daemon always rebuilds the full
  root from its own op store); Merkle is used for its shape + future room,
  not partial proofs today.
- No change to multiplicity, r consumption, or per-op apply semantics.
- Does not replace the per-op grant path; a daemon that predates this simply
  fails batch grants closed (unknown field ⇒ validation error ⇒ op stays
  pending, per-op approve still works).
