# SafeClaw Daemon — Security Audit

> **⚠️ HISTORICAL (pre-phantom-only).** This scope doc predates the 2026-07-03
> pivot. Two facts are now inverted or wrong and must not be trusted here: the
> port model is **control/API 23293 / credential proxy 23294** (this doc's
> "admin 23294 public / proxy 23295 internal" is stale AND backwards — today the
> proxy is loopback-only and the control plane is the browser/CLI-facing one),
> and the `/use` forward-proxy plane it audits is retired (canon =
> `docs/CREDENTIAL_BROKER.md`). The crypto/auth/op-flow items below still read
> true. Kept for provenance.

**Branch under review:** `v1/crypto-redesign` (the multi-tenant SUDP daemon at `safeclaw/safeclaw`)
**Out of scope:** the per-VM `dev` branch (legacy stack, being deprecated), SaaS pro-backend, frontend.

This audit prepares the daemon for OSS release. The goal is high confidence in the **crypto correctness**, **input handling**, and **auth boundaries** of the daemon as a multi-tenant credential broker. **Do not** treat this as a general code-quality review — focus on adversarial behavior.

---

## Context for the auditor

SafeClaw is a passkey-gated credential broker. The daemon:

- Stores per-vault sealed state (`vault.dat` per tenant), encrypted with a DEK that's KEK-wrapped under a passkey-derived `userKey`.
- Issues short-lived challenges (`r`) for each op; user signs a `β = binding(r, op)` with their passkey; daemon verifies and unwraps.
- Operates two ports: **admin (`23294`, public)** for ops/grants/metadata, **proxy (`23295`, internal-only in prod)** for upstream forwards.
- Uses the [sudp](https://github.com/xhyumiracle/sudp) Rust crate for the protocol primitives (HPKE, AEAD, key wrapping). Audit assumes sudp crate is correct — bugs inside sudp are out of scope but please flag any *usage* mistakes from the daemon side.

Read [PROTOCOL.md](PROTOCOL.md) first — especially §4 (auth model), §6 (locked/unlocked semantics + memory residence), §7 (op kinds).

---

## Already-fixed (do NOT re-flag)

These were closed during the 2026-05-25 hardening pass; mention only if you find evidence they're incomplete.

1. **`vault_id` leak in registry response** — fixed in `dae4c2b`. `RegistryResponse` no longer carries `vault_id`. Invariant: nothing on the agent-facing `/api/*` surface returns vault_id outbound. (See [src/server/handlers/registry.rs](src/server/handlers/registry.rs).)

2. **`Use` ops via control-plane endpoint** — fixed in `3e5c711`. `POST /v/{vid}/op` rejects `ActType::Use` so the broker plane (proxy port) is the only forward-producing surface. (See `reject_broker_kind` in [src/server/handlers/op.rs](src/server/handlers/op.rs).)

3. **`/c/registry` legacy alias** — removed `9a033ac`. Catalog endpoint is `/menu` (2026-05-27: dropped `/c/` prefix; was `/c/menu`).

---

## Scope: what to audit

### P0 — must close before OSS

| # | Category | Where to look | What to check |
|---|---|---|---|
| P0.1 | **AEAD usage** | `src/crypto/aead.rs`, all callers | Are nonces unique per key? Any nonce reuse risk on rekey/retry paths? Is the AAD field actually verified on decrypt (sealAd / wrapBindingAd domain separation)? |
| P0.2 | **W_c lifecycle** | `src/server/handlers/approve.rs`, `src/server/broker.rs` | `W_c` should never be retained across an op boundary. Verify zeroize on every drop path including error returns. PROTOCOL.md §6 says daemon never holds W_c — confirm in code. |
| P0.3 | **Grant verification** | `src/server/handlers/approve.rs::confirm` | Is the binding β verified against the *canonical* op (`json-canonical` from sudp)? Replay protection on `r`? What stops the same grant from being submitted twice? |
| P0.4 | **Op input validation** | `src/server/handlers/op.rs::create` | `vault_id` is validated (length, charset) — check it's enforced everywhere a path captures `:vid`. `op.act.target`, `op.act.scope` — bounded sizes? Sane shapes? Reject hostile shapes (huge scope JSON, deeply nested objects)? |
| P0.5 | **Rate limit coverage** | `src/passkey/challenge.rs` + every public endpoint | Today only challenge issuance is rate-limited (per-IP). What other endpoints can be hammered: `/v/{vid}/op` create, `/op/{id}/approve` (computationally heavy — passkey verify + decrypt), `/v/{vid}/events` (SSE connection count)? |
| P0.6 | **HPKE recipient handling** | sudp Export ops + broker forwarder | When `Export` is sealed to a recipient pk, is the pk *bound* to the op (so it can't be swapped mid-flight)? Check sudp's `RecipientPk` plumbing. |

### P1 — fix before opening to public traffic

| # | Category | Where to look | What to check |
|---|---|---|---|
| P1.1 | **`cargo audit`** | repo root | Run `cargo audit` and `cargo deny check`. Resolve all advisories. |
| P1.2 | **vault.dat persistence** | `src/storage/sealed_vault.rs`, `src/storage/plaintext.rs` | Atomic write (write to tmpfile + rename)? Power-loss safety? Concurrent writes from two requests on the same vault — is there a per-vault mutex? |
| P1.3 | **External store credentials** | `src/store/adapters/gcp.rs` | GCP service-account JSON ends up in native-secrets. Is it ever logged? Is the in-memory `external_stores` cache cleared on lock? Are adapter HTTP clients reused safely across requests? |
| P1.4 | **Audit log integrity** | `src/audit.rs` | What stops a malicious caller from filling the audit table? Retention prune respects `audit_retention_days` — is the SQL parameterized? Can a malformed op kind crash the row insert? |
| P1.5 | **Locked-vault enforcement** | `src/server/handlers/op.rs` + every handler that touches cache | The "vault locked" gate at op.rs:38 only covers op create. Confirm other endpoints (`keys-known`, `registry`, `events`, `usage`) handle locked state gracefully without leaking data. |
| P1.6 | **CORS / origin checks** | `src/server/mod.rs` | What origins are allowed to call the daemon? Browser-direct hits assume same-origin or specific allowlist — verify. |
| P1.7 | **Error message leakage** | `src/error.rs` + every handler | Internal errors (`AppError::Internal("..."`)) — are they passed verbatim to the client? Do they leak filesystem paths, tenant ids, or internal state? |

### P2 — nice to close, not blockers

| # | Category | Where to look | What to check |
|---|---|---|---|
| P2.1 | **SSE backpressure** | `src/server/handlers/events.rs` | Channel capacity is 128. What happens if a subscriber lags? Slow-consumer doesn't block fast ones? Per-tenant max-subscriber cap? |
| P2.2 | **Timing side-channels** | passkey verification, token comparison | Use constant-time compare for everything that involves secret material. |
| P2.3 | **Dependency footprint** | `Cargo.toml` | Is every dep load-bearing? Smaller surface = smaller audit. |
| P2.4 | **OSS-mode threat model doc** | new file | Write a short THREAT_MODEL.md describing: who's an adversary, what's in the TCB, what self-host vs cloud assume. OSS users need this to deploy safely. |

---

## How to execute

1. **Triage**: walk the P0 list first. For each item, open the named file(s), read the relevant section, and write findings as you go.
2. **Findings format**: one issue per finding, with:
   - Severity (Critical / High / Med / Low)
   - File:line
   - What's wrong
   - Suggested fix (rough — implementation comes later)
3. **Output**: a single markdown file `SECURITY_FINDINGS.md` in the repo root. The maintainer reads, then decides which to fix in this session vs. defer.
4. **Don't fix as you go.** Audit first, fix after. Mixing them loses the bird's-eye view.

## Tools

- `cargo audit` (install via `cargo install cargo-audit`)
- `cargo deny` (install via `cargo install cargo-deny`)
- `rg` for searching
- Read sudp crate source at `~/.cargo/registry/src/index.crates.io-*/sudp-0.1.0/src/` when needed

## Time budget guidance

- P0: ~half a day if findings are minor, multiple days if you find real issues
- P1: another half-day
- P2: skip unless quick

## What to do if you find a Critical

Stop, write up the finding, surface to the maintainer immediately. Don't continue auditing — focused fix first.
