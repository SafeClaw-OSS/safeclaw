# Credential Broker v2 — Build Plan (implements the LOCKED design)

> **Companion to [CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md) (the LOCKED spec).** That doc is the *what* (frozen — don't re-litigate); this is the *how*: concrete, code-grounded, sequenced, testable. Every stage is **additive** over the shipped v1 (the connection layer + `/use`/`/stream` already exist). Passthrough is governed by the **§11 three-gate ordering rule** — encoded as the stage order below.
>
> **v1 STATUS (shipped to `dev` 2026-07-01, v1.0.29, build-verified, LIVE-e2e pending):** `/export` off the agent surface (403 stub); distinct `423 vault_locked`; connect-agent modal → agent self-provisions its key; skill field-name casing; OAuth *needs-reauth* console signal (on the already-cloud-blind daemon refresh path — see §OAuth note). v2 builds on top of this.

---

## 0. Code anchors — where v2 hooks in (verified on `dev`)

| Concern | Location | v1 today | v2 change |
|---|---|---|---|
| Connection struct | `src/storage/plaintext.rs:76` `Connection{service,config}` | curated: `service`=recipe id | **add** raw: `service:""` + `config.host` |
| Conn→service resolve | `src/state.rs:325` `resolve_connection_service` | `conn==service` default | raw conn resolves to "" (no recipe) |
| Secret address | `src/storage/plaintext.rs` `secret_address(conn,svc,role)` | bare / `<conn>:<role>` | unchanged (phantom maps through it) |
| Egress host guard | `src/service/validate.rs:128` `host_egress_allowed` | blocks private/metadata/localhost; **allows any public host** | **add** `resolved_hosts` exact-FQDN allowlist ON TOP (keep this as the private/metadata floor) |
| Host-literal guard | `src/server/broker.rs` `upstream_host_has_unsafe_template` | rejects `{{secret.*}}` in authority | unchanged (still forbids raw phantom in a *recipe* authority) |
| Approval cache | `src/state.rs:93,111` `allow_secrets`/`entries` keyed by `conn_id`; grant bound to `(connection_id, rule_id, method)` | host is recipe-fixed → not in key | **add** resolved host to the key on the passthrough path (gate 3) |
| Forward core | `src/server/broker.rs:61` `execute_use_forward`, `:216` `resolve_use_primary`, `:738` `resolve_auth_value`, `:845` `forward_to_upstream_with_extras` | `/use`+`/stream` call these | `/proxy` reuses `execute`/`forward`; extract `Ingress::shape`+`decide`/`execute` (additive) |
| Routes | `src/server/mod.rs:106` `broker_router` | `/use`,`/stream`,`/export`(403) | **add** `POST /v/{vid}/proxy` behind the same agent-key gate |
| Template render | `src/server/broker.rs` `render_template` (`{{…}}`) | recipe fill | **add** `__conn.role__` phantom pass (disjoint delimiter) on the passthrough path only |

---

## 1. Stage order (the §11 gate rule, as a DAG)

```
A. resolved_hosts + exact-FQDN enforce   ─┐  (gates 1+2)
B. host in passthrough approval-cache key ─┤  (gate 3)
                                           ▼
C. /proxy ingress + __conn.role__ phantom     (first passthrough surface — MUST follow A+B)
   ▼
D. additive Ingress/decide/execute refactor   (fold /use,/stream,/proxy into one core)
   ▼
E. MITM + `sc run` env-CA (escalation ladder) (second passthrough surface)
   ▼
F. sc status discovery · MCP · agent-authored recipes · deep-link
```

**Hard rule:** no passthrough ingress (C, E) may reach users before A **and** B are enforced (not warn-mode). A and B are safe to land alone (they only tighten the recipe path, which is already host-safe). D can interleave with C. DNS-pin is an *optional* hardening, never a gate (§11).

---

## 2. Stage A — `resolved_hosts` + exact-FQDN enforcement (foundation; no new ingress)

**Goal:** one anchor function + tighten egress to an exact-FQDN allowlist per connection. Ships alone; gates 1+2.

1. **`resolved_hosts(conn) -> Vec<Host>`** (new, in `broker.rs` or `service/`):
   - `conn.service` names a recipe → for each `upstream[*].url`, `render(url, conn.config)` and extract the authority (reuses the existing host-literal + `{{connection.x}}` render path). Multi-host recipes (github: `github.com`+`api.github.com`+`*.githubusercontent.com`→ **enumerate exact FQDNs**, no wildcard) yield all.
   - `conn.service == ""` (raw, v2) → `[conn.config.host]` (single host).
2. **Enforce at forward time:** in `forward_to_upstream_with_extras` (broker.rs:845), before the request goes out, assert `egress_authority ∈ resolved_hosts(conn)` by **exact FQDN** (case-insensitive, port-aware per existing `host_egress_allowed` which already handles `host:port`). `host_egress_allowed` **stays** as the private/metadata/localhost floor beneath it.
3. **Allow raw connections:** `Connection` validation + `resolve_connection_service` accept `service:""` with a non-empty `config.host`; the console/`sc connect` (Stage F) can create them. `host_egress_allowed(config.host)` must pass at creation (reject private/metadata at anchor time too).
4. **Rollout:** land in **warn/log mode** first (`resolved_hosts` computed, mismatch logged + audited, NOT denied) for one release, confirm zero false-positives on curated recipes (their multi-host lists are already exact FQDNs), then flip to **deny**.

**Test:** unit `resolved_hosts` for single/multi-host curated + raw; curated `/use` still forwards (exact match); a synthetic mismatch is denied (post-flip); private/metadata still blocked by the floor.

## 3. Stage B — host in the passthrough approval-cache key (gate 3)

**Goal:** an approval for host A must not authorize host B within the TTL on `/proxy`.

- Today the grant is bound to `(connection_id, rule_id, method)` (state.rs:111) and the caches key by `conn_id` (`entries`/`allow_secrets`). Host isn't in the key — **safe for `/use`/`/stream`** (host is recipe-fixed per connection) but unsafe once `/proxy` makes host request-data.
- **Change:** thread the **resolved egress host** into the cache key **for passthrough grants** (`cache_insert`/`cache_lookup*` at state.rs:360-440). Cleanest: extend the key to `(conn_id, rule_id, method, host)`; for recipe connections the host is constant so behavior is unchanged; for raw/multi-host it scopes the grant to the approved host.
- Connection-scoping already bounds this to the connection's `resolved_hosts`; the key add matters mainly for **multi-host** connections.

**Test:** approve `/proxy` to host A → a within-TTL call to host B on the same connection misses the cache → re-approval required.

## 4. Stage C — `/proxy` ingress + connection-qualified `__conn.role__` phantom

**Goal:** the generic explicit-transport passthrough (top-right of the §3 matrix). MUST follow A+B.

1. **Route:** `POST /v/{vid}/proxy` in `broker_router` (mod.rs:106), behind the same `require_api_key` gate. Body `{ url, method, headers, body }` (== the future MCP tool schema).
2. **Phantom parse:** scan `headers`/`body`/`url` for `__<conn>.<role>__` (delimiter **disjoint** from `{{…}}`; distinctive `sc__…__` breadcrumb for un-substituted-leak detection). Resolve `<conn>` → connection → `resolved_hosts` + the secret at `secret_address(conn, svc, role)`. **Reject a bare `__role__` when >1 connection could match** (ambiguity → 400 with the candidate list).
3. **Enforce + substitute:** assert the request's `url` authority ∈ `resolved_hosts(conn)` (Stage A), substitute the phantom with the real secret, then hand to the **same** `decide`/`execute`/`forward` path as `/use` (policy eval, captive-portal approval with host in the key, egress). The agent never receives the substituted value back (residue-free, like `/stream`).
4. **Audit/approval** render the resolved connection + host + role (not the raw value).

**Test:** `/proxy` with `__gh.token__` to `api.github.com` → substituted + forwarded; same phantom to `evil.com` → denied by Stage A; bare `__token__` with two github connections → 400 ambiguous.

## 5. Stage D — additive `Ingress`/`decide`/`execute` refactor

**Goal:** fold `/use`,`/stream`,`/proxy` into one core without rewriting the 2-RTT ceremony or `approve.rs` (§4).

- `trait Ingress { fn shape(self) -> BrokerRequest }` — one impl per route (extract path/host/phantom/body shaping out of each handler).
- `broker::decide(BrokerRequest) -> Decision` where `Decision = Forward(allow+cache-hit) | NeedsApproval(OpHandle) | Deny` — **leg 1** (what `/use` returns `202` from today).
- `broker::execute(op, grant_ctx) -> BrokerResponse` — **leg 2**, post-passkey forward + one-shot `Consumed` + cache write. **Stays in `approve.rs`'s existing flow** — this refactor only *names* the seam, it does not move the ceremony.
- Migrate `/use` first (behavior-preserving; existing tests are the oracle), then `/stream`, then `/proxy` drops in as a third `Ingress`.

**Test:** the full existing `/use` + `/stream` suites pass unchanged after each migration step (refactor is behavior-neutral).

## 6. Stage E — MITM + `sc run` env-CA (escalation ladder)

**Goal:** cover dumb subprocess CLIs with hardcoded URLs. Silent, **child-scoped**, opt-in — never the default (§5, §15).

- **Escalation ladder** (prefer residue-free; only descend when forced): ① agent HTTP → `/use`|`/proxy`; ② per-command override (`git clone <…/stream/…>`, `npm --registry`, `pip -i`) — **zero `sc run`**; ③ recipe/`/use`; ④ hardcoded-URL + env-cred CLI with no cheap route → suggest `sc run` **once**, record in a per-project manifest, don't re-nag.
- **`sc run -- <cmd>`:** generate an **ephemeral, per-process CA**; start a localhost MITM proxy; export **into the child only** the CA trust env (`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/…) + `HTTPS_PROXY=127.0.0.1:<port>`. The proxy substitutes `__conn.role__` by connection (Stage A/C machinery), enforces `resolved_hosts`, forwards. **No system trust store touched; no sudo; CA dies with the process.** (Competitor teardown confirms child-scoped env-CA ≠ "whole-machine traffic" — see memory `reference_competitor_agent_vault`.)
- **Clean removal = the per-project manifest**, not agent memory (§10).

**Test:** `sc run -- curl https://api.x.com/...__conn.role__...` → substituted via the proxy; a sibling process (no env) is unaffected; CA absent after exit.

## 7. Stage F — discovery, MCP, agent-authored recipes, deep-link

- **`sc status` agent-discovery shape** (§9): `{ secrets:[{name, anchored_host}], call_here, under_sc_run }`. **Preflight:** a phantom-dependent dumb CLI checks `under_sc_run` first; if not routed, explain ("needs `sc run`") instead of a mystery 401.
- **MCP ingress:** one tool whose schema == the `/proxy` body; DX sugar, not the front door.
- **Agent-authored recipes:** merge `feat/per-vault-custom-recipes` first (`aux.recipes`, 1 commit, absent from `dev`). Scope agent-authored to **insertion auth + human-anchored host** (verifiable); OAuth/signing stay **curated-only** — a non-expert can't audit a subtly-wrong OAuth recipe, and it keeps the `client_secret`-marked-public gate intact (`client_type=public` validator). See the OAuth note below.
- **Deep-link handoff** (§8): `{{console}}/…/secrets/new?name=…&hosts=…` — hints prefilled, user pastes only the **value** + one passkey; **value never in the URL**.

---

## OAuth note (why refresh is already cloud-blind — reconciles the "abandoned" memory)

The current OAuth path is **cloud-blind by construction**, so v2 keeps OAuth **curated-only** rather than reopening it:
- `services/_providers/google.toml` ships the **public Desktop OAuth client** (`client_type="public"`); Google explicitly treats a Desktop client's `client_secret` as **non-confidential** (installed-app design). It's committed in the recipe on purpose; the validator's `client_type="public"` gate keeps the *confidential Web-app* secret out of any recipe.
- Refresh happens **in the daemon** (`broker.rs:738 resolve_auth_value` → `perform_refresh`, on the user's machine), calling Google's token endpoint directly with the shipped public client + the vault's refresh_token. **The `.pro` backend is never in the refresh path** → the cloud never sees the plaintext token.
- So the earlier "abandoned OAuth because the cloud would see the token on refresh" applies to a **Web-client / backend-refresh** design, **not** this one. The live risk that remains is **Google production verification** for Gmail *restricted* scopes: in Google **test mode**, sensitive-scope refresh tokens **expire ~7 days** → periodic re-consent (the "copy-auth" grind). The `needs_reauth` signal shipped in v1 surfaces exactly that recurring state. Escapes if/when we want non-expiring production tokens **without** breaking cloud-blind: (a) get the **Desktop client verified** for the scopes (if Google permits), or (b) **BYO-OAuth-client** (user supplies their own client_id/secret → their secret in their vault → daemon-local refresh stays cloud-blind, at signup friction). Both keep refresh on the daemon; **never move it to the backend.** — strategic call, deferred.

---

## Testing & rollout summary

- Each stage lands behind the existing test suites; **A and B ship in warn/log mode first**, then flip to deny once curated traffic shows zero false-positives.
- Version-bump on each behavior change (`Cargo.toml`; the version double-gates frontend compat via `health.version`).
- Distribute + validate via merge → tag → release → `sc upgrade` → real-machine e2e (per `feedback_e2e_user_perspective`).
