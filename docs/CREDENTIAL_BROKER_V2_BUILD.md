# Credential Broker — Build Plan (phantom-only proxy)

> **Companion to [CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md) (the LOCKED spec).**
> That doc is the *what* (frozen); this is the *how*: code-grounded, testable.
> **Build it all at once** — pre-launch, 0 users, wipe+re-enroll, nothing to be
> back-compat with. The staged `v1→v2` ordering of the old plan is dropped.

---

## 0. What changes vs shipped (`dev`, v1.0.42)

Shipped today: the connection layer (`Connection{service,config}`), `/use` +
`/stream` endpoints, `{{secret.X|filter}}` filters (built), per-connection policy
tree (v1.0.27), captive-portal approval, `/export` agent-surface 403,
OAuth-refresh cloud-blind on the daemon. The move to the phantom-only proxy:

| Concern | Shipped | Target |
|---|---|---|
| Agent surface | `POST /use/<conn>/<path>`, `/stream/<conn>/<path>` | **one local HTTPS proxy (CONNECT)**; `/use` + `/stream` **retired** |
| Intent carrier | URL connection + (partly) service toml | **phantom `__sc__<conn>__` only** |
| Transport | agent learns our `/use` URL | agent uses the **real upstream URL**, routed via proxy env-bundle |
| Injection trigger | URL-conn ⇒ service-template fill | phantom ⇒ resolve → produce → substitute |
| CA / proxy | n/a | **resident** CA file + resident proxy; `sc run` = env-paster |

The pure injection core is reused unchanged: `render_template`,
`forward_to_upstream_with_extras` (auth-strip, broker.rs), `host_egress_allowed`
floor, OAuth mint (`resolve_auth_value`). Ingress is what's rewritten.

---

## 1. Components

```
A. Resident CA + resident local HTTPS proxy (CONNECT), selective MITM by SNI
B. Phantom resolver: __sc__<conn>__[<role>__] → connection → secret value (or OAuth-minted token)
C. Host anchor: resolved_hosts(conn), exact-FQDN enforce, host in approval-cache key
D. sc run / --export-env: paste the env bundle onto a child / shell (thin)
E. sc set: interactive host-required; --host creates raw connection; --no-broker
F. git adaptor specials: Basic decode/re-encode in proxy; optional zero-schema sc git-credential
G. Retire /use + /stream; skill → the one-proxy concept; sc status discovery shape
```

All land together. Order within the merge is mechanical, not a safety gate (the
old three-gate ordering existed to protect a passthrough endpoint shipping ahead
of the anchor; here there is one surface built whole).

## 2. A — resident CA + proxy

- **Install:** generate `~/.safeclaw/ca.pem` (+ key `chmod 600`) once; never
  installed into any system trust store, never leaves the machine.
- **Proxy:** a localhost HTTPS MITM (HTTP CONNECT) owned by the daemon (resident;
  see §Open for per-run vs resident — resolved to resident).
- **Selective MITM:** on CONNECT, decrypt + substitute **only** when SNI ∈ union
  of all connections' `resolved_hosts`; else **blind-tunnel** (relay bytes, no
  decrypt). Privacy + perf + leaves unrelated pinned tools alone.
- **Auth:** the proxy is localhost + session-associated; **no `<key>@proxy`
  userinfo convention** (dropped). The agent key gate that guards vault ops
  applies at the daemon boundary as today.
- **Probe host:** the proxy self-answers a magic probe (e.g. `http://sc.probe/`)
  so liveness is checkable *through* the proxy path — `sc status` uses it for
  `routed` (env vars present but proxy dead ⇒ `routed:false`).

**Test:** a connection host is intercepted + substituted; a non-connection host
tunnels untouched; CA absent from the system keychain; probe answers through the
proxy only.

## 3. B — phantom resolver

- **Syntax:** `__sc__<conn>__<role>__`, `<conn>`/`<role>` ∈ `[a-z0-9_]`, no `__`
  inside; `__sc__<conn>__` = the connection's sole injectable secret. Charset is
  round-trip-safe (env value / URL / JSON / base64-after-decode).
- **Resolve:** phantom → `<conn>` → connection (single-ownership, §3 spec) →
  secret at `secret_address(conn, svc, role)`. Bare `__sc__<conn>__` with >1
  injectable secret → error listing keys. **Unknown conn in a syntactically-valid
  phantom → fail-closed: proxy 4xx with the name** (never forwarded — inside
  routing, phantom errors are our precise errors; spec §14).
- **Scan sites:** request headers, query, **URL path** (telegram's
  `/bot<token>/…` — never the authority), body, and inside
  `Authorization: Basic` (decode → match → re-encode).
- **Produce:** the stored value as-is (default) or the `[oauth2]`-minted access
  token (mint machinery built); `[oauth2] exposes` values (e.g. codex
  `account_id`) resolve via role-qualified phantoms. Egress filters
  (`|b64`,`|basic`) are CUT (spec §9). Then `forward_to_upstream_with_extras` strips agent-supplied auth and
  forwards; the agent never gets the value back.

**Test:** `__sc__github__` in a header → substituted to `api.github.com`; same to
`evil.com` → denied by C; ambiguous bare conn → error; Basic-embedded phantom in
git → decoded, substituted, forwarded.

## 4. C — host anchor

- **`resolved_hosts(conn)`** (new): `conn.service` set → exact service entries
  ∪ conn-pinned exact FQDNs (each ⊆ a `*.suffix` service entry; single-label
  leftmost wildcard, TLS-cert rule); raw (`service: None`) → `conn.hosts`.
  Runtime enforcement always exact FQDN; wildcards never reach it; bare `*`
  rejected.
- **Struct change:** `Connection{service: Option<String>, hosts: Option<Vec<Host>>}`;
  `config` deleted (spec §4). Wipe + re-enroll, no migration.
- **Enforce** at forward time in `forward_to_upstream_with_extras`: destination
  authority ∈ `resolved_hosts(conn)` by **exact FQDN** (case-insensitive,
  port-aware). `host_egress_allowed` stays as the private/metadata/localhost floor
  beneath it. **No wildcard host accepted at anchor creation.**
- **Approval-cache key** gains the resolved host: `(conn_id, rule_id, method,
  host)` (state.rs cache_insert/lookup). Single-host connections: unchanged
  behaviour.
- **Widen UX:** first unmatched host → higher-friction captive-portal one-tap that
  writes an **exact FQDN** permanent grant. Ship **warn/log** first, then deny.

**Test:** curated multi-host still forwards (exact match); synthetic mismatch
denied; approve host A then call host B same conn/TTL → cache miss → re-approve.

## 5. D — `sc run` (thin env-paster)

- `sc run -- <cmd>`: export the §6-spec bundle into the **child only**
  (`HTTPS_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY=1`, the CA-path var family),
  then exec. No phantom env pre-setting (the agent writes `VAR=__sc__conn__`
  itself — tool contracts are the agent's knowledge). No per-process CA or
  proxy — points at the resident ones.
- `eval "$(sc run --export-env)"`: same bundle onto the current shell.
- **Escalation ladder** (prefer residue-free): ① agent's own HTTP already carries
  a phantom + proxy env → nothing; ② per-command adaptor (git cred / `npm
  --registry`) → no `sc run`; ③ dumb env-reading CLI not under the proxy →
  suggest `sc run` **once**, record in a per-project manifest, don't re-nag.
- **Old plaintext-export `sc run` is removed** — not ported.

**Test:** `sc run -- curl https://<conn-host>/… __sc__conn__ …` → substituted via
the resident proxy; a sibling process (no env) unaffected.

## 6. E — `sc set`

Interactive + non-interactive (§11 spec). Host **required**; hidden value prompt;
`--host` creates the raw connection (`service: None` + `hosts`, reject
private/metadata/`*` at creation); `--no-broker` writes a broker-invisible
item; non-TTY missing host → error with both fixes; every interactive prompt
echoes the intent of args already supplied.

**Test:** `sc set K` prompts value(hidden)+host; `sc set K v --host h` creates a
raw connection reachable via `__sc__k__`; `sc set K v --no-broker` → agent 4xx
"no-broker" on use; piped `sc set K v` (no host) → error, no hang.

## 7. F — git adaptor specials

- **No `[basic]` section exists** (spec §4): the proxy decodes
  `Authorization: Basic` natively and substitutes the phantom inside. Pair
  construction = phantom placement: URL userinfo
  (`https://x:__sc__github__@github.com/…`; Bitbucket-class real username typed
  there — instance data). `sc git-credential` = OPTIONAL zero-schema
  convenience, one documented global rule (emit `("x", <phantom of the host
  connection's sole injectable secret>)`; multiple/none → decline). Not
  load-bearing; docker needs no helper at all (`docker login -p <phantom>`).
- Helper registration residue-free: `sc run` injects
  `GIT_CONFIG_COUNT/KEY_0=credential.helper/VALUE_0="!sc git-credential"`
  (git's native per-process config env) — no gitconfig writes.
- Proxy decodes `Authorization: Basic`, substitutes the phantom, re-encodes (B).
- Streaming (smart-HTTP) relays natively through CONNECT.
- **Service-toml schema rewrite, retired UNIFORMLY** (all tomls, parser + validator;
  spec §4): `[[upstream]]` → first-class `hosts = [...]` (exact FQDNs or `*.suffix`);
  `[upstream.headers]` templates + declared-slot replace-all override + `[[api]]`
  steps deleted; `secrets = [...]` list + auth-mechanism sections ONLY:
  `[oauth2]` (= `[upstream.auth]` upgraded in place, same fields) as the SOLE
  auth section (Basic: proxy-native decode, no section; the proxy never
  classifies traffic by tool); tool-named sections forbidden;
  **keep** wildcard-subset host validation, policy, provider mint. Future
  `[sigv4]` when real.
- **github service.toml target shape:**

```toml
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]

secrets = ["GITHUB_TOKEN"]
# no auth section at all — Basic self-describes on the wire

setup = """
Routed (under `sc run` / the env bundle)? Nothing to configure — $GITHUB_TOKEN is
already the phantom; git resolves credentials via the safeclaw helper.
Not routed? Prefix: `sc run -- git clone https://github.com/<owner>/<repo>`.
Multi-account: switch the phantom value (GITHUB_TOKEN=__sc__github_work__ gh ...),
or for git put the phantom in the URL username:
https://__sc__github_work__@github.com/<owner>/<repo>.
Use HTTPS remotes; SSH is outside the broker.
"""
```

  (`policy.toml` unchanged — rules now match real (host, path, method); a rule
  may carry an optional host qualifier for multi-host services. gitlab analog:
  gitlab: identical two-liner. gmail = `hosts` + `[oauth2]`.)

**Test:** `git clone https://github.com/<private>` under `sc run` → succeeds; the
real token never appears in git config or process env; same clone NOT under the
proxy + agent following setup → `sc run -- git clone …` succeeds.

### 7.5 — in-tree toml sweep (2026-07-03; migration inventory)

All 19 services classified — **no fifth auth shape exists** (full table:
SERVICES.md v4 §6). Migration notes:
- Direct-insertion variants (Bearer / custom header / raw / query / URL-path)
  → `hosts` + `secrets` only. **URL-path scan required** (telegram).
- github+gitlab → hosts+secrets only (Basic handled natively); gmail/gdrive/gcalendar → `[oauth2]`;
  **openai-codex → `[oauth2] exposes = ["account_id"]`** (its
  `chatgpt-account-id` header value; the static `openai-beta` header is the
  agent's to write).
- **nodpay + system/files: OUT of broker schema** — daemon-upstream (`system`
  category, spec §13); keep `hidden`, don't contort.
- Field deletions across all tomls: `auth.env` hints, `locked={response}`
  (global 423), `stream=true`, `[[api]]`, header/query templates, `|basic`
  filters. `setup` texts rewritten (npm loses `--registry` re-point; **cargo's
  local-git-index workaround is deleted** — justification: cargo natively
  honours proxy+CA env ⇒ the env bundle is its adaptor on EVERY routing path,
  incl. per-command `sc run --` outside any wrapped session; nothing the index
  carried is still needed. NOT "because MITM exists").
- `_providers/*.toml` unchanged.
- **v3 → v4 field migration (mechanical, per toml):**

| v3 | v4 |
|---|---|
| `[[upstream]] url` | `hosts = [...]` (authorities only) |
| `[upstream.auth] secret=`/`env=` + `placeholder` | `secrets = [...]` + `[placeholders]` (env-name hints deleted — tool contracts are the agent's knowledge) |
| `[upstream.headers]` / `[upstream.query]` templates | deleted — phantom placement |
| `{{secret.X \| basic[:user]}}` / `{{secret_b64.X}}` filters | deleted — proxy decodes Basic natively; b64 pre-encoding cut (YAGNI) |
| `auth = { type = "oauth2" }` + provider | `[oauth2]` |
| `{{auth.account_id}}` header template | `[oauth2] exposes` + role-qualified phantom |
| `[[api]]` / steps / targets / `recipe.toml` | deleted — the route is in the traffic |
| `stream = true` | deleted — streaming relays natively through CONNECT |
| `locked = { response }` | deleted — global `423 vault_locked` is self-evident |
| `setup` transport instructions (URL-rewrite / `--registry` / local-index) | rewritten: routed ⇒ nothing; unrouted ⇒ `sc run --` prefix |

- **Format decision (kept: TOML authoring + JSON interchange):** author-vs-wire
  split is the industry norm (Cargo.toml → crates.io API); serde_yaml archived
  2024-03 (`v0.9.34+deprecated`, fragmented forks) — no unmaintained parser in
  the security-critical service-toml parsing path; YAML implicit-typing/anchor footguns are
  wrong for a security config; the v4 schema is flat, so TOML's one weakness
  (deep nesting) died with `[[upstream]]`/`[[api]]`. `registry.json` + vault
  JSON unchanged.
- **SERVICES.md = lean EXTERNAL authoring reference** (what it is + how to
  write, nothing else — decisions/rationale/migration/plans stay in THIS doc
  and the spec); banners on CONNECTION_SCHEMA / CONNECTIONS_AND_AUTH /
  GIT_INTEGRATION / STREAMING_APPROVAL; PROTOCOL.md endpoint table carries a
  forward note (op plane unchanged).

## 8. G — retire endpoints + discovery + skill

- Remove `/use`, `/stream` routes and their handlers (keep the pure core they
  called). `/export` stays 403 on the agent surface.
- Discovery = ONE projection, two faces: `GET /registry` (HTTP; keeps the
  existing `?view=summary` / `?ids=` context filters UNCHANGED — only the row
  shape changes: `hosts` + the **`phantoms` map (role → ready-made string)**
  replace `endpoints`/`vault_fields`) and `sc status` (CLI; same rows **plus
  `routed`**, which only the CLI can know — it inspects its own inherited env
  + liveness-probes the proxy). Agents copy phantoms, never construct.
- Skill delta = REPLACE the `/use` "Call shape" section with the phantom +
  routed-discipline section (drafted in spec §14); connect-guidance, setup
  hints, vault_locked, approval-polling sections stay (approval response shape
  through the proxy re-verified at build).
- Skill: one concept + the **routing discipline** (spec §14: phantom ⟺ routed;
  preflight `sc status`; unroutable → tell the user, never fire a phantom
  unrouted). Generic; no per-service specifics.
- Version-bump `Cargo.toml` (protocol-level; double-gates frontend compat via
  `health.version`).

## 9. Frontend (console — coordinate with the console-refactor thread; core schema lands FIRST, UI after)

- **One Connections list** (unify the two shipped tabs). A row = one
  connection: name · service badge (or *raw*) · **anchored hosts** · **the
  phantom string `__sc__<conn>__` with a copy button** (the agent-facing
  currency — this replaces every `/use` URL the console ever showed) ·
  status (connected / needs_reauth / *no-broker: stored · agent cannot
  use · add host*). Secrets collapsed inside the row; OAuth-internal hidden.
- **Add-connection = one flow, two paths**:
  - *From catalog* (curated): existing flow — OAuth consent / paste the
    service-declared secrets; wildcard hosts pinned here.
  - *Custom raw*: **ONE form, one step, one passkey** — name (`[a-z0-9_]`,
    live-validated) + hosts (required; reject `*`/private/metadata) + N secret
    rows (KEY + hidden value). No auth selector, no toml textbox, no OAuth
    here (that would force an `oauth` field onto the 2-field connection
    record). No two-phase secret-then-connect. Folded explicit "no-broker (no
    host)" escape, never the default. Phantom preview shown as a human aid.
- **Customize service (separate LOW-frequency page — never inside
  add-connection):** a v4 toml editor — whatever the schema supports is
  writable — validated on submit (hosts rules; `[oauth2].provider` must be a
  shipped `_providers/*` entry; `client_type=public` gate; no tool-named
  sections) → stored per-vault (**`aux.services`** — absorb the useful parts of the built-unmerged `feat/per-vault-custom-recipes` branch, renamed; then DELETE the branch and remove the `wt-recipes-core` / `wt-recipes-frontend` worktrees, per the standing worktree-cleanup rule) → appears in the catalog → added like any curated service, so the
  connection stays `{service, hosts}`. Provider-declared user params surface
  as connect-form fields; values land as that connection's secrets. CLI twin:
  `sc service add <file.toml>` (cli/service_def.rs). A NEW provider or auth
  mechanism = repo issue/PR.
  - Second entry point: a no-broker row's **"add host"** action promotes the
    existing bare secret into a raw connection (same form, prefilled).
- **`sc connect <name>`** (new verb) = the CLI twin of the Custom form:
  interactive hosts → secret names → hidden values; non-TTY flags
  (`--host … --secret KEY [--use-existing KEY]`); `sc set KEY --host h` stays
  as the single-secret one-liner sugar (conn named after the key). Same
  creation logic underneath.
- **Wildcard pinning at connect**: a service with `*.suffix` hosts requires the
  user to type the exact FQDN(s), validated ⊆ the pattern, confirmed with the
  connect passkey.
- **Approval pages**: proxy ops render connection + resolved host + method/path
  (+ effective risk, v1.0.27). **One-tap-widen** (first unmatched host) is a
  distinct, higher-friction approve variant: exact FQDN shown with its eTLD+1,
  labeled as a PERMANENT grant — not the ordinary approve.
- **Catalog/registry cards** consume the v4 `registry.json`: hosts + oauth
  badge; env-var names and `/use` endpoints disappear from all copy.
- **Kill in console**: connection `config`/`host` form fields (→ `hosts`),
  the temp "Services" tab remnants, any `/use`/`/stream` URL rendering.
  **Keep**: human `sc secret get`-equivalent reveal (passkey Export ceremony —
  the op plane is untouched), vault-policy.tsx (policy tree unchanged).
- Deep-link handoff (`…/secrets/new?name=…&hosts=…`; value never in URL) —
  post-core, with agent-authored services.

## 10. OAuth note (unchanged — cloud-blind by construction)

Refresh runs in the daemon with the shipped **public Desktop client**
(`client_type="public"`); the `.pro` backend is never in the refresh path. Live
residual = Google production verification for Gmail *restricted* scopes (test mode
→ ~7-day refresh expiry → periodic re-consent; surfaced by the `needs_reauth`
signal). Escapes without breaking cloud-blind: verify the Desktop client, or
BYO-OAuth-client. Never move refresh to the backend. Deferred.

## 11. Open (resolve during build — no design decisions left, these are build-time verifications)

- **Proxy listener placement**: CONNECT on the main port `:23294` vs an
  internal localhost port. Agent-invisible either way (env carries the
  address); pick whichever hyper makes cleaner.
- **Proxy client trust — DECIDED, revisit-if**: localhost, no proxy auth
  (the `<key>@proxy` convention was dropped as over-design). The real gates =
  host anchor + policy tree + passkey approvals; trust level ≡ an agent key in
  env. Revisit only if a concrete local-adversary scenario demands it.
- **Captive-portal response shape through a dumb tool**: the
  reject-before-forward + SSE + passkey mechanism survives as-is; verify at
  build what git/curl actually SURFACE (401 body with the approve link) so the
  agent/user sees the link, not a mystery failure.
- **policy.toml path review**: rules move from `/use`-relative to real
  `(host, path, method)` — mechanical per-service pass at migration time.
- **openai-codex `exposes` mechanics**: where `account_id` comes from in the
  token exchange — implementation detail of the mint, schema settled.
- **Per-run vs resident proxy/CA — RESOLVED: resident.** `sc run` only pastes env.
- **Parked by decision (not open)**: `system` category (spec §13), signing
  family (`[web3sign]`/`[sigv4]`), MCP ingress, agent-authored services +
  deep-link (absorb `feat/per-vault-custom-recipes` first), self-hosted+OAuth
  combo, aux/connections whole-blob sync (per-item cutover's known remainder —
  separate thread).

## 12. Acceptance criteria (the definition of DONE for this wave)

Unit level: the existing `/use`/`/stream` behavioural suites are the **oracle
for the proxy path** (same core, new ingress) — port, don't rewrite. Anchor
enforcement ships warn/log → flip to deny once curated traffic shows zero
false positives.

**E2E (user-perspective, per the iron rule: merge → tag → release →
`sc upgrade` on the real box; wipe + re-enroll first). ALL must pass:**

1. **Raw cold-start:** `sc set STRIPE_KEY` (interactive: hidden value + host
   prompt) → `sc status` shows the connection + `phantoms` map + `routed` →
   `sc run -- curl https://api.stripe.com/... -H "Authorization: Bearer
   __sc__stripe_key__"` → substituted, forwarded; plaintext never in the
   child's env or output.
2. **Curated OAuth:** connect Gmail in the console (consent) → agent sends
   `Authorization: Bearer __sc__gmail__` under the proxy → minted token
   substituted; refresh secret never injectable/visible.
3. **git:** `sc run -- git clone https://github.com/<private>` (helper path)
   AND `git clone https://x:__sc__github__@github.com/<private>` (URL-userinfo
   path, no helper) both succeed; token never lands in gitconfig/env/output.
4. **Routing discipline:** outside the proxy `sc status` → `routed:false`;
   the skill-driven agent does NOT fire the phantom, suggests `sc run --`
   once. Under routing, `__sc__typo__` → proxy 4xx `unknown_connection`
   (never forwarded).
5. **Anchor:** same phantom toward `evil.com` → denied; wildcard service:
   pinned tenant host forwards, un-pinned sibling tenant denied; approve
   host A → call host B same conn within TTL → cache miss, re-approval.
6. **Approval:** ask-level request → captive-portal link surfaces through the
   dumb tool's error output → passkey → retry succeeds. One-tap-widen renders
   as the distinct permanent-grant variant.
7. **no-broker:** `sc set K v --no-broker` → invisible to `sc status`
   connections / phantoms; agent use attempt → self-evident 4xx; human reveal
   via `sc secret get` (passkey ceremony) still works.
8. **Selective MITM:** a non-connection host under `sc run` blind-tunnels
   (bytes relayed, not decrypted); CA absent from the system keychain;
   `http://sc.probe/` answers only through the proxy.
9. **Console:** one Connections list (phantom copy-button, hosts, states);
   custom-raw one-form add works; **Customize service** page: paste a v4 toml
   (validator rejects tool-named sections / bad hosts / unknown provider) →
   appears in catalog → add → connection is `{service, hosts}`.
10. **Discovery:** `GET /registry` rows carry `phantoms`/`hosts`;
    `?view=summary` / `?ids=` behave as today; skill (new "Using a
    connection" section) drives a fresh agent through 1–4 with no other
    instruction.
11. **`sc run` / CA / bundle (explicitly in-wave):** first daemon start
    generates `~/.safeclaw/ca.pem` once (key `chmod 600`; regenerate = same
    path, never system keychain); `sc run -- env` shows the FULL bundle
    (`HTTPS_PROXY`/`HTTP_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY=1`,
    `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/
    `NODE_EXTRA_CA_CERTS`/`GIT_SSL_CAINFO`/`DENO_CERT`, `GIT_CONFIG_*`
    helper registration) in the CHILD and none of it in a sibling shell;
    `eval "$(sc run --export-env)"` covers the current shell the same way;
    a Node-24 tool fetches through the proxy (NODE_USE_ENV_PROXY honoured);
    old plaintext-export behaviour is nowhere (no `-k`/`--k-all` flags,
    no plaintext in child env ever).
12. **Version/compat:** `Cargo.toml` bumped; `health.version` gates the
    frontend; `sc upgrade` prints X → Y and lands the new binary.

## 13. Deletion inventory (leave no corpses)

- **Core:** `/use` + `/stream` routes & handlers (`proxy/use_broker.rs`,
  `proxy/stream.rs`), the `/export` 403 stub route file if superseded by
  routing changes (keep the op-plane Export), header/query template rendering
  + declared-slot replace-all override, `{{secret.X | b64|basic}}` filters,
  `[[api]]`/steps/targets parsing, `[[upstream]]` parsing, `locked={response}`,
  `auth.env` hints, `stream=true`, `Connection.config` field + all readers,
  old plaintext-export `sc run` remnants (design-only — never shipped).
- **Recipes-in-tree:** every `service.toml` migrated per the §7.5 table;
  cratesio local-index + npm `--registry` + git insteadOf setup texts deleted.
- **Skill:** the `/use` "Call shape" section (replaced); field-casing rows
  stay.
- **Branch/worktrees:** absorb `feat/per-vault-custom-recipes` → then DELETE
  the branch and remove `wt-recipes-core` + `wt-recipes-frontend` worktrees.
- **Docs at land time:** PROTOCOL.md R-side sugar table updated for real (the
  forward note replaced by the actual endpoint state; op plane untouched);
  CONNECTION_SCHEMA.md / CONNECTIONS_AND_AUTH.md / GIT_INTEGRATION.md /
  STREAMING_APPROVAL.md banners resolved into updated text or the docs merged
  into the canon; `CONNECTION_IMPL_PLAN.md` (checklist doc) deleted per its
  own header once landed.
- **Frontend:** temp "Services" tab, `config`/host form fields, any `/use`
  URL rendering.
