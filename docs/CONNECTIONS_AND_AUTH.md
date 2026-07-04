# Connections & Auth — finalized schema (the implementation spec)

> **⚠️ PARTIALLY SUPERSEDED (2026-07-03 phantom-only pivot).** The `{{secret.X | filter}}` template grammar (§7) and `/use` addressing here are retired (no injection templates; phantom placement instead); `[provider.*]` blocks, the cloud-blind OAuth connect flow, and namespaced secret addressing remain valid. Canon = [CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md); toml rules = [SERVICES.md](./SERVICES.md) v4.

> **Status: DECIDED design, to be implemented.** This supersedes the auth/oauth
> bits of [SERVICES.md](./SERVICES.md) and adds the **connection layer**. It is
> grounded in mainstream prior art — **not invented here**:
> [Nango `providers.yaml`](https://nango.dev/docs/reference/api-configuration),
> [Composio auth configs](https://docs.composio.dev/docs/authentication),
> [OpenAPI 3.x `securityScheme`], and [RFC 6749]/[RFC 7636]. Citations inline.

## 0. The three concepts (mirror Nango / Composio)

| Layer | Nango | Composio | SafeClaw |
|-------|-------|----------|----------|
| **Provider** — shared API auth template (endpoints, client app) | `providers.yaml` | (in Auth Config) | **`[provider.<name>]`** block |
| **Service** — one API + its scopes + injection | Integration | Auth Config | the **recipe** (`service.toml`) |
| **Connection** — a per-account instance holding the token | Connection | Connected Account | the **connection** (vault-side) |

And **three lifecycle phases** (these are *operations*, not separate config files):

1. **Connect / setup** — one-time. Acquire the durable credential (OAuth consent, or "paste your API key").
2. **Refresh** — ongoing. Mint a short-lived access token from the durable one.
3. **Inject** — per request. Put the credential into the outbound request.

> Mainstream keeps connect+refresh in **one** auth block, distinguished by field
> prefix (`authorization_*` vs `token_*`/`refresh_*`), **not** by separate
> sections. We follow that. The trigger for "which algorithm" is **`auth_mode`**
> (= our existing `type`), never field-name sniffing.

## 1. Naming conventions (DECIDED)

- **snake_case everywhere internally.** Internal consistency wins; an OpenAPI
  (`authorizationUrl`) or Nango import maps mechanically to our snake form.
- **`env` → `secret`.** The old `auth.env` field (the vault-entry key holding a
  credential) is renamed `secret`. Renamed across all in-tree recipes this wave.
- **`connection_id`** is a slug: `^[a-z0-9][a-z0-9_-]{0,63}$` (no `:`, no `/`,
  no `..`). The human label is a separate `label` field.
- **A recipe never holds a secret VALUE** — only the *key* (role → vault-entry
  name). Values live in the sealed vault (written by connect / the user).

## 2. `[provider.<name>]` — shared OAuth template

One block per provider, reused by every service on that provider (= Nango
`providers.yaml`). Lives in `services/_providers/<name>.toml`.

```toml
[provider.google]
auth_mode         = "oauth2"          # = Nango auth_mode; our `type` for a service inherits this
flow              = "authorization_code"
authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"   # CONNECT step
token_url         = "https://oauth2.googleapis.com/token"            # REFRESH + code-exchange
pkce              = true
client_id         = "499410884315-…apps.googleusercontent.com"      # public Desktop client
client_secret     = "GOCSPX-…"                                       # public Desktop client
client_type       = "public"          # RFC 6749 §2.1: "confidential" | "public"
```

- **`client_type`** — RFC 6749 §2.1 vocabulary. The validator **requires
  `client_type = "public"` whenever a literal `client_secret` is present** in a
  recipe (recipes are public/OSS; a confidential Web-app secret must never be
  committed). Confidential providers omit `client_secret` from the recipe.
- The Desktop client's `client_secret` is *non-confidential by Google's design*
  ([OAuth for Desktop apps] — "the client secret is obviously not treated as a
  secret"), so it ships in the recipe. Refresh/exchange happen **on the daemon**
  with these public creds — the confidential Web-app secret never leaves the cloud.
- **The public secret can't be dropped for pure PKCE.** Empirically (2026-06),
  Google's *Desktop* client **requires `client_secret` at the token endpoint even
  with PKCE** — omitting it returns `invalid_request: "client_secret is missing."`.
  "Optional" in the spec doesn't apply to the Desktop client type, so the public
  secret must ship. (GitHub push-protection flags the `GOCSPX-` pattern; this
  value is allow-listed as a public Desktop client, not a leak.)

## 3. `[upstream.auth]` — a service's auth

A service references a provider (inheriting `auth_mode` + endpoints + client) and
adds only what's unique: scopes, the secret slot, and the injection.

```toml
[[upstream]]
url = "https://gmail.googleapis.com"

  [upstream.auth]
  provider = "google"                 # inherits auth_mode/endpoints/client — do NOT re-declare `type`
  scopes   = [                        # a LIST (= Nango default_scopes); Google's consent shows descriptions
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
  ]
  secret   = "gmail_refresh_token"    # single-secret form (renamed `env`); default <service>_refresh_token

  [upstream.headers]
  Authorization = "Bearer {{oauth.access_token}}"
```

- **No `type` when `provider` is set** — `auth_mode` comes from the provider.
  (Inline auth without a provider still declares `type` + endpoints locally.)
- **`scopes` is a list.** Per-scope descriptions (OpenAPI's map form) aren't
  needed — the consent screen is Google's.
- **Multi-secret** (rare): a table instead of the single `secret` string —
  ```toml
  [upstream.auth.secrets]   # role = vault-entry key
  refresh_token = "gmail_refresh_token"
  webhook_key   = "gmail_webhook"
  ```

## 4. OAuth lifecycle

### 4a. Connect (one-time, **cloud-blind**, headless-OK)

The browser drives consent with the **Desktop client + PKCE**; the daemon does
the code→token exchange (Google's token endpoint has **no CORS**, so a browser
can't exchange directly — verified). To stay cloud-blind, the code is relayed to
the daemon **through the sealed vault**, not the cloud backend:

```
1. web "Connect gmail" → Google consent (Desktop client_id, PKCE, redirect=loopback)
2. user authorizes; copies the code from the loopback redirect  (auto-caught if the
   daemon is local; one-time paste if the daemon is remote/headless — the gcloud
   `--no-launch-browser` pattern)
3. browser SEALS {code, verifier, redirect_uri} into the vault as the transient
   item  <connection_id>_oauth_pending  → uploads (cloud sees only ciphertext)
4. daemon syncs the blob (long-poll, seconds) → reads the pending item →
   exchanges (public Desktop client_id/secret + verifier) at token_url →
   refresh_token
5. daemon writes  <connection_id>_refresh_token  and DELETES  *_oauth_pending
```

- **No extra passkey approval for the daemon's write.** It is the completion of
  the user-initiated connect (already authorized by the passkey that sealed the
  code + the live Google login). Approval-ops gate *agent* requests, not the
  daemon's own connect-completion → the daemon **re-seals directly** (it holds
  W_c while unlocked). An agent cannot forge a Google login + a passkey-sealed code.
- **Cloud-blind:** the cloud only ever stores/syncs ciphertext; the
  refresh_token is minted on the daemon and never traverses the cloud.
- **Caveat — code TTL:** Google auth codes are single-use and expire ~10 min;
  the browser→vault→daemon round-trip is normally seconds. If the daemon is
  offline/locked > TTL, reconnect.
- **Caveat — write-back:** the daemon persists the refresh_token locally and
  refreshes from it. Syncing it back into the cloud blob (multi-device + clearing
  the pending item there) needs the daemon's **blob push-back** (deferred in
  Slice 3). Single-daemon works without it.

### 4b. Refresh (ongoing, invisible) — and it's **cached**

The daemon mints an access_token from the refresh_token at `token_url`. **It is
cached in memory keyed by `sha256(refresh_token)` with its expiry (~1 h)** —
keying on the refresh VALUE (not `(vault, service)`) auto-invalidates on reconnect
/ token rotation and never collides across accounts; wiped on lock. See
[CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md) §9. 1000 requests in an hour =
**1 refresh + 999 cache hits**. Re-minted only after expiry / lock / restart.
`oauth_style = "form" | "json"` parameterizes the body.

### 4c. Inject (per request)

`Authorization = "Bearer {{oauth.access_token}}"` in `[upstream.headers]`.

## 5. The connection layer (recipe = TYPE, connection = INSTANCE)

- A **recipe is the type** (template). A **connection is a user-created instance**
  of it, holding the credential binding + a label. Addressed as
  **`/use/<connection_id>`** (and `/stream/<connection_id>`).
- **Back-compat:** a service's default/only connection uses `connection_id ==
  service_id` (e.g. `gmail`); existing flat secrets map to it with zero migration.
- **Secrets are namespaced** `<connection_id>:<role>` in the flat vault map
  (delimiter **`:`** — invalid in env-var names, so a namespaced key can never
  masquerade as an env var). Default connection → the legacy flat name.
- **Re-map, NOT arbitrary override** (= Nango `connection_config`): the **recipe
  declares which slots are per-connection** (the credential roles; and *only if
  the recipe marks it*, a param like a `host`/`subdomain`). The connection fills
  **only those**. Everything else (endpoints, `auth_mode`, scopes, the egress
  host of a normal recipe) is **fixed by the type** — a connection can never
  re-point an audited recipe's host/token-endpoint (that would be SSRF/hijack).
  - **Standard credential roles** (`refresh_token`, `api_key`) are shared vocab so
    the UI/connection layer handle them uniformly; **dynamic params** (`host`,
    `subdomain`) are per-recipe-declared.
- **`connection_id` flows through** routes / cache / op-scope / audit; the daemon
  resolves `connection_id → service_type` once per request to fetch the recipe.

> Web UI: connection-centric (the user's connections are the main view; the
> service catalog becomes the "+ Add connection" template picker). See the
> connections-tab design in the session checkpoint memory.

## 6. `[setup]` — tool-config (the git case)

Distinct from OAuth connect: this configures an **external tool** (git, an SDK)
to route through SafeClaw. The **agent** runs it. Per the iron rule
([[feedback_agent_transparent_cooperation]]): give the **goal + building blocks +
a canonical example**, let the agent **adapt** to the user's real config — not a
rigid script.

```toml
[setup]
goal  = "Route the user's git remotes through SafeClaw so the GitHub token never enters git"
route = "{{proxy_base}}/stream/github-git/"
auth  = "Authorization: Bearer {{api_key}}"
example = '''
git config --global url."{{route}}".insteadOf "https://github.com/"
git config --global http."{{route}}".extraHeader "{{auth}}"
'''
```

### ✅ DECIDED: `recipe.toml` is deleted — `[setup]` is the only setup mechanism

`recipe.toml` (the `[[steps]]` run/files/config_patches/restart provisioner in
SERVICES.md, target `openclaw`) was built for the **OpenClaw agent product line**,
now deprioritized. The vault product is **agent-agnostic + agent-self-configures**.
So **`recipe.toml` is removed**; **`[setup]` is the single, light, declarative,
agent-facing setup mechanism**, covering both:

- **tool-config** — e.g. git `insteadOf` (above);
- **runtime-config** — what recipe.toml mainly did: e.g. "point your OpenAI
  `base_url` at `{{proxy_base}}/openai/v1` with a dummy key." This becomes a
  `[setup]` hint the agent reads and applies to itself (iron rule: goal+blocks).

Knowledge is preserved by **moving recipe.toml step content into each service's
`[setup]`** (the actual provider-registration / config commands become the
example/blocks).

> **Reference for the future agent product line.** The planned rebuild — *each
> agent launches in its own VM with a vault daemon; the OpenClaw-dashboard-style
> frontend is simplified on the vault model* — should have the agent configure
> **itself** via `[setup]` (it owns its VM: it can write its files / restart
> itself). **Do NOT resurrect `recipe.toml`'s provisioner.** Reintroduce a
> provisioner only if that rebuild proves it needs *deterministic,
> non-agent-driven* provisioning (reliability/security reasons) — and then build
> it on the vault model, not legacy recipe.toml.

## 7. Template grammar — TWO contexts (DECIDED)

| Context | When | Tokens | Rendered by |
|---------|------|--------|-------------|
| **auth injection** | every request | `{{secret.X}}`, `{{secret.X\|b64}}`, `{{secret.X\|basic}}`, `{{oauth.access_token}}`, `{{uuid_v4}}` | **daemon**, vault open — **secrets never reach the agent** |
| **setup** | one-time | `{{proxy_base}}`, `{{api_key}}`, `{{route}}`, `{{vault}}` | for the **agent**, in its env — **touches no vault secret** (api_key is the agent's own broker key) |

- Grammar: `{{ <source>.<key> }}` or `{{ <builtin> }}`. `secret.*` reads the
  vault; `oauth.*` is **derived** (the minted access token — `access_token` is
  its only key today); `uuid_v4` is a builtin.
- **Filter syntax (NEW, DECIDED):** encoding variants unify into a pipe filter —
  `{{secret_b64.X}}` → `{{secret.X | b64}}`, `{{secret_basic.X}}` →
  `{{secret.X | basic}}`. Cleaner and extensible (future filters: `urlenc`, …).
  The bare `secret_b64`/`secret_basic` prefixes are kept as deprecated aliases
  during migration.
- Unknown/unresolvable token = **hard error** (never forward a literal `{{…}}`).
  Host portion of a URL must be a literal (anti-SSRF); path may be templated.

## 8. Finalized example (Google family)

```toml
# services/_providers/google.toml
[provider.google]
auth_mode = "oauth2"; flow = "authorization_code"; pkce = true
authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
client_id = "499410884315-…apps.googleusercontent.com"
client_secret = "GOCSPX-…"
client_type = "public"
```
```toml
# services/integration/gmail/service.toml  (gcalendar/gdrive identical shape, different scopes)
[service]
id = "gmail"; name = "Gmail"; sub = "Google"; category = "integration"

[[upstream]]
url = "https://gmail.googleapis.com"
  [upstream.auth]
  provider = "google"
  scopes   = ["…/gmail.send", "…/gmail.readonly", "…/gmail.modify"]   # actual web scopes
  secret   = "gmail_refresh_token"
  [upstream.headers]
  Authorization = "Bearer {{oauth.access_token}}"

[[api]]
path = "*"
  [[api.steps]]
  target = "upstream:default"
  returns = true
```

Per Q7: **gmail / gcalendar / gdrive stay separate services, separate scopes,
separate tokens** (Desktop clients can't do incremental authorization anyway, so
combining scopes is the wrong move).

## 9. Implementation checklist (the build)

0. **Delete `recipe.toml`** (decided, §6): remove the recipe.toml parser/loader +
   the in-tree recipe.toml files; migrate any still-needed step content into the
   relevant service's `[setup]`. `[setup]` is the only setup mechanism.
1. **Parser/schema**: `[provider.<name>]` blocks (load `services/_providers/*`);
   `auth.provider` inheritance (drop redundant `type`); `secret` (rename from
   `env`) + `[upstream.auth.secrets]`; `scopes`; `[setup]`; `client_type`.
2. **Template engine**: add the `{{secret.X | filter}}` pipe grammar (keep
   `secret_b64`/`secret_basic` as aliases); add the **setup** template context
   (`proxy_base`/`api_key`/`route`).
3. **OAuth connect (daemon)**: read `<conn>_oauth_pending` from the open vault →
   exchange (public Desktop creds + PKCE) → write `<conn>_refresh_token` → delete
   pending. Direct re-seal, no approval op.
4. **Frontend connect**: Desktop consent URL (PKCE) → code (auto-loopback or
   one-time paste) → seal `{code,verifier,redirect_uri}` into the vault → upload.
5. **Connection layer** (its own stage): `connection_id` addressing, `:`
   namespacing, re-map binding, default-connection back-compat. (Compose with the
   reviewed custom-recipe branches — see their MERGE-AFTER-FIXES blockers.)
6. **Validator**: `client_secret` literal ⇒ require `client_type="public"`;
   recipe-id slug rule; host-literal (existing).

[OpenAPI 3.x `securityScheme`]: https://spec.openapis.org/oas/v3.1.0#oauth-flows-object
[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
[OAuth for Desktop apps]: https://developers.google.com/identity/protocols/oauth2/native-app
