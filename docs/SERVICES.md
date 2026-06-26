# SafeClaw Service Protocol

**Protocol version: 3** — Breaking changes from v2; see [Migration from v2](#migration-from-v2) at the end.

This document defines the declarative service protocol used by SafeClaw. Each service is a folder in `services/{category}/{id}/` containing two TOML files:

- **`service.toml`** — runtime behavior (how requests are handled when the service is active)
- **`recipe.toml`** — setup behavior (what happens when the service is first enabled)

Both files share a common execution primitive: **step**. A step is a single action with a `target` specifying where it runs.

**Related docs**:
- [STORES_AND_ITEMS.md](./STORES_AND_ITEMS.md) — vault schema, stores, items, adapter contract (referenced by `{{X}}` templates in this doc)
- [PROTOCOL.md](./PROTOCOL.md) — wire protocol, sealed-state mechanics

---

## Shared concepts

### Target

Every step (in both `service.toml` and `recipe.toml`) has a required `target` field specifying where it executes.

| Value | Description |
|-------|-------------|
| `safeclaw` | Execute inside the SafeClaw container (vault host). |
| `safeclaw.vault` | Read/write the SafeClaw vault (passkey-protected). |
| `openclaw` | Execute inside the OpenClaw container (agent runtime). In Pro, dispatched via provisioner. |
| `upstream:<id>` | Forward HTTP request to the `[[upstream]]` block with matching `id`. |

Separator semantics:
- **`.`** = subsystem of a host (`safeclaw.vault` = vault within safeclaw)
- **`:`** = reference to a named module (`upstream:default` = the upstream block with `id = "default"`)

Reserved words: `safeclaw`, `openclaw`. Any other bare word is invalid; upstream references must use the `upstream:` prefix.

### Step

The atomic unit of execution in both TOML files. Recipe steps and API steps share the same core fields:

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | **Required.** Where to execute. See Target table above. |
| `title` | string | Human-readable label. Required in recipe steps; optional in API steps. |
| `run` | string | Shell command to execute. Used with `safeclaw`, `openclaw` targets. |
| `env` | table | Environment variables injected into `run` subprocess. Optional. |
| `note` | string | Human-readable note. Optional. |

Additional fields available only in recipe steps: `files`, `config_patches`, `restart`, `cwd`, `description`.
Additional fields available only in API steps: `returns`, `retry`, `method` (inherited from parent `[[api]]`).

### Template substitution

String values in `[upstream.headers]`, `[upstream.query]`, and the upstream `url` itself support `{{...}}` template expressions. The broker's v3 engine renders these at forward time; **every token is namespaced by its first segment** so a vault item can never collide with a builtin, and an unknown/unresolvable token is a **hard error** (the broker never forwards a literal `{{…}}`).

| Form | Resolves to | Notes |
|------|-------------|-------|
| `{{secret.NAME}}` | vault item NAME's bytes (UTF-8) | the common case — bearer tokens, API keys |
| `{{secret_b64.NAME}}` | `base64(item NAME)` | |
| `{{secret_basic.NAME}}` | `base64(item NAME + ':')` | key-as-username HTTP Basic (Stripe shape) |
| `{{oauth.access_token}}` | the minted OAuth access token | only on oauth2 upstreams (see `[upstream.auth]`) |
| `{{uuid_v4}}` | a fresh UUID v4 | generated per request |

Multiple `{{secret.*}}` references in one recipe are fully supported (e.g. a Twilio-style `account_sid` + `auth_token` pair) — the grant opens the whole vault once and every referenced item is resolved from that one view. The full released set is recorded on the operation's `scope.secrets` and shown at approval / in the audit log.

The set of items a recipe needs is derived by scanning `{{secret.*}}` occurrences across the upstream URL + header + query templates. The **primary** item is declared explicitly via `auth.env` (see below) — it drives `op.act.target` (the credential the grant is bound to) and is what gets bootstrapped into the allow-fast-path cache at unlock.

> **Implemented vocabulary (this build).** The five tokens above are exactly what the broker engine renders today. The bare `{{X}}` / `{{b64:X}}` store-order forms, `[upstream.path_params]` `:placeholder` substitution, and the separate `recipe.toml` / NL-Cooker flow described later in this doc are the **broader roadmap**, not yet wired into the runtime broker. Recipes in-tree use the namespaced `{{secret.*}}` / `{{oauth.access_token}}` forms.

---

## File structure

```
services/
  system/                       ← runs first (before all other categories)
    openclaw-runtime/
      service.toml
      recipe.toml
  llm/
    anthropic/
      service.toml
      recipe.toml
    openai/
    claude-code/
    ...
  channel/
    telegram/
    wechat/
  integration/
    github/
    nodpay/
    openclaw-dashboard/
    ...
```

### Category execution order

| Category | Priority | Description |
|----------|----------|-------------|
| `system` | **first** | Environment bootstrap. Runs before any service recipe to set up gateway lifecycle, model catalog, exec approvals, etc. Not user-visible. |
| `llm`, `channel`, `integration` | normal | User-facing services. Run after system recipes, in vault enumeration order. |

`dispatch_cook` loads all `category = "system"` recipes first, then iterates enabled services. System recipe steps are idempotent — they run on every cook.

---

## service.toml

Defines how a service behaves at runtime: identity, upstream connections, API endpoints, and access policy.

### `[service]` — Identity

```toml
[service]
id = "openai"                   # Machine identifier (vault key, proxy route). Required.
name = "OpenAI"                 # Human-readable name. Required.
sub = "API Key"                 # Short tagline (card subtitle). Optional.
category = "llm"                # system | llm | channel | integration. Required.
group = "openai"                # UI merge key — services with the same group value
                                # display as one card with multiple auth tabs. Optional.
```

### `[[upstream]]` — Named upstream destinations

Zero or more upstream blocks. Each defines a remote HTTP endpoint that API steps can forward to.

```toml
[[upstream]]
id   = "default"                # Unique identifier, referenced by target = "upstream:<id>". Required.
url  = "https://api.openai.com" # Base URL. Required.
auth = { env = "openai_api_key" } # Primary-secret declaration (see below).
```

The `auth` inline table declares the **primary** vault item this upstream needs:

- `auth.env` — the bare vault item name of the primary credential. It drives `op.act.target` (the credential the passkey grant is bound to) and is the item bootstrapped into the allow-fast-path cache at unlock. For oauth2 services it names the long-lived **refresh_token** item.
- `auth.type` — `"oauth2"` marks a stateful-auth upstream (see `[upstream.auth]` fields below). Omit for plain API-key/bearer services; the credential is injected purely via the `{{secret.*}}` templates in `[upstream.headers]` / `[upstream.query]`.

The **host portion of `url` must be a literal** (no `{{…}}` in scheme+authority) — the broker refuses to forward otherwise (anti-SSRF). A template in the *path* is fine (e.g. Telegram's `/bot{{secret.telegram_bot_token}}`).

#### `[upstream.headers]` — Headers injected on every forward

```toml
[upstream.headers]
Authorization     = "Bearer {{openai_api_key}}"
"anthropic-beta"  = "oauth-2025-04-20"
"x-session-id"    = "{{uuid_v4}}"
```

**Replace-all-matching semantics**: for each header name set here, the broker removes all matching headers from the incoming agent request, then writes the value from this section. The agent cannot pollute auth.

#### `[upstream.query]` — Query parameters auto-attached

```toml
[upstream.query]
api_key = "{{some_service_key}}"
```

Same replace-all-matching semantics as headers. Query keys present here are stripped from the incoming agent request and replaced.

#### URL path templates

The token can live in the URL path itself (Telegram's Bot API: `/bot<TOKEN>/<method>`). Put a `{{secret.*}}` in the path portion of `url` — the host stays literal:

```toml
[[upstream]]
url  = "https://api.telegram.org/bot{{secret.telegram_bot_token}}"
auth = { env = "telegram_bot_token" }
```

The agent's relative path (`/sendMessage`, …) is appended after the rendered base URL.

> `[upstream.path_params]` `:placeholder` substitution is roadmap, not in the current broker engine — use a path template as above.

#### `[upstream.auth]` — OAuth2 stateful auth

For oauth2 services, the `auth` block (inline or `[upstream.auth]`) carries the refresh-cycle config. The broker mints a fresh access_token from the stored refresh_token at forward time and exposes it as `{{oauth.access_token}}`:

```toml
[[upstream]]
id  = "default"
url = "https://gmail.googleapis.com"

[upstream.auth]
type              = "oauth2"
provider          = "google"                         # IdP key (consent-flow side)
env               = "gmail_refresh_token"            # vault item holding the refresh_token (primary)
token_url         = "https://oauth2.googleapis.com/token"
client_id_env     = "GOOGLE_CLIENT_ID"               # daemon-startup env var
client_secret_env = "GOOGLE_CLIENT_SECRET"           # omit for PKCE clients
oauth_style       = "form"                           # "form" (default) | "json" (Anthropic)

[upstream.headers]
Authorization = "Bearer {{oauth.access_token}}"
```

Only the immutable refresh_token enters the vault; the short-lived access_token is derived state held in memory (re-minted after lock / restart). Non-oauth services omit the `type`/`token_url`/`client_*` fields and just declare `auth = { env = "..." }`.

Other stateful providers (`aws-sigv4`, `hmac-sha256`, ...) are reserved for the future and not implemented.

#### `stream = true` — Streaming passthrough (raw transports like git)

```toml
[[upstream]]
id     = "default"
url    = "https://github.com"
stream = true
auth   = { env = "github_token" }

[upstream.headers]
Authorization = "Basic {{secret_basic.github_token}}"

[policy.levels]
read  = "allow"
write = "allow"
```

A `stream = true` upstream opts the service into the generic **streaming-passthrough** route `ANY /v/{vid}/stream/{service}/{*rest}` (distinct from the buffered `/use/` broker). Request and response bodies are proxied as **byte streams with no buffering**, and the route's body-size limit is lifted — for transports like git's smart-HTTP where a single packfile can be hundreds of MB. The daemon does **not** interpret the wire protocol: it injects the recipe's auth header(s) and forwards verbatim, so one route serves git and any future raw transport.

Constraints (enforced at request time):
- **allow-policy only.** Streaming bypasses the per-request passkey ceremony (the agent reaches it transparently, e.g. via a `git insteadOf` it configured at connect time), so the service must be `allow` and its credential already resident in the unlocked cache. ask / ask-always / deny are rejected.
- Same **host-literal** + **replace-all-matching** auth stance as the broker.

This is the one recipe shape that is deliberately **not OpenAPI-describable** (git is a binary transport, not a REST API); normal `[[api]]` recipes stay OpenAPI-mappable. The in-tree `github-git` recipe (hidden, reuses the `github_token` secret, HTTP Basic — the `https://<token>@github.com` form) is the reference.

#### `[upstream.locked]` — Response when vault is locked

```toml
[upstream.locked]
response = "Please unlock the SafeClaw vault to use this service."
```

Plain text. The proxy wraps it into the upstream's API response format (OpenAI / Anthropic / etc.) so the agent receives it as a natural completion rather than a 5xx.

### `[[api]]` — Runtime endpoints

Each `[[api]]` is a request handler containing one or more steps executed sequentially.

```toml
[[api]]
method = "POST"                 # HTTP method. Optional (matches all if omitted).
path   = "/sign"                # URL path pattern. Required.
                                # Exact paths match literally.
                                # "*" matches all paths (catch-all).
                                # When multiple [[api]] match, longest prefix wins
                                # (nginx-style longest-prefix-match).

  [[api.steps]]
  target  = "safeclaw"
  run     = "npx nodpay sign"
  returns = true
```

**If no `[[api]]` is declared**, the service has no runtime endpoints. Valid for services that only need a recipe (setup-only) or only serve as upstream definitions consumed by other services.

**Catch-all forwarding** (e.g., proxy all requests to upstream):

```toml
[[api]]
path = "*"

  [[api.steps]]
  target  = "upstream:default"
  returns = true
```

### API step fields

In addition to the shared step fields, API steps support:

| Field | Type | Description |
|-------|------|-------------|
| `returns` | bool | If `true`, this step's output is the API response. At most one step per `[[api]]` may set this. Default: `false`. |
| `retry` | table | Retry policy: `{ attempts = 6, interval_ms = 500 }`. Optional. |

**Response rules:**
1. Steps execute in declaration order.
2. If any step fails → stop, return that step's error.
3. If all succeed → return the output of the step marked `returns = true`.
4. If no step has `returns = true` → return `{ "ok": true }`.

### `[policy]` — Access control

```toml
[policy.levels]
read  = "allow"                 # Default read level: allow | ask | ask-always | deny
write = "allow"                 # Default write level

[[policy.rules]]                # Per-path overrides. Optional.
method     = "GET"
path_exact = "/v1/models"
level      = "allow"

[[policy.rules]]
method      = "DELETE"
path_suffix = "/admin"
level       = "ask-always"
```

Rules are evaluated most-specific-first. A matching rule overrides service-level defaults.

### `help` — Service help text

```toml
help = """
A shared wallet is configured. **Skip the SKILL.md setup** — already done.
- **Safe address:** `{{nodpay_safe}}`
"""
```

A markdown string under `[service]`. Serves two purposes:
1. **`GET /{service}/help`** — returns the resolved help text (always allowed, no policy check)
2. **`safeclaw.md`** — rendered as a section when the service is connected

Template variables resolve via items lookup. Optional.

### `[[vault]]` — Item field declarations (UI / masking)

Declares the vault items a service uses, for the connect-service form and value masking. `kind = "secret"` masks the value in the UI and keeps it out of logs; `kind = "config"` (default) is for non-sensitive values.

```toml
[[vault]]
name        = "openai_api_key"
kind        = "secret"
description = "Your OpenAI API key from platform.openai.com"
```

Optional — the required `{{secret.*}}` set is still derived from the template scan, so a service works without `[[vault]]` blocks; they exist for UI labels + masking.

> The flatter `[items]` descriptions-only block is roadmap; the implemented form is `[[vault]]`.

---

## recipe.toml

Defines first-time setup instructions. Consumed by:
- **NL-Cooker** (`safeclaw connect <id>`) — renders as human-readable steps (OSS)
- **Provisioner** (Pro) — executes automatically via `dispatch_cook`

### `[recipe]` — Metadata

```toml
[recipe]
id           = "nodpay"
display_name = "NodPay"
```

Whether a service requires items in the vault is derived from `service.toml` template scan (no explicit declaration).

### `[passkey_sharing]` — Cross-origin passkey access

```toml
[passkey_sharing]
enabled = true
origins = ["https://nodpay.ai"]
```

Configures `/.well-known/webauthn` to allow external origins to use passkeys registered on this SafeClaw instance. Optional.

### `[[steps]]` — Setup steps

```toml
[[steps]]
title       = "Install NodPay CLI"
target      = "openclaw"
run         = "npm install -g nodpay"
cwd         = "openclaw"
description = "Detailed explanation"
note        = "Requires Node.js 18+"

[[steps]]
title  = "Create config files"
target = "openclaw"
files = [
  { path = ".nodpay/config.json", content = '{"remote_wallet":"http://localhost:{{safeclaw.proxy_port}}/nodpay"}' },
  { path = "accounts/safeclaw.json", content = '{"token":"...","baseUrl":"..."}' },
]

[[steps]]
title  = "Enable channel"
target = "openclaw"
config_patches = [
  { path = "channels.telegram.enabled", value = true },
]

[[steps]]
title   = "Restart OpenClaw"
target  = "openclaw"
restart = true
```

#### Recipe step fields

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | **Required.** Where to execute. |
| `title` | string | **Required.** Human-readable label. |
| `run` | string | Shell command. |
| `cwd` | string | Working directory for `run`. |
| `files` | array | Files to create (see below). |
| `config_patches` | array | Config key-value patches (see below). |
| `restart` | bool | Restart target container after step. |
| `description` | string | Detailed description. |
| `note` | string | Additional note. |
| `env` | table | Environment variables for `run`. |

**`files` sub-fields:**

| Field | Description |
|-------|-------------|
| `path` | Destination path (relative to `~`). Required. |
| `content` | Inline content. Mutually exclusive with `template`. |
| `template` | Template file name in the service folder. Mutually exclusive with `content`. |
| `upsert_block` | If set, only replace the named block within the file (idempotent update). |

**`config_patches` sub-fields:**

| Field | Description |
|-------|-------------|
| `path` | Dot-separated config key path (e.g., `channels.telegram.enabled`). |
| `value` | Any JSON-compatible value (bool, string, number, object). |

**Template variables in recipe step values:**

| Variable | Description |
|----------|-------------|
| `{{safeclaw.proxy_port}}` | SafeClaw proxy port (default: 23295) |
| `{{safeclaw.admin_port}}` | SafeClaw admin port (default: 23294) |
| `{{safeclaw.admin_url}}` | SafeClaw admin URL |
| `{{service.id}}` | Current service ID |
| `{{X}}` | Item X — same resolution as service.toml templates |

---

## Complete examples

### LLM proxy service (OpenAI)

```toml
# ═══ services/llm/openai/service.toml ═══

[service]
id       = "openai"
name     = "OpenAI"
sub      = "API Key"
category = "llm"
group    = "openai"

[[upstream]]
id   = "default"
url  = "https://api.openai.com"
auth = { env = "openai_api_key" }

[upstream.headers]
Authorization = "Bearer {{secret.openai_api_key}}"

[upstream.locked]
response = "Please unlock the SafeClaw vault to use this service."

[[api]]
path = "*"

  [[api.steps]]
  target  = "upstream:default"
  returns = true

[policy.levels]
read  = "allow"
write = "allow"

[[vault]]
name        = "openai_api_key"
kind        = "secret"
description = "Your OpenAI API key from platform.openai.com"
```

```toml
# ═══ services/llm/openai/recipe.toml ═══

[recipe]
id           = "openai"
display_name = "OpenAI"

[[steps]]
title  = "Register OpenAI provider"
target = "openclaw"
run    = """openclaw config set models.providers.openai '{"apiKey":"sk-safeclaw-proxy","baseUrl":"http://localhost:{{safeclaw.proxy_port}}/openai/v1","api":"openai-completions","models":[]}' --strict-json"""

[[steps]]
title   = "Restart OpenClaw"
target  = "openclaw"
restart = true
```

### LLM proxy with OAuth (OpenAI Codex)

```toml
# ═══ services/llm/openai-codex/service.toml ═══

[service]
id       = "openai-codex"
name     = "OpenAI Codex"
sub      = "ChatGPT"
category = "llm"
group    = "openai"

[[upstream]]
id  = "default"
url = "https://api.openai.com"

[upstream.headers]
Authorization        = "Bearer {{auth.access_token}}"
"openai-beta"        = "responses=experimental"
"chatgpt-account-id" = "{{auth.account_id}}"

[upstream.auth]
provider = "oauth2"

[upstream.locked]
response = "Please unlock the SafeClaw vault to use this service."

[[api]]
path = "*"

  [[api.steps]]
  target  = "upstream:default"
  returns = true

[policy.levels]
read  = "allow"
write = "allow"
```

### Local exec service (NodPay)

```toml
# ═══ services/integration/nodpay/service.toml ═══

[service]
id       = "nodpay"
name     = "NodPay"
sub      = "Web3 agent wallet"
category = "integration"

[[api]]
method = "POST"
path   = "/sign"

  [[api.steps]]
  target  = "safeclaw"
  run     = "npx nodpay sign"
  env     = { NODPAY_AGENT_KEY = "{{nodpay_agent_key}}" }
  returns = true

[[api]]
method = "GET"
path   = "/wallets"

  [[api.steps]]
  target  = "safeclaw"
  run     = "npx nodpay wallets --json"
  returns = true

[policy.levels]
read  = "allow"
write = "allow"

help = """
A shared on-chain wallet is configured and ready. **Skip the NodPay SKILL.md setup section** — \
keygen and wallet creation are already done by SafeClaw.

- **Safe address:** `{{nodpay_safe}}`
- Run `npx nodpay wallets` to get full wallet details (signers, passkey coords, recovery, etc.)
- When the user asks to send ETH/crypto/tokens or make a payment, use `npx nodpay propose` to create the transaction
- Signing is handled automatically via SafeClaw — you do not have the private key and don't need it
"""

[items]
nodpay_agent_key = "NodPay agent signing key"
nodpay_safe      = "Safe contract address (0x...)"
```

NodPay carries multiple items (`nodpay_agent_key`, `nodpay_safe`, ...) — all flat in the items namespace, all resolved through `store_order`. No per-service vault namespace.

### Channel with path-token auth (Telegram)

```toml
# ═══ services/channel/telegram/service.toml ═══

[service]
id       = "telegram"
name     = "Telegram"
sub      = "Bot API"
category = "channel"

[[upstream]]
id   = "default"
url  = "https://api.telegram.org/bot{{secret.telegram_bot_token}}"
auth = { env = "telegram_bot_token" }

[[api]]
path = "*"

  [[api.steps]]
  target  = "upstream:default"
  returns = true

[policy.levels]
read  = "allow"
write = "allow"

[[vault]]
name        = "telegram_bot_token"
kind        = "secret"
description = "Bot token from @BotFather"
```

```toml
# ═══ services/channel/telegram/recipe.toml ═══

[recipe]
id           = "telegram"
display_name = "Telegram"

[[steps]]
title  = "Enable Telegram channel"
target = "openclaw"
run    = "openclaw config set channels.telegram.enabled true --strict-json"

[[steps]]
title   = "Restart OpenClaw"
target  = "openclaw"
restart = true
```

### LLM proxy with OAuth + credential file (Claude Code)

```toml
# ═══ services/llm/claude-code/service.toml ═══

[service]
id       = "claude-code"
name     = "Claude Code"
sub      = "Claude Code OAuth"
category = "llm"
group    = "anthropic"

[[upstream]]
id  = "default"
url = "https://api.anthropic.com"

[upstream.headers]
Authorization              = "Bearer {{auth.access_token}}"
"anthropic-beta"           = "oauth-2025-04-20,interleaved-thinking-2025-05-14"
"user-agent"               = "claude-cli/2.1.87 (external, cli)"
"x-claude-code-session-id" = "{{uuid_v4}}"

[upstream.auth]
provider = "oauth2"
style    = "json"

[upstream.locked]
response = "Please unlock the SafeClaw vault to use this service."

[[api]]
path = "*"

  [[api.steps]]
  target  = "upstream:default"
  returns = true

[policy.levels]
read  = "allow"
write = "allow"
```

```toml
# ═══ services/llm/claude-code/recipe.toml ═══

[recipe]
id           = "claude-code"
display_name = "Claude Code"

[[steps]]
title  = "Register Anthropic provider"
target = "openclaw"
run    = """openclaw config set models.providers.anthropic '{"apiKey":"sk-safeclaw-proxy","baseUrl":"http://localhost:{{safeclaw.proxy_port}}/anthropic/v1","api":"anthropic-messages","models":[]}' --strict-json"""

[[steps]]
title  = "Write Claude CLI credentials"
target = "openclaw"
files = [
  { path = ".claude/.credentials.json", template = "claude-credentials.json" },
]
note   = "Writes OAuth tokens to the Claude CLI credentials file"

[[steps]]
title   = "Restart OpenClaw"
target  = "openclaw"
restart = true
```

### Dashboard embedding (OpenClaw Dashboard)

The dashboard is embedded as an iframe in the SafeClaw Pro console. This requires a multi-layer proxy chain and a `trusted-proxy` auth mode in the gateway. The v3 protocol does not change this architecture; see git history for the full `openclaw-dashboard` example (auth-model heavy, orthogonal to the v3 changes).

For v3, the relevant excerpt is that `openclaw-dashboard` has no `[[upstream]]` (trusted-proxy mode), no items required, just `[policy]` and a recipe to set gateway config.

---

## Enable flow

```
Frontend → POST /vault/services/add → vault stores service_state entry
         → dispatch_cook(secrets, service_only = "service-id")
           → builds ops from this service's recipe only
           → POST /cook to provisioner
           → provisioner executes steps sequentially
```

`dispatch_cook` supports incremental execution via the `service_only` parameter:

| Mode | When | What runs |
|------|------|-----------|
| Full (`None`) | `admin_setup`, `vault_update` | System recipes → workspace files → vault config → all service recipes |
| Incremental (`Some(id)`) | `services/add`, `services/remove` | Workspace files → that service's recipe only |

Vault unlock does **not** trigger cook. Config persists in the docker volume; unlock only decrypts the vault in memory.

### Runtime flow (API call)

```
Agent → GET /proxy/{service_id}/wallets
      → match [[api]] by path
      → execute [[api.steps]] sequentially
        → step N: resolve templates via store_order (see STORES_AND_ITEMS.md §5)
                  ↳ headers / query / path_params get replace-all-matching injection
        → forward to upstream (target = upstream:default)
      → return output of step marked returns = true
```

---

## Categories

| Category | Description | Examples |
|----------|-------------|---------|
| `llm` | LLM providers | anthropic, openai, google, deepseek, groq |
| `channel` | Messaging channels | telegram, wechat |
| `integration` | Apps, tools, APIs | github, gmail, nodpay, openclaw-dashboard |

---

## Design principles

- **Step is the universal primitive.** Both recipe setup and runtime APIs are sequences of steps with the same `target` vocabulary.
- **CLI first.** Recipe steps prefer `openclaw config set` / `openclaw plugins install` over direct file manipulation.
- **Declarative over imperative.** TOML definitions, not Rust code per service.
- **Templates over typed auth.** Common auth flows (bearer, header, query, basic, path-token) are expressed as `{{secret.NAME}}` template substitutions in `[upstream.headers]` / `.query` / the URL path. Stateful auth (OAuth refresh, signing) uses `auth = { type = "oauth2", … }` + `{{oauth.access_token}}`.
- **Replace-all-matching is the auth contract.** For every name set by upstream config, broker strips agent's matching entries first, then writes upstream's value. Agent cannot pollute.
- **Namespaced item references.** Templates reference vault items by namespaced name (`{{secret.openai_api_key}}`) so an item never collides with a builtin (`{{oauth.*}}`, `{{uuid_v4}}`). The flat bare-`{{X}}` store_order model is the broader roadmap.
- **Explicit over implicit.** Every `[[api]]` declares its steps and target. No default forwarding; catch-all requires `path = "*"`.
- **SafeClaw manages openclaw lifecycle.** Recipe steps use `openclaw config set` with `gateway.reload.mode off` to batch config changes, then explicitly `restart = true` at the end.

---

## Migration from v2

Pre-launch — no user data migration. In-tree service definitions migrate mechanically.

### Field-by-field changes

| v2 | v3 (as implemented) |
|----|-----|
| `auth = { type = "bearer", env = "X" }` | `auth = { env = "X" }` + `[upstream.headers] Authorization = "Bearer {{secret.X}}"` |
| `auth = { type = "header", header = "X-Key", env = "X" }` | `auth = { env = "X" }` + `[upstream.headers] X-Key = "{{secret.X}}"` |
| `auth = { type = "query", param = "key", env = "X" }` | `auth = { env = "X" }` + `[upstream.query] key = "{{secret.X}}"` |
| `auth = { type = "path", env = "X" }` | `auth = { env = "X" }` + URL path template `…/bot{{secret.X}}` |
| `auth = { type = "basic", env = "X" }` | `auth = { env = "X" }` + `[upstream.headers] Authorization = "Basic {{secret_basic.X}}"` |
| `{{auth_value}}` magic single-secret token | Named `{{secret.X}}` (multi-secret capable) |
| `auth = { type = "oauth2", … }` | Kept. `auth.env` names the refresh_token; templates reference `{{oauth.access_token}}` |
| `[[vault]]` schema declarations | Kept — UI labels + `kind = "secret"` masking. Required set still derived from template scan |
| `{{ env.X }}` / `{{service.vault.X}}` template prefixes | `{{secret.X}}` (namespaced, no `env.` prefix) |

### Conceptual changes

- **No per-service vault namespace.** v2 had `secrets.services.<id>.<key>` referenced by `{{service.vault.X}}`. v3 has one flat items namespace. Service authors prefix item names for clarity (e.g., `nodpay_safe` instead of `service.vault.safe`).
- **No `[[vault]]` block.** What items a service needs is derived from `{{X}}` occurrences in service.toml. `[items]` is optional, descriptions only.
- **Storage is decoupled from service definition.** v2 implied "credentials live in env namespace". v3 has the items+stores model — service.toml never references store names. Where an item lives is the user's vault configuration, not the service author's concern. See [STORES_AND_ITEMS.md](./STORES_AND_ITEMS.md).
- **`auth.placeholder` legacy template parsing dropped.** Broker no longer parses `{{ env.X }}` out of placeholders. Templates live in headers/query/path_params.

### Vault state changes (orthogonal but related)

- `services.<name>.upstream` / `services.<name>.auth` (registry-shadow fields in vault.enc) — no longer stored. Broker reads service.toml at runtime.
- Top-level service-defined keys (`wallet`, `gatewayToken`, ...) — moved into `stores["native-secrets"].items` (see STORES_AND_ITEMS.md §14 for migration).
- `files: [{id, name, size}]` — moved into `stores["native-files"].items`.

Protocol version bump: `health.version` increments to 3. Frontend gates compat via the version handshake.

---

## Vault partial read (wire endpoint, unchanged)

The `POST /vault/credentials` endpoint supports an optional `select` field for returning only matching subtrees. See [PROTOCOL.md](./PROTOCOL.md) for full wire-protocol details. The v3 vault schema affects what paths are valid (`stores.prod-gcp.credentials_item`, `stores["native-secrets"].items.openai_api_key`, etc.) but the endpoint mechanics are unchanged.
