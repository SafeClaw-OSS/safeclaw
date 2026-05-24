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

String values in `[upstream.headers]`, `[upstream.query]`, `[upstream.path_params]`, the URL itself, and step `run` / `env` fields support `{{...}}` template expressions:

| Form | Resolves to | Notes |
|------|-------------|-------|
| `{{X}}` | item X's string value | item resolved via `store_order`; see STORES_AND_ITEMS.md §5 |
| `{{b64:X}}` | item X's value, base64-encoded | useful for Basic auth |
| `{{uuid_v4}}` | a fresh UUID v4 | generated per request |
| `{{auth.access_token}}` / `{{auth.account_id}}` / ... | OAuth-managed token bundle fields | only when `[upstream.auth] provider = "oauth2"` |

If an item referenced by `{{X}}` is unresolvable (no store provides it), the request errors. Required items are derived by scanning `{{X}}` occurrences across service.toml — see [the `[items]` block](#items--optional-ui-descriptions) for optional descriptions.

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
url  = "https://api.openai.com" # Base URL. Required. Keep clean — no auth in the URL.
```

`url` may contain `:placeholder` path parameters (Express/OpenAPI style), substituted via `[upstream.path_params]`.

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

#### `[upstream.path_params]` — URL `:placeholder` substitution

Used with `:name`-style placeholders in `url`:

```toml
[[upstream]]
url = "https://api.telegram.org/:bot_token"

[upstream.path_params]
bot_token = "{{telegram_bot_token}}"
```

Only declared placeholders are substituted. Undeclared `:placeholder` in URL → error at registration time.

#### `[upstream.auth]` — Stateful auth (reserved)

Used **only** for auth that cannot be expressed as a simple template (OAuth refresh cycles, SigV4 signing, HMAC). In v3.0, `provider = "oauth2"` is the only supported value:

```toml
[upstream.auth]
provider = "oauth2"             # discriminator; only "oauth2" supported in v3.0
# Provider-specific tuning fields go here. For oauth2:
#   style = "json" | "form"     # request encoding when refreshing
#
# OAuth tokens are managed by the OAuth subsystem (refresh, rotation).
# Templates reference fields from the managed token bundle:
#   {{auth.access_token}}, {{auth.account_id}}, ...
```

Service.toml without `[upstream.auth]` is valid and common (most services use only `[upstream.headers]` / `.query` / `.path_params`).

Other providers (`aws-sigv4`, `hmac-sha256`, ...) are reserved for the future and not implemented.

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

### `[items]` — Optional UI descriptions

Pure UI hint for the connect-service flow. Required items are derived from scanning `{{X}}` template occurrences across service.toml (no need to declare them here). This block is **only** for human-readable descriptions used by the connect-service form:

```toml
[items]
openai_api_key = "Your OpenAI API key from platform.openai.com"
github_app_pem = "GitHub App private key (PEM file)"
```

Optional. Absent entries fall back to the bare item name in the UI.

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
id  = "default"
url = "https://api.openai.com"

[upstream.headers]
Authorization = "Bearer {{openai_api_key}}"

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

[items]
openai_api_key = "Your OpenAI API key from platform.openai.com"
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
id  = "default"
url = "https://api.telegram.org/:bot_token"

[upstream.path_params]
bot_token = "{{telegram_bot_token}}"

[[api]]
path = "*"

  [[api.steps]]
  target  = "upstream:default"
  returns = true

[policy.levels]
read  = "allow"
write = "allow"

[items]
telegram_bot_token = "Bot token from @BotFather"
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
- **Templates over typed auth.** Common auth flows (bearer, header, query, basic, path-token) are expressed as `{{X}}` template substitutions in `[upstream.headers]` / `.query` / `.path_params`. Stateful auth (OAuth refresh, signing) uses `[upstream.auth] provider = "..."`.
- **Replace-all-matching is the auth contract.** For every name set by upstream config, broker strips agent's matching entries first, then writes upstream's value. Agent cannot pollute.
- **Single items namespace.** Templates reference items by bare name (`{{openai_api_key}}`), resolved across all stores per `store_order`. Service authors don't see store boundaries.
- **Explicit over implicit.** Every `[[api]]` declares its steps and target. No default forwarding; catch-all requires `path = "*"`.
- **SafeClaw manages openclaw lifecycle.** Recipe steps use `openclaw config set` with `gateway.reload.mode off` to batch config changes, then explicitly `restart = true` at the end.

---

## Migration from v2

Pre-launch — no user data migration. In-tree service definitions migrate mechanically.

### Field-by-field changes

| v2 | v3 |
|----|-----|
| `auth = { type = "bearer", env = "X" }` | Removed. Use `[upstream.headers] Authorization = "Bearer {{X}}"` |
| `auth = { type = "header", header = "X-Key", env = "X" }` | Removed. Use `[upstream.headers] X-Key = "{{X}}"` |
| `auth = { type = "query", param = "key", env = "X" }` | Removed. Use `[upstream.query] key = "{{X}}"` |
| `auth = { type = "path", env = "X" }` | Removed. URL with `:placeholder` + `[upstream.path_params]` |
| `auth = { type = "basic", env = "X" }` | Removed. Use `[upstream.headers] Authorization = "Basic {{b64:X}}"` |
| `auth = { type = "oauth2" }` | Repurposed as `[upstream.auth] provider = "oauth2"`; templates reference `{{auth.access_token}}` etc. |
| `[[vault]]` schema declarations | Removed. Required items derived from template scan; optional `[items]` block for descriptions |
| `{{ env.X }}` / `{{service.vault.X}}` template prefixes | Removed. Just `{{X}}` |
| `placeholder = "sk-..."` (legacy UI hint via template-parsing) | Removed. Use `[items]` for descriptions |

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
