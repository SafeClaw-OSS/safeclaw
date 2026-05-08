# SafeClaw Service Protocol

**Protocol version: 2** — Breaking changes from v1; see migration notes at the end.

This document defines the declarative service protocol used by SafeClaw. Each service is a folder in `services/{category}/{id}/` containing two TOML files:

- **`service.toml`** — runtime behavior (how requests are handled when the service is active)
- **`recipe.toml`** — setup behavior (what happens when the service is first enabled)

Both files share a common execution primitive: **step**. A step is a single action with a `target` specifying where it runs.

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
Additional fields available only in API steps: `read`, `returns`, `retry`, `method` (inherited from parent `[[api]]`).

### Vault field declarations

Services can declare what fields they store in the vault using `[[vault]]` blocks in `service.toml`. This serves as schema documentation, enables frontend form generation, and powers validation on service add.

```toml
[[vault]]
name = "gatewayToken"
kind = "secret"
description = "Gateway auth token for dashboard WebSocket"
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** Key name in the vault JSON (`secrets.services.{id}.{name}`). |
| `kind` | string | `"secret"` (masked in UI, never logged) or `"config"` (default). |
| `description` | string | Human-readable description for docs and UI labels. |

All declared fields are required — if a service declares a vault field, `POST /vault/services/add` will reject requests missing that field. Services that only use standard auth credentials (defined by `[[upstream]]` auth type) do not need `[[vault]]` declarations.

Recipe steps reference vault values via `{{service.vault.KEY}}` template variables (see Template variables below).

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
id = "default"                          # Unique identifier, referenced by target = "upstream:<id>". Required.
url = "https://api.openai.com"          # Base URL. Required.

[upstream.auth]                         # Credential injection. Optional.
type = "bearer"                         # bearer | basic | header | query | path | oauth2
placeholder = "sk-..."                  # Input hint for UI. Optional.
# Type-specific fields:
#   header:  header = "x-api-key", prefix = "Bearer " (optional)
#   query:   param = "key"
#   basic:   username_label = "Account SID"
#   oauth2:  oauth_style = "json" | "form" (default: form)
#            provider = "google" (for shared OAuth flows)

[upstream.headers]                      # Custom headers injected per-request. Optional.
"anthropic-beta" = "oauth-2025-04-20"
"x-session-id" = "{{uuid_v4}}"         # Template: random UUID v4
"chatgpt-account-id" = "{{auth.account_id}}"  # Template: from vault auth config

[upstream.locked]                       # Response when vault is locked. Optional.
response = "Please unlock the SafeClaw vault to use this service."
                                        # Plain text. The proxy wraps it into the appropriate
                                        # API response format (OpenAI, Anthropic, etc.)
                                        # so the agent receives it as a natural completion.
```

If no `[[upstream]]` is declared, the service has no HTTP forwarding capability.

### `[[api]]` — Runtime endpoints

Each `[[api]]` is a request handler containing one or more steps executed sequentially.

```toml
[[api]]
method = "POST"                         # HTTP method. Optional (matches all if omitted).
path = "/sign"                          # URL path pattern. Required.
                                        # Exact paths match literally.
                                        # "*" matches all paths (catch-all).
                                        # When multiple [[api]] match, longest prefix wins
                                        # (nginx-style longest-prefix-match).

  [[api.steps]]
  target = "safeclaw"
  run = "npx nodpay sign"
  returns = true
```

**If no `[[api]]` is declared**, the service has no runtime endpoints. This is valid for services that only need a recipe (setup-only) or only serve as upstream definitions consumed by other services.

**Catch-all forwarding** (e.g., proxy all requests to upstream):

```toml
[[api]]
path = "*"

  [[api.steps]]
  target = "upstream:default"
  returns = true
```

### API step fields

In addition to the shared step fields, API steps support:

| Field | Type | Description |
|-------|------|-------------|
| `read` | string | Vault key path to read (dot-separated). Used with `target = "safeclaw.vault"`. |
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
read = "allow"                  # Default read level: allow | ask | ask-always | deny
write = "allow"                 # Default write level

[[policy.rules]]                # Per-path overrides. Optional.
method = "GET"
path_exact = "/v1/models"
level = "allow"

[[policy.rules]]
method = "DELETE"
path_suffix = "/admin"
level = "ask-always"
```

Rules are evaluated most-specific-first. A matching rule overrides service-level defaults.

### `help` — Service help text

```toml
help = """
A shared wallet is configured. **Skip the SKILL.md setup** — already done.
- **Safe address:** `{{wallet.safe}}`
"""
```

A markdown string under `[service]`. Serves two purposes:
1. **`GET /{service}/help`** — returns the resolved help text (always allowed, no policy check)
2. **`safeclaw.md`** — rendered as a section when the service is connected

Template variables `{{wallet.*}}` are resolved from vault service data. Optional.

---

## recipe.toml

Defines first-time setup instructions. Consumed by:
- **NL-Cooker** (`safeclaw connect <id>`) — renders as human-readable steps (OSS)
- **Provisioner** (Pro) — executes automatically via `dispatch_cook`

### `[recipe]` — Metadata

```toml
[recipe]
id = "nodpay"
display_name = "NodPay"
```

Whether a service requires vault credentials is derived from `service.toml` — if any `[[upstream]]` has `[upstream.auth]`, credentials are required.

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
title = "Install NodPay CLI"            # Human-readable label. Required.
target = "openclaw"                     # Required. See Target table.
run = "npm install -g nodpay"           # Shell command. Optional.
cwd = "openclaw"                        # Working directory for run. Optional.
description = "Detailed explanation"    # Optional.
note = "Requires Node.js 18+"          # Optional.

[[steps]]
title = "Create config files"
target = "openclaw"
files = [                               # Files to create. Optional.
  { path = ".nodpay/config.json", content = '{"remote_wallet":"http://localhost:{{safeclaw.proxy_port}}/nodpay"}' },
  { path = "accounts/safeclaw.json", content = '{"token":"...","baseUrl":"..."}' },
]

[[steps]]
title = "Enable channel"
target = "openclaw"
config_patches = [                      # Config changes to openclaw.json. Optional.
  { path = "channels.telegram.enabled", value = true },
]

[[steps]]
title = "Restart OpenClaw"
target = "openclaw"
restart = true                          # Restart the target container. Optional.
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

**Template variables** (resolved in `run`, `content`, `path`, `config_patches` values):

| Variable | Description |
|----------|-------------|
| `{{safeclaw.proxy_port}}` | SafeClaw proxy port (default: 23295) |
| `{{safeclaw.admin_port}}` | SafeClaw admin port (default: 23294) |
| `{{safeclaw.admin_url}}` | SafeClaw admin URL |
| `{{service.id}}` | Current service ID |
| `{{service.vault.KEY}}` | Value of `KEY` from this service's vault data |

Two namespaces: `safeclaw.*` for runtime properties, `service.*` for the current service context. `{{service.vault.KEY}}` reads from `secrets.services.{service.id}.KEY` in the vault.

---

## Complete examples

### LLM proxy service (OpenAI)

```toml
# ═══ services/llm/openai/service.toml ═══

[service]
id = "openai"
name = "OpenAI"
sub = "API Key"
category = "llm"
group = "openai"

[[upstream]]
id = "default"
url = "https://api.openai.com"
auth = { type = "bearer", placeholder = "sk-..." }
locked = { response = "Please unlock the SafeClaw vault to use this service." }

[[api]]
path = "*"

  [[api.steps]]
  target = "upstream:default"
  returns = true

[policy.levels]
read = "allow"
write = "allow"
```

```toml
# ═══ services/llm/openai/recipe.toml ═══

[recipe]
id = "openai"
display_name = "OpenAI"

[[steps]]
title = "Register OpenAI provider"
target = "openclaw"
run = """openclaw config set models.providers.openai '{"apiKey":"sk-safeclaw-proxy","baseUrl":"http://localhost:{{safeclaw.proxy_port}}/openai/v1","api":"openai-completions","models":[]}' --strict-json"""

[[steps]]
title = "Restart OpenClaw"
target = "openclaw"
restart = true
```

### LLM proxy with OAuth (OpenAI Codex)

```toml
# ═══ services/llm/openai-codex/service.toml ═══

[service]
id = "openai-codex"
name = "OpenAI Codex"
sub = "ChatGPT"
category = "llm"
group = "openai"

[[upstream]]
id = "default"
url = "https://api.openai.com"
auth = { type = "oauth2" }
headers = { "openai-beta" = "responses=experimental", "chatgpt-account-id" = "{{auth.account_id}}" }
locked = { response = "Please unlock the SafeClaw vault to use this service." }

[[api]]
path = "*"

  [[api.steps]]
  target = "upstream:default"
  returns = true

[policy.levels]
read = "allow"
write = "allow"
```

### Local exec service (NodPay)

```toml
# ═══ services/integration/nodpay/service.toml ═══

[service]
id = "nodpay"
name = "NodPay"
sub = "Web3 agent wallet"
category = "integration"

[[vault]]
name = "wallet"
kind = "config"
description = "On-chain wallet state (safe address, signers, passkey coords)"

[[api]]
method = "POST"
path = "/sign"

  [[api.steps]]
  target = "safeclaw"
  run = "npx nodpay sign"
  env = { NODPAY_AGENT_KEY = "{{auth.secret}}" }
  returns = true

[[api]]
method = "GET"
path = "/wallets"

  [[api.steps]]
  target = "safeclaw"
  run = "npx nodpay wallets --json"
  returns = true

[policy.levels]
read = "allow"
write = "allow"

help = """
A shared on-chain wallet is configured and ready. **Skip the NodPay SKILL.md setup section** — \
keygen and wallet creation are already done by SafeClaw.

- **Safe address:** `{{wallet.safe}}`
- Run `npx nodpay wallets` to get full wallet details (signers, passkey coords, recovery, etc.)
- When the user asks to send ETH/crypto/tokens or make a payment, use `npx nodpay propose` to create the transaction
- Signing is handled automatically via SafeClaw — you do not have the private key and don't need it
"""
```

### Dashboard embedding (OpenClaw Dashboard)

The dashboard is embedded as an iframe in the SafeClaw Pro console. This requires a multi-layer proxy chain and careful auth coordination.

#### Proxy chain

```
HTTP + WS: browser → Railway rewrite (same-origin) → relay → VM:18789
```

Both HTTP and WebSocket go through the same-origin Railway proxy. The dashboard iframe loads at `www.safeclaw.pro/api/v/{id}/oc/` and derives its WebSocket URL from `window.location` — no explicit `gatewayUrl` is needed. The `sc_token` cookie (set by the parent page with `path=/api/v/`) is sent automatically for same-origin requests.

> **Note:** Vercel rewrites do **not** proxy WebSocket upgrades. Railway does. This architecture requires Railway (or equivalent) for the frontend host.

#### Auth model: trusted-proxy

The gateway runs in `trusted-proxy` auth mode. The relay is the auth boundary — it verifies account session (via `sc_token` cookie) before proxying. The gateway trusts the relay via IP whitelist.

```json
{
  "gateway": {
    "auth": {
      "mode": "trusted-proxy",
      "trustedProxy": { "userHeader": "x-safeclaw-user" }
    },
    "trustedProxies": ["RELAY_EGRESS_IP"],
    "bind": "lan",
    "controlUi": {
      "enabled": true,
      "allowedOrigins": ["https://www.safeclaw.pro"]
    }
  }
}
```

**Prerequisites:**
- Relay must have a **fixed egress IP** (Railway paid feature). Currently `162.220.232.99`.
- VM firewall must allow inbound on port 18789 (`ufw allow 18789/tcp`).
- Gateway must bind to LAN (`gateway.bind lan`) for external access.

**Relay responsibilities:**
- HTTP proxy: inject `<base href>`, rewrite CSP (`frame-ancestors`, `base-uri`), strip browser headers, set `x-safeclaw-user`
- WS upgrade: verify `sc_token` cookie + instance ownership, set `x-safeclaw-user`, pipe TCP to VM:18789

**Limitations:**
- If Railway egress IP changes, `gateway.trustedProxies` must be updated on all VMs (via recipe re-cook or admin API).
- `trustedProxies` is per-VM config, not centralized. A bulk update mechanism may be needed.

#### service.toml

```toml
[service]
id = "openclaw-dashboard"
name = "OpenClaw Dashboard"
category = "integration"

[policy.levels]
read = "allow"
write = "allow"
```

No `[[vault]]` or `[[api]]` needed — trusted-proxy mode eliminates the need for gateway tokens and `/access` endpoints.

#### recipe.toml

```toml
[recipe]
id = "openclaw-dashboard"
display_name = "OpenClaw Dashboard"

[[steps]]
title = "Enable Control UI"
target = "openclaw"
run = "openclaw config set gateway.controlUi.enabled true --strict-json"

[[steps]]
title = "Set allowed origins"
target = "openclaw"
run = """openclaw config set gateway.controlUi.allowedOrigins '["https://www.safeclaw.pro"]' --strict-json"""

[[steps]]
title = "Set trusted proxy auth"
target = "openclaw"
run = """openclaw config set gateway.auth '{"mode":"trusted-proxy","trustedProxy":{"userHeader":"x-safeclaw-user"}}' --strict-json"""

[[steps]]
title = "Set trusted proxy IPs"
target = "openclaw"
run = """openclaw config set gateway.trustedProxies '["{{safeclaw.relay_egress_ip}}"]' --strict-json"""

[[steps]]
title = "Bind to LAN"
target = "openclaw"
run = "openclaw config set gateway.bind lan"

[[steps]]
title = "Open firewall port"
target = "host"
run = "ufw allow 18789/tcp"

[[steps]]
title = "Restart OpenClaw"
target = "openclaw"
restart = true
```

`{{safeclaw.relay_egress_ip}}` is a template variable resolved from SafeClaw config, making the IP updateable without changing the recipe.

### Channel with plugin setup (Telegram)

```toml
# ═══ services/channel/telegram/service.toml ═══

[service]
id = "telegram"
name = "Telegram"
sub = "Bot API"
category = "channel"

[[upstream]]
id = "default"
url = "https://api.telegram.org"
auth = { type = "path" }

[[api]]
path = "*"

  [[api.steps]]
  target = "upstream:default"
  returns = true

[policy.levels]
read = "allow"
write = "allow"
```

```toml
# ═══ services/channel/telegram/recipe.toml ═══

[recipe]
id = "telegram"
display_name = "Telegram"

[[steps]]
title = "Enable Telegram channel"
target = "openclaw"
run = "openclaw config set channels.telegram.enabled true --strict-json"

[[steps]]
title = "Restart OpenClaw"
target = "openclaw"
restart = true
```

### LLM proxy with OAuth + credential file (Claude Code)

```toml
# ═══ services/llm/claude-code/service.toml ═══

[service]
id = "claude-code"
name = "Claude Code"
sub = "Claude Code OAuth"
category = "llm"
group = "anthropic"

[[upstream]]
id = "default"
url = "https://api.anthropic.com"
auth = { type = "oauth2", oauth_style = "json" }
headers = { "anthropic-beta" = "oauth-2025-04-20,interleaved-thinking-2025-05-14", "user-agent" = "claude-cli/2.1.87 (external, cli)", "x-claude-code-session-id" = "{{uuid_v4}}" }
locked = { response = "Please unlock the SafeClaw vault to use this service." }

[[api]]
path = "*"

  [[api.steps]]
  target = "upstream:default"
  returns = true

[policy.levels]
read = "allow"
write = "allow"
```

```toml
# ═══ services/llm/claude-code/recipe.toml ═══

[recipe]
id = "claude-code"
display_name = "Claude Code"

[[steps]]
title = "Register Anthropic provider"
target = "openclaw"
run = """openclaw config set models.providers.anthropic '{"apiKey":"sk-safeclaw-proxy","baseUrl":"http://localhost:{{safeclaw.proxy_port}}/anthropic/v1","api":"anthropic-messages","models":[]}' --strict-json"""

[[steps]]
title = "Write Claude CLI credentials"
target = "openclaw"
files = [
  { path = ".claude/.credentials.json", template = "claude-credentials.json" },
]
note = "Writes OAuth tokens to the Claude CLI credentials file"

[[steps]]
title = "Restart OpenClaw"
target = "openclaw"
restart = true
```

---

## Enable flow

```
Frontend → POST /vault/services/add → vault stores secret
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
        → step 1: run command (target = safeclaw)
        → step 2: forward to upstream (target = upstream:default)
      → return output of step marked returns = true
```

---

## Vault partial read

`POST /vault/credentials` supports an optional `select` field for returning only matching subtrees instead of the full vault.

```json
{ "userKey": "...", "select": "services.telegram,channels.telegram" }
```

| Aspect | Detail |
|--------|--------|
| Format | Comma-separated dot-notation path prefixes |
| Semantics | OR (union) — "services.telegram,model" returns both |
| Default | Omit `select` → full vault (backward compatible) |
| Structure | Returned JSON preserves the original path hierarchy |

The VM decrypts the full vault in memory, extracts matching subtrees, re-encrypts the subset, and zeros out the plaintext. This enables per-service credential reveal without exposing the entire vault.

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
- **CLI first.** Recipe steps prefer `openclaw config set` / `openclaw plugins install` over direct file manipulation. Use the same CLI commands a human would use.
- **Declarative over imperative.** TOML definitions, not Rust code per service.
- **Single source of truth.** `service.toml` = runtime; `recipe.toml` = setup. No God functions translating vault state — each service's recipe declares its own setup.
- **Explicit over implicit.** Every `[[api]]` declares its steps and target. No default forwarding; catch-all requires `path = "*"`.
- **Upstream is a reusable module.** Named `[[upstream]]` blocks are referenced by `target = "upstream:<id>"`, not inlined per API.
- **Vault stores only user-specific data.** Auth credentials, generated tokens, and per-user config live in the vault. Service definitions (auth types, upstream URLs, policies) live in TOML. `[[vault]]` declarations make the schema explicit.
- **Locked response is a plain string.** The proxy wraps it into the appropriate API format automatically.
- **SafeClaw manages openclaw lifecycle.** Recipe steps use `openclaw config set` with `gateway.reload.mode off` to batch config changes, then explicitly `restart = true` at the end. This prevents race conditions from openclaw auto-restarting on each config write. SafeClaw is the orchestrator; openclaw is the managed runtime.

---

## Migration from v1

| v1 | v2 | Notes |
|----|-----|-------|
| `[upstream]` singleton | `[[upstream]]` array with `id` | Supports multiple upstreams per service |
| `upstream.type = "local"` | No `[[upstream]]`; use `target = "safeclaw"` in `[[api.steps]]` | Local exec is a step target, not an upstream type |
| `upstream.type = "proxy"` | `[[upstream]]` with `url` | Proxy is defined by having a URL |
| `[[upstream.apis]]` | `[[api]]` with `[[api.steps]]` | APIs are top-level; steps replace inline command |
| `upstream.locked.template` + `upstream.locked.routes` | `upstream.locked.response` (plain text) | Single string; proxy auto-formats per API type |
| `[openclaw]` in recipe.toml | Removed | `models` removed from protocol (frontend-only concern); `plugin`/`api`/`env_key`/`proxy_path` either moved to `[[steps]]` or handled by runtime |
| Implicit catch-all (no `[[api]]` = forward all) | Explicit `[[api]] path = "*"` | All forwarding must be declared |
| `command` in `[[upstream.apis]]` | `run` in `[[api.steps]]` | Unified with recipe step vocabulary |
| `target` optional (default "openclaw") | `target` required on every step | Self-documenting; no hidden defaults |
