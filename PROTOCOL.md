# SafeClaw Service Protocol

**Protocol version: 1** — Breaking changes require a version bump and migration notes.

This document defines the declarative service protocol used by SafeClaw. Each service is a folder in `services/{category}/{id}/` containing TOML definition files.

## File structure

```
services/
  llm/                          # LLM providers
    anthropic/
      service.toml              # Runtime interface definition
      recipe.toml               # First-time installation instructions
    openai/
    openai-codex/
    ...
  channel/                      # Messaging channels
    telegram/
    weixin/
  integration/                  # Apps, tools, CLI services
    github/
    nodpay/
      service.toml              # Local CLI bridge (type = "local")
      recipe.toml               # Install steps (target = "safeclaw")
    ...
```

## service.toml

Defines how a service behaves at runtime: identity, upstream connection, and access policy.

### `[service]` — Identity

```toml
[service]
id = "openai"                   # Machine identifier (vault key, proxy route). Required.
name = "OpenAI"                 # Human-readable name. Required.
sub = "API Key"                 # Short tagline (card subtitle, tab label). Optional.
category = "llm"                # llm | channel | integration. Required.
group = "openai"                # UI merge key. Services with the same group value
                                # are displayed as one card with multiple auth tabs.
                                # Optional — omit for standalone services.
```

**`group` semantics**: If `openai-codex` has `group = "openai"`, the frontend merges it into the `openai` card. The group value must match the `id` of an existing service. Both the parent and variant should declare `group` explicitly.

### `[upstream]` — How to reach the service

Two types: `proxy` (forward HTTP to remote URL) and `local` (execute commands locally).

#### Proxy type (default)

```toml
[upstream]
url = "https://api.openai.com"  # Upstream base URL. Required for proxy.
                                # type = "proxy" is the default; can be omitted.
```

#### Local type

```toml
[upstream]
type = "local"                  # Service runs locally, not proxied.

[[upstream.apis]]               # Sub-API declarations. One per endpoint.
method = "POST"
path = "/sign"
command = "npx nodpay sign"     # Command to execute. Request body is piped to stdin.
                                # Stdout is returned as the HTTP response body.

[[upstream.apis]]
method = "GET"
path = "/address"
command = "npx nodpay address"
```

Local services can also be implemented as custom binaries. Place the source code in the service folder; the `recipe.toml` handles building/installing it. The `command` in `[[upstream.apis]]` simply invokes the installed binary.

### `[upstream.auth]` — Credential injection (proxy only)

```toml
[upstream.auth]
type = "bearer"                 # bearer | basic | header | query | path | oauth2
key_placeholder = "sk-..."     # Input hint for UI. Optional.

# Type-specific fields:
# header:  header = "x-api-key"
#          prefix = "Bearer "       (optional, prepended to secret value)
# query:   param = "key"
# basic:   username_label = "Account SID"
# oauth2:  oauth_style = "json" | "form" (default: form)
#          provider = "google" (for shared OAuth flows)
# path:    (pathTemplate is set in vault, not here)
```

### `[upstream.headers]` — Custom header injection (proxy only)

```toml
[upstream.headers]
"anthropic-beta" = "oauth-2025-04-20"
"x-session-id" = "{{uuid_v4}}"
"chatgpt-account-id" = "{{auth.account_id}}"
```

**Template variables** (resolved per-request):
- `{{uuid_v4}}` — random UUID v4
- `{{auth.<field>}}` — value from the service's auth config (e.g., `account_id`, `client_id`)

Static strings (no `{{`) are passed through as-is.

Headers are only injected for OAuth2 services with a resolved bearer token. API-key services use standard auth injection and skip custom headers.

### `[upstream.locked]` — Vault-locked response (proxy only)

```toml
[upstream.locked]
template = "openai"             # Template name. Built-in: anthropic, openai,
                                # openai-responses, gemini.

[upstream.locked.routes]        # Path-based template overrides. Optional.
"/responses" = "openai-responses"
```

When the vault is locked, the proxy returns an API-format-aware error response using the named template. If no template matches, a generic JSON error is returned.

### `[policy]` — Access control

```toml
[policy.levels]
read = "allow"                  # Default read access level
write = "allow"                 # Default write access level

# Access levels: allow | ask | ask-always | deny
#   allow      — immediate, no approval needed
#   ask        — approve once, cache for session
#   ask-always — approve every request
#   deny       — block unconditionally
```

### `[[policy.rules]]` — Per-request rule overrides

```toml
[[policy.rules]]
method = "GET"                  # HTTP method to match. Optional (matches all if omitted).
path_exact = "/v1/models"        # Exact path match. Mutually exclusive with path_suffix.
level = "allow"

[[policy.rules]]
method = "DELETE"
path_suffix = "/admin"           # Suffix path match.
level = "ask-always"
```

Rules are evaluated most-specific-first. A matching rule overrides the service-level access levels.

**Future extensibility**: Additional match fields (e.g., `body_contains`, `header_match`) can be added to rules without protocol changes. Existing rules without these fields continue to work.

## recipe.toml

Defines first-time installation instructions. Consumed by:
- **NL-Cooker** (`safeclaw connect <id>`) — renders as human-readable steps
- **Provisioner** (pro) — executes automatically

### `[recipe]` — Metadata

```toml
[recipe]
id = "weixin"
display_name = "WeChat iLink"
```

Whether a service needs vault credentials is derived from `service.toml` — if `[upstream.auth]` exists, credentials are required.

### `[openclaw]` — OpenClaw runtime integration

```toml
[openclaw]
plugin = "anthropic"            # OpenClaw plugin name (for plugins.allow). Optional.
api = "anthropic-messages"      # OpenClaw provider API type. Optional.
env_key = "ANTHROPIC_API_KEY"   # Environment variable for API key marker. Optional.
env_base_url = "ANTHROPIC_BASE_URL"  # Environment variable for base URL. Optional.
proxy_path = "/anthropic/v1"    # SafeClaw proxy path. Optional.

[[openclaw.models]]             # Available models (id + display name). Optional.
id = "claude-sonnet-4-20250514"
name = "Claude Sonnet 4"
```

### `[passkey_sharing]` — Cross-origin passkey access

```toml
[passkey_sharing]
enabled = true
origins = ["https://nodpay.ai"]
```

Configures `/.well-known/webauthn` to allow external origins to use passkeys registered on this SafeClaw instance.

### `[[steps]]` — Installation steps

```toml
[[steps]]
title = "Install WeChat plugin"         # Step title. Required.
description = "Detailed explanation"    # Optional.
run = "npm install @tencent-weixin/openclaw-weixin@latest"  # Shell command. Optional.
cwd = "openclaw"                        # Working directory for `run`. Optional.
note = "Requires Node.js 18+"          # Additional note. Optional.
restart = true                          # Restart OpenClaw after this step. Optional.
target = "openclaw"                     # openclaw | safeclaw. Required.

[[steps]]
title = "Create account config"
target = "openclaw"
files = [                               # Files to create. Optional.
  { path = "accounts.json", content = '["safeclaw"]' },
  { path = "accounts/safeclaw.json", template = "weixin-account.json" },
]

[[steps]]
title = "Enable channel"
target = "openclaw"
config_patches = [                      # Config changes (dot-path notation). Optional.
  { path = "channels.openclaw-weixin.enabled", value = true },
]
```

**`target` field** (required): Controls which environment executes the step.

| Value | Description |
|-------|-------------|
| `openclaw` | Executed on the OpenClaw/agent side. Sent to provisioner via webhook. |
| `safeclaw` | Executed on the SafeClaw vault machine locally. Used for local service dependencies (e.g., CLI tools). |

**`files` field**: Creates files on the target environment.

| Sub-field | Description |
|-----------|-------------|
| `path` | Destination file path. Required. |
| `content` | Inline file content (string). Mutually exclusive with `template`. |
| `template` | File name (with extension) within the same service folder (e.g., `"weixin-account.json"` resolves to `services/channel/weixin/weixin-account.json`). Mutually exclusive with `content`. |

**`config_patches` field**: Applies key-value changes to the OpenClaw config file.

`path` uses **dot-separated notation** for nested JSON keys: `channels.openclaw-weixin.enabled` sets `config["channels"]["openclaw-weixin"]["enabled"]`. `value` can be any JSON-compatible type (bool, string, number, object).

**Template variables** (resolved at execution time in string values):

| Variable | Description |
|----------|-------------|
| `{{proxy_port}}` | SafeClaw proxy port (default: 23295) |
| `{{admin_port}}` | SafeClaw admin port (default: 23294) |
| `{{admin_url}}` | SafeClaw admin URL (e.g., `http://localhost:23294`) |
| `{{service_id}}` | Current service ID |

Template variables can appear in `run`, `content`, `path`, and `config_patches` values. NL-Cooker prints them as-is (placeholders); `dispatch_cook` substitutes real values at execution time.

## Enable flow

Enabling a service (built-in or custom) follows a single unified path:

```
Frontend → POST /vault/services/add → vault stores secret
         → dispatch_cook(secrets)
           → builds ops from vault state + recipe steps
           → POST /cook to cooker endpoint
           → cooker executes ops (file write, config, exec, etc.)
```

**Built-in services**: `service.toml` and `recipe.toml` come from the compiled TOML registry. The frontend only sends the secret (API key, OAuth tokens, etc.).

**Custom services**: The frontend sends the full definition inline:

```json
{
  "name": "my-custom-service",
  "service": { "upstream": { "url": "...", "auth": { "type": "bearer" } } },
  "recipe": { "steps": [...] },
  "secret": { "key": "sk-..." }
}
```

Fields `service` and `recipe` are optional — omit for built-in services. The vault stores whatever the frontend sends; `dispatch_cook` merges built-in TOML with vault data.

**Equivalences**:
- `enable(service)` = `vault.store(service)` + `cook(recipe.steps)`
- `setup` = batch enable all services = single `dispatch_cook` with merged ops

### Cook ops

Recipe steps are translated into cook ops sent to the cooker:

| Recipe field | Cook op type | Description |
|--------------|-------------|-------------|
| `files` | `file` | Write file at `path` (relative to `~/.openclaw/`) with `content` |
| `config_patches` | `config` | Deep-merge patch into `openclaw.json` |
| `run` | `exec` | Execute shell command in openclaw environment |

File paths in cook ops are relative to the openclaw home directory (`~/.openclaw/`). The cooker resolves them to host-side paths.

## Adding a new service

1. Create a folder: `services/{category}/{id}/`
2. Write `service.toml` (if the service needs proxy or local handler)
3. Write `recipe.toml` (if the service needs installation steps)
4. Run `cargo build` — build.rs auto-discovers and compiles the TOML files
5. No Rust code changes needed

## Categories

| Category | Description | Examples |
|----------|-------------|---------|
| `llm` | LLM providers | anthropic, openai, google, deepseek, groq |
| `channel` | Messaging channels | telegram, weixin |
| `integration` | Apps, tools, APIs | github, gmail, nodpay, brave |

## Design principles

- **Declarative over imperative**: TOML definitions, not Rust code per service
- **Single source of truth**: service.toml defines runtime behavior; recipe.toml defines installation
- **Unified enable path**: built-in and custom services follow the same vault → dispatch_cook → cooker flow
- **Vault stores only secrets**: auth type, upstream URL, and other static config live in service.toml, not vault
- **No hidden protocols**: every field has one clear meaning; grouping is explicit via `group`
- **Backward-compatible extension**: new fields can be added to any section without breaking existing definitions
- **Separation of concerns**: `[service]` = identity, `[upstream]` = connection, `[policy]` = access control
