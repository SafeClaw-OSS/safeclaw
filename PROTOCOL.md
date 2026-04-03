# SafeClaw Service Protocol

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
      recipe.toml               # Recipe-only (no proxy)
      [custom code/binary]      # Optional: service-specific bridge
    ...
```

## service.toml

Defines how a service behaves at runtime: identity, upstream connection, and access policy.

### `[service]` — Identity

```toml
[service]
id = "openai"                   # Machine identifier (vault key, proxy route). Required.
name = "OpenAI"                 # Human-readable name. Required.
sub = "API Key"                 # Short tagline (card subtitle, tab label). Required.
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
pathExact = "/v1/models"        # Exact path match. Mutually exclusive with pathSuffix.
level = "allow"

[[policy.rules]]
method = "DELETE"
pathSuffix = "/admin"           # Suffix path match.
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
requires_credential = true      # Whether vault credential is needed. Default: true.
```

### `[openclaw]` — OpenClaw runtime integration

```toml
[openclaw]
plugin = "anthropic"            # OpenClaw plugin name (for plugins.allow)
api = "anthropic-messages"      # OpenClaw provider API type
env_key = "ANTHROPIC_API_KEY"   # Environment variable for API key marker
env_base_url = "ANTHROPIC_BASE_URL"
proxy_path = "/anthropic/v1"    # SafeClaw proxy path

[[openclaw.models]]             # Available models (id + display name)
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
cwd = "openclaw"                        # Working directory. Optional.
note = "Requires Node.js 18+"          # Additional note. Optional.
restart = true                          # Restart OpenClaw after this step. Optional.
target = "openclaw"                     # openclaw | safeclaw. Default: openclaw.

[[steps]]
title = "Create account config"
files = [                               # Files to create. Optional.
  { path = "accounts.json", content = '["safeclaw"]' },
  { path = "accounts/safeclaw.json", template = "weixin-account" },
]

[[steps]]
title = "Enable channel"
config_patches = [                      # OpenClaw config changes. Optional.
  { path = "channels.openclaw-weixin.enabled", value = true },
]
```

**`target` field**: Controls which environment executes the step.

| Value | Description |
|-------|-------------|
| `openclaw` | Executed on the OpenClaw/agent side (default). Sent to provisioner via webhook. |
| `safeclaw` | Executed on the SafeClaw vault machine locally. Used for local service dependencies (e.g., CLI tools). |

Steps without `target` default to `openclaw` for backward compatibility. NL-Cooker (`safeclaw connect`) prints all steps with their target noted.

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
- **No hidden protocols**: every field has one clear meaning; grouping is explicit via `group`
- **Backward-compatible extension**: new fields can be added to any section without breaking existing definitions
- **Separation of concerns**: `[service]` = identity, `[upstream]` = connection, `[policy]` = access control
