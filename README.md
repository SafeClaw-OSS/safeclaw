# SafeClaw

Protect your API keys with passkeys. No passwords, no `.env` files, no plaintext secrets on disk.

SafeClaw is a local vault + proxy for AI agents. You store your API keys encrypted with your fingerprint (via WebAuthn passkeys), and your agent talks to a local proxy that injects credentials on-the-fly.

```
Your AI Agent → SafeClaw Proxy (localhost:23295) → OpenAI / Anthropic / Google
                      ↑
              Injects API key from encrypted vault
              (unlocked via your fingerprint)
```

## Why?

- **No plaintext keys** — API keys are encrypted at rest with your biometric
- **No passwords to remember** — unlock with Touch ID, Windows Hello, or a security key
- **No code changes** — point your agent at `localhost:23295` instead of the API directly
- **Single binary** — ~5MB, no runtime dependencies, runs anywhere

## Quick start

```bash
# Download
curl -fsSL https://github.com/xhyumiracle/safeclaw/releases/latest/download/safeclaw-linux-x86_64.tar.gz \
  | tar xz
chmod +x safeclaw

# Start
./safeclaw

# Open http://localhost:23294/admin/setup in your browser
# Register your passkey, paste your API keys, done.
```

Or build from source:

```bash
git clone https://github.com/xhyumiracle/safeclaw.git
cd safeclaw
cargo build --release
./target/release/safeclaw
```

Then point your agent at the proxy:

```yaml
# Example: agent config
services:
  openai:
    baseUrl: http://localhost:23295/openai/v1
    apiKey: sk-dummy  # SafeClaw injects the real key
```

```bash
# Or just set the base URL
export OPENAI_BASE_URL=http://localhost:23295/openai/v1
```

## Daily workflow

1. **Start** SafeClaw → open `http://localhost:23294/admin` (dashboard)
2. **Unlock** — tap your passkey to decrypt the vault and activate the proxy
3. **Work** — your agent uses the proxy transparently
4. **Lock** — tap again to wipe keys from memory (or just close SafeClaw)

## Services

SafeClaw uses a **declarative service protocol**. Services are organized by category in `services/`:

```
services/
  llm/                          # LLM providers
    anthropic/
      service.toml              # Runtime interface (upstream, auth, policy)
      recipe.toml               # First-time installation instructions
    claude-code/                # Claude Code OAuth variant
    openai/
    openai-codex/               # Codex OAuth variant
    google/
    deepseek/
    groq/
  channel/                      # Messaging channels
    telegram/
    weixin/
  integration/                  # Apps & tools
    github/
    brave/
    gmail/
    nodpay/                     # Local CLI bridge (type = "local")
    openclaw-dashboard/         # OpenClaw native dashboard
    ...
```

### service.toml — runtime interface definition

```toml
[service]
id = "anthropic"
name = "Anthropic"
sub = "API Key"
category = "llm"

[upstream]
url = "https://api.anthropic.com"

[upstream.auth]
type = "header"
header = "x-api-key"

[upstream.locked]
template = "anthropic"

[policy.levels]
read = "allow"
write = "allow"
```

### recipe.toml — first-time installation instructions

```toml
[openclaw]
plugin = "anthropic"
api = "anthropic-messages"
env_key = "ANTHROPIC_API_KEY"
env_base_url = "ANTHROPIC_BASE_URL"
proxy_path = "/anthropic/v1"

[[openclaw.models]]
id = "claude-sonnet-4-20250514"
name = "Claude Sonnet 4"
```

### Adding a new service

Create a folder in `services/` with a `service.toml`. No Rust code needed — the registry loads all definitions at startup.

For services that need installation steps (plugins, env vars, config patches), add a `recipe.toml`. Each step declares `target = "safeclaw"` or `target = "openclaw"` to specify which environment executes it.

### Connect a service (open-source)

```bash
# List available services
safeclaw connect

# Get step-by-step setup instructions for a service
safeclaw connect weixin
safeclaw connect nodpay
```

The `connect` command reads the service's `recipe.toml` and prints human-readable instructions for manual setup.

### Service protocol

See [PROTOCOL.md](PROTOCOL.md) for the full service.toml and recipe.toml specification, including auth types, header templates, policy rules, local service handlers, and step targets.

## Remote deployment

If you run SafeClaw on a remote server (not localhost), WebAuthn requires **HTTPS**. Put it behind a reverse proxy:

```bash
# Behind Caddy/nginx with TLS
./safeclaw \
  --origin https://safeclaw.example.com \
  --rp-id safeclaw.example.com
```

> `--origin` must exactly match the URL in your browser (e.g. `https://safeclaw.example.com`). `--rp-id` is just the hostname. If these are wrong, passkey auth will silently fail.

## Data & backup

SafeClaw stores everything in `./data` (or `--data-dir`):

```
data/
  sc_pk.jwk          # Server public key
  sc_sk.jwk          # Server private key (keep secret!)
  vault.enc          # Encrypted API keys
  passkeys.json      # Registered passkey metadata
  audit.db           # Audit log (SQLite)
  templates/         # Agent templates (safeclaw.md, skill.md, etc.)
```

**Backup**: Copy the entire `data/` directory. Your passkeys are tied to your device (biometric), but as long as you have the same passkey device, you can unlock the vault on any machine with the same `data/` directory.

**Permissions**: On shared machines, restrict access: `chmod 700 data/`

## Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--data-dir` | `SAFECLAW_DATA` | `./data` | Where vault data is stored |
| `--port` | `SAFECLAW_PORT` | `23294` | Admin UI port |
| `--bind` | `SAFECLAW_BIND` | `0.0.0.0` | Admin server bind address |
| `--proxy-port` | `SAFECLAW_PROXY_PORT` | `23295` | Proxy port (point your agent here) |
| `--proxy-bind` | `SAFECLAW_PROXY_BIND` | `127.0.0.1` | Proxy bind address |
| `--origin` | `SAFECLAW_ORIGIN` | `http://localhost:{port}` | WebAuthn origin (must match browser URL) |
| `--rp-id` | `SAFECLAW_RP_ID` | `localhost` | WebAuthn relying party ID (hostname only) |
| `--admin-url` | `SAFECLAW_ADMIN_URL` | `http://localhost:{port}` | URL shown in "vault locked" and approval responses |
| `--rate-limit` | `SAFECLAW_RATE_LIMIT` | `300` | Max requests/min per IP (0 = unlimited) |
| `--on-setup-hook` | `SAFECLAW_ON_SETUP_HOOK` | — | Webhook URL called after setup (POST /cook format) |
| `--init` | — | — | Generate server keypair and exit |

## CLI commands

```bash
safeclaw                    # Start the server
safeclaw connect            # List available services with recipes
safeclaw connect <service>  # Print setup instructions for a service
safeclaw update             # Full self-update (binary + templates)
safeclaw update --check     # Check for new version
safeclaw update --templates # Update templates only (hot reload)
```

---

## Architecture

```
src/
├── main.rs              # Entry point: starts admin server + proxy server
├── config.rs            # CLI flags & env var parsing
├── state.rs             # Shared application state (AppState, VaultState)
│
├── core/                # Core proxy engine
│   ├── router.rs        # Proxy request handler + routing
│   ├── forward.rs       # Upstream HTTP forwarding (reqwest)
│   ├── policy.rs        # Access policy evaluation (allow/deny/approve)
│   ├── approval.rs      # Human-in-the-loop approval flow
│   └── audit.rs         # SQLite audit log
│
├── service/             # TOML-driven service registry
│   ├── mod.rs           # ServiceRegistry: loads services/*/service.toml
│   └── locked.rs        # Locked-vault response templates (per API format)
│
├── auth/                # Service auth (upstream credential injection)
│   ├── mod.rs           # AuthConfig, ServiceConfig, inject_auth(), transform_url()
│   ├── bearer.rs        # Bearer token injection
│   ├── basic.rs         # HTTP Basic auth
│   ├── header.rs        # Custom header (x-api-key, etc.)
│   ├── query.rs         # Query parameter injection
│   ├── path.rs          # URL path injection
│   └── oauth2.rs        # OAuth2 token refresh (form + JSON styles)
│
├── passkey/             # User auth (WebAuthn passkey verification)
│   ├── mod.rs           # AuthenticatedRequest extractor, PasskeyEntry
│   ├── webauthn.rs      # ECDSA P-256 assertion verification
│   ├── challenge.rs     # Challenge store (TTL, single-use)
│   └── nonce.rs         # Replay-protection nonce store
│
├── crypto/              # Cryptographic primitives
│   ├── keys.rs          # P-256 keypair management (JWK)
│   ├── ecies.rs         # ECIES encrypt/decrypt (ECDH + AES-GCM)
│   ├── aes.rs           # AES-256-GCM
│   ├── kdf.rs           # HKDF-SHA256
│   ├── envelope.rs      # Sealed envelope format
│   └── zeroize.rs       # Zeroize-on-drop JSON values
│
├── server/              # Admin HTTP server
│   ├── routes.rs        # All admin/vault/passkey endpoints
│   └── static_files.rs  # Embedded static assets
│
├── notify/              # Push notifications
│   ├── mod.rs           # PushSubscription, PushKeys types
│   └── webpush.rs       # VAPID + ECE + WebPush delivery
│
├── cli/                 # CLI subcommands
│   ├── connect.rs       # NL-Cooker: safeclaw connect (setup instructions)
│   ├── generate.rs      # Workspace file generation (safeclaw.md, etc.)
│   └── update.rs        # Self-update from GitHub releases
│
└── services/            # Service protocol definitions (TOML)
    ├── llm/             # LLM providers
    │   ├── anthropic/   #   service.toml + recipe.toml
    │   ├── claude-code/ #   Claude Code OAuth variant
    │   ├── openai/
    │   ├── openai-codex/
    │   ├── google/
    │   ├── deepseek/
    │   └── groq/
    ├── channel/         # Messaging channels
    │   ├── telegram/
    │   └── weixin/
    └── integration/     # Apps & tools
        ├── github/
        ├── nodpay/      #   recipe.toml only
        └── openclaw-dashboard/
```

## Technical details

<details>
<summary>API reference</summary>

### Public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | `{ status, locked, uptime, version }` |
| GET | `/pk` | Server P-256 public key (JWK) |
| GET | `/challenge` | Issue replay-protection challenge (TTL 5min, single-use) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/admin/setup` | Setup page / create vault |
| GET/POST | `/admin/unlock` | Unlock page / decrypt vault |
| GET | `/admin` | Dashboard |
| GET | `/admin/safeclaw.md` | Generated workspace doc listing proxy URLs |
| GET | `/admin/agents-snippet` | AGENTS.md snippet for agent workspace |
| POST | `/admin/upgrade` | Trigger self-update via provisioner (authenticated) |

### Vault (authenticated via passkey + ECIES)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/vault/lock` | Wipe keys from memory |
| POST | `/vault/update` | Update stored secrets |
| POST | `/vault/credentials` | Get encrypted credential for a passkey |

### Services (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vault/services` | List configured services (names only, no auth) |
| POST | `/vault/services/add` | Add a service (name, upstream, auth config) |
| POST | `/vault/services/update` | Update service config |
| POST | `/vault/services/remove` | Remove a service |

### Proxy (port 23295)

| Method | Path | Description |
|--------|------|-------------|
| ANY | `/health` | Proxy health check |
| ANY | `/{service}/{*path}` | Forward to upstream (requires unlocked vault) |

### Approvals

| Method | Path | Description |
|--------|------|-------------|
| GET | `/approve/pending` | List pending approval requests |
| GET | `/approve/{id}` | Get approval info / poll result |
| POST | `/approve/{id}/details` | Decrypt request details (authenticated) |
| POST | `/approve/{id}/confirm` | Approve request (authenticated) |
| POST | `/approve/{id}/reject` | Reject request (authenticated) |

> **Note:** "authenticated" endpoints require ECIES-encrypted payloads with passkey assertion.

</details>

<details>
<summary>Crypto protocol</summary>

- **Key exchange**: P-256 ECDH + HKDF-SHA256 + AES-256-GCM
- **Vault encryption**: AES-256-GCM with KEK derived from WebAuthn PRF output
- **Auth**: P-256 ECDSA assertion verification with origin + rpId checks
- **Replay protection**: Nonce-based (in-memory, hourly rotation)
- **Memory safety**: All key material zeroized on drop (Rust compiler guarantees)

### Wire formats

| Context | Format |
|---------|--------|
| E2E request | `{ epk: JWK, iv: base64, ct: base64 }` |
| Symmetric (vault) | `iv(12B) \|\| ciphertext+tag` |
| E2E response | `{ sealed: base64 }` |

### HKDF info strings

| Derivation | Info |
|------------|------|
| PRF normalization (client) | `safeclaw-user-key` |
| KEK | `safeclaw-kek-v1` |
| E2E request | `safeclaw-e2e` |
| E2E response | `safeclaw-response-v1` |

</details>

## License

Apache 2.0 — see [LICENSE](LICENSE)
