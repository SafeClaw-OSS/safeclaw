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
- **Single binary** — ~4MB, no runtime dependencies, runs anywhere

## Quick start

```bash
# Download (or build from source: cargo build --release)
curl -fsSL https://github.com/xhyumiracle/safeclaw/releases/latest/download/safeclaw-linux-x86_64 -o safeclaw
chmod +x safeclaw

# Start
./safeclaw

# Open http://localhost:23294/admin/setup in your browser
# Register your passkey, paste your API keys, done.
```

Then point your agent at the proxy:

```yaml
# Example: OpenClaw config
providers:
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

## Supported services

The proxy routes requests by path prefix and injects the appropriate auth:

| Your agent calls | SafeClaw forwards to | Auth injected |
|------------------|----------------------|---------------|
| `localhost:23295/openai/v1/...` | `api.openai.com/v1/...` | `Authorization: Bearer` |
| `localhost:23295/anthropic/v1/...` | `api.anthropic.com/v1/...` | `x-api-key` |
| `localhost:23295/google/v1beta/...` | `generativelanguage.googleapis.com/...` | `x-goog-api-key` |

When locked, the proxy returns a friendly API-compatible error (works with OpenAI/Anthropic SDKs) with a link to unlock.

## Remote deployment

If you run SafeClaw on a remote server (not localhost), WebAuthn requires **HTTPS**. Put it behind a reverse proxy:

```bash
# Behind Caddy/nginx with TLS
./safeclaw \
  --origin https://safeclaw.example.com \
  --rp-id safeclaw.example.com
```

> ⚠️ `--origin` must exactly match the URL in your browser (e.g. `https://safeclaw.example.com`). `--rp-id` is just the hostname. If these are wrong, passkey auth will silently fail.

## Data & backup

SafeClaw stores everything in `./data` (or `--data-dir`):

```
data/
  sc_pk.jwk          # Server public key
  sc_sk.jwk          # Server private key (keep secret!)
  vault.enc          # Encrypted API keys
  passkeys.json      # Registered passkey metadata
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
| `--admin-url` | `SAFECLAW_ADMIN_URL` | `http://localhost:{port}` | URL shown in "vault locked" responses |
| `--instance-id` | `SAFECLAW_INSTANCE_ID` | — | Optional instance identifier (included in health/webhook responses) |
| `--rate-limit` | `SAFECLAW_RATE_LIMIT` | `20` | Max requests/min per IP (0 = unlimited) |
| `--on-setup-hook` | `SAFECLAW_ON_SETUP_HOOK` | — | Webhook URL for non-secret setup data |
| `--init` | — | — | Generate server keypair and exit |

## Build from source

```bash
git clone https://github.com/xhyumiracle/safeclaw.git
cd safeclaw
cargo build --release
# Binary at target/release/safeclaw
```

---

## Technical details

<details>
<summary>API reference</summary>

### Public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | `{ status, locked, uptime, version }` |
| GET | `/pk` | Server P-256 public key (JWK) |
| GET | `/challenge` | Issue replay-protection challenge (TTL 5min, single-use, 60/min/IP) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/admin/setup` | Setup page / create vault |
| GET/POST | `/admin/unlock` | Unlock page / decrypt vault |
| GET | `/admin` | Dashboard |
| POST | `/admin/shutdown` | Lock vault + exit (process manager handles restart) |
| GET | `/admin/safeclaw.md` | Generated workspace doc listing proxy URLs |
| GET | `/admin/agents-snippet` | AGENTS.md snippet with URL rewrite rules |

### Vault (authenticated via passkey + ECIES)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/vault/lock` | Wipe keys from memory |
| POST | `/vault/credentials` | Read vault contents |
| POST | `/vault/update` | Update stored secrets |

### Services (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vault/services` | List configured services (names only) |
| POST | `/vault/services/add` | Add a service (name, upstream, auth config) |
| POST | `/vault/services/update` | Update service config |
| POST | `/vault/services/remove` | Remove a service |

### Policy

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vault/policy` | Get policy defaults (no auth) |
| POST | `/vault/policy/update` | Update policy defaults (authenticated) |

### Files (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/vault/files` | List stored files (names + metadata, no auth) |
| POST | `/vault/files/upload` | Encrypt and store a file |
| POST | `/vault/files/read` | Decrypt and download a file |
| POST | `/vault/files/remove` | Delete a file |

### Notifications

| Method | Path | Description |
|--------|------|-------------|
| POST | `/vault/notifications/subscribe` | Store push subscription (authenticated) |
| GET | `/notifications` | Poll + clear pending notifications (no auth) |

### Approvals

| Method | Path | Description |
|--------|------|-------------|
| GET | `/approve/pending` | List pending approval requests (no auth) |
| GET | `/approve/{id}` | Get approval info (no auth) |
| GET | `/approve/{id}/status` | Get approval status (no auth) |
| POST | `/approve/{id}/details` | Decrypt request details (authenticated) |
| POST | `/approve/{id}/confirm` | Approve request (authenticated) |
| POST | `/approve/{id}/reject` | Reject request (authenticated) |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/audit/log?limit=50` | Recent audit entries (no auth, zero sensitive data) |

### Proxy

| Method | Path | Description |
|--------|------|-------------|
| ANY | `/health` | Proxy health check (`{ status, locked, version }`) |
| ANY | `/{service}/{*path}` | Forward to upstream (requires unlocked vault) |

### Passkeys (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/passkeys/add` | Add a passkey device |
| POST | `/passkeys/remove` | Remove a passkey device |

> **Note:** "authenticated" endpoints require ECIES-encrypted payloads with passkey assertion.
> "no auth" endpoints expose only non-sensitive metadata.
> Process lifecycle (restart/stop) is managed by your process supervisor (systemd, Docker, etc.).

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

<details>
<summary>Setup webhook</summary>

For integration with external systems, SafeClaw can forward non-secret setup data via webhook:

```bash
./safeclaw --on-setup-hook http://localhost:8080/on-setup
```

The setup payload has two categories:
- **`secrets`** — Encrypted in vault. **Never** sent to webhook.
- **`config`** — Not stored in vault. Forwarded to the webhook URL.

</details>

## License

MIT — see [LICENSE](LICENSE)
