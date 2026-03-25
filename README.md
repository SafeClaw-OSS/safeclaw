# SafeClaw

Passkey-encrypted credential vault and proxy for AI agents.

SafeClaw protects your API keys behind WebAuthn passkeys and P-256 ECIES encryption. Your agent talks to a local proxy that injects credentials on-the-fly — no plaintext keys in config files, no passwords, no browser extensions.

## How it works

```
Your AI Agent → SafeClaw Proxy (localhost:23295) → OpenAI / Anthropic / etc.
                      ↑
              Injects API key from encrypted vault
              (unlocked via your passkey)
```

1. **Setup** — Register a passkey and store your API keys. Keys are encrypted with a key derived from your biometric (WebAuthn PRF).
2. **Unlock** — Tap your passkey to decrypt the vault and activate the proxy.
3. **Use** — Point your agent at `localhost:23295/{service}/v1`. The proxy injects auth headers transparently.
4. **Lock** — Tap again to wipe keys from memory. The proxy returns a friendly "vault locked" message until you unlock.

## Install

### Download binary

```bash
# Linux x86_64
curl -fsSL https://github.com/xhyumiracle/safeclaw/releases/latest/download/safeclaw-linux-x86_64 -o safeclaw
chmod +x safeclaw
```

### Build from source

```bash
git clone https://github.com/xhyumiracle/safeclaw.git
cd safeclaw
cargo build --release
# Binary at target/release/safeclaw (~3.6MB)
```

## Quick start

```bash
# Start SafeClaw
./safeclaw

# Open browser to setup
open http://localhost:23294/admin/setup
```

Register your passkey, add API keys, done. Then configure your agent:

```yaml
# Example: OpenClaw config
providers:
  openai:
    baseUrl: http://localhost:23295/openai/v1
    apiKey: sk-dummy  # SafeClaw injects the real key
```

## Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--data-dir` | `SAFECLAW_DATA` | `./data` | Vault storage directory |
| `--port` | `SAFECLAW_PORT` | `23294` | Admin server port |
| `--proxy-port` | `SAFECLAW_PROXY_PORT` | `23295` | Proxy port |
| `--proxy-bind` | `SAFECLAW_PROXY_BIND` | `127.0.0.1` | Proxy bind address |
| `--origin` | `SAFECLAW_ORIGIN` | `http://localhost:{port}` | Expected WebAuthn origin |
| `--rp-id` | `SAFECLAW_RP_ID` | `localhost` | WebAuthn relying party ID |
| `--admin-url` | `SAFECLAW_ADMIN_URL` | `http://localhost:{port}` | URL shown in locked responses |
| `--rate-limit` | `SAFECLAW_RATE_LIMIT` | `20` | Requests/min per IP (0 = off) |
| `--on-setup-hook` | `SAFECLAW_ON_SETUP_HOOK` | — | Webhook URL for setup `config` data |
| `--init` | — | — | Generate keypair and exit (for deploy scripts) |

## API

### Public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (`{ status, locked, uptime, version }`) |
| GET | `/pk` | Server P-256 public key (JWK `{ pk: {...} }`) for E2E encryption |

### Admin (instance management)

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/admin/setup` | GET: setup page. POST: create vault + register passkeys |
| GET/POST | `/admin/unlock` | GET: unlock page. POST: decrypt vault → activate proxy |
| GET | `/admin` | Dashboard page |
| POST | `/admin/restart` | Lock vault + exit 0 (for systemd restart) |
| POST | `/admin/shutdown` | Lock vault + exit 1 |

### Vault (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/vault/lock` | Wipe keys from memory → deactivate proxy |
| POST | `/vault/credentials` | Read vault contents (encrypted response) |
| POST | `/vault/update` | Update stored secrets |

### Passkeys (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/passkeys/add` | Register a new passkey device |
| POST | `/passkeys/remove` | Remove a passkey device |

### Proxy

The proxy listens on port 23295 and forwards requests to upstream APIs, injecting credentials from the vault.

```
POST http://localhost:23295/openai/v1/chat/completions
→ Adds Authorization: Bearer sk-... header
→ Forwards to https://api.openai.com/v1/chat/completions
```

When locked, the proxy returns API-format-aware responses (OpenAI/Anthropic/SSE compatible) with a link to unlock.

## Crypto protocol

- **Key exchange**: P-256 ECDH + HKDF-SHA256 + AES-256-GCM
- **Vault encryption**: AES-256-GCM with HKDF-derived KEK from WebAuthn PRF output
- **WebAuthn**: P-256 ECDSA assertion verification with origin + rpId checks
- **Nonce**: In-memory HashSet with hourly rotation (replay protection)
- **Zeroize**: All key material zeroized on drop (Rust compiler guarantees)

### Wire formats

| Context | Format |
|---------|--------|
| E2E request | `{ epk: JWK, iv: base64, ct: base64 }` |
| Symmetric (vault, wrapped DEK) | `iv(12 bytes) \|\| ciphertext+tag` |
| E2E response | `{ sealed: base64 }` (symmetric format inside) |

### HKDF info strings

| Derivation | Info |
|------------|------|
| KEK (vault key encryption key) | `safeclaw-kek-v1` |
| E2E (request encryption) | `safeclaw-e2e` |
| Response encryption | `safeclaw-response-v1` |

## Setup webhook

For integration with external systems, SafeClaw can forward non-secret setup data via webhook.

The setup payload supports two data categories:
- **`secrets`** — Encrypted in vault. Never sent to webhook.
- **`config`** — Not stored in vault. Forwarded to `--on-setup-hook` URL.

```bash
./safeclaw --on-setup-hook http://localhost:8080/on-setup
```

Auth protocol fields (passkeys, userKeys, nonce, assertions) are used during setup and discarded.

## Security model

- **Zero plaintext at rest** — API keys encrypted with passkey-derived key
- **Zero trust server** — Server never sees user's key derivation material
- **Passkey-only auth** — No passwords, no tokens, no shared secrets
- **Memory isolation** — Proxy runs on separate port, vault keys zeroized on lock
- **Nonce replay protection** — Every authenticated request requires a fresh nonce

## Prior art

The JS version (`v0.2.x`) is preserved at the `legacy/js` git tag. The Rust rewrite (`v0.3.0+`) is wire-compatible with the original browser client (`safeclaw-client.js`).

## License

MIT
