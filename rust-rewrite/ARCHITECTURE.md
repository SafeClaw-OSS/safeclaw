# SafeClaw Rust Architecture

## Overview
Single-binary credential isolation proxy with passkey-based vault encryption.
Rewrite of JS v0.2.15 reference implementation.

## Binary
- Static linked, ~5MB target
- `include_bytes!()` for all HTML/JS assets
- Single `safeclaw` binary, no runtime deps

## Crate Dependencies (minimal)
- `axum` + `tokio` — HTTP server + async runtime
- `p256` — P-256 ECDH key exchange
- `aes-gcm` — AES-256-GCM encryption
- `hkdf` + `sha2` — HKDF-SHA256 key derivation
- `ecdsa` + `p256` — ECDSA P-256 signature verification (WebAuthn)
- `zeroize` — compile-time guaranteed memory clearing
- `serde` + `serde_json` — JSON serialization
- `base64` — encoding
- `rand` — secure random generation

## API Routes (new path structure)

### Public (no auth)
- `GET  /health` — `{ status, locked, uptime, version }`
- `GET  /vm-pk` — server P-256 public key as JWK
- `POST /setup` — initial vault setup (first-time: no auth; overwrite: requires existing passkey)
- `GET  /` `/setup` `/unlock` `/admin` — static HTML pages

### Vault (passkey auth required)
- `POST /vault/unlock` — decrypt DEK → load secrets into proxy
- `POST /vault/lock` — clear secrets from memory
- `POST /vault/credentials` — return encrypted vault contents
- `POST /vault/update` — re-encrypt vault with new secrets

### Identity (passkey auth required)
- `POST /identity/add-passkey` — add new passkey credential
- `POST /identity/remove-passkey` — remove passkey (cannot remove last)

### System (passkey auth required)
- `POST /system/status` — vault status (basic without auth, full with auth)
- `POST /system/restart` — lock + exit 0
- `POST /system/shutdown` — lock + exit 1

## Auth Middleware (axum extractor)
All authenticated endpoints use a shared `AuthenticatedRequest` extractor:
1. Read E2E encrypted payload
2. ECIES decrypt (ephemeral P-256 ECDH + HKDF + AES-GCM)
3. Check nonce (in-memory HashSet with time-window rotation)
4. Load passkey (x, y) from passkeys.json
5. Verify WebAuthn assertion (P-256 ECDSA)
6. Return parsed payload + credential ID

## Crypto Protocol (unchanged from JS)
- **Envelope encryption**: DEK (random 32B) encrypts vault, KEK (derived) wraps DEK
- **KEK derivation**: `HKDF-SHA256(ikm=userKey, salt=vmSk.d, info="safeclaw-kek-v1")`
- **E2E transport**: ephemeral P-256 ECDH → `HKDF-SHA256(salt=zeros, info="safeclaw-e2e")` → AES-256-GCM
- **Response encryption**: `HKDF-SHA256(ikm=userKey, salt=nonce, info="safeclaw-response-v1")`
- **Wire format E2E**: `{ epk: JWK, iv: base64, ct: base64 }`
- **Wire format symmetric**: `iv(12) || ciphertext+tag`

## Nonce Storage
- In-memory `HashSet<[u8; 32]>` (not file-based)
- Time-window rotation: every 1 hour, swap current → previous, clear previous
- Two-set scheme: check both current and previous before accepting

## Proxy (locked response formats)
When locked, return API-format-aware responses:
- Anthropic Messages API (JSON + SSE)
- OpenAI Chat Completions (JSON + SSE)
- OpenAI Responses API (JSON + SSE)
- Google Gemini (JSON)
- Includes `safeclaw_unlock_url` for consumer rendering

## Static Assets
All HTML/JS files from `public/` embedded at compile time.
Served with `Content-Type` detection and `Cache-Control: no-cache`.

## Config
- `SAFECLAW_DATA` — data directory (default: `./data`)
- `SAFECLAW_PORT` — server port (default: 23294)
- `SAFECLAW_PROXY_PORT` — proxy port (default: 23295)
- `SAFECLAW_PROXY_BIND` — proxy bind address (default: 127.0.0.1)
- `SAFECLAW_ORIGIN` — expected WebAuthn origin
- `SAFECLAW_RP_ID` — WebAuthn relying party ID
- `SAFECLAW_ADMIN_URL` — URL shown in locked response
- `SAFECLAW_INSTANCE_ID` — optional instance identifier
- `--rate-limit N` — requests/min per IP (default: 20, 0=disabled)

## Module Structure
```
src/
  main.rs          — CLI args, startup, signal handling
  config.rs        — env/CLI config parsing
  crypto/
    mod.rs         — re-exports
    keys.rs        — VM keypair generation/loading (P-256)
    ecies.rs       — E2E encrypt/decrypt
    envelope.rs    — DEK/KEK/wrap/unwrap
    kdf.rs         — HKDF derivations (KEK, response key)
    aes.rs         — AES-256-GCM encrypt/decrypt
  auth/
    mod.rs         — AuthenticatedRequest extractor
    webauthn.rs    — assertion verification (P-256 ECDSA)
    nonce.rs       — nonce tracking (HashSet + rotation)
  server/
    mod.rs         — router setup
    routes.rs      — all endpoint handlers
    static_files.rs — embedded asset serving
  proxy/
    mod.rs         — proxy server
    locked.rs      — locked response generators (anthropic/openai/gemini)
    forward.rs     — upstream request forwarding
  state.rs         — shared app state (vault, proxy, config)
```
