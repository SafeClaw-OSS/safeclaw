# SafeClaw — System Design

> **⚠️ PARTIALLY SUPERSEDED (2026-07-03 phantom-only pivot).** The **proxy data
> plane** described below — the `/use` forward-proxy, base-URL rewriting, the
> `[[api]]` multi-step engine, and the two-port model with **Admin 23294 /
> Proxy 23295** — is retired. Canon for credential flow = the resident
> phantom-only local HTTPS proxy in [docs/CREDENTIAL_BROKER.md](./docs/CREDENTIAL_BROKER.md).
> Ports are now **control/API 23295 (`CONTROL_PORT`) / credential proxy 23294
> (`PROXY_PORT`)** — swapped from what this doc shows. The crypto primitives,
> vault state machine, passkey/auth boundary, sync, and op/approval flow remain
> accurate.

**Audience.** This document is the canonical design reference for the open-source `safeclaw` Rust binary. It is written for two readers:

1. A future contributor who needs to understand what the system does and why each piece exists.
2. A separate agent extracting content for the SUDP paper (`safeclaw-paper/`). Section 16 maps the implementation onto the paper's $U/R/T/E$ vocabulary so claims can be transferred without re-deriving them.

**What this doc covers.** Process layout, trust boundary, on-disk artifacts, cryptographic primitives as actually implemented, the vault state machine, authentication paths, the proxy data plane, the policy engine, the approval flow, the service registry, lifecycle endpoints, and the multi-step API engine.

**What it does not cover.**

- Service protocol TOML schema — see [PROTOCOL.md](PROTOCOL.md).
- SafeClaw Pro infrastructure (relay, dashboard iframe, console).
- Front-end (`safeclaw-pro-frontend/`) and console backend (`safeclaw-pro-backend/`).
- Aspirational cryptographic features (per-write DEK rotation, per-credential PRF salt) drafted in `safeclaw-protocol/PROTOCOL.md` — those are **not** in the current binary; current state is documented in §4–5 of this file, and gaps versus that draft are summarized in §18.

Code references use `path:line` and refer to the tree at `safeclaw/`.

---

## 1. Purpose and non-goals

### 1.1 Purpose

SafeClaw is a single Rust binary that runs on the user's machine (or a user-controlled VM) and does two things at once:

- **Custodian.** Holds long-lived API keys, OAuth refresh tokens, and per-service config encrypted at rest, unlockable only via a WebAuthn passkey. Plaintext exists in process memory only between unlock and lock.
- **Proxy.** Exposes a localhost HTTP endpoint (default `:23295`) that an agent points at instead of provider URLs (OpenAI, Anthropic, GitHub, Telegram, …). The proxy parses the first path segment as a service name, looks up the service's vault config, evaluates an access policy, optionally interrupts for human approval, then forwards the request with the credential injected.

The agent never holds, sees, or transmits the secret. Its only handle to the secret is the ability to *cause uses* of it via the proxy, subject to policy.

### 1.2 Non-goals

- **Not a TEE.** When the vault is unlocked, plaintext credentials and the DEK live in process memory. A coresident adversary who can read this process's memory (root, a debugger, `/proc/$pid/mem`) gets everything.
- **Not a multi-tenant secret manager.** A single SafeClaw instance is operated by one user (one passkey or a small set of co-equal passkeys for that user).
- **Not a transport-layer crypto scheme.** Confidentiality on the wire is delegated to TLS for remote deployments and to the loopback assumption for local. The application-layer ECIES envelope (§7.1) is for *authentication payload integrity*, not transport confidentiality.
- **Not a key custody service for arbitrary apps.** Only services declared via `service.toml` are reachable; the proxy refuses unknown service names.

### 1.3 Two ports, one process

`main.rs:160-186` binds two listeners served from the same process:

| Port | Default | Bind | Purpose |
|------|---------|------|---------|
| Admin | 23294 | `0.0.0.0` | Setup / unlock / lock / passkey management / approval console / static UI |
| Proxy | 23295 | `127.0.0.1` | Agent-facing forward-proxy, gated by policy and approval |

Splitting the ports lets the proxy bind loopback-only while the admin UI stays reachable from a browser on the user's network. Both listeners share `AppState` (`state.rs:19-31`) so vault unlock/lock observed by either port is immediately visible to the other.

---

## 2. Trust boundary and threat model

The binary distinguishes four zones, in increasing order of distrust:

| Zone | Trusted? | Examples |
|------|----------|----------|
| Authenticator (FIDO2 hardware, platform passkey) | yes | Touch ID, YubiKey, Windows Hello |
| Browser/JS during an active SafeClaw page | partially trusted | rawPRF and userKey live briefly in JS memory |
| `safeclaw` process when unlocked | trusted while live; plaintext in RAM | DEK, full vault JSON |
| Disk (`data/`), network, other processes | untrusted | backups, cloud sync, sibling processes |

Adversaries explicitly handled:

- **One-shot or persistent disk leak** of `data/`. Cannot decrypt without the authenticator (DEK is wrapped with a KEK that requires PRF evaluation).
- **Stolen laptop.** Same as disk leak; passkey UV gates rawPRF emission.
- **Compromised agent.** Agent never has the credential. The worst it can do via the proxy is request operations within whatever policy the user has set; `ask` / `ask-always` rules force an out-of-band human approval before the credential is used.
- **Replay of authenticated admin requests.** Each request carries a `challenge` (server-issued, single-use, 5min TTL) or a `nonce` (client-generated, single-use, ≥16 bytes), both stored in-memory and consumed on use.

Out of scope:

- Memory-resident attacker on the SafeClaw host while unlocked.
- TLS-stripping MitM on a remote deployment without TLS.
- Compromise of the FIDO2 authenticator itself.
- Side channels on AES-GCM, ECDSA-P256, HKDF-SHA-256.

---

## 3. On-disk artifacts

Everything persistent lives under `--data-dir` (default `./data/`). The binary owns this directory and never reaches outside it.

| File | Format | Sensitivity | Written by |
|------|--------|-------------|------------|
| `sc_pk.jwk` | JWK public key | public | `crypto::keys::load_or_create_keypair` |
| `sc_sk.jwk` | JWK private key (P-256) | secret (server identity) | same |
| `vault.enc` | `iv(12) ‖ ct ‖ tag` (AES-256-GCM) | encrypted | `setup`, `vault_update` |
| `wrapped_dek_<credfile>.bin` | `iv(12) ‖ ct ‖ tag` wrapping a 32-byte DEK | encrypted | one per registered credential |
| `passkeys.json` | `{ credentialId → {x, y, deviceName, createdAt} }` | metadata only (public coords) | `setup`, `passkeys/add`, `passkeys/remove` |
| `audit.db` | SQLite (`audit_log`, `approvals`) | metadata only (no payloads) | `core::audit::AuditLog` |
| `index.json` | service & file metadata cache for offline UI | metadata only | `write_index` after vault writes |
| `files/<uuid>.enc` | per-file `iv ‖ ct ‖ tag` (same DEK as vault) | encrypted | `vault_files_upload` |

**`vault.enc` content (after decrypt).** A JSON object with these top-level keys (all optional except `services`):

- `services`: `{ name → { upstream?, auth?, levels?, rules?, rule_overrides?, category?, ... } }`. Per-service config used by the proxy.
- `policy_defaults`: global defaults for access levels, including per-category overrides (`type_levels`).
- `notifications.subscriptions` / `push_subscriptions`: Web Push subscriber set (consumed by the approval flow).
- `vapid_private_key`: server VAPID key for Web Push, generated at first setup or migrated in on first unlock.
- `files`: list of `{id, name, size}` for vault-stored files (data lives in `files/<id>.enc`).
- Service-defined keys (e.g. `wallet`, `gatewayToken`) declared by `[[vault]]` blocks in `service.toml`.

**Index leakage.** `index.json` is unencrypted and lists service names + categories + a few non-sensitive fields (e.g. wallet `safe` address). It exists so the static UI can render a stub before the user unlocks. It contains zero credentials.

---

## 4. Cryptographic primitives (as implemented)

All primitives live in `src/crypto/`. The implementation is intentionally narrow: one curve, one KDF, one AEAD, no negotiation.

| Primitive | Algorithm | Implementation |
|-----------|-----------|----------------|
| Asymmetric | ECDSA-P256 (signatures) + ECDH-P256 | `p256` crate, `crypto::keys` |
| KEM-equivalent | ECIES = ECDH-P256 + HKDF + AES-GCM | `crypto::ecies::e2e_decrypt` |
| KDF | HKDF-SHA-256 | `hkdf` crate, `crypto::kdf` |
| AEAD | AES-256-GCM (12-byte IV, 16-byte tag) | `aes-gcm` crate, `crypto::aes` |
| Hash | SHA-256 | `sha2` crate |
| RNG | OS CSPRNG | `rand::OsRng` / `rand::thread_rng` |
| Zeroization | `zeroize` crate, applied to `userKey`, `kek`, `dek`, response keys, `pending_deks`, `vapid.private_key`, vault plaintext on lock | `crypto::zeroize`, `vault.rs` |

### 4.1 HKDF info strings (domain separation)

Three derivations, each with a fixed `info` label (`crypto/kdf.rs`):

| Derivation | salt | ikm | info | output |
|------------|------|-----|------|--------|
| KEK | `sk_d` (server private key bytes, 32B) | `userKey` (PRF output, base64 from client) | `safeclaw-kek-v1` | 32B AES-256 KEK |
| E2E request | `[0u8; 32]` | ECDH shared secret | `safeclaw-e2e` | 32B AES-256 key |
| Response | `nonce` (from inner payload) | `userKey` | `safeclaw-response-v1` | 32B AES-256 key |

`sk_d` participates in the KEK as a *salt*, not a secret input — it provides cross-instance domain separation but does not contribute to confidentiality once `data/` is exfiltrated together with `vault.enc` and `wrapped_dek_*.bin`. This is a deliberate simplification (see §18 for the gap versus the per-credential `prf_salt` aspirational design).

### 4.2 ECIES wire format (`crypto::ecies`)

Used only for encrypting the *inner authenticated payload* sent from browser/CLI to the SafeClaw server.

```
{ "epk": <JWK P-256 public>, "iv": <base64 12B>, "ct": <base64 ciphertext + 16B tag> }
```

Decryption (server side):

1. Parse JSON.
2. Import ephemeral pk from JWK.
3. ECDH(server_sk, epk) → shared secret.
4. HKDF-SHA-256(salt = zero32, ikm = shared, info = `safeclaw-e2e`) → 32B key.
5. AES-256-GCM-decrypt(key, iv, ct) → plaintext.

Note: ECIES here is **not** used for transport confidentiality (TLS does that). It exists so the server can take an authenticated request even when the outer transport is HTTP loopback, and to keep the request payload integrity-protected end-to-end against any reverse-proxy in front (the relay in Pro deployments cannot tamper with `userKey` or assertions inside the envelope).

### 4.3 Zeroization policy

The codebase makes a credible effort to overwrite key material before drop:

- `Vault::lock()` zeroizes the JSON plaintext (`crypto::zeroize::zeroize_json_option`), VAPID private key, OAuth2 token cache, approval session cache (overwriting `auth` to `Null`), and `pending_deks`.
- Every per-request derived key (`kek`, `dek`, `response_key`, ECIES `aes_key`) is `Zeroize::zeroize`d after use.
- `pending_deks` (file-approval DEK stash) is keyed by approval ID and removed on consumption.

Limitations: serde-rs allocations and intermediate strings may not be zeroized (Rust's `String`/`Vec` re-allocation can leak past contents). This is documented as accepted residual exposure; the protocol does not claim memory-resident attacker resistance.

---

## 5. Key hierarchy

```
                 ┌──────────────────────────────┐
                 │ FIDO2 hmac-secret (PRF)      │  authenticator-bound, never extractable
                 │  per credential, per salt    │
                 └──────────────┬───────────────┘
                                │ user verification
                                ▼
                 ┌──────────────────────────────┐
                 │ rawPRF (32B)                 │  in browser memory only
                 └──────────────┬───────────────┘
                                │ HKDF (client-side)
                                ▼
                 ┌──────────────────────────────┐
                 │ userKey (32B)                │  travels in ECIES envelope
                 └──────────────┬───────────────┘
                                │ HKDF(salt = sk_d, info = safeclaw-kek-v1)
                                ▼
                 ┌──────────────────────────────┐
                 │ KEK (32B)                    │  per credential, ephemeral
                 └──────────────┬───────────────┘
                                │ AES-256-GCM unwrap
                                ▼
                 ┌──────────────────────────────┐
                 │ DEK (32B)                    │  random, generated at setup
                 └──────────────┬───────────────┘
                                │ AES-256-GCM
                                ▼
                 ┌──────────────────────────────┐
                 │ vault.enc plaintext (JSON)   │  full vault, in memory while unlocked
                 │ files/<id>.enc plaintext     │  same DEK encrypts each file
                 └──────────────────────────────┘
```

Independent server keypair `(sk_d, pk)` is generated at first run (`crypto::keys::load_or_create_keypair`). It is used for:

- Salt input into the KEK derivation (cross-instance domain separation).
- ECIES decryption of inbound authenticated payloads (`e2e_decrypt(wire, sk_d)`).
- Identifying the server (clients fetch `pk` via `GET /pk` to encrypt to it).

The keypair never participates in WebAuthn verification — it is purely a transport-layer identity for the application-layer ECIES envelope.

A separate **VAPID** keypair lives inside the encrypted vault as `vapid_private_key` and is loaded into memory on unlock for Web Push delivery (`notify::webpush`). Migrated in on first unlock if absent (`vault_unlock` in `server/routes.rs:589-602`).

---

## 6. Vault state machine

`Vault` (`vault.rs:113`) is a single in-memory object with three peer regions:

```
struct Vault {
    plaintext:         Mutex<Option<Value>>,        // None = locked
    service_names:     Mutex<Vec<String>>,          // derived
    policy_defaults:   Mutex<PolicyDefaults>,        // derived
    push_subscriptions:Mutex<Vec<PushSubscription>>, // derived
    vapid:             Mutex<Option<VapidKeypair>>, // derived
    cache: VaultCache {
        oauth2_tokens: Mutex<HashMap<String,(String,u64)>>,
        approvals:     Mutex<HashMap<String,ApprovalSession>>,
        pending_deks:  Mutex<HashMap<String,[u8;32]>>,
    }
}
```

Two states: **Locked** (`plaintext = None`) and **Unlocked** (`plaintext = Some(...)`).

Transitions:

| Event | Action |
|-------|--------|
| `setup` | Decrypt nothing (fresh DEK), set plaintext = the user-supplied vault, derive lists, dispatch full cook. |
| `unlock` | Read `wrapped_dek_<cid>.bin`, derive KEK, unwrap DEK, decrypt `vault.enc`, **set plaintext, derive lists, drop DEK**, optionally migrate VAPID. |
| `lock` | Zeroize plaintext, clear all derived lists, clear all caches (with zeroization of DEKs and approval auth). |
| `vault/update` | While unlocked, the caller passes a new vault JSON (E2E-encrypted with their userKey), server re-encrypts with current DEK and persists; in-memory plaintext is replaced. |
| TTL expiry | Periodic 60s task (`main.rs:140`) calls `cleanup_expired_sessions`, `RateLimiter::cleanup`, `ChallengeStore::cleanup`. Approval sessions whose `expires_at <= now` have their `auth` overwritten before removal. |

**Strip on unlock for sensitive services.** When `set_plaintext` loads the JSON, it walks `services` and removes the `auth` field for any service whose effective levels include `ask` or `ask-always` (`vault.rs:82-110, 152-170`). Auth for those services is *never* held in steady-state memory; it is decrypted again on the fly inside the approval-confirm path and cached for at most the configured TTL in `cache.approvals`.

This is the implementation of "sensitive credentials are not persistently in RAM": for `ask-always` services (e.g. anything destructive without the user's per-call OK), the credential is fetched from disk, used once, and zeroized.

The `files` synthetic service is auto-injected with `upstream = http://localhost:23294/vault/files` so that file reads can flow through the same proxy + approval pipeline (`vault.rs:153-161`).

---

## 7. Authentication

There are two distinct authentication concerns:

- **User auth.** "Did this request come from a holder of a registered passkey?" — gates admin and vault endpoints.
- **Service auth.** "Inject the right credential into the upstream HTTP request." — handled by `auth/` modules.

### 7.1 Outer wire format

All admin/vault endpoints take a single body shape:

```json
{ "payload": "<base64 of E2E wire JSON>" }
```

Where the inner ECIES wire JSON is `{ epk, iv, ct }` (§4.2). The server decrypts to get the **inner payload**.

### 7.2 Inner payload

```json
{
  "credentialId": "<base64url passkey credential id>",
  "challenge"|"nonce": "<base64>",
  "userKey": "<base64 32B>",         // for unlock / vault read paths
  "assertion": { authenticatorData, clientDataJSON, signature, credentialId? },
  ... endpoint-specific fields ...
}
```

The shape is strict — `credentialId` is required, exactly one of `challenge` or `nonce` is required, and an `assertion` is required (`passkey/mod.rs:110-152`).

### 7.3 Replay protection — dual track

`passkey/mod.rs:116-152` accepts two replay-protection schemes:

- **Server challenge** (`challenge`): preferred path. Client first calls `GET /challenge` (`server/routes.rs:125`) which returns a 32-byte random base64 string. The server stores `(challenge → (issued_at, ip))` in memory (`passkey::challenge::ChallengeStore`). TTL 5min, single-use, 60/min/IP. On verify, the entry is `remove`d — second use returns `false`.
- **Client nonce** (`nonce`): used during initial setup before any challenge can be issued. Must be ≥16 bytes. Verified against an in-memory `NonceStore` HashSet — present means already used. The server never issues these; they are client-generated random bytes.

In both paths the value is included inside the ECIES envelope, so the AEAD tag commits to it. This means a network MitM cannot strip or substitute the replay token — they would have to break GCM.

Note: `passkey/webauthn.rs:90-97` does **not** independently re-verify the WebAuthn `clientDataJSON.challenge` against the server-issued challenge. The `challenge`/`nonce` consumed in §7.3 protects the *envelope* from replay; the WebAuthn assertion's own challenge is whatever the JS client put there. The two are different layers (this is one of the gaps versus the aspirational `safeclaw-protocol/PROTOCOL.md` v2 design — see §18).

### 7.4 WebAuthn assertion verification

`passkey/webauthn.rs::verify_assertion`:

1. Decode `authenticatorData`, `clientDataJSON`, `signature` from base64.
2. Parse `clientDataJSON`. Reject if `type != "webauthn.get"`.
3. Reject if `clientDataJSON.origin != effective_origin`. Origin comes from `--origin` flag or `SAFECLAW_ORIGIN` env (default `http://localhost:<port>`).
4. Reject if `authenticatorData[0..32] != SHA-256(rp_id)`.
5. Reject if UP (User Present) flag (`authenticatorData[32] & 0x01`) is unset.
6. Build signed bytes = `authenticatorData ‖ SHA-256(clientDataJSON)`.
7. DER-decode the ECDSA signature to raw `r||s` (64B). Verify with `p256::ecdsa::VerifyingKey` over the signed bytes (the verifier hashes with SHA-256 internally).

Rejected if any check fails. There is no UV (User Verified) flag enforcement in code; UV is implied by UP for platform authenticators in practice but a hardware token configured to skip biometric would still pass.

### 7.5 The `AuthenticatedRequest` extractor

An Axum extractor (`passkey/mod.rs:65-83`) that performs §7.1 → §7.4 in one shot. Routes that include this extractor in their signature (`approval_confirm`, `vault_unlock`, `vault_update`, `passkeys/add`, etc.) get a verified `AuthenticatedRequest { payload, credential_id, passkeys }` automatically; if any step fails, the route never runs and the client sees `401`/`400`.

This is the single chokepoint for user authentication. The 22 routes that mutate state all go through it.

### 7.6 Service auth (`src/auth/`)

Six injection styles, dispatched on `auth.type` (`auth/mod.rs:77-95`):

| Type | Where injected | Notes |
|------|----------------|-------|
| `bearer` | `Authorization: Bearer <secret>` | Standard. |
| `basic` | `Authorization: Basic base64(user:pass)` | `username` + `password`. |
| `header` | Configurable header name + optional prefix | `x-api-key`, etc. |
| `query` | URL query `?<param>=<secret>` | Google Cloud-style. |
| `path` | URL path segment templated via `pathTemplate` | Telegram bot tokens. |
| `oauth2` | Bearer header, but `secret` is a freshly refreshed access token | See §8.4. |

The proxy strips inbound `Authorization` and `x-api-key` headers from the agent before injecting the real one (`core/forward.rs:130-135`), so an agent cannot smuggle its own credentials past the proxy.

Per-service custom headers (e.g. `chatgpt-account-id: {{auth.account_id}}`) are declared in `[upstream.headers]` of `service.toml` and resolved by a small template engine in `service::apply_service_headers`. Supported placeholders: `{{uuid_v4}}`, `{{auth.<field>}}` with field ∈ `{account_id, client_id, secret}`.

---

## 8. Proxy data plane

Proxy entry point: `core::router::proxy_handler` (`core/router.rs:284`).

### 8.1 Route parsing

`parse_route("/anthropic/v1/messages?q=1") = ("anthropic", "/v1/messages", "?q=1")`. The first path segment is treated as the service id; everything after is the upstream path.

Special cases handled before policy:

- `GET /health` → uptime + locked state + version (`core/router.rs:42`).
- `GET /approve/{id}` → poll an approval (§9.4).
- `GET /<service>/help` → service help text (no auth, no policy).
- `<service>` not in vault → 403 with `code: UNKNOWN_SERVICE`.

### 8.2 Locked-state behavior

If `vault.is_locked()`, the proxy must not forward but also must not break the agent's response stream. The handler:

1. Sniffs whether the request expects SSE (`Accept: text/event-stream`, `?stream=true` in URL, or `"stream": true` in body).
2. Looks up the service's `[upstream.locked].response` text (or default).
3. Calls `service::locked::render_for_upstream(upstream_url, is_stream, admin_url, custom_message)` which auto-detects the API format from the upstream host:
   - `*.anthropic.com` → Anthropic Messages format (full `message_start`/`content_block_delta`/`message_stop` SSE if streaming).
   - `*.openai.com`, `*.groq.com`, `*.deepseek.com`, `*.openrouter.ai` → OpenAI Chat Completions format.
   - `generativelanguage.googleapis.com` → Gemini `candidates` format.
   - Anything else → fallback OpenAI format.

The agent receives a normal "assistant message" telling it the vault is locked, with a clickable URL back to the admin page. This matters because most agent runtimes treat upstream errors as fatal — emitting a structured "completion" instead lets the agent surface the message to the user without crashing the conversation.

### 8.3 Policy evaluation (called on every unlocked request)

`evaluate_policy(method, path, body, rules, levels, defaults, category)` (`core/policy.rs:253`).

Rule sources, in priority order:

1. Per-service rules from the vault (`service_vault.rules`) — fully custom; takes complete precedence.
2. Else: `service_vault.rule_overrides` (sparse, keyed by rule `id`) **patched onto** built-in `service.toml` / `policy.toml` rules via `merge_rule_overrides`.
3. Else: built-in rules from `policy.toml` / `service.toml` `[[policy.rules]]`.
4. Service-level `levels` (`{read, write, ask_ttl}`).
5. Per-category default (`policy_defaults.type_levels[category]`) — e.g. `llm` defaults to `allow/allow` so chat completions don't prompt.
6. Global `policy_defaults.levels` — defaults to `ask-always/ask-always`.

**Specificity scoring** (`core/policy.rs:191`). When multiple rules match, the most specific wins (nginx-style longest-match). Score:

- +1000 if the rule has a `body` regex (more conditions = more specific).
- +5 if a method is given.
- +10 per literal (non-wildcard) path segment.

Patterns: `match = "POST /v1/chat/completions"` or `"/admin/*"` (no method = matches any). `*` = exactly one segment. Body regex matches against the request body text.

`AccessLevel`:

| Level | Behavior |
|-------|----------|
| `allow` | Forward immediately. |
| `ask` | Forward if there is a still-valid approval session (cached after a previous human OK); otherwise create a pending approval and 202. |
| `ask-always` | Always create a pending approval, never cache. |
| `deny` | 403 with `code: DENIED`. |

### 8.4 OAuth2 refresh

For services with `auth.type = "oauth2"` (Anthropic/Claude OAuth, OpenAI Codex via ChatGPT account):

1. Check `vault.cache.oauth2_tokens[service]` — if present and `expires_at > now+60`, use it.
2. Otherwise call `auth::oauth2::refresh_token(auth, oauth_style)` (`auth/oauth2.rs`):
   - Style is `Form` (default) or `Json` (Anthropic, Claude). Picked from `service.toml`'s `auth.oauth_style` field; falls back to a URL heuristic.
   - POST `token_url` with grant_type=refresh_token, client_id, refresh_token, optionally client_secret.
   - Parse response, extract `access_token` and `expires_in`.
3. Store `(access_token, now + expires_in)` in `oauth2_tokens` and inject as Bearer.

The refresh runs inline on the request path; latency on refresh requests is the OAuth provider's response time. The cache lifetime is bounded by `expires_in` from the provider.

The cache is part of `VaultCache`, which means **lock wipes all OAuth access tokens** — the next request after unlock triggers a fresh refresh.

### 8.5 Forward pipeline

For non-local services, after policy says allow:

1. Read service's `upstream`, `auth`, headers from vault config (`forward::forward_request`).
2. Build forwarded headers: copy through agent's headers minus `host`, `content-length`, `transfer-encoding`. If we are injecting auth, also strip incoming `authorization` and `x-api-key`.
3. Inject auth (bearer/basic/header) and per-service custom headers (with template resolution).
4. Issue the upstream request via a shared `reqwest::Client` (HTTPS, redirects disabled).
5. Stream the upstream response body back to the agent unmodified, preserving status and headers.
6. Log to audit DB: `service, method, path, level, decision, duration_ms, upstream_status` (no payloads).

### 8.6 Local exec (multi-step API engine)

Some services have no upstream (`type = local` or no `[[upstream]]` block); their `[[api.steps]]` use `target = "safeclaw"` to run a shell command, or `target = "safeclaw.vault"` to read a vault path.

`handle_local_service` (`core/router.rs:772`) walks `api.steps` sequentially. For each step:

- **`safeclaw.vault`**: `execute_vault_read` follows the dotted `read` path through the unlocked plaintext (e.g. `services.openclaw-dashboard.gatewayToken`). Returns `Value`.
- **`safeclaw` / `openclaw`**: `execute_command` spawns a subprocess. Body bytes are piped to stdin; stdout is parsed as JSON (or wrapped as a string). `env` template variables are resolved against the service vault (`{{auth.secret}}`). `HOME` is set to `data_dir` so CLIs find their config.

Retry policy per step: `retry = { attempts, interval_ms }`. Failure handling: if any step fails *before* a `returns = true` step has succeeded, the whole API fails. If a `returns = true` step has already produced a value, later step failures are logged but do not change the response.

This engine is what turns SafeClaw from a pure proxy into a small workflow runtime: it can chain a vault-read into a CLI invocation into an upstream forward, all within one logical agent-facing endpoint.

---

## 9. Approval flow

The interactive consent path that gates `ask` and `ask-always` requests.

### 9.1 Architecture: 202 + poll

When an approval is needed, the proxy does **not** hold the agent connection. It returns immediately:

```
HTTP/1.1 202 Accepted
{ "id": "<uuid>",
  "safeclaw_approve_url": "<admin>/approve/<id>",
  "expires_at": <unix> }
```

The agent then polls `GET /approve/{id}` on the **proxy** port every few seconds. The user receives a Web Push notification (if subscribed) and approves/rejects from the admin UI. On approve, the next poll executes the upstream call and returns the response inline.

Why 202 + poll instead of long-polling: agent runtimes universally support retry-on-202; few support holding a single TCP connection for several minutes during a human review.

### 9.2 `PendingApproval` state machine

`core::approval::PendingApproval` (`core/approval.rs:38`) holds the full request shadow needed to replay later:

```
service, method, path, uri_path, upstream,
req_headers (hop-by-hop + auth stripped),
req_body, details (sanitized), approval_status,
approved_auth (set on confirm, cleared after execute),
auth_executing (single-execute flag),
cached_response  (set after first execute)
```

States: `Pending → {Approved, Rejected, Expired}`. Once Approved, transitions:

- First poll after approval: `take_auth_for_execute` atomically takes `approved_auth` and sets `auth_executing = true`. If concurrent polls race, only one wins.
- The winning poll executes the upstream call (with possibly an OAuth2 refresh first), buffers the response, calls `set_cached_response` which also clears `approved_auth` (defense in depth — once consumed, don't keep it).
- Subsequent polls return the cached response → idempotent.

Expiry: `tokio::spawn` task fires at `timeout` seconds, calling `expire(id)`. Approval sessions are also evicted if they outlive their TTL.

### 9.3 Request integrity at replay time

The replay deliberately uses the **shadow body** stored at approval-creation time, not anything from the polling agent. This means:

- An adversary controlling the agent cannot swap the body between user OK and execute.
- The user reviewed exactly the bytes that will go upstream.
- The approval is bound to one concrete request, not "the next request from this agent."

`req_headers` has hop-by-hop and inbound auth stripped at creation (`core/router.rs:744-767`). The replay runs through `forward_request` again, which re-injects the real credential.

For the synthetic `files` service, the replay URI gets `?approval=<id>` appended so the file endpoint can find the stashed DEK (§9.7).

### 9.4 Confirm / Details / Reject

Three admin endpoints, all via `AuthenticatedRequest`:

- `POST /approve/{id}/confirm` (`server/routes.rs:1738`). Requires user passkey. For non-`files` services: decrypts the vault to extract `services.<name>.auth` (the credential that was stripped at unlock), passes it into `approval_manager.confirm(id, Some(auth_json))`. Stores it on the `PendingApproval.approved_auth`. For `files`: derives the DEK on the spot and stores it in `vault.cache.pending_deks[id]` for one-time use.
- `POST /approve/{id}/details` (`server/routes.rs:1704`). E2E-encrypted return of the sanitized request preview (URI, content-type, body preview ≤2KB). Sealed under `derive_response_key(userKey, nonce)`.
- `POST /approve/{id}/reject` writes audit, marks rejected.

The auth credential is therefore kept **only inside `PendingApproval`** and only between confirm and the first poll — once the upstream replay runs, `approved_auth = None` and the credential is gone from that record.

### 9.5 Approval session cache

For `ask` (not `ask-always`), after a successful execute:

```rust
state.vault.set_approval_session(&service, auth, ttl_secs = 3600);
```

Subsequent requests in the next `ask_ttl` (configurable per rule or service; default 3600s, capped at 3600) skip the approval prompt. The session sits in `vault.cache.approvals[service]`. Lock wipes it.

`ask-always` skips this cache entirely. This is the right knob for high-stakes operations (delete, send-money) where every single use deserves an explicit OK.

### 9.6 Web Push notifications

On approval creation, the proxy fires off a non-blocking Web Push to all subscribers (`notify::webpush::send_push_notification`). VAPID signing key is the in-memory VAPID private key from the unlocked vault. Dead subscriptions (404/410) are removed from the active list.

This lets the user OK things from a phone or watch without keeping the admin tab open.

### 9.7 Files-service approval gate

Reading a vault-stored file is treated as a proxied request to the synthetic `files` service. Policy can therefore gate file reads with the same `ask` / `ask-always` levels. Mechanism:

1. Agent calls `GET /files/{id}` on the proxy port.
2. Policy says `ask`. 202 returned with approval id.
3. User approves. `approval_confirm` derives the DEK from their userKey and stashes it in `vault.cache.pending_deks[id]`.
4. Agent's next poll triggers the replay; the proxy forwards `GET /vault/files/{id}?approval=<id>` to the admin port.
5. `vault_files_read_approved` (`server/routes.rs:1356`) takes the DEK out of `pending_deks` (one-time consume), decrypts the file, returns content. Then zeroizes the DEK.

The DEK lives in process memory only between confirm and read, with one-shot semantics. Approval expiry triggers `pending_deks` zeroization in `cache.clear()` paths.

---

## 10. Service registry

`service::ServiceRegistry::load()` (`service/mod.rs:286`) loads service definitions at startup from three layers, in priority order:

1. **Compiled-in defaults** (`build.rs` walks `services/` and emits `generated_services.rs` with `(id, toml_str)` arrays). These are *always* loaded first; everything else overrides them.
2. **`$SAFECLAW_DATA/services/`** runtime overrides — for dev/staging, lets you swap a service definition without rebuilding.
3. **`~/.safeclaw/services/`** user-installed services — highest priority. Can be installed via `safeclaw install <name>` (§12).

A service folder contains:

- `service.toml` — required, runtime behavior (see PROTOCOL.md §service.toml).
- `recipe.toml` — optional, first-time setup steps.
- `policy.toml` — optional, default access policy (per-rule `id`/`label` for sparse vault overrides).

`scan_dir` accepts both flat (`services/openai/`) and nested-by-category (`services/llm/openai/`) layouts.

### 10.1 What the registry exposes

The registry is read by both the proxy (`core::router`) and the admin server (`server::routes`). Key methods (`service/mod.rs:281+`):

- `get(name) -> Option<&ServiceDef>` — full definition.
- `default_category(name) -> &str` — used by policy evaluation.
- `default_policy_levels(name) / default_policy_rules(name)` — built-in policy if the vault has no override.
- `is_local(name) -> bool` — true if all `[[api.steps]]` target `safeclaw`/`openclaw`/`safeclaw.vault` (no `upstream:` step).
- `is_auto_activated(name)` — `[service].activation = "auto"`; service starts without user credentials (e.g. brave search).
- `is_agent_visible(name)` — has upstream OR api OR help → safe to expose in `safeclaw.md`.
- `oauth_style(name)` — `"json"` for Anthropic/Claude path, else default `Form`.
- `locked_response(name, is_stream, admin_url, path)` — see §8.2.
- `find_local_api(name, method, path) -> Option<&ApiDef>` — resolves which `[[api]]` handles a request for the local-exec engine (longest-prefix match, method match).
- `apply_service_headers(auth, resolved_bearer, headers, registry, name)` — runs the header template engine against the matching upstream's `[upstream.headers]`.

### 10.2 Vault field declarations

`[[vault]]` blocks in `service.toml` declare what the service stores in the vault (`name`, `kind: secret|config`, `description`). The admin add-service endpoint uses these to validate the user's input and to generate UI form fields. They also serve as documentation for what `secrets.services.<id>.<key>` paths exist.

This is how `service.toml` becomes self-describing: the runtime knows what to ask for, the UI knows what to render, and the recipe knows what `{{service.vault.KEY}}` it can reference.

---

## 11. Lifecycle endpoints (admin server)

`server/mod.rs:60-131` lists all routes. The mutating ones go through `AuthenticatedRequest`. The interesting ones:

### 11.1 Setup (`POST /admin/setup`)

First-time vault creation, or **reset** if a passkey-authenticated existing-credential assertion is also provided.

Inputs (inside the ECIES envelope):
- `nonce` (single-use)
- `passkeys[]`: each with `{credentialId, x, y, deviceName}`
- `userKeys[]`: per-passkey 32B userKey (parallel array)
- `assertions[]`: per-passkey WebAuthn assertion (each must verify against its `(x,y)`)
- `vault`: initial vault JSON
- If vault already exists: `existingCredentialId` + `existingAssertion` (must verify against an existing `passkeys.json` entry).

Steps:

1. Verify all per-passkey assertions inside the ECIES envelope (defense in depth: if assertion has `credentialId`, it must match the passkey it's being verified against).
2. If reset, verify existing-credential assertion.
3. Generate VAPID keypair if absent.
4. Generate fresh DEK; encrypt vault with it.
5. For each passkey: derive KEK = HKDF(userKey, salt=sk_d, info=`safeclaw-kek-v1`); wrap DEK with KEK; write `wrapped_dek_<filename>.bin`. Zeroize KEK.
6. Write `passkeys.json`, `vault.enc`, `index.json`. Unlock in memory. Dispatch full cook (system recipes + service recipes).

Why all assertions live inside the ECIES envelope: a tampering reverse-proxy cannot forge or substitute them; they are AEAD-tagged.

### 11.2 Unlock (`POST /admin/unlock`)

Inputs (inside envelope): `userKey`, `credentialId`, `assertion`. Verified by `AuthenticatedRequest`.

Steps:
1. Look up `wrapped_dek_<filename>.bin`.
2. Derive KEK from `userKey + sk_d`. Unwrap DEK.
3. Decrypt `vault.enc`. Parse JSON. Migrate VAPID if absent.
4. Zeroize KEK and DEK. Set vault plaintext.

No cook on unlock — config persists in the docker volume across lock/unlock; only the in-memory vault changes state.

### 11.3 Lock (`POST /vault/lock`)

Wipes `Vault::plaintext` and all caches. The user can keep using the admin UI to re-unlock.

### 11.4 Vault read (`POST /vault/credentials`)

Returns the decrypted vault, optionally a **subtree-select**: `{userKey, select?: "services.telegram,channels.telegram"}`. The server decrypts the full vault, picks matching subtrees (OR semantics across paths, preserving the original hierarchy), re-encrypts the subset under a per-request response key (`derive_response_key(userKey, nonce)`), and zeros plaintext. This is how the console UI reveals one credential at a time without round-tripping the entire vault.

### 11.5 Vault write (`POST /vault/update`)

Decrypts the user's new vault payload (E2E), re-encrypts with the existing DEK, writes `vault.enc`, updates `index.json`, dispatches **full** cook (so any new service definition gets its recipe applied).

Note: The current implementation does **not** rotate the DEK on write. The aspirational design in `safeclaw-protocol/PROTOCOL.md` calls for a fresh DEK per write — see §18.

### 11.6 Add passkey (`POST /passkeys/add`)

Adds a second passkey to the same vault, in two flavors:

- **Inline** (two-device co-located): the request payload contains `newPasskey` + `newUserKey` directly. The auth comes from an existing passkey.
- **Deposit** (cross-device "save for later"): the request contains `newPasskeyDeposit`, an inner ECIES envelope encrypted to `vmPk` with `{newPasskey, newUserKey}` inside. This lets the user create a new credential on Device A (no old passkey) and finalize from Device B (which has the old passkey). Same crypto primitives, no new protocol.

In both cases:
1. Old passkey verifies; old wrapped-DEK is unwrapped to recover DEK.
2. Derive new KEK from `newUserKey`. Wrap DEK under it. Write `wrapped_dek_<newcid>.bin`.
3. Append the new entry to `passkeys.json`. The vault itself is unchanged.

### 11.7 Remove passkey (`POST /passkeys/remove`)

Authenticated by a *different* registered passkey (you can't remove the last one). Deletes the corresponding `wrapped_dek_*.bin` and removes the `passkeys.json` entry. Vault contents untouched.

---

## 12. Service install CLI

Beyond `safeclaw connect <id>` (which only prints recipe steps for manual execution), the CLI supports installing services from GitHub:

```
safeclaw install <name>                # short name → official registry
safeclaw install owner/repo[/subdir]   # arbitrary repo
safeclaw uninstall <name>
safeclaw enable <name>
safeclaw disable <name>                # writes ~/.safeclaw/services/<name>/.disabled
safeclaw services                      # list user-installed
```

Resolution (`cli/install.rs`):
- Short name: fetch `safeclaw/services/index.toml` from GitHub. If `<name>` is listed, download `safeclaw/services/<name>/{service,recipe,policy}.toml` to `~/.safeclaw/services/<name>/`.
- Path form: same fetch from `<owner>/<repo>/<subdir>/`.

Disable is idempotent via the `.disabled` marker, which the registry loader skips at startup.

The service shows up in the registry on next `safeclaw` restart (the registry is loaded once at boot).

---

## 13. Files vault

A small encrypted blob store using the same DEK as the vault.

- **List** (`GET /vault/files`, no auth) → metadata from `index.json`. Names + sizes only, no content.
- **Upload** (`POST /vault/files/upload`, passkey) → derive DEK, AES-256-GCM encrypt, write `files/<uuid>.enc`, append to vault `files[]` (which writes `index.json` via `write_index`).
- **Read** (`POST /vault/files/read`, passkey, E2E-sealed return) → decrypt and seal under per-request response key.
- **Read-after-approval** (`GET /vault/files/{id}?approval=<id>`, no passkey at this hop) → consume DEK from `pending_deks` cache that approval-confirm placed there. One-shot, zeroized after read.

Files are stored individually rather than inside the vault JSON because they can be large (PDFs, transcripts) and we don't want to re-encrypt the entire vault for one upload.

---

## 14. Audit log

`core::audit::AuditLog` is a SQLite database at `data/audit.db` with two tables:

- `audit_log(timestamp, service, method, path, level, decision, duration_ms, upstream_status, approval_id)`. One row per proxied request. **Never** contains payloads, headers, or query strings — `path` is the *route path after service prefix*, e.g. `/v1/messages`.
- `approvals(id, service, method, path, status, created_at, expires_at, decided_at)`. Tracks each approval through its lifecycle.

The audit log is the only persistent record of what the agent did. It is intentionally low-resolution — it answers "what did I authorize" but not "what was in the body." Body previews live in the volatile `PendingApproval.details` and disappear when the approval expires.

---

## 15. Locked-response auto-formatting

A small but important UX detail. Without this, an agent talking to a locked vault would see a 503 and crash the conversation (most agent runtimes treat upstream failure as fatal). Instead, `service::locked::render_for_upstream` returns a normal "the assistant says" response in whatever API format the upstream uses, with the lock message inline.

Implementation: pattern-match `upstream_url` against known hosts (`anthropic.com`, `openai.com`, `googleapis.com`, ...), pick a JSON shape, optionally render as SSE if the agent expected streaming. Fallback is OpenAI Chat Completions (the most widely supported).

This is one of the reasons SafeClaw is a *drop-in* substitute for raw provider URLs: the lock state is observable to the user *through* the agent rather than as an out-of-band crash.

---

## 16. Mapping to the SUDP paper

For the paper extractor: this section maps the implementation to the abstract roles in `safeclaw-paper/sections/04-safeclaw-protocol/`.

| SUDP role | SafeClaw realization |
|-----------|----------------------|
| Requester $R$ | The LLM agent / its tool runtime / the LM-provider client. Speaks to SafeClaw via `localhost:23295` (HTTP). |
| Authorizer $U$ | The human user, with a registered WebAuthn passkey and a browser (or phone) on the admin UI. |
| Custodian $T$ | The `safeclaw` daemon process — both the admin server (`:23294`) and the proxy (`:23295`). |
| Environment $E$ | The upstream service (OpenAI, Anthropic, GitHub, Telegram, …) reached via outbound HTTPS. Outside the protocol. |
| Operation $o$ | The HTTP request as captured at proxy-handler time: `(service, method, path, body)`, with `details` (URI, content-type, body preview) shown to $U$. |
| Grant $G$ | A successful `approval_confirm` — equivalent to the conjunction of: a fresh server `challenge` (`r`), a WebAuthn assertion ($\sigma^\star$) over the inner ECIES payload, and the `approved_auth` field set on `PendingApproval`. |
| Sealed state $\Sigma$ | `vault.enc` + `wrapped_dek_<cid>.bin`. The credential never leaves $T$'s memory. |

| SUDP primitive | SafeClaw instantiation |
|----------------|-----------------------|
| Tamper-resistant module $\mathcal{A}_c$ | FIDO2 authenticator (Touch ID / YubiKey / Windows Hello). |
| $\mathsf{Sig}_{sk_c}$ | WebAuthn ECDSA-P256 assertion (signed bytes = `authenticatorData ‖ SHA-256(clientDataJSON)`). Verified per §7.4. |
| $\mathsf{PRF}$ (authenticator-bound, per-credential) | WebAuthn `hmac-secret` extension → `rawPRF` (32B, in JS only) → `userKey` (32B, sent in ECIES envelope). |
| $\mathsf{H}$ | SHA-256. |
| $\mathsf{KDF}$ | HKDF-SHA-256 with three info labels (§4.1). |
| AEAD $\mathsf{Enc}/\mathsf{Dec}$ | AES-256-GCM (12B IV, 16B tag). |
| $\mathsf{Wrap}/\mathsf{Unwrap}$ | AES-GCM-as-wrap (KEK encrypts the 32B DEK; output is `iv ‖ ct ‖ tag`). |
| $\mathsf{Encap}/\mathsf{Decap}$ | An ad-hoc ECIES (P-256 + HKDF + AES-GCM) — *not* HPKE. The paper's concrete profile names HPKE; the implementation has the simpler bespoke ECIES. This is a known gap (§18). |
| Authenticated channel $U \leftrightarrow T$ | TLS 1.3 (Caddy/nginx in front) for remote, plus the application-layer ECIES envelope which authenticates inner payload integrity end-to-end across any reverse proxy. |
| Sender-constrained grant $G$ | `approved_auth` is bound to one `PendingApproval.id`, single-execute (`auth_executing` flag), and tied to the specific recorded `(method, path, body, headers)`. The replay reuses the stored body — the agent cannot substitute. |

**Mapping the three phases:**

- **Phase I (Setup)** corresponds to `POST /admin/setup`: each passkey contributes a WebAuthn assertion + a `userKey`; server generates DEK; KEK = HKDF($u_c$, salt=$s$, info=`safeclaw-kek-v1`); $W_c \gets \mathsf{Wrap}(K, KEK)$ stored as `wrapped_dek_<cid>.bin`; vault sealed under $K$ written as `vault.enc`.
- **Phase II (Grant)** corresponds to `proxy_handler` → `create_approval` → `approval_confirm`. `r` is the random `id` (UUID v4) embedded in the approval URL; $o$ is `(service, method, path, body)`; the user's signature $\sigma^\star$ is the WebAuthn assertion validated by `AuthenticatedRequest` on `/approve/{id}/confirm`. Single-use semantics: the approval transitions to `Approved` once; `take_auth_for_execute` atomically extracts $\sigma^\star$'s effect (the `approved_auth`).
- **Phase III (Consumption)** corresponds to the first poll after confirm: $T$ unwraps $K$ (only when actually needed for `files` or pre-stripped sensitive auth), executes `o` against $E$, redacts $\sigma^\star$ (`approved_auth = None`), caches the response. Subsequent polls return the cache → exactly-once delivery from $R$'s perspective.

**Properties that hold by construction in the implementation:**

- $R$ never sees the credential. The credential is injected by `auth/` into the upstream request after $R$ has already left the loop (§8.5).
- An `ask-always` operation cannot be performed without a fresh per-request user assertion (no caching).
- The body the user sees in `details` is byte-for-byte the body that will be replayed (`req_body` shadow in `PendingApproval`).
- A revoked passkey (deleted via `/passkeys/remove`) cannot decrypt new vault writes — `wrapped_dek_<cid>.bin` is gone, so there is no path from that credential to $K$. (Forward secrecy across an *un*-rotated DEK is bounded — see §18.)

**Properties that hold under TLS but not under loopback assumption:**

- Confidentiality of credentials in transit between $T$ and $E$ — relies on TLS to the upstream host.
- Confidentiality of admin requests in transit between $U$'s browser and $T$ — relies on TLS for remote deployments. Local loopback deployments accept that a sibling process snooping localhost can also read `data/`.

**Properties not currently provided (relative to paper claims):**

See §18.

---

## 17. Notable design decisions

A non-exhaustive list of decisions worth understanding before changing things:

1. **No transport crypto layer above TLS.** Application-layer ECIES exists for *authentication payload integrity*, not transport confidentiality. Reverse proxies can route, can't tamper.
2. **Two HTTP ports, one process.** Splitting admin from proxy keeps the proxy bound to loopback while admin can be remote-via-TLS. Sharing process state means lock observed by either is immediate.
3. **Vault is one JSON object.** All service config + secrets + policy + push subs live in one encrypted blob. Simple, atomic writes; trade-off is per-update cost is O(vault).
4. **Files are blobs outside the JSON.** Same DEK, separate files, so a 5MB PDF doesn't force re-encrypting the whole vault.
5. **Strip auth on unlock for `ask*` services.** Sensitive credentials are never in steady-state RAM; they round-trip through a derived KEK only under explicit consent.
6. **202 + poll instead of long-polling.** Survives connection timeouts, agent retries, and works with every agent runtime.
7. **Single-execute approvals.** A successful approve → one upstream call → result is cached → repeat polls return the cache. Prevents replay of approved auth.
8. **Approval session cache is in `VaultCache`.** Lock wipes it. No way to "leave it logged in" across a vault lock.
9. **Locked-response auto-formatting per upstream API.** Locks are observable through the agent, not as crashes.
10. **Declarative services.** `service.toml` + `recipe.toml` mean adding GitHub, Telegram, NodPay, etc. requires zero Rust code. The 3-layer registry (compiled-in / data-dir / `~/.safeclaw/services/`) supports both internal evolution and user customization.
11. **Multi-step API engine.** The same primitive (`step`) drives both first-time setup (recipe) and runtime API endpoints, with a small target vocabulary (`safeclaw`, `safeclaw.vault`, `openclaw`, `upstream:<id>`). This is what lets a service like NodPay run its `npx nodpay sign` CLI through the same proxy + policy + audit pipeline as an OpenAI HTTP forward.
12. **OAuth2 cache is part of the vault state.** Lock = cache wipe = next request re-refreshes. Avoids stale tokens across a fast lock-unlock cycle (which can happen, e.g. during passkey rotation).
13. **No write rotation of DEK.** Trade-off: simpler crypto, faster writes; no narrow-window forward secrecy at-rest. See §18.

---

## 18. Known gaps versus paper claims and aspirational drafts

Listed here for the paper extractor. Do not claim these as implemented properties.

- **Per-credential `prf_salt`.** `safeclaw-protocol/PROTOCOL.md` (the v2 draft) calls for storing a per-credential rotating PRF salt in the wrapped-DEK file and using *that* as the HKDF salt. The current code uses `sk_d` (server private key) as the salt instead. Effect: a backup of `data/` made today plus a rawPRF capture tomorrow can decrypt today's vault. With per-credential salt that rotates, the same scenario fails.
- **Per-write DEK rotation.** Calls in the v2 draft for a fresh DEK on every `vault/update`. Not implemented. Effect: the same DEK protects all historical vault states present on disk backups. Rotating per-write would mean a captured-after-the-fact KEK only decrypts vaults from before the most recent rotation.
- **HPKE.** The paper's concrete profile names HPKE for $\mathsf{Encap}/\mathsf{Decap}$. The implementation uses an ad-hoc ECIES (P-256 + HKDF(`info=safeclaw-e2e`) + AES-GCM). Functionally equivalent for the security argument but does not match the named primitive.
- **WebAuthn `clientDataJSON.challenge` re-binding.** The current `verify_assertion` does not re-derive the expected challenge from the request body and compare against `clientDataJSON.challenge`. Replay protection is provided by the *envelope*'s `challenge`/`nonce` consumed by the server; the WebAuthn assertion's own challenge is whatever the JS client sent. The two layers are independent, so a misbehaving client could submit a freshly-signed assertion over an arbitrary challenge string and pass the envelope check. This is mitigated in practice because the envelope is AEAD-tagged with the same `userKey` the client chose, but it is not a per-operation cryptographic binding $G \to \mathsf{H}(o)$ in the SUDP sense.
- **Memory-resident attacker.** The implementation zeroizes `kek`/`dek`/userKey/responseKey/approvalAuth/pendingDek as best-effort. An attacker with `/proc/$pid/mem` access during an unlocked window gets everything. This matches the documented threat model but is not "secret never leaves the boundary" in the strong cryptographic sense.
- **AAD on AEAD.** `aes_encrypt` takes no associated data, so on-disk ciphertexts do not commit to a `DS` label or version tag. Versioning is implicit (file path + length checks).
- **Audit integrity.** `audit.db` is a plain SQLite file. No append-only commitment, no tamper detection. A user with write access to `data/` can rewrite history.

These gaps are not bugs — they are the trade-offs of a small single-binary v1 against a larger spec'd v2. The paper distinguishes between the protocol abstraction (which is what should be claimed) and the concrete profile (which is what the implementation realizes a subset of).

---

## File index for the paper extractor

If the extractor needs to follow up on a specific claim:

- **Crypto primitives** → `src/crypto/{aes,ecies,kdf,keys,envelope,zeroize}.rs`
- **Vault state** → `src/vault.rs`
- **Passkey verification** → `src/passkey/{mod,webauthn,challenge,nonce}.rs`
- **Proxy + policy + approval + audit** → `src/core/{router,policy,approval,audit,forward}.rs`
- **Service registry + locked-response** → `src/service/{mod,locked}.rs`
- **Auth injection (per type)** → `src/auth/{mod,bearer,basic,header,query,path,oauth2}.rs`
- **Admin endpoints** → `src/server/{mod,routes,static_files}.rs`
- **Lifecycle endpoints** (`setup`, `unlock`, `lock`, `vault/*`, `approve/*`) → `src/server/routes.rs`
- **Web Push** → `src/notify/{mod,webpush}.rs`
- **CLI install / connect / update** → `src/cli/{install,connect,update,generate}.rs`
- **Service definitions** → `services/{system,llm,channel,integration}/<id>/{service,recipe,policy}.toml`
- **Service protocol spec** (TOML schema) → `PROTOCOL.md`
- **README / quick-start / API reference** → `README.md`
