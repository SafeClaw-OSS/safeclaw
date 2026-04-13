# SafeClaw Cryptographic Protocol v2

**Status:** Draft
**Version:** 2.0
**Scope:** OSS SafeClaw (open source repository); not Pro-specific infrastructure

> **Note on versioning.** SafeClaw has never shipped a formally-versioned
> cryptographic protocol. The "v1" this document sometimes compares against
> refers to the implicit pre-v2 implementation that existed in early
> development branches. There is no v1-to-v2 migration path in the released
> code; v2 is the first protocol version.

---

## Abstract

SafeClaw is a local vault and HTTP proxy that protects user API keys, OAuth tokens, and related secrets on the user's machine. The vault is unlockable only via a WebAuthn passkey and is encrypted at rest using keys derived from the passkey's PRF extension (FIDO2 `hmac-secret`). This document specifies version 2 of SafeClaw's cryptographic protocol: the on-disk file formats, the key derivation chain, the authentication ceremonies, and the operational state transitions that together implement a passkey-gated envelope-encrypted vault with per-write key rotation, channel-bound assertions, and multi-credential disaster recovery.

Key design choices:

1. **KEK derivation** uses a per-credential `prf_salt` (stored in each wrapped DEK entry on disk) as the HKDF salt — not any server-held secret. Each credential's wrapping is domain-separated via `credentialId` in the HKDF info, and the protocol version is embedded via a `wrap_version` field.
2. **WebAuthn assertions are channel-bound** to the specific HTTP request being authorized via `clientDataJSON.challenge`. The server recomputes the binding from the actual request and compares in constant time.
3. **Transport confidentiality is delegated entirely to TLS.** There is no application-layer encryption layer. Local loopback deployments accept that a sibling process which can snoop loopback traffic can also read `/proc/$pid/mem` and `data/`.
4. **The DEK rotates on every vault write.** Combined with per-credential `prf_salt` rotation, this provides narrow-window forward secrecy against the realistic "historical disk backup leak plus later one-shot rawPRF memory capture" scenario.

Foundational choices kept throughout: envelope encryption (DEK wrapped by credential-derived KEK), WebAuthn PRF as the key derivation primitive, and WebAuthn ECDSA as the authentication primitive.

---

## 1. Introduction

### 1.1 Motivation

SafeClaw is a local vault and proxy for LLM agents. The user stores API credentials encrypted on disk, unlockable with a biometric or security-key gesture. An HTTP proxy on localhost (default port 23295) accepts plain-text agent requests and injects credentials into the outgoing upstream requests. The vault and the proxy share the same process; the vault is encrypted at rest and decrypted into memory only while the user has unlocked it.

The protocol aims to satisfy four properties that a naive design easily misses:

- **KEK derivation hygiene.** KEKs are derived exclusively from credential-local material (PRF output + rotating `prf_salt`), with domain separation via `credentialId` and `wrap_version` in the HKDF info. No server-held long-lived secret participates in the at-rest key derivation, so there is no entanglement between transport-layer and at-rest key lifecycles.

- **Spec-compliant WebAuthn verification.** Every WebAuthn assertion's `clientDataJSON.challenge` is explicitly verified against a server-recomputed channel binding hash. This closes WebAuthn Level 3 §7.2 step 11, which a surprising number of RPs skip. The binding includes `server_random ‖ request_hash`, so the assertion commits to the specific operation.

- **Transport delegated to TLS.** The protocol has no application-layer confidentiality envelope. Remote deployments run under TLS 1.3; local loopback deployments accept that a sibling process which can snoop loopback can also read the vault files directly.

- **Forward-secret-ish at-rest rotation.** The DEK rotates on every write, and the acting credential's `prf_salt` rotates via a single two-eval PRF ceremony. This gives narrow-window forward secrecy against the "past backup + later rawPRF capture" scenario without requiring interactive protocols or hardware-assisted key destruction.

### 1.2 Scope of this document

This document specifies:

- The cryptographic primitives and domain separation conventions used by v2.
- The byte-level format of every file stored in the `data/` directory.
- The HTTP request and response schemas for all vault-related endpoints.
- The state transitions for setup, unlock, vault read, vault write, passkey management, and offline unlock.
- The security properties v2 achieves, and the attacks it explicitly does not attempt to mitigate.

This document does **not** specify:

- The service protocol (see [PROTOCOL.md](PROTOCOL.md) for the declarative `service.toml` and `recipe.toml` format).
- The proxy forwarding logic or access policy evaluation.
- CLI tooling for the offline unlock handshake (the wire format is specified here; the implementation lives in a separate repository).
- Pro-specific infrastructure outside the OSS SafeClaw binary.

### 1.3 Relationship to `PROTOCOL.md`

`PROTOCOL.md` (versioned independently, also at v2) defines the **service protocol**: the shape of `service.toml` and `recipe.toml`, the `[[api]]` block semantics, the access policy rules, and so on. It answers the question *what SafeClaw proxies and how*.

This document (`PROTOCOL-v2.md`) defines the **cryptographic protocol**: the shape of the at-rest vault, the key derivation chain, and the authenticated request schemas. It answers the question *how SafeClaw stores and gates the secrets it proxies*.

The two protocols are orthogonal. Changes to the service protocol generally do not touch cryptographic state, and changes to the cryptographic protocol generally do not touch service definitions. Each evolves on its own version number.

---

## 2. Threat Model

Security claims are only meaningful relative to an explicit threat model. Being precise about what is and is not in scope is a requirement of this specification, not a disclaimer.

### 2.1 Trust boundary

**Trusted:**

- The user's authenticator: the FIDO2 hardware token, platform authenticator (Touch ID, Windows Hello), or OS-level passkey store that holds the ECDSA signing key and the `hmac-secret` material for each credential. The `hmac-secret` is assumed to be non-extractable and to be evaluable only under user verification.
- The browser process and its memory during an active SafeClaw session. Specifically, we trust that intermediate values like `rawPRF` and `userKey`, which live briefly in JavaScript memory, are not continuously exfiltrated by a persistent adversary.
- The SafeClaw server process and its memory while the vault is unlocked. The DEK and the full vault plaintext are present in RAM during unlocked periods.
- The operating system's CSPRNG (`/dev/urandom` or equivalent).

**Untrusted:**

- All files written to `data/`, after they are written and before they are unlinked. Files may leak via backups, forensic imaging, stolen laptops, cloud sync, or routine disk forensics.
- Network traffic, in all cases except where TLS 1.3 is active end to end.
- Other processes on the same host.
- Any system the vault has been restored to, other than the original.

### 2.2 Threats in scope

v2 is designed to defend against the following attacker capabilities.

| # | Capability | v2 defense |
|---|------------|------------|
| A1 | One-shot exfiltration of `data/` | Cannot decrypt without the authenticator. |
| A2 | Persistent exfiltration of `data/` over time | Same as A1; no additional exposure. |
| A3 | One-shot memory capture of `rawPRF` for a specific `prf_salt` | Attacker gains access to the vault state current at the moment of capture. After the next write by that credential, the `prf_salt` rotates and the captured `rawPRF` is useless. Historical snapshots protected if the acting credential has rotated since the snapshot. |
| A4 | Historical backup plus later one-shot `rawPRF` capture | If any credential active in the window between the backup and the capture has rotated its `prf_salt`, the historical wrapped entries for that credential are not decryptable with the captured `rawPRF`. A credential dormant across the entire window remains a liability (see §9.4). |
| A5 | Full network traffic capture | TLS protects transport. Local loopback deployments assume no network adversary. |
| A6 | Replay of a captured valid request | `ChallengeStore` single-use enforcement combined with channel binding makes replay infeasible. |
| A7 | Cross-request assertion transplantation | `request_hash` is part of the channel binding, so the signature is bound to one specific operation. |

### 2.3 Threats explicitly out of scope

| # | Capability | Rationale |
|---|------------|-----------|
| B1 | Authenticator compromise (physical theft of an unlocked device, biometric bypass, malicious hardware firmware) | The entire trust anchor of v2 is that `hmac-secret` is non-extractable and gated on user verification. If the authenticator will sign whatever is asked of it, no protocol can save us. |
| B2 | Sustained malicious browser extension or injected script | A persistent adversary inside the browser can exfiltrate `rawPRF` on every session, effectively turning the authenticator into an oracle. Channel binding limits the blast radius of any one request but does not prevent ongoing compromise. |
| B3 | Sustained compromise of the SafeClaw host process | A rootkit that reads `/proc/$safeclaw_pid/mem` has direct access to DEK plaintext after unlock. Zeroization mitigates the idle window but does not close it. |
| B4 | Side-channel attacks (power analysis, EM, cache-timing against AEAD) | Out of scope; mitigation provided only by constant-time primitive selection. |
| B5 | Supply-chain attacks against the SafeClaw binary or its dependencies | Handled by reproducible builds and dependency auditing, outside this document. |
| B6 | Quantum adversaries | ECDH and ECDSA are not post-quantum secure. A hybrid migration is future work (§11). |

### 2.4 Non-threats

Two scenarios sometimes appear in vault threat models that v2 explicitly does not treat as threats:

- **Forgotten passkey.** If the user loses access to their passkey, the vault is unrecoverable by design (unless they registered a recovery credential). This is a usability concern, not a security failure. The protocol provides multi-credential registration as a mitigation.

- **Rubber-hose cryptanalysis.** An adversary who can compel the user to unlock the vault wins by definition. No cryptographic protocol helps here.

---

## 3. Design Decisions

This section records the key design choices, with the reasoning for each. Changes to these choices in future versions should be accompanied by the corresponding reasoning.

### 3.1 WebAuthn PRF is the key derivation primitive (not ECDSA signing)

A WebAuthn credential exposes two distinct capabilities, each backed by separate authenticator-internal material:

- **ECDSA P-256 signing** over the assertion payload. The signature is public and randomized. This is an *authentication* primitive: it proves possession of the credential but does not produce reusable secret output.
- **PRF extension** (FIDO2 `hmac-secret`), which evaluates `HMAC-SHA-256` under a per-credential key, `hmac_secret`, that never leaves the authenticator. The output is deterministic given the same salt and is suitable for direct use as symmetric key material. This is a *key derivation* primitive.

v2 uses PRF for key derivation and ECDSA for assertion verification. Signatures are never used as keys; they are public by design and structurally unsuitable.

### 3.2 Envelope encryption: DEK wrapped under KEK

The vault content is encrypted with a **Data Encryption Key (DEK)**, a 32-byte value generated by the operating system CSPRNG. The DEK has no mathematical relationship to the passkey. The DEK is wrapped (encrypted) under a **Key Encryption Key (KEK)** derived from the passkey's PRF output.

The DEK/KEK split is the standard envelope-encryption pattern used by AWS KMS, GCP KMS, Signal, and every serious at-rest encryption design. It enables operations that are otherwise impossible or prohibitively expensive:

- Adding a recovery credential without re-encrypting the vault.
- Rotating credential wrapping without re-encrypting the vault.
- Rotating the DEK without re-deriving everything from the passkey.

The user-facing claim "your vault is encrypted with your passkey" remains accurate: the decryption path terminates in PRF output from the passkey, and no alternative unlocking mechanism exists.

### 3.3 Per-write DEK rotation with in-vault peer KEKs (Option D)

Every vault write generates a fresh `DEK_new` and re-encrypts the entire vault plaintext under it. To support multiple registered credentials without requiring all credentials to be present for each rotation, v2 stores each credential's current KEK inside the vault plaintext, under a reserved `peer_keks` field.

On a write by credential A:

1. A unwraps its own entry in `wrapped_deks.bin` using its PRF output, yielding `DEK_old`.
2. A decrypts the vault, reading out `peer_keks` (a map from `credentialId` to its current KEK, base64-encoded).
3. A generates `DEK_new`, re-encrypts the (mutated) vault plaintext, and updates only `peer_keks[credentialId_A]` to A's new KEK (the new KEK being derived from A's rotated `prf_salt_next`).
4. A constructs new wrapping entries for every credential: A's own entry uses the new KEK; every other credential's entry uses the stored `peer_keks[X]` value.

The invariant is: **`peer_keks[X]` is updated only when credential X itself performs a write.** Between X's writes, its KEK is stable, so any other credential can use the stored value. X's next read operation derives the same KEK from its (unchanged) PRF output, matching the stored entry.

This design achieves:

- Any-of-N unilateral DEK rotation (a single credential can rotate without help).
- Bounded storage (the `peer_keks` map is O(N) in the number of registered credentials, not O(writes)).
- Per-credential independent `prf_salt` rotation schedules.
- No append-only growth, no catch-up chain walks.

The alternative design that was considered and rejected is a DEK forward chain (append-only `dek_chain.enc`, each entry encrypting `DEK_{i+1}` under `DEK_i`). It provides equivalent forward secrecy properties but has unbounded storage growth. Option D is equivalent in security and strictly better in storage and complexity.

### 3.4 Per-credential `prf_salt` rotation via two-eval PRF

When a credential performs a write, it rotates its own `prf_salt` from `salt_curr` to a freshly generated `salt_next`. In a single WebAuthn ceremony, the client requests two PRF evaluations:

```text
rawPRF_curr = PRF(hmac_secret, salt_curr)   // to unwrap the existing entry
rawPRF_next = PRF(hmac_secret, salt_next)   // to wrap under the new KEK
```

This uses the WebAuthn Level 3 `prf.eval.first` and `prf.eval.second` fields, backed by the CTAP2 `hmac-secret` extension's dual-salt mode. Interoperability has been verified on the authenticators relevant to this project; see `scripts/prf-test.html` for the verification page.

A single user gesture (one Touch ID or one security key tap) yields both outputs. The user experience is identical to a non-rotating unlock.

### 3.5 Transport: TLS only, no application-layer ECIES

v1 wrapped every sensitive request body in an application-layer ECIES envelope: an ephemeral client P-256 key × the server's long-lived `sc_pk`, followed by HKDF and AES-256-GCM. v2 removes this layer entirely. Three reasons:

1. **Redundant for remote deployments.** A SafeClaw instance reachable only via HTTPS gets transport confidentiality, integrity, and forward secrecy from TLS 1.3 directly. The application-layer envelope is a second, weaker, slower copy of the same function.
2. **Not actually forward-secure.** The v1 envelope used the server's long-lived private key on the server side of the DH. Capture of `sc_sk.jwk` at any time decrypts every past captured envelope. TLS 1.3 ephemeral-ephemeral does not have this problem.
3. **Loopback deployments are already accepted as open.** On a purely local deployment, a sibling process with access to read loopback traffic also has access to read `data/` and `/proc/$pid/mem`. Adding an application-layer envelope changes none of those, and the protection it provides against "one specific process snooping loopback without having any other access" is not a threat model we adopt.

Consequences of this decision:

- `src/crypto/ecies.rs` is deleted.
- `data/sc_pk.jwk` and `data/sc_sk.jwk` are not created by v2, and are removed during migration.
- The client helper `e2eEncrypt` in `public/safeclaw-client.js` is deleted.
- Request and response bodies are plaintext JSON inside the TLS tunnel (or inside loopback HTTP).

### 3.6 Channel binding: assertion commits to the specific request

Every WebAuthn-authenticated request in v2 binds the signed assertion to the specific operation being authorized. The server issues a one-time `server_random` (16 bytes from the `ChallengeStore`); the client computes a `binding` hash over `(server_random, request_hash)`; the `binding` is used as the WebAuthn challenge passed to `navigator.credentials.get`; on return, the authenticator has signed over `authenticatorData ‖ SHA-256(clientDataJSON)` where `clientDataJSON.challenge` is the `binding`.

The server, after parsing the request, recomputes the `binding` from the actual request fields and the claimed `server_random`, and **explicitly verifies** that `clientDataJSON.challenge` equals the recomputed binding. This closes the v1 spec compliance gap and also binds the signature to the specific HTTP method, path, and body of the operation.

### 3.7 XChaCha20-Poly1305 for all symmetric encryption

v2 standardizes on **XChaCha20-Poly1305** (IETF ChaCha20-Poly1305 with the 24-byte extended nonce construction) for every symmetric encryption in the protocol: the vault, the wrapped DEK manifest, the files in `files/`, and the offline handshake transport.

Rationale:

- 24-byte nonces eliminate the birthday-bound concerns that AES-GCM has when nonces are generated randomly, extending the safe-use ceiling from ~2^32 to ~2^80 encryptions per key.
- Constant-time software implementations are uniform across architectures, without requiring AES-NI hardware.
- The `RustCrypto/chacha20poly1305` crate is a peer of the existing `RustCrypto/aes-gcm` dependency in v1, with the same `aead::Aead` trait surface. The binary size increase is 30–60 KB.

`aes-gcm` remains a compile-time dependency during the migration window, isolated in `src/crypto/v1_compat.rs`. It is removed in a subsequent minor version once migration support is no longer required.

### 3.8 P-256 for all elliptic-curve operations

WebAuthn mandates P-256 ECDSA for the credential signing key. v2 continues to use P-256 for the ECDH operations in the offline unlock handshake, and retains the existing `p256` crate. This keeps the elliptic-curve implementation footprint to one library and one curve.

### 3.9 Minimalism: no server identity, no credential hash in binding

v2 explicitly does not include two fields that might plausibly appear in a conservative design:

- **Server instance identity.** v1 had `sc_pk.jwk` and `sc_sk.jwk`; one might preserve `sc_pk.jwk` as a passive "instance fingerprint" used inside the channel binding. v2 does not. The one-time `server_random` is issued by, and consumed by, a single SafeClaw instance's in-memory `ChallengeStore`. Cross-instance replay fails at the `ChallengeStore` check (another instance never issued that random) regardless of whether instance identity is in the binding. Adding `instance_id` would provide no additional defense at the cost of a new persistent file and a new rotation concern.

- **Credential ID hash.** One might include `H(credentialId)` in the binding to "bind the assertion to the credential that signed it". v2 does not, because this is already cryptographically enforced by signature verification: the server looks up the claimed `credentialId` in `passkeys.json` to find `(x, y)`, and verifies the signature under that public key. Only the holder of the corresponding private key can produce a signature that verifies. Adding `H(credentialId)` to the binding would introduce a redundant consistency check whose maintenance is non-trivial (must be re-verified on every refactor of the lookup path) without providing new protection.

Both omissions follow the principle: only include in the binding what is cryptographically necessary and semantically distinct. Defense in depth through redundancy is a valid engineering stance in general, but for a binding hash, every extra field widens the invariant surface area without widening the attack surface it protects against.

---

## 4. Cryptographic Primitives

### 4.1 Notation

- `‖` denotes byte string concatenation.
- `H(X)` denotes SHA-256(X), 32 bytes output.
- `KDF(ikm, salt, info, L)` denotes HKDF-SHA-256 with the given parameters and output length `L` in bytes. When `L` is omitted, it is 32.
- `AEAD(k, n, p, a)` denotes XChaCha20-Poly1305 with 32-byte key `k`, 24-byte nonce `n`, plaintext `p`, and associated data `a`. The output is `ciphertext ‖ tag` where the Poly1305 tag is 16 bytes.
- `AEAD⁻¹(k, n, c, a)` is the inverse: decryption with authentication check. Returns plaintext on success, error on AEAD tag verification failure.
- `OsRng(L)` is `L` bytes of cryptographically secure randomness from the operating system CSPRNG.
- `b64(X)` is standard base64 with padding (for binary-in-JSON wire representation).
- `b64u(X)` is URL-safe base64 without padding (for WebAuthn and JWK conventions).
- `u16_be(n)` is `n` encoded as 2 bytes, big-endian.

### 4.2 Primitives used

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Hash | SHA-256 (FIPS 180-4) | `sha2` |
| KDF | HKDF-SHA-256 (RFC 5869) | `hkdf` |
| AEAD | XChaCha20-Poly1305 (extended-nonce ChaCha20-Poly1305) | `chacha20poly1305` |
| Signature verification | ECDSA-P-256 (FIPS 186-4), for WebAuthn assertions | `p256::ecdsa` |
| Key agreement | ECDH-P-256 (NIST SP 800-56A), for offline unlock handshake | `p256::ecdh` |
| PRF (authenticator-internal) | HMAC-SHA-256 via FIDO2 `hmac-secret` | Authenticator firmware |
| Constant-time comparison | Subtle (timing-safe) equality | `subtle` |
| Secure random | OS CSPRNG | `rand::rngs::OsRng` |

All primitives are provided by the RustCrypto suite of crates except the authenticator-internal HMAC, which is evaluated inside the user's authenticator hardware under the WebAuthn PRF extension.

### 4.3 Domain separation conventions

Every HKDF `info` string and every AEAD `associated_data` blob begins with a stable prefix of the form `"safeclaw/v2/<purpose>"`. A single byte 0x00 follows the purpose string; subsequent bytes are context-specific. Info strings are never reused across different purposes, and AADs for different file types are always distinguishable.

The complete inventory of domain separators appears in Appendix A.

---

## 5. Key Hierarchy

```text
┌──────────────────────────────────────────────────────────────────┐
│ Authenticator (FIDO2 / OS passkey store)                         │
│   Per credential:                                                │
│     - ECDSA P-256 signing key     (assertions)                   │
│     - hmac_secret, 32B, opaque    (PRF extension)                │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       │  prf.eval.first  = prf_salt
                       │  prf.eval.second = prf_salt_next   (on writes)
                       ▼
  rawPRF = HMAC-SHA-256(
              hmac_secret,
              "WebAuthn PRF" ‖ 0x00 ‖ prf_salt
           )
                       │
                       │  HKDF-Expand
                       │    ikm  = rawPRF
                       │    salt = zeros(32)
                       │    info = "safeclaw/v2/userkey" ‖ 0x00 ‖ credentialId
                       │    L    = 32
                       │
                       │  [computed in browser; zeroized after transmission]
                       ▼
  userKey (32B)
                       │
                       │  HKDF-Expand
                       │    ikm  = userKey
                       │    salt = prf_salt
                       │    info = "safeclaw/v2/kek" ‖ 0x00 ‖ u16_be(wrap_version)
                       │           ‖ credentialId
                       │    L    = 32
                       │
                       │  [computed on server; zeroized after wrap/unwrap]
                       ▼
  KEK (32B)
                       │
                       │  AEAD⁻¹ / AEAD (XChaCha20-Poly1305)
                       │    nonce = aead_nonce  (from wrapped_deks entry)
                       │    aad   = "safeclaw/v2/wrap" ‖ 0x00 ‖ u16_be(wrap_version)
                       │            ‖ credentialId
                       ▼
  DEK (32B)
                       │
                       │  AEAD⁻¹ / AEAD (XChaCha20-Poly1305)
                       │    nonce = vault_nonce (from vault.enc header)
                       │    aad   = "safeclaw/v2/vault" ‖ 0x00 ‖ u16_be(version)
                       │            ‖ vault_nonce
                       ▼
  Vault plaintext JSON
  {
    "services":        { ... },
    "files":           [ ... ],
    "model":           { ... },
    "policy_defaults": { ... },
    "notifications":   { ... },
    "peer_keks": {
      "<credentialId_b64>": "<KEK_b64 32B>",
      ...
    }
  }
```

### 5.1 Key roles and lifetimes

| Name | Derivation | Lifetime | Zeroization trigger |
|------|-----------|----------|---------------------|
| `hmac_secret` | Authenticator-generated at credential creation | Credential lifetime | Handled by authenticator firmware; never reaches software |
| `rawPRF` | `HMAC(hmac_secret, "WebAuthn PRF" ‖ 0x00 ‖ prf_salt)` | One WebAuthn ceremony | Browser JS overwrites the `Uint8Array` after HKDF |
| `userKey` | `HKDF(rawPRF, salt=0, info="safeclaw/v2/userkey" ‖ 0x00 ‖ credentialId)` | One request round-trip | Browser: after request transmission. Server: after KEK derivation. |
| `KEK` | `HKDF(userKey, salt=prf_salt, info="safeclaw/v2/kek" ‖ ...)` | One cryptographic operation on the server | Immediately after AEAD wrap or unwrap |
| `DEK` | Random (fresh generation) or unwrap from `wrapped_deks.bin` | One write operation (write path) or the in-memory unlocked session (read path) | After vault encrypt/decrypt completes; on vault lock |
| `peer_keks[X]` | Value stored inside vault plaintext | Until credential X performs its next write | Zeroized when vault locks or when X rotates |

### 5.2 Why these derivation parameters

- **PRF salt in HKDF-Expand for KEK.** The KEK derivation uses `prf_salt` as the HKDF `salt` parameter. This serves as domain separation between KEKs derived from the same credential with different `prf_salt` values, and it is colocated with the wrapped entry on disk (the `prf_salt` lives in the `wrapped_deks.bin` header), so there is no separate "salt state file" that can get out of sync.

- **`credentialId` in info strings.** Including `credentialId` in the HKDF info string for both `userKey` and `KEK` derivations domain-separates credentials from each other. A rawPRF leak for credential A does not give information about credential B's KEKs, even if both are derived from the same underlying PRF ceremony on a shared hardware token.

- **`wrap_version` in KEK info and wrap AAD.** The `wrap_version` field is a 2-byte big-endian protocol version (currently 0x0002). It is included in the KEK HKDF info and in the wrap AEAD AAD. This ensures that an attacker cannot trick a v3 server into unwrapping a v2 wrapped entry with v3 semantics, even if the underlying cryptographic keys happened to collide.

---

## 6. Wire Formats

All binary files begin with a 4-byte magic and a 2-byte big-endian version. All multi-byte integers are big-endian unless otherwise specified. All strings are UTF-8. JSON values follow RFC 8259.

### 6.1 `wrapped_deks.bin`

The manifest of all registered credentials' wrapping entries. Rewritten atomically on every vault write, on add-passkey, and on remove-passkey. This file is the single source of truth for how each credential reaches the DEK.

```text
File layout:

Offset  Size  Field
------  ----  -------------------------------------------------
  0      4   magic          = "SCW2"    (0x53 0x43 0x57 0x32)
  4      2   version        = 0x0002
  6      2   entry_count    (uint16, number of credentials, ≥ 1)
  8    var   entries        (concatenation of Entry records)

Entry record layout:

Offset  Size  Field
------  ----  -------------------------------------------------
  0      2   entry_length     (uint16, total length of this record
                               in bytes, including this field itself)
  2      2   cred_id_length   (uint16)
  4      N   credential_id    (raw bytes, N = cred_id_length)
  4+N   32   prf_salt         (random, current prf_salt)
 36+N   24   aead_nonce       (random, fresh per wrap)
 60+N   48   wrapped          (XChaCha20-Poly1305 output:
                               32 bytes ciphertext + 16 bytes tag)
```

The ciphertext protects a 32-byte DEK:

```text
wrapped = AEAD(
  key   = KEK,
  nonce = aead_nonce,
  plain = DEK,
  aad   = "safeclaw/v2/wrap" ‖ 0x00 ‖ u16_be(0x0002) ‖ credential_id
)

KEK = KDF(
  ikm  = userKey,
  salt = prf_salt,
  info = "safeclaw/v2/kek" ‖ 0x00 ‖ u16_be(0x0002) ‖ credential_id,
  L    = 32
)
```

Each entry self-contains the `prf_salt` required to derive its KEK. A credential performing a read fetches `prf_salt` from its entry, derives `userKey` and `KEK` client-side and server-side respectively, and unwraps the DEK.

**Note on credential ordering.** The order of entries in `wrapped_deks.bin` is not cryptographically significant. Servers MAY rewrite the file in any order, and clients MUST search by `credential_id` rather than by position.

### 6.2 `vault.enc`

A single XChaCha20-Poly1305 ciphertext of the vault plaintext JSON, plus a header.

```text
Offset  Size  Field
------  ----  ------------------------------------------------
  0      4   magic         = "SCV2"    (0x53 0x43 0x56 0x32)
  4      2   version       = 0x0002
  6      2   reserved      = 0x0000
  8     24   aead_nonce    (random, fresh per write)
 32    var   wrapped_vault (AEAD output, variable length)
```

The AEAD call:

```text
wrapped_vault = AEAD(
  key   = DEK,
  nonce = aead_nonce,
  plain = UTF-8 bytes of the vault plaintext JSON,
  aad   = "safeclaw/v2/vault" ‖ 0x00 ‖ u16_be(0x0002) ‖ aead_nonce
)
```

The plaintext is UTF-8 encoded JSON. The plaintext JSON has a reserved top-level key, `peer_keks`:

```json
{
  "services":        { ... },
  "files":           [ ... ],
  "model":           { ... },
  "policy_defaults": { ... },
  "notifications":   { ... },
  "peer_keks": {
    "<credentialId_1_b64>": "<KEK_1_b64>",
    "<credentialId_2_b64>": "<KEK_2_b64>"
  }
}
```

**Invariants for `peer_keks`:**

1. The key set of `peer_keks` MUST equal the set of `credential_id` values in `wrapped_deks.bin`.
2. `peer_keks[credential_id_X]` MUST equal the KEK that would be derived from credential X's current PRF output under credential X's current `prf_salt` (which is stored in X's `wrapped_deks.bin` entry).
3. The server never trusts the client to set or modify `peer_keks`. Every operation that accepts vault plaintext from the client strips any client-supplied `peer_keks` and substitutes the server's authoritative value before re-encryption.

### 6.3 `passkeys.json`

JSON metadata for registered credentials. Contains public material only.

```json
{
  "<credentialId_b64>": {
    "x":          "<b64 32B P-256 x coordinate>",
    "y":          "<b64 32B P-256 y coordinate>",
    "deviceName": "<string>",
    "createdAt":  <unix_millis>
  }
}
```

v2 does not add any new fields to this file beyond the v1 schema. The per-credential `prf_salt` is part of `wrapped_deks.bin`, not `passkeys.json`.

### 6.4 `files/<uuid>.enc`

Each uploaded vault file is sealed under a per-file DEK. The per-file key is stored in the vault plaintext's `files` array next to the file's metadata. This change from v1 (where files shared the vault DEK) enables file revocation via key deletion and bounds any nonce-collision blast radius to a single file.

```text
Offset  Size  Field
------  ----  ------------------------------------------------
  0      4   magic        = "SCF2"    (0x53 0x43 0x46 0x32)
  4      2   version      = 0x0002
  6      2   reserved     = 0x0000
  8     24   aead_nonce   (random)
 32    var   wrapped      (XChaCha20-Poly1305 output)
```

The AEAD call:

```text
wrapped = AEAD(
  key   = file_key,              // 32B from OsRng at upload time
  nonce = aead_nonce,
  plain = file bytes,
  aad   = "safeclaw/v2/file" ‖ 0x00 ‖ u16_be(0x0002) ‖ file_uuid_bytes
)
```

Vault-side metadata for a file:

```json
{
  "id":        "<uuid>",
  "name":      "<display name>",
  "size":      <int, bytes>,
  "file_key":  "<b64 32B>"
}
```

Removing a file deletes both the `files/<uuid>.enc` file and the metadata entry from the vault `files` array. The vault plaintext without the `file_key` is cryptographically undecryptable even if the on-disk `.enc` file is later recovered from backup, because the per-file key exists only inside the vault plaintext.

### 6.5 `instance.json`

Optional runtime bookkeeping for the server. Contains no cryptographic material.

```json
{
  "protocol_version": 2,
  "initialized_at":   <unix_millis>,
  "last_write_at":    <unix_millis>
}
```

If missing, the server creates it on first successful write. It exists to aid forensics and startup consistency checks but is not part of the cryptographic trust boundary.

---

## 7. Channel Binding

### 7.1 Purpose

WebAuthn assertions by themselves prove "the user authenticated recently", but without an explicit binding to the request they do not prove "the user authorized *this specific request*". v2 binds every assertion to the specific HTTP operation being authorized, so that captured assertions cannot be transplanted to any other request.

### 7.2 Definition

Given a pending HTTP operation with method `M`, path `P`, and JSON body `B`, the binding is computed as:

```text
request_hash = SHA-256(
     uppercase_ascii(M)
  ‖  0x00
  ‖  utf8(P)
  ‖  0x00
  ‖  canonical_body_bytes(B)
)

binding = SHA-256(
     "safeclaw/v2/binding"
  ‖  0x00
  ‖  server_random                (16B)
  ‖  request_hash                 (32B)
)
```

The `binding` hash is 32 bytes. It is passed verbatim as the WebAuthn `challenge` parameter to `navigator.credentials.get`:

```js
navigator.credentials.get({
  publicKey: {
    challenge: binding,               // Uint8Array, 32B
    rpId: "safeclaw.example.com",
    userVerification: "required",
    allowCredentials: [{ type: "public-key", id: credentialId }],
    extensions: {
      prf: {
        eval: {
          first:  prf_salt_curr,
          second: prf_salt_next       // only on write operations
        }
      }
    }
  }
})
```

The browser serializes `binding` as base64url without padding and writes it into the `challenge` field of `clientDataJSON`. The authenticator signs over `authenticatorData ‖ SHA-256(clientDataJSON)`. The server, on receiving the request, recomputes the binding and verifies that `clientDataJSON.challenge` (after base64url decode) equals the recomputed binding.

### 7.3 Canonicalization of the request body

The `canonical_body_bytes(B)` function is defined as follows:

1. Start with the JSON object `B` as sent in the HTTP request body.
2. Remove the following top-level fields if present:
   - `assertion`
   - `server_random`
   - `user_key`
   - `user_key_next`
3. Serialize the remaining object using **RFC 8785 JSON Canonicalization Scheme (JCS)**: keys sorted lexicographically at every level of nesting, no insignificant whitespace, shortest roundtrip form for numbers, UTF-8 encoding for strings.
4. The result is the UTF-8 byte string to be hashed.

#### 7.3.1 Why exclude `assertion`

The assertion is the signed output produced *using* the binding. If the binding included the assertion, the dependency graph would be circular: `binding` would depend on `assertion` which depends on `binding`. Excluding the assertion breaks the cycle.

The assertion itself is not a field the user is "authorizing" — it is the authorization. All of the *semantic* fields the user consents to (the vault update, the file upload, the credential to register) are included in the hash.

#### 7.3.2 Why exclude `server_random`

`server_random` is included directly in the binding as its own 16-byte segment, not via the body hash. Including it redundantly in the body canonicalization would be harmless but wasteful, and excluding it matches the "only include fields that represent user intent" stance.

#### 7.3.3 Why exclude `user_key` and `user_key_next`

These are cryptographic values produced by the client from its PRF output. They are not user-visible semantic fields, and they are what the client is conveying *to* the server rather than an expression of user intent. They also vary unpredictably from request to request in ways that do not affect what the user is authorizing. Excluding them keeps the canonical form focused on intent.

#### 7.3.4 Why include `prf_salt_next`

`prf_salt_next` *is* a semantic claim: the user is authorizing "rotate my credential's salt to this specific new value". An attacker who could substitute `prf_salt_next` could force a silent rotation to a value the user does not know, effectively locking the user out. Binding prevents this.

### 7.4 Server-side verification

After receiving a request and decoding its body:

```text
1. Verify the request body is valid JSON and has the expected top-level fields
   (server_random, credential_id, assertion, and operation-specific fields).

2. Look up server_random in ChallengeStore:
   - If absent or expired: return 401 Unauthorized.
   - Otherwise: consume (remove) it from the store.

3. Compute request_hash from the actual request fields:
   - method and path from the HTTP request line
   - canonical_body_bytes(body_with_exclusions)

4. Compute binding_expected = SHA-256(
     "safeclaw/v2/binding" ‖ 0x00 ‖ server_random ‖ request_hash
   )

5. Parse clientDataJSON from assertion.client_data_json (base64-decoded):
   - Verify JSON parses cleanly.
   - Verify clientDataJSON.type == "webauthn.get" (or "webauthn.create" for
     setup/identity variants).
   - Verify clientDataJSON.origin is in the allowed origin list
     (constant-time compare after canonicalization).

6. Verify clientDataJSON.challenge:
   - Decode as base64url without padding.
   - Constant-time compare to binding_expected.
   - Abort on mismatch.

7. Verify rpIdHash:
   - Compute expected_rp_id_hash = SHA-256(rpId)
   - Compare against authenticatorData[0..32] (constant-time).

8. Verify User Present flag:
   - authenticatorData[32] & 0x01 == 0x01

9. Look up (x, y) in passkeys.json by credential_id.

10. Build signed_message = authenticatorData ‖ SHA-256(clientDataJSON).

11. Verify ECDSA-P-256 signature against (x, y) and signed_message.

All eleven checks must pass. Any failure returns 401 Unauthorized with a generic
error message (no timing side channel on which check failed).
```

### 7.5 Variant binding strings for special flows

Setup and identity operations use a different domain-separator suffix to prevent cross-flow assertion replay:

| Flow | Domain separator |
|------|-----------------|
| Normal vault operation | `"safeclaw/v2/binding"` |
| Setup (initial vault creation) | `"safeclaw/v2/binding-setup"` |
| Identity (add/remove passkey) | `"safeclaw/v2/binding-identity"` |
| Offline unlock handshake | `"safeclaw/v2/binding-offline"` |

Each of these is followed by `0x00` and the same `(server_random, request_hash)` or equivalent fields. A normal unlock assertion cannot be replayed as a setup assertion, and so on.

---

## 8. Operations

This section specifies each protocol operation: its purpose, its pre- and post-conditions, the HTTP schemas, and the client and server flows.

### 8.1 Setup: initial vault creation

**Purpose.** Create a fresh vault and register one or more passkeys that can unlock it. No prior vault state exists (or the user is overwriting an existing vault after proving possession of an existing passkey).

**Pre-state.** Either `data/` is empty, or it contains a v2 vault that the user wants to overwrite.

**Post-state.** `data/vault.enc`, `data/wrapped_deks.bin`, and `data/passkeys.json` exist and are mutually consistent.

**Client flow.**

1. Client calls `GET /session` to obtain a fresh `server_random`. Pre-setup, the response's `wrapped_deks` list is empty; this is expected — setup uses the same `/session` endpoint as every other authenticated operation so that all requests share the same `ChallengeStore` freshness discipline.
2. For each passkey being registered:
   - Call `navigator.credentials.create` with PRF extension enabled. Receive the new credential, extract `credentialId`, `x`, `y`.
   - Generate `prf_salt_initial = OsRng(32)`.
3. Compose the `/vault/setup` body (with `server_random` and without assertion fields), then compute the setup channel binding:
   ```
   binding_setup = SHA-256(
       "safeclaw/v2/binding-setup" || 0x00
     || server_random
     || SHA-256("POST" || 0x00 || "/vault/setup" || 0x00 || canonical_body_without_assertions)
   )
   ```
4. For each passkey, call `navigator.credentials.get` with `challenge = binding_setup` and `prf.eval.first = prf_salt_initial`. This yields a channel-bound assertion plus `rawPRF_initial`. Derive `userKey_initial = HKDF(rawPRF_initial, salt=0, info="safeclaw/v2/userkey" || 0x00 || credentialId)`.
5. Client POSTs to `/vault/setup`:
   ```json
   {
     "server_random": "<b64 16B>",
     "vault":         { /* initial vault JSON, client MUST NOT set peer_keks */ },
     "passkeys": [
       {
         "credential_id":     "<b64>",
         "x":                 "<b64 32B>",
         "y":                 "<b64 32B>",
         "device_name":       "<string>",
         "prf_salt_initial":  "<b64 32B>",
         "user_key_initial":  "<b64 32B>",
         "assertion":         { "authenticator_data":"<b64>", "client_data_json":"<b64>", "signature":"<b64>" }
       }
     ],
     "existing_credential_id": "<b64>" | null,
     "existing_assertion":     { ... } | null
   }
   ```

**Server flow.**

1. Consume `server_random` from `ChallengeStore`. On miss: 401.
2. Reject if `vault.enc` exists and `existing_credential_id` is null, unless the server is configured to allow clobber.
3. If `vault.enc` exists, verify the `existing_assertion` against the existing passkey identified by `existing_credential_id` with binding domain `"safeclaw/v2/binding-setup-overwrite"`.
4. For each passkey entry in the request, recompute the setup binding and verify the assertion under the provided `(x, y)` with binding domain `"safeclaw/v2/binding-setup"`. Every assertion is fully channel-bound to the specific setup request.
5. Generate `DEK = OsRng(32)`.
6. For each passkey, derive `KEK_initial_i = HKDF(user_key_initial_i, salt=prf_salt_initial_i, info="safeclaw/v2/kek" || 0x00 || u16_be(2) || credentialId_i)`.
7. Build `peer_keks = { credentialId_i: b64(KEK_initial_i) }`.
8. Insert `peer_keks` into the vault JSON (stripping any client-supplied `peer_keks` first).
9. Encrypt vault with `DEK` and a fresh `aead_nonce` to produce `vault.enc`.
10. Build `wrapped_deks.bin` with one entry per passkey, each wrapping `DEK` under `KEK_initial_i` with a fresh per-entry `aead_nonce`.
11. Write `passkeys.json` with the public material `(credentialId, x, y, deviceName, createdAt)`.
12. Atomically commit: write `.tmp` files, then rename in the order specified in §10.2.
13. Zeroize `DEK`, all `KEK_initial_i`, all `user_key_initial_i`, and any intermediate buffers.
14. Respond `{ "ok": true }`.

### 8.2 Session

**Purpose.** Provide the client with the public material needed to prepare a WebAuthn request: the `server_random` freshness token and the list of `(credentialId, prf_salt)` pairs for each registered passkey.

**Pre-state.** Vault exists.

**Request.**

```text
GET /session
(no body, no auth)
```

**Response.**

```json
{
  "server_random": "<b64 16B>",
  "wrapped_deks": [
    {
      "credential_id": "<b64>",
      "prf_salt":      "<b64 32B>"
    }
  ]
}
```

**Server flow.**

1. Call `ChallengeStore::issue(client_ip)` which generates `server_random = OsRng(16)`, records `(server_random, now, ip)` in the store, and enforces per-IP rate limits.
2. Read `wrapped_deks.bin`. For each entry, extract `credential_id` and `prf_salt` from the entry header.
3. Return the JSON response.

**Notes.**

- This endpoint is deliberately unauthenticated. It reveals only public material: the credential IDs (which are not secret) and the current `prf_salt` values (which are cryptographically public, like any HKDF salt).
- Rate limiting protects against a flood of `server_random` issuances that would exhaust the in-memory store. Default: 60 per minute per IP.
- The `server_random` lifetime is 5 minutes from issuance to consumption.

### 8.3 Unlock

**Purpose.** Decrypt `vault.enc` into server memory, enabling the proxy to inject credentials into upstream requests.

**Pre-state.** Vault exists and is locked.

**Post-state.** Vault is unlocked; `Vault::plaintext` holds the decrypted JSON in server memory.

**Client flow.**

1. `GET /session` to fetch `server_random` and `wrapped_deks`.
2. Choose a credential (or use discoverable credential flow). Let its `credential_id` and `prf_salt` be known.
3. Prepare body fields for `/vault/unlock`: `{credential_id, server_random}` (no other semantic fields for unlock).
4. Compute `request_hash` over `(POST, /vault/unlock, canonical_body_bytes)`.
5. Compute `binding = SHA-256("safeclaw/v2/binding" ‖ 0x00 ‖ server_random ‖ request_hash)`.
6. Call `navigator.credentials.get` with `challenge=binding`, `allowCredentials=[credential_id]`, `extensions.prf.eval.first=prf_salt`.
7. Extract `rawPRF` from the assertion's PRF extension result.
8. Derive `userKey = KDF(rawPRF, 0, "safeclaw/v2/userkey" ‖ 0x00 ‖ credentialId)`.
9. POST to `/vault/unlock`:
   ```json
   {
     "server_random": "<b64>",
     "credential_id": "<b64>",
     "user_key":      "<b64 32B>",
     "assertion":     { ... }
   }
   ```
10. Overwrite `rawPRF` and `userKey` in the browser after send.

**Server flow.**

1. Consume `server_random` from `ChallengeStore`. On miss: 401.
2. Verify assertion with full channel binding (§7.4).
3. Look up the credential's entry in `wrapped_deks.bin`; extract `prf_salt`, `aead_nonce`, `wrapped`.
4. Compute `KEK = KDF(user_key, prf_salt, "safeclaw/v2/kek" ‖ 0x00 ‖ u16_be(2) ‖ credentialId)`.
5. `DEK = AEAD⁻¹(KEK, aead_nonce, wrapped, aad="safeclaw/v2/wrap" ‖ 0x00 ‖ u16_be(2) ‖ credentialId)`. On AEAD failure: 401 (indicates wrong key).
6. Read `vault.enc` header, extract `aead_nonce`.
7. Decrypt: `plaintext = AEAD⁻¹(DEK, aead_nonce, wrapped_vault, aad="safeclaw/v2/vault" ‖ 0x00 ‖ u16_be(2) ‖ aead_nonce)`.
8. Parse plaintext as JSON. Install into `Vault::plaintext`.
9. Zeroize `user_key`, `KEK`, `DEK`, and the plaintext buffer (the in-memory `Vault::plaintext` is a fresh owned copy).
10. Respond `{ "ok": true }`.

### 8.4 Vault write (rotation)

**Purpose.** Replace the vault contents with a new JSON value, simultaneously rotating the acting credential's `prf_salt` and rotating the DEK. This is the only operation that rotates key material.

**Pre-state.** Vault exists. May or may not be currently unlocked (unlock is not a precondition; the operation unwraps its own DEK).

**Post-state.** `vault.enc` contains the new plaintext under `DEK_new`. `wrapped_deks.bin` is rewritten with fresh entries for every registered credential. The acting credential's entry has a new `prf_salt`, new `aead_nonce`, and new `wrapped`. Other credentials' entries have a new `aead_nonce` and new `wrapped` (wrapping `DEK_new` under their unchanged `peer_keks` KEK), but retain their existing `prf_salt`.

**Client flow.**

1. `GET /session`.
2. Choose the acting credential. Extract `prf_salt_curr`.
3. Generate `prf_salt_next = OsRng(32)`.
4. Build request body (omit `assertion`, `server_random`, `user_key`, `user_key_next`): `{credential_id, prf_salt_next, new_vault}`.
5. Compute `request_hash` and `binding` as in §8.3 steps 4-5.
6. `navigator.credentials.get` with `prf.eval.first=prf_salt_curr, prf.eval.second=prf_salt_next`, `challenge=binding`.
7. Extract `rawPRF_curr` and `rawPRF_next`.
8. Derive `userKey_curr` and `userKey_next`.
9. POST to `/vault/write`:
   ```json
   {
     "server_random":  "<b64>",
     "credential_id":  "<b64>",
     "user_key":       "<b64 32B>",
     "user_key_next":  "<b64 32B>",
     "prf_salt_next":  "<b64 32B>",
     "new_vault":      { ... new full vault JSON ... },
     "assertion":      { ... }
   }
   ```
10. Zeroize client-side secrets after send.

**Server flow.**

1. Consume `server_random`, verify assertion with channel binding.
2. Look up acting credential's entry in `wrapped_deks.bin`; extract current `prf_salt`, `aead_nonce`, `wrapped`.
3. Compute `KEK_curr = KDF(user_key, prf_salt, "safeclaw/v2/kek" ‖ ...)` and unwrap `DEK_old`.
4. Decrypt `vault.enc` with `DEK_old` to obtain `plaintext_old`.
5. Parse `plaintext_old`, extract `peer_keks` (base64-decode each entry into 32-byte KEKs).
6. Strip any client-supplied `peer_keks` from `new_vault`.
7. Start `plaintext_new = new_vault`, inject `plaintext_new["peer_keks"] = peer_keks_map` (the authoritative map from step 5).
8. Compute `KEK_new = KDF(user_key_next, prf_salt_next, "safeclaw/v2/kek" ‖ ...)` for the acting credential.
9. Update `plaintext_new["peer_keks"][credential_id] = b64(KEK_new)`.
10. Generate `DEK_new = OsRng(32)`.
11. Encrypt `plaintext_new` under `DEK_new` with fresh `aead_nonce_vault` → `vault.enc.tmp`.
12. Build new `wrapped_deks.bin.tmp`:
    - For the acting credential: entry with `prf_salt_next`, fresh `aead_nonce_wrap`, `wrapped = AEAD(KEK_new, aead_nonce_wrap, DEK_new, wrap_aad)`.
    - For each other credential X: preserve X's existing `prf_salt`; fresh `aead_nonce_wrap`; `wrapped = AEAD(peer_keks[X], aead_nonce_wrap, DEK_new, wrap_aad)`.
13. Atomic commit: `fsync` both `.tmp` files and the directory, `rename(wrapped_deks.bin.tmp)`, `rename(vault.enc.tmp)`, `fsync` the directory.
14. Update `Vault::plaintext` in memory with `plaintext_new`.
15. Zeroize `DEK_old`, `DEK_new`, `KEK_curr`, `KEK_new`, `user_key`, `user_key_next`, all intermediate buffers.
16. Respond `{ "ok": true }`.

### 8.5 Vault read (with optional filter)

**Purpose.** Return a subset (or all) of the vault plaintext to the client.

**Transport.** v2 returns plaintext JSON directly over TLS. There is no response-sealing layer: the `user_key` and `server_random` required to derive any such seal are already in the request body, so an adversary that can observe the response can also observe the inputs that would regenerate the seal. TLS provides the only meaningful confidentiality boundary for network traffic; on loopback deployments, the threat model (§2.1) already accepts that a sibling process can read the response directly.

**Client flow.** Identical to unlock (§8.3), with an additional optional `select` field in the body:

```json
{
  "server_random": "<b64>",
  "credential_id": "<b64>",
  "user_key":      "<b64>",
  "select":        "services.openai,services.anthropic",
  "assertion":     { ... }
}
```

`select` is an optional comma-separated list of dot-notation path prefixes. When present, the server returns only the matching subtrees. When absent, the server returns the full vault minus `peer_keks`.

**Server flow.**

1. Verify `server_random` and channel binding.
2. Unwrap DEK via this credential.
3. Decrypt vault plaintext.
4. If `select` is present, filter by path prefixes. Path prefixes are treated as an OR/union; the returned JSON preserves the original nesting structure.
5. Remove `peer_keks` from the result.
6. Return the filtered plaintext as JSON.
7. Zeroize `DEK`, `KEK`, `user_key`, plaintext.

**Note on `peer_keks`:** The server MUST strip `peer_keks` from the returned plaintext. `peer_keks` is server-internal state, not user data, and returning it would leak each credential's current KEK to every client that reads the vault.

### 8.6 Identity: add passkey

**Purpose.** Register an additional credential that can unlock the existing vault.

**Pre-state.** Vault exists, at least one registered passkey.

**Post-state.** A new entry appears in `passkeys.json`, `wrapped_deks.bin`, and the vault's `peer_keks`.

**Client flow.**

1. Obtain both credentials in sequence in the same user session:
   - Credential A: the existing unlocking credential. Client gets `server_random`, runs WebAuthn `get` with two-eval PRF to obtain `userKey_A_curr` and `userKey_A_next` under `prf_salt_A_next = OsRng(32)`.
   - Credential B: the new credential. Client calls `navigator.credentials.create` with PRF extension, then `navigator.credentials.get` with `prf.eval.first=prf_salt_B_initial=OsRng(32)` to obtain `rawPRF_B` and an assertion proving possession.
2. POST to `/vault/passkeys/add`:
   ```json
   {
     "server_random":    "<b64>",
     "credential_id":    "<b64 credential A>",
     "user_key":         "<b64>",
     "user_key_next":    "<b64>",
     "prf_salt_next":    "<b64>",
     "assertion":        { ... A's assertion ... },
     "new_passkey": {
       "credential_id":    "<b64 credential B>",
       "x":                "<b64>",
       "y":                "<b64>",
       "device_name":      "<string>",
       "prf_salt_initial": "<b64>",
       "user_key_initial": "<b64>",
       "assertion":        { ... B's assertion ... }
     }
   }
   ```

**Server flow.**

1. Verify A's assertion with binding `"safeclaw/v2/binding-identity"`.
2. Verify B's assertion under the provided `(x, y)` with a nested binding.
3. Unwrap DEK via A. Decrypt vault, obtain `peer_keks`.
4. Compute `KEK_A_new` from `user_key_next` and `prf_salt_next`.
5. Compute `KEK_B_initial` from `user_key_initial` and `prf_salt_initial`.
6. Update `peer_keks[A] = KEK_A_new`, `peer_keks[B] = KEK_B_initial`.
7. Generate `DEK_new`, re-encrypt vault with `plaintext_new` (including the new `peer_keks`).
8. Build new `wrapped_deks.bin`:
   - A's entry: uses `prf_salt_next`, wraps `DEK_new` under `KEK_A_new`.
   - B's entry: uses `prf_salt_initial`, wraps `DEK_new` under `KEK_B_initial`.
   - Any other existing credentials: unchanged `prf_salt`, wrap `DEK_new` under their stored `peer_keks` KEK.
9. Update `passkeys.json` to include B.
10. Atomic commit. Zeroize.

### 8.7 Identity: remove passkey

**Purpose.** Remove a credential from the set that can unlock the vault.

**Pre-state.** Vault exists, at least two registered passkeys, and the acting credential is not the one being removed (attempting to remove the acting credential is rejected).

**Post-state.** The removed credential no longer appears in `passkeys.json`, `wrapped_deks.bin`, or `peer_keks`.

**Client flow.** Standard write (§8.4) with body fields `{credential_id: acting, credential_id_to_remove: X}`.

**Server flow.**

1. Verify assertion.
2. Unwrap, decrypt, rotate DEK as usual.
3. Remove the target credential from `peer_keks` and `passkeys.json`.
4. Rebuild `wrapped_deks.bin` without the removed credential's entry.
5. Commit atomically.

**Backup caveat.** Soft-deleting a credential from the live `data/` directory does not invalidate any backups that still contain the removed credential's old wrapped entry. The README documents that full revocation requires rotating the affected backups.

### 8.8 Files: upload, read, remove

File operations follow the same channel-binding model. Each file has its own random `file_key` generated at upload and stored in the vault's `files` array.

**Upload** goes through the vault write path (§8.4). Server flow:

1. Verify channel binding.
2. Unwrap DEK for acting credential, decrypt vault.
3. `file_key = OsRng(32)`, `file_id = uuid_v4()`.
4. Encrypt file bytes: `AEAD(file_key, fresh_nonce, bytes, aad="safeclaw/v2/file" ‖ 0x00 ‖ u16_be(2) ‖ file_id_bytes)`.
5. Write `files/<file_id>.enc` with the format in §6.4.
6. Append `{id, name, size, file_key}` to vault's `files` array.
7. Run the normal vault rotation path (§8.4 steps 10-15), which re-encrypts the vault with a fresh DEK and the new file metadata.
8. Zeroize `file_key` and all intermediate keys.

**Read** returns the file plaintext as base64 JSON:

1. Verify channel binding.
2. Unwrap DEK via acting credential.
3. Decrypt vault, find the file's `file_key` in the `files` array.
4. Read `files/<id>.enc`, decrypt using `file_key`.
5. Return `{ "name": "<filename>", "data": "<base64>" }` over TLS.
6. Zeroize DEK, KEK, file_key, plaintext.

**Remove** goes through the vault write path:

1. Verify channel binding.
2. Unwrap DEK, decrypt vault, find and remove the file's entry from the `files` array.
3. Delete `files/<id>.enc` from disk.
4. Run the normal vault rotation (§8.4 steps 10-15).
5. Zeroize.

### 8.9 Offline unlock handshake (wire format specification)

The offline unlock handshake allows a user to unlock a SafeClaw instance running on Machine C (the "CLI machine") from a browser running on Machine B, where C and B cannot reach each other over IP. The only communication channel is a short human-readable string that the user copies (or a QR code the user scans) between the two devices.

This section specifies the wire format and the cryptographic protocol. The actual CLI implementation that reads the handshake strings from stdin/QR is deferred to a separate repository.

**Participants.**

- **CLI (C).** Holds `vault.enc`, `wrapped_deks.bin`, `passkeys.json`. Does not have direct access to a browser or to the passkey.
- **Browser (B).** Has access to the user's passkey via WebAuthn. Does not have access to the vault files.
- **Human channel.** The user, who can copy a string of up to ~500 characters from C to B and from B to C.

**Protocol overview.**

```text
CLI (C)                                                    Browser (B)
-------                                                    -----------
generate session_id, cli ephemeral key pair
compose H1
  ────────────────────  "safeclaw:v2:h1:<b64>"  ──────────► (via human)

                                          parse H1
                                          do WebAuthn with channel binding
                                          derive userKey from PRF
                                          generate browser ephemeral key
                                          compute ECDH(br_sk, cli_pk)
                                          derive enc_key
                                          seal (userKey, assertion) under enc_key

                    ◄─────  "safeclaw:v2:h2:<b64>"  ─────── (via human)
parse H2
ECDH(cli_sk, br_pk) → shared
derive enc_key
unseal → (userKey, assertion)
verify assertion (with channel binding to H1)
unwrap DEK, decrypt vault
zeroize ephemeral keys
```

**H1 payload format (CBOR).**

```text
H1 = {
  1: int        // version, must be 2
  2: bytes(16)  // session_id (OsRng from CLI)
  3: bytes(33)  // cli_eph_pk in SEC1 compressed P-256 encoding
  4: bytes(32)  // prf_salt_curr (copied from wrapped_deks entry of target credential)
  5: bytes      // credential_id (the target passkey)
  6: int        // expires_at (Unix seconds, CLI sets to now + 600)
}
```

**H2 payload format (CBOR).**

```text
H2 = {
  1: int        // version, must be 2
  2: bytes(16)  // session_id (copied from H1)
  3: bytes(33)  // br_eph_pk in SEC1 compressed P-256 encoding
  4: bytes(24)  // aead_nonce for XChaCha20-Poly1305
  5: bytes      // ciphertext + tag (the sealed payload)
}
```

**Key derivation for H2 sealing.**

```text
shared   = ECDH(br_eph_sk, cli_eph_pk)                // 32 bytes, x-coordinate
enc_key  = KDF(
             ikm  = shared,
             salt = session_id,
             info = "safeclaw/v2/offline-transport",
             L    = 32
           )
h1_hash  = SHA-256(canonical CBOR of H1)
aad      = "safeclaw/v2/offline-aad" ‖ 0x00 ‖ h1_hash
```

**Sealed payload plaintext (CBOR).**

```text
SealedPayload = {
  1: bytes(32)  // user_key
  2: {          // assertion
    1: bytes    // authenticator_data
    2: bytes    // client_data_json
    3: bytes    // signature
  }
}
```

**Channel binding for offline flow.**

When the browser runs WebAuthn to produce the assertion that will be sealed into H2, the challenge passed to `navigator.credentials.get` is:

```text
binding_offline = SHA-256(
   "safeclaw/v2/binding-offline"
  ‖ 0x00
  ‖ session_id
  ‖ h1_hash
)
```

This commits the assertion to: the session the CLI initiated, the CLI's ephemeral public key, the targeted credential, and the prf_salt being used. An assertion signed in a different context cannot be reused here.

**CLI's verification of H2.**

1. Parse H2 CBOR. Verify `version == 2` and `session_id` matches the outstanding session (the CLI tracks at most one outstanding session at a time).
2. Verify `session_id` has not expired (`now < expires_at` from H1).
3. Compute `shared = ECDH(cli_eph_sk, br_eph_pk)`. Derive `enc_key` and `aad` as above.
4. `sealed_payload_bytes = AEAD⁻¹(enc_key, aead_nonce, ciphertext, aad)`. On AEAD failure: abort, zeroize `cli_eph_sk`.
5. Parse `sealed_payload_bytes` as CBOR. Extract `user_key` and `assertion`.
6. Verify the assertion:
   - Parse `client_data_json`.
   - Verify `type == "webauthn.get"`.
   - Verify `origin` is in allowed list.
   - Verify `clientDataJSON.challenge == base64url(binding_offline)`.
   - Verify `rpIdHash` matches `SHA-256(rpId)`.
   - Verify UP flag.
   - Verify ECDSA signature under the credential's stored `(x, y)`.
7. Derive `KEK = KDF(user_key, prf_salt_curr, "safeclaw/v2/kek" ‖ 0x00 ‖ u16_be(2) ‖ credential_id)`.
8. Look up the credential's entry in `wrapped_deks.bin`, extract `aead_nonce` and `wrapped`.
9. `DEK = AEAD⁻¹(KEK, aead_nonce, wrapped, wrap_aad)`.
10. Decrypt `vault.enc` with `DEK`. Install into `Vault::plaintext`.
11. Zeroize all of: `cli_eph_sk`, `shared`, `enc_key`, `user_key`, `KEK`, `DEK`, and the `sealed_payload_bytes` buffer.

**Security properties.**

1. **Forward secrecy against a passive observer of the human channel.** Capture of both H1 and H2 does not yield the sealed payload, because `shared = ECDH(br_eph_sk, cli_eph_pk)` requires at least one of the ephemeral private keys, and both are ephemeral and zeroized after use.
2. **Replay resistance.** `session_id` is single-use on the CLI side. An H2 replayed to the same session after successful consumption finds no matching outstanding session.
3. **Cross-session binding.** The assertion is bound to `session_id` and `h1_hash`. A browser-side assertion created for a different session cannot be substituted.
4. **Cross-instance binding.** The binding implicitly binds to the specific SafeClaw instance via `credential_id` (which identifies the target passkey) and via `prf_salt_curr` (which differs per instance).

**What this does not protect against.**

- A CLI machine that is already compromised cannot be made safe by any handshake: the attacker will have the vault files, the ephemeral keys, and eventually the decrypted vault.
- A browser that is already compromised will leak the user's passkey usage to the attacker in real time.
- A human-in-the-middle attack on the human channel (someone who can read, modify, and rewrite the displayed strings or QR codes in real time) is outside the threat model. The user is responsible for verifying the strings came from a legitimate CLI and were not altered in transit.

---

## 9. Security Analysis

This section summarizes the security properties of v2 and the proofs-of-concept for each.

### 9.1 Forward secrecy

#### 9.1.1 Wrap-layer forward secrecy (credential A)

**Claim.** For a credential A, after A performs a vault write at time `t` and rotates `prf_salt_A`, an attacker who captures `rawPRF_A_{<t}` (A's rawPRF for any past salt) cannot unwrap A's entry in any `wrapped_deks.bin` snapshot taken after time `t`.

**Proof sketch.** After time `t`, A's entry in `wrapped_deks.bin` uses `prf_salt_A_next` and is wrapped under `KEK_A_new = KDF(userKey_A_new, prf_salt_A_next, ...)` where `userKey_A_new = KDF(HMAC(hmac_secret_A, prf_salt_A_next), ...)`. The attacker holds only `HMAC(hmac_secret_A, prf_salt_A_prev)` for some `prf_salt_A_prev ≠ prf_salt_A_next`. Without access to `hmac_secret_A` (which is non-extractable by assumption), the attacker cannot compute `HMAC(hmac_secret_A, prf_salt_A_next)` and therefore cannot derive `userKey_A_new`, `KEK_A_new`, or unwrap the new entry.

#### 9.1.2 Vault-layer forward secrecy

**Claim.** For a past snapshot of `vault.enc` taken at time `t` and containing ciphertext `vault.enc_t`, an attacker who later captures `rawPRF_X_{current}` for some credential X that has rotated its `prf_salt` since time `t` cannot decrypt `vault.enc_t`.

**Proof sketch.** `vault.enc_t` was encrypted under `DEK_t`. `DEK_t` does not appear in the current snapshot; it was zeroized after the next write past time `t`. To recover `DEK_t`, the attacker would need to unwrap some wrapped entry in a past snapshot. The past snapshot contains `wrapped_deks.bin_t`, which for credential X uses `prf_salt_X_t` and is wrapped under `KEK_X_t`. The current `rawPRF_X_{current}` uses `prf_salt_X_{current} ≠ prf_salt_X_t`, so it cannot reproduce `KEK_X_t`. The wrap is unopenable.

#### 9.1.3 Limitation: dormant credential

**Claim.** For a credential Y that has been dormant (no writes) from before time `t` up to `current`, an attacker with `rawPRF_Y_{current}` plus a past snapshot of `wrapped_deks.bin_t` can decrypt `vault.enc_t`.

**Proof sketch.** Because Y is dormant, `prf_salt_Y_t == prf_salt_Y_{current}`. The attacker's `rawPRF_Y_{current}` produces the same `KEK_Y` that was in effect at time `t`. The past `wrapped_deks.bin_t` unwraps to `DEK_t`, which decrypts `vault.enc_t`.

This is intrinsic to any any-of-N protocol without a global re-keying ceremony. Mitigations are operational: periodically exercise all credentials; warn the user when a credential has not rotated in a configurable number of days.

#### 9.1.4 Limitation: `peer_keks` widens the dormancy attack surface

**Claim.** In a multi-credential vault, compromising *any* credential grants the attacker the current KEKs of *all* other credentials via the `peer_keks` field.

**Proof sketch.** A credential's rawPRF → userKey → KEK → unwrap wrapped_deks entry → DEK → decrypt vault → read `peer_keks` → obtain all other credentials' current KEKs (verbatim, as stored).

**Consequences.** The dormancy limitation in §9.1.3, which would otherwise only affect the compromised credential, is widened: if any credential has been dormant since a backup was taken, the attacker can now unwrap that credential's wrapped entry in the backup using the KEK extracted from `peer_keks`. This is a trade-off of Option D (see §3.3): the "any-of-N unilateral rotation" capability fundamentally requires a stable shared access path, which creates this cross-credential exposure. The alternative designs that avoid it (DEK forward chain, require-all-credentials-present rotation) are either unboundedly growing or UX-hostile.

**Mitigation.** Ensure every credential is exercised regularly. A future version may surface "credential X has not rotated in N days" warnings.

### 9.2 Replay resistance

**Claim.** Any replay of a captured valid request fails.

**Proof sketch.** Each request carries a `server_random` that is single-use in `ChallengeStore`. A second attempt with the same `server_random` is rejected. A different `server_random` requires the attacker to obtain a fresh one from `GET /session`, but that fresh `server_random` does not match the captured request's `clientDataJSON.challenge` (which was bound to the original `server_random`), so the assertion's channel binding check fails.

### 9.3 Cross-request assertion transplantation

**Claim.** A captured assertion signed for operation `(M1, P1, B1)` cannot be used to authorize `(M2, P2, B2)` where any of M, P, or B differs.

**Proof sketch.** The binding includes `request_hash = H(M ‖ 0x00 ‖ P ‖ 0x00 ‖ canonical(B))`. Changing any of M, P, B produces a different `request_hash` and therefore a different `binding`. The authenticator signed over `SHA-256(clientDataJSON)` which includes the original `binding`, and cannot retroactively be convinced to sign for a different `binding` without a new user gesture.

### 9.4 Known limitations

1. **Dormant credential time-travel** (§9.1.3). Mitigated operationally.
2. **`peer_keks` cross-credential exposure** (§9.1.4). Intrinsic to Option D.
3. **Authenticator compromise** (§2.3 B1). Not in scope.
4. **Sustained browser or host compromise** (§2.3 B2, B3). Not in scope.
5. **Backup-based credential revocation.** Removing a passkey from the live `data/` does not invalidate prior backups containing that credential's old wrapped entry. Documented in the README.
6. **Loopback HTTP on local-only deployments.** Accepted per §2.1. Any local adversary that can read loopback traffic also has direct `data/` and `/proc` access.
7. **Vault size growth.** Each registered credential adds ~60 bytes to the `peer_keks` field. For the expected N ≤ 10, this is negligible.
8. **Key-committing AEAD.** XChaCha20-Poly1305 is not key-committing — an attacker in possession of two candidate keys can craft a ciphertext that decrypts to different plaintexts under each. This does not affect SafeClaw's single-party threat model, where no one holds multiple candidate keys, but is documented for completeness.
9. **JCS number canonicalization.** The RFC 8785 JCS implementation in `crypto::canonical` handles integers, strings, booleans, null, arrays, and objects; floating-point numbers are not canonicalized to full JCS specification. SafeClaw request bodies contain no floats, so this is not triggered in practice.
10. **Post-quantum.** v2 uses ECDH/ECDSA with no quantum-resistant fallback. Migration path is future work.

---

## 10. Implementation Notes

### 10.1 Zeroization

The following variables hold key material that must be zeroized as soon as it is no longer needed. "As soon as" means within the same function scope where possible; longer-lived values are wrapped in `Drop` impls that zeroize.

**Server side:**

- `user_key`, `user_key_next` (function-local after parsing the request)
- `KEK`, `KEK_new` (function-local after AEAD operations)
- `DEK`, `DEK_old`, `DEK_new` (function-local; never stored long-term; the DEK used for reads is re-derived each time via the unwrap path, not cached)
- `file_key` (function-local during upload/read)
- The decrypted vault plaintext buffer used for re-encryption on write (function-local, drops zeroize)

**Client side:**

- `rawPRF_curr`, `rawPRF_next` (JavaScript `Uint8Array`, overwritten with zeros after HKDF)
- `userKey_curr`, `userKey_next` (same)
- Intermediate `sharedBits` values from `crypto.subtle.deriveBits`

JavaScript cannot guarantee that garbage-collected values are immediately purged from memory, but overwriting via `.fill(0)` on owned `Uint8Array` instances provides a best-effort barrier against idle heap snapshots.

The Rust `zeroize::Zeroize` trait is used for all `[u8; 32]` arrays and for `Vec<u8>` plaintexts via `Zeroizing<Vec<u8>>`. The `zeroize_on_drop` feature is used where possible to make cleanup automatic.

### 10.2 Crash recovery and atomicity

A vault write touches two files: `vault.enc` and `wrapped_deks.bin`. Both must move from the old state to the new state as a single atomic event from the user's perspective. POSIX does not provide multi-file atomic rename, so v2 uses the following write ordering:

```text
1.  Generate new state in memory: DEK_new, plaintext_new (with updated peer_keks),
    wrapped_deks contents.

2.  Write vault.enc.tmp with the new ciphertext.
3.  fsync(vault.enc.tmp).

4.  Write wrapped_deks.bin.tmp with the new manifest.
5.  fsync(wrapped_deks.bin.tmp).

6.  fsync(data/) to ensure both .tmp files are in the directory.

7.  rename(wrapped_deks.bin.tmp, wrapped_deks.bin)
8.  rename(vault.enc.tmp, vault.enc)
9.  fsync(data/) to ensure both renames are durable.

10. Update in-memory Vault::plaintext to plaintext_new.
11. Zeroize ephemeral keys.
```

**Crash scenarios:**

- **Crash between steps 2 and 7.** Neither file has been committed. On next startup, the server finds orphan `.tmp` files and deletes them. State is old v1/v2 and consistent.
- **Crash between steps 7 and 8.** `wrapped_deks.bin` has been updated but `vault.enc` has not. The new `wrapped_deks.bin` points to `DEK_new`, but `vault.enc` is still encrypted under `DEK_old`. On next unlock, `DEK_new` successfully unwraps from `wrapped_deks.bin`, then fails AEAD verification on `vault.enc` because the AAD version matches but the key differs. The server detects this inconsistency via a startup check that tries to decrypt `vault.enc` with each credential's unwrapped DEK; if none succeed, the server refuses to start and instructs the user to restore from backup.

  Note: we choose this ordering (wrapped_deks before vault.enc) because the alternative (vault.enc first) leaves the opposite inconsistency, where `vault.enc` is the new ciphertext but `wrapped_deks.bin` still points to the old DEK that cannot decrypt it. Either ordering has a vulnerable window; this one produces a detectable failure mode rather than an undetectable data loss.

- **Crash between steps 8 and 10.** All files on disk are consistent with the new state. The in-memory `Vault::plaintext` is still the old one, but on next unlock it will be re-read from disk, so the inconsistency is transient and benign.

**Advisory lock.** Vault writes acquire `flock(LOCK_EX)` on `data/.write.lock` before beginning the sequence and release it after step 9. A single in-process `tokio::sync::Mutex` serializes writes within the same SafeClaw process. Cross-process mutual exclusion is left to the advisory file lock.

### 10.3 Concurrency

Read operations do not acquire the write lock. They read from `Vault::plaintext` in memory, which is protected by its own `std::sync::Mutex`. Writes take the file lock first, update the files, then update `Vault::plaintext` under the mutex. This ordering ensures that a read in progress during a write sees either the pre-write or post-write state but never a torn state.

### 10.4 Canonicalization of JSON request bodies

Channel binding requires deterministic serialization of request bodies. v2 uses the RFC 8785 JCS subset described in §7.3. The implementation lives in `src/crypto/canonical.rs` and has the following properties:

- Object keys are sorted by their UTF-16 code unit sequence (the RFC 8785 rule).
- No insignificant whitespace.
- Integer numbers use `serde_json`'s default shortest representation.
- Strings are UTF-8, re-escaped via `serde_json::to_string`.
- Floats are **not** canonicalized to full JCS specification. SafeClaw request bodies contain only integers and strings, so this is not a problem in practice, but a future version that introduces floats must upgrade to a full JCS implementation.

The client JavaScript implementation (`public/safeclaw-client.js`) produces byte-identical output for the subset of JSON values SafeClaw uses.

### 10.5 Constant-time comparisons

All equality checks on secrets, including `clientDataJSON.challenge == binding_expected` and `server_random == stored_random`, use `subtle::ConstantTimeEq` to prevent timing side channels.

---

## 11. Future Work

The following extensions are consistent with v2's design and can be added in future minor versions without breaking the wire format:

1. **Global re-keying ceremony.** An admin-triggered operation that rotates `DEK`, `peer_keks`, and every credential's `prf_salt` in a single ceremony requiring all credentials to be present. Addresses the dormant-credential limitation (§9.1.3).

2. **Audit log encryption.** `data/audit.db` is currently plaintext SQLite. A later version would seal it under `DEK` or a derived audit key.

3. **DEK forward chain.** An alternative rotation mode (opt-in) that uses an append-only `dek_chain.enc` file instead of `peer_keks`, for users who prefer unbounded chain growth over O(N) write I/O.

4. **Post-quantum hybrid.** When WebAuthn adds support for post-quantum signature schemes, SafeClaw adopts a hybrid mode that combines ECDH-P-256 and a lattice-based KEM for the offline unlock handshake.

5. **Remote attestation.** For high-security deployments, the server runs inside a TPM-sealed or SGX-enclave environment that attests to its code and configuration before accepting unlock requests.

6. **Credential catch-up log.** A small append-only log of `(credential_id, salt_rotation_timestamp)` entries that the UI can surface to warn about dormant credentials.

These are listed as future work to avoid scope creep in v2.0; none are blocking issues for the current release.

---

## Appendix A: Domain separator inventory

| Purpose | String (all followed by `0x00` and context-specific bytes) | Appears in |
|---|---|---|
| userKey derivation | `"safeclaw/v2/userkey"` | HKDF info on client |
| KEK derivation | `"safeclaw/v2/kek"` | HKDF info on client and server |
| Wrapped DEK AEAD AAD | `"safeclaw/v2/wrap"` | AEAD associated data |
| Vault AEAD AAD | `"safeclaw/v2/vault"` | AEAD associated data |
| File AEAD AAD | `"safeclaw/v2/file"` | AEAD associated data |
| Standard channel binding | `"safeclaw/v2/binding"` | SHA-256 input |
| Setup channel binding | `"safeclaw/v2/binding-setup"` | SHA-256 input |
| Setup overwrite binding | `"safeclaw/v2/binding-setup-overwrite"` | SHA-256 input |
| Identity channel binding | `"safeclaw/v2/binding-identity"` | SHA-256 input |
| Offline channel binding | `"safeclaw/v2/binding-offline"` | SHA-256 input |
| Offline transport key | `"safeclaw/v2/offline-transport"` | HKDF info |
| Offline AEAD AAD | `"safeclaw/v2/offline-aad"` | AEAD associated data |

## Appendix B: File magic inventory

| File | Magic | Version | Extension |
|------|-------|---------|-----------|
| `vault.enc` | `SCV2` (0x53 0x43 0x56 0x32) | 0x0002 | `.enc` |
| `wrapped_deks.bin` | `SCW2` (0x53 0x43 0x57 0x32) | 0x0002 | `.bin` |
| `files/*.enc` | `SCF2` (0x53 0x43 0x46 0x32) | 0x0002 | `.enc` |

## Appendix C: HTTP endpoint summary

All authenticated endpoints use POST with a JSON body carrying `server_random`,
`credential_id`, `user_key`, `assertion`, and any operation-specific fields.
Write operations additionally carry `user_key_next` and `prf_salt_next`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health` | none | Liveness check |
| GET | `/session` | none | Issue `server_random`, list `(credentialId, prf_salt)` |
| POST | `/auth/verify` | assertion | Verify passkey identity without unlocking |
| POST | `/vault/setup` | setup-assertion | Initial vault creation |
| POST | `/vault/unlock` | assertion | Decrypt vault into memory |
| POST | `/vault/lock` | assertion | Zeroize in-memory vault |
| POST | `/vault/read` | assertion | Return (optionally filtered) vault JSON |
| POST | `/vault/write` | assertion + rotation | Replace vault (rotates DEK + prf_salt) |
| GET | `/vault/services` | none | List service metadata (public) |
| GET | `/vault/services/{name}/{key}` | none | Read a single vault field (vault must be unlocked) |
| POST | `/vault/services/add` | assertion + rotation | Add service |
| POST | `/vault/services/remove` | assertion + rotation | Remove service |
| GET | `/vault/files` | none | List file metadata (public) |
| POST | `/vault/files/add` | assertion + rotation | Upload encrypted file (per-file DEK) |
| POST | `/vault/files/read` | assertion | Decrypt and return file plaintext |
| POST | `/vault/files/remove` | assertion + rotation | Delete file |
| GET | `/vault/files/{id}` | approval | Approval-gated file read (one-shot key) |
| POST | `/vault/passkeys/add` | assertion + rotation + identity-assertion | Register additional credential |
| POST | `/vault/passkeys/remove` | assertion + rotation | Remove credential |
| GET | `/vault/passkeys/public` | none | Public `(x, y)` coordinates (for NodPay etc.) |

**Naming conventions**:
- Everything vault-related sits under `/vault/`.
- Verbs are consistent: `setup`, `unlock`, `lock`, `read`, `write`, `add`, `remove`.
- `read`/`write` are the high-level vault operations; `add`/`remove` are the item-level operations.
- `GET` is used only for endpoints that return publicly-readable data (no auth body).
- Pre-auth: only `/health`, `/session`, `/vault/services` (metadata), `/vault/files` (metadata), and `/vault/passkeys/public`.

---

*End of SafeClaw Cryptographic Protocol v2 specification.*
