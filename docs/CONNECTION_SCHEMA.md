# Connection Data Schema

> THE data-schema reference for *connections* — the exact shapes in a vault and
> how secrets, status, and routing derive from them. Companion to
> [CONNECTIONS_AND_AUTH.md](CONNECTIONS_AND_AUTH.md) (lifecycle + rationale).
>
> **Pre-launch: no migration.** This supersedes the minimal shape shipped in
> v1.0.20/.21 (§8). Landing = **delete the vault, recreate, re-test.** No
> back-compat, no dual-read.
>
> **Vocabulary.** At the SafeClaw vault layer the sealed body has three pools:
> **`secrets`**, **`passkeys`**, **`aux`**. (At the lower `sudp` protocol layer
> these are still the abstract field names `targets` / `peers` / `aux` —
> unchanged; this doc speaks the SafeClaw domain names.)

---

## 1. Where the data lives

The vault's decrypted body is sealed under the per-vault key `K` (ciphertext at
rest *and* in the cloud blob):

- **`secrets`** — flat `name → value` map (the native-secrets store). The
  credential values (§3).
- **`passkeys`** — each enrolled passkey's wrapped copy of `K`. Crypto plumbing,
  not user data.
- **`aux`** — structured metadata: stores, policy, and the two connection
  collections **`connecting`** + **`connections`** (§2).

---

## 2. Two collections — `connecting` (in-flight) and `connections` (established)

Parallel maps, both keyed by **`connection_id`**. A connection sits in exactly
one at a time (the only overlap is a transient re-auth of an already-connected
service). `len(connecting)` = how many connects are in flight.

### `aux.connecting[<connection_id>]` — in-flight

Holds **everything** the connect needs. On a successful exchange the daemon
writes the secret and **moves the whole entry into `connections`, dropping it
from `connecting`** — there is never a partial/duplicate record.

```jsonc
"aux": {
  "connecting": {
    "gmail-work": {
      "service":  "gmail",                 // the recipe (TYPE) being instantiated
      "config":   { },                     // recipe-declared re-map slots (§4); usually empty
      "code":     "<authorization code>",  // single-use; from the loopback redirect
      "verifier": "<PKCE code_verifier>"   // browser-generated; the daemon needs it to exchange
    }
  }
}
```

`redirect_uri` is **not** here — it's a fixed property of the OAuth client, held
in the provider config (§5).

### `aux.connections[<connection_id>]` — established

```jsonc
"aux": {
  "connections": {
    "gmail":       { "service": "gmail" },
    "gmail-work":  { "service": "gmail" },                              // 2nd instance, same type
    "acme-gitlab": { "service": "gitlab", "config": { "host": "git.acme.com" } }
  }
}
```

| field | notes |
|---|---|
| **`<connection_id>`** (map key) | The user's **handle** *and* its identity — a slug `^[a-z0-9][a-z0-9_-]{0,63}$`. The routing / cache / audit unit. No separate `label` (one field, no duplicated semantic; rename = new id = re-key, fine pre-launch). |
| **`service`** | Which recipe (TYPE) this instantiates. Decouples id from type → many connections per service. |
| **`config`** | Per-connection values for the recipe-declared re-map slots only (§4). Omitted when none. |

---

## 3. Secrets — mainstream names, optional connection prefix

- Secret keys are **mainstream, ALL-CAPS, community-standard** — `GITHUB_TOKEN`,
  `OPENAI_API_KEY`, `GOOGLE_REFRESH_TOKEN`. **Never invented.** The recipe
  **DEFINEs** them (§4).
- A secret's address is **`[<connection_id>:]<MAINSTREAM_KEY>`**:
  - **default / single** connection → **no prefix** → bare `GOOGLE_REFRESH_TOKEN`.
  - **named** connection → `gmail-work:GOOGLE_REFRESH_TOKEN`.
- The `:` delimiter is invalid in env-var names → a namespaced key can never
  masquerade as an env var.
- The address resolves through the normal **`store_order`** (native secrets →
  GCP → …) exactly as any secret today — **no per-connection store binding, no
  new mechanism.** The optional prefix is the only connection-specific part.

```jsonc
"secrets": {
  "GOOGLE_REFRESH_TOKEN":            "<bytes>",   // default gmail connection — bare
  "gmail-work:GOOGLE_REFRESH_TOKEN": "<bytes>",   // named connection — prefixed
  "acme-gitlab:GITLAB_TOKEN":        "<bytes>"
}
```

**Why default-bare (the asymmetry is principled).** It's the AWS-default-profile
pattern. The bare mainstream name maps **1:1** to `env` import, GCP Secret
Manager, and the wider ecosystem — **zero remap / translate**, which is the
whole point of speaking mainstream names. A named connection's `:`-prefix is a
**native-store-internal** detail (ecosystem-invisible); storing a *named*
connection's secret in an external store is an edge case for later.

---

## 4. The recipe DEFINEs the roles + the config slots

The `service.toml` (the TYPE) declares two things a connection may fill, and
nothing else:

- **secret roles** — by mainstream name (e.g. `GOOGLE_REFRESH_TOKEN`). A
  connection supplies *values* for exactly these; it **cannot add or rename**
  keys.
- **config params** that are per-connection (e.g. `host` for a self-hosted
  upstream).

Everything else — endpoints, `auth_mode`, scopes, the egress host of a normal
recipe — is **fixed by the type**. A connection can **never** re-point an
audited recipe's host or token endpoint (that would be SSRF / hijack). This is
the hard security boundary of the connection layer.

**Why DEFINE, not SUGGEST.** A credential's role name is a property of the
upstream **type**, not the instance (`gmail` always needs `GOOGLE_REFRESH_TOKEN`
regardless of which account). With mainstream names, letting a connection rename
keys would break the very ecosystem-interop §3 buys — so the "flexibility" of
suggest is a footgun here. A genuine variant (an upstream that needs an extra
credential) is a **custom recipe**, not a per-connection key definition.

---

## 5. Status (DERIVED) + the connect handshake

**Status is never stored — it's read off the two collections:**

| condition | status |
|---|---|
| in `aux.connecting` | **Connecting** |
| in `aux.connections`, required secret(s) present | **Connected** |
| in `aux.connections`, some required secret missing | **Partly configured** |
| in neither | **Not configured** |

**Connect (cloud-blind).** The browser drives Google consent (public Desktop
client + PKCE), captures the `code`, and seals `{ service, config, code,
verifier }` into `aux.connecting[<id>]` → uploads (the cloud only ever stores
ciphertext). The daemon syncs the blob, exchanges (`code` + `verifier` + the
provider's fixed `client` / `token_url` / `redirect_uri`), writes the secret,
and **moves the entry into `aux.connections`**. No backend ever sees the token.

`redirect_uri` is a constant of the OAuth client → it lives in the **provider
config**, not in each handshake.

---

## 6. Routing

- A connection is addressed at **`/use/<connection_id>`** and
  **`/stream/<connection_id>`**.
- Per request the daemon resolves **`connection_id → connections[id].service →
  recipe`** once, then injects using the recipe + that connection's secrets.
- `connection_id` is the broker cache key `(vault, connection_id)`, the op
  scope, and the audit unit.

---

## 7. Full example — two Gmail accounts + a self-hosted GitLab

```jsonc
"aux": {
  "connecting": {
    "gmail-work": { "service": "gmail", "config": {}, "code": "4/0Ab…", "verifier": "dBj…" }
  },
  "connections": {
    "gmail":       { "service": "gmail" },
    "acme-gitlab": { "service": "gitlab", "config": { "host": "git.acme.com" } }
  }
},
"secrets": {
  "GOOGLE_REFRESH_TOKEN":      "<bytes>",   // default gmail — Connected
  "acme-gitlab:GITLAB_TOKEN":  "<bytes>"    // named gitlab  — Connected
}
// gmail-work is mid-connect (in `connecting`, no secret yet) → "Connecting".
```

Lifecycle of `gmail-work`: consent → `connecting["gmail-work"] = {service, config,
code, verifier}` → daemon exchanges → writes `gmail-work:GOOGLE_REFRESH_TOKEN`
→ moves to `connections["gmail-work"] = {service:"gmail"}` → status flips to
Connected.

---

## 8. No migration

Pre-launch. This replaces the v1.0.20/.21 minimal shape (`connection_id ==
service_id`, flat `gmail_refresh_token`, a legacy-flat read path). The old read
path is deleted; existing test vaults are recreated from scratch. **No dual-read,
no compat layer.**
