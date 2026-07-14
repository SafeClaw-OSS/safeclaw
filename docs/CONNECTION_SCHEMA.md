# Connection Data Schema

> **⚠️ PARTIALLY SUPERSEDED (2026-07-03 phantom-only pivot; schema rework
> 2026-07-04).** The `Connection{service, config}` struct described here is now
> `Connection{service?, hosts?, secrets?}` — `config` deleted, `hosts` promoted,
> and an explicit `secrets` list added (REQUIRED for a raw connection, omitted for
> a service-backed one — §2/§3). `/use`/`/stream` routing is retired (phantom
> placement instead); `aux.connecting[<id>]` now nests its OAuth temps under an
> `oauth2` key (`{code, code_verifier, error?}`, was flat `code`/`verifier`). The
> connecting→connections OAuth lifecycle and the cloud-blind connect stay valid.
> The recipe **config-slot / `{{template}}`** mechanism (§4, §8) is retired — a
> self-hosted upstream is now just a **raw connection**. Canon =
> [CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md); toml rules =
> [SERVICES.md](./SERVICES.md) v4.

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
- **`aux`** — structured metadata: stores, the **`policy`** tree, and the two
  connection collections **`connecting`** + **`connections`** (§2). Per-connection
  user policy lives under **`aux.policy.connections.<connection_id>`** (§5.1) —
  the same `connection_id` keys the established connection in `aux.connections`.

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
    "gmail_work": {
      "service": "gmail",                  // the service (TYPE) being instantiated
      "hosts":   null,                     // pinned FQDNs for a *.suffix service, else absent
      "oauth2": {                          // mechanism handshake state nests under its key
        "code":          "<authorization code>",  // RFC 6749; single-use, from the loopback redirect
        "code_verifier": "<PKCE verifier>",        // RFC 7636; browser-generated
        "error":         null              // set by the daemon on terminal invalid_grant
      }
    }
  }
}
```

Generic identity (`service`, `hosts`) is top-level; mechanism handshake state
nests under the mechanism key (`oauth2`), so a future auth mechanism nests under
ITS key without the schema getting messy. `redirect_uri` is **not** here — it's a
fixed property of the OAuth client, held in the provider config (§5).

### `aux.connections[<connection_id>]` — established

```jsonc
"aux": {
  "connections": {
    "gmail":      { "service": "gmail" },                          // default: hosts+secrets derived
    "gmail_work": { "service": "gmail" },                          // 2nd instance, same type
    "stripe_key": { "hosts": ["api.stripe.com"], "secrets": ["STRIPE_KEY"] }  // RAW: no service
  }
}
```

| field | notes |
|---|---|
| **`<connection_id>`** (map key) | The user's **handle** *and* its identity — a lowercase slug `[a-z0-9_]`, starting alphanumeric, ≤64 chars, no `__` (the phantom delimiter). The routing / cache / audit unit. No separate `label` (one field, no duplicated semantic; rename = new id = re-key, fine pre-launch). |
| **`service`** | Which service (TYPE) this instantiates, or **absent** for a **raw** connection. Decouples id from type → many connections per service. |
| **`hosts`** | Anchored egress FQDNs. **Absent** when a service declares exact hosts (derived, no stored copy); the pinned exact FQDNs (⊆ the service's `*.suffix`) when the service is wildcard; **required** for a raw connection. Enforced exact-FQDN, case-insensitive; never a bare `*`. |
| **`secrets`** | The UPPERCASE secret KEYs this connection uses. **Required for a raw connection** (answers "which secrets" directly, killing the reverse-index-by-casing hack); **omitted** for a service-backed one (derived from the service's declared `secrets`, incl. the oauth2 refresh key). |
| **`keys`** | Service-backed only: sparse `{ROLE → KEY}` bindings (§3). A missing role binds to its bare mainstream name — so a default connection stores none; a named connection's creator writes distinct keys (suggested `<ROLE>_<QUALIFIER>`, editable / may point at an existing key). |

---

## 3. Secrets — ALL keys bare; the connection RECORD binds roles to keys

- **Native** secret keys are **mainstream, UPPERCASE `[A-Z0-9_]`, community-standard** —
  `GITHUB_TOKEN`, `OPENAI_API_KEY`, `GMAIL_REFRESH_TOKEN`. **Never invented.**
  `sc set` / the console **force-uppercase** on input (a lowercase key is
  auto-converted, never stored lowercase) — one canonical form for the pool WE own.
- **Key resolution is case-SENSITIVE exact** (env-var / secret-manager convention).
  It was only ever case-insensitive because `sc get` uppercased its argument and
  native keys are stored uppercase; the resolver itself has always been an exact
  `HashMap` lookup. `sc get` no longer uppercases, so a native key must be named
  as stored (`GITHUB_TOKEN`, not `github_token`), and an **external** store's keys
  (GCP Secret Manager, … — which preserve their own casing, e.g. `xh-gcp-test`)
  are reachable ONLY verbatim.
- Connection ids and hosts are lowercase; **conn-id ↔ host comparison is
  case-insensitive** (keys are not — see above). For a service-backed connection
  the service DEFINEs the roles (§4); a raw connection names its own in `secrets` (§2).
- **Every secret lives at a bare, env-valid KEY** — the flat pool is ONE env
  namespace; nothing is namespaced. Every key maps **1:1** to `env` import and
  external-store read-through (GCP Secret Manager, …) via the normal
  **`store_order`** — zero remap, for **every** connection, named ones included.
- **The connection RECORD is the binding layer** — a connection OWNs no
  namespace; it **references** keys:
  - **raw** connection → its `secrets` list IS the binding (role == KEY; two
    connections naming the same KEY share it — sharing is explicit at creation).
  - **service-backed** connection → the sparse **`keys` map** `{ROLE → KEY}`;
    a missing role binds to its own bare mainstream name. So a **default**
    connection (`conn_id == service_id`) stores no map at all
    (`GMAIL_REFRESH_TOKEN` as-is), and a **named** one is created with distinct
    keys — suggested `<ROLE>_<QUALIFIER>` (`GMAIL_REFRESH_TOKEN_WORK`), editable:
    the creator may pick / autocomplete any existing key to share it.
- **The binding is stored data, never a computed convention** (`secret_key_for`
  in `storage/plaintext.rs` is the sole resolver: record map wins, identity
  otherwise). Writers and readers cannot drift, because there is no address
  formula to disagree on.

```jsonc
"secrets": {
  "GMAIL_REFRESH_TOKEN":      "<bytes>",   // default gmail connection — identity binding
  "GMAIL_REFRESH_TOKEN_WORK": "<bytes>",   // named gmail_work conn — via its keys map
  "STRIPE_KEY":               "<bytes>"    // raw stripe_key connection — referenced by list
},
"connections": {
  "gmail":      { "service": "gmail" },
  "gmail_work": { "service": "gmail",
                  "keys": { "GMAIL_REFRESH_TOKEN": "GMAIL_REFRESH_TOKEN_WORK" } },
  "stripe_key": { "hosts": ["api.stripe.com"], "secrets": ["STRIPE_KEY"] }
}
```

**Why all-bare + record binding.** The bare mainstream name is the whole point
of speaking mainstream names (1:1 with the ecosystem); pushing the instance
axis into the RECORD instead of the key keeps that true for named connections
too, and matches how every mature store separates instance from field (mount
path / vault / SecretStore — always an outer axis, never inside the leaf key).

---

## 4. The service DEFINEs the secret roles

The `service.toml` (the TYPE) declares what a connection may fill, and nothing
else:

- **secret roles** — by mainstream name (e.g. `GMAIL_REFRESH_TOKEN`). A
  service-backed connection supplies *values* for exactly these; it **cannot add
  or rename** keys.
- The old per-connection **config slots** (`{{connection.host}}` for a
  self-hosted upstream) are **retired** — a self-hosted upstream is now just a
  **raw connection** (its own `hosts` + `secrets`, no service). A wildcard service
  lets an instance only PIN an exact FQDN ⊆ its `*.suffix`, never re-point.

Everything else — endpoints, `auth_mode`, scopes, the egress host of a normal
service — is **fixed by the type**. A connection can **never** re-point an
audited service's host or token endpoint (that would be SSRF / hijack). This is
the hard security boundary of the connection layer.

**Why DEFINE, not SUGGEST.** A credential's role name is a property of the
upstream **type**, not the instance (`gmail` always needs `GMAIL_REFRESH_TOKEN`
regardless of which account). With mainstream names, letting a connection rename
keys would break the very ecosystem-interop §3 buys — so the "flexibility" of
suggest is a footgun here. A genuine variant (an upstream that needs an extra
credential) is a **custom service**, not a per-connection key definition.

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
client + PKCE), captures the `code`, and seals `{ service, hosts?, oauth2: {
code, code_verifier } }` into `aux.connecting[<id>]` → uploads (the cloud only
ever stores ciphertext). The daemon syncs the blob, exchanges (`code` +
`code_verifier` + the provider's fixed `client` / `token_url` / `redirect_uri`),
writes the secret, and **moves the entry into `aux.connections`**. No backend
ever sees the token.

`redirect_uri` is a constant of the OAuth client → it lives in the **provider
config**, not in each handshake.

### 5.1 Per-connection policy

A connection's policy is keyed by the same `connection_id` under
**`aux.policy.connections.<connection_id>`** — NOT per-service. The built-in rule
set comes from the connection's *service* recipe (`policy.toml`); the user's
sparse edits/additions merge on top (`ConnectionPolicy { default?, rules }`). Two
connections of the same service (`gmail`, `gmail_work`) therefore get independent
policy overrides. The full policy model — per-action `level` decisions, the
default floors, deny-override resolution, `ttl` — is in
[POLICY.md](POLICY.md); the whole `aux.policy` tree is in
[STORES_AND_ITEMS.md §7](STORES_AND_ITEMS.md).

---

## 6. Routing

- A connection is **not addressed by URL** — the **phantom**
  `__sc__<connection_id>__[<role>__]` carries the intent, and the traffic goes
  through the local HTTPS proxy (`/use` / `/stream` endpoints are retired). See
  [CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md).
- The proxy resolves **phantom → `connection_id` → its secret(s)**, validates the
  destination host against the connection's `resolved_hosts`, then substitutes at
  egress.
- `connection_id` is the op scope and the audit unit. The OAuth mint cache keys on
  **`sha256(refresh_token)`** (in-memory, wiped on lock) — not `(vault,
  connection_id)`.

---

## 7. Full example — two Gmail accounts + a raw self-hosted GitLab

```jsonc
"aux": {
  "connecting": {
    "gmail_work": { "service": "gmail", "oauth2": { "code": "4/0Ab…", "code_verifier": "dBj…" } }
  },
  "connections": {
    "gmail":       { "service": "gmail" },                                   // default, service-backed
    "acme_gitlab": { "hosts": ["git.acme.com"], "secrets": ["GITLAB_TOKEN"] } // RAW (self-hosted)
  }
},
"secrets": {
  "GMAIL_REFRESH_TOKEN": "<bytes>",   // default gmail — Connected
  "GITLAB_TOKEN":        "<bytes>"    // raw acme_gitlab — Connected (bare)
}
// gmail_work is mid-connect (in `connecting`, no secret yet) → "Connecting".
```

Lifecycle of `gmail_work`: consent → `connecting["gmail_work"] = {service, oauth2:
{code, code_verifier}}` → daemon exchanges → writes
`gmail_work:GMAIL_REFRESH_TOKEN` → moves to `connections["gmail_work"] =
{service:"gmail"}` → status flips to Connected.

---

## 8. Recipe side (what drives this schema)

> **RETIRED shape — kept for history.** The `[upstream.auth] secret=` /
> `{{oauth.access_token}}` / `{{connection.host}}` recipe-template toml below is
> superseded by **service.toml v4** ([SERVICES.md](./SERVICES.md)): `[oauth2]` with
> RFC field names (`refresh_token = "<KEY>"`), a uniform top-level `secrets`, no
> `[upstream.*]`, no templates. A self-hosted upstream is a **raw connection**, not
> a `{{connection.host}}` slot.

The recipe (TYPE) DEFINEs everything a connection may fill:

```toml
# services/integration/gmail/service.toml
[upstream.auth]
provider = "google"
scopes   = [ "…/gmail.send", "…/gmail.readonly", "…/gmail.modify" ]
secret   = "GMAIL_REFRESH_TOKEN"     # mainstream role this recipe injects (DEFINEd)

# The OAuth client's fixed redirect_uri lives in the service's [oauth2] section,
# not in each handshake:
[oauth2]
# … client_id / token_url / pkce …
redirect_uri = "http://127.0.0.1:8765/safeclaw/oauth/callback"
```

A recipe with a per-connection slot (self-hosted host) marks ONLY that slot:

```toml
[[upstream]]
url = "https://{{connection.host}}"   # templated from the connection's config

[upstream.connection]
params = ["host"]                      # the ONLY connection-fillable slots (anti-SSRF)
```

The daemon resolves `secret` → `[<connection_id>:]GMAIL_REFRESH_TOKEN` for the
active connection, and substitutes `{{connection.host}}` from `config.host`.

## 9. Open at implementation (settle in plan mode)

- **DP1 — same-provider multi-service naming.** `gmail` / `gdrive` / `gcalendar`
  are separate services sharing Google OAuth, each with its own scoped token. As
  *default* (unprefixed) connections their secret names must not collide. **Lean:**
  service-distinct mainstream names (`GMAIL_REFRESH_TOKEN`,
  `GOOGLE_DRIVE_REFRESH_TOKEN`, `GOOGLE_CALENDAR_REFRESH_TOKEN`), with a validator
  check that shipped recipes' default secret names are unique. *Alt:* always-prefix
  (loses the bare-name 1:1), or one unified `google` connection (one token, breaks
  separate-services).
- **DP2 — config-slot TOML syntax.** The `{{connection.host}}` + `[upstream.connection].params`
  shape above is the proposal; confirm or adjust.

## 10. No migration

Pre-launch. This replaces the v1.0.20/.21 minimal shape (`connection_id ==
service_id`, flat `gmail_refresh_token`, a legacy-flat read path). The old read
path is deleted; existing test vaults are recreated from scratch. **No dual-read,
no compat layer.**
