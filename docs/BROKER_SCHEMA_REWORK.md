# Broker schema rework — post-build review decisions (2026-07-04, LOCKED)

The 2026-07-04 review of the first phantom-only build found several schemas were
deviated-from or under-specified. These decisions are AUTHORITATIVE and supersede
the earlier shapes in `CREDENTIAL_BROKER.md` / `SERVICES.md` where they differ.
**Build the rework on branches `feat/broker-phantom` (core) + `feat/broker-phantom-fe`
(console)**, fold these into the canonical docs, then delete this file. Do NOT
re-litigate — every point below is settled with the user.

---

## 1. Secret key casing (global)
- Secret KEYs are ALWAYS uppercase `[A-Z0-9_]`. `sc set` / console force-uppercase
  on input; a lowercase key is auto-converted, never stored lowercase. One canonical
  form — no "two paths".
- Connection ids + roles are lowercase (phantom charset `[a-z0-9_]`).
- Every comparison crossing key ↔ conn-id ↔ host is **case-insensitive** (host already
  is; add for the reverse-index / role lookups). Audit all compare sites.

## 2. Connection stores its secrets  (`aux.connections[<id>]`)
```jsonc
{ "service": "github",          // string | absent = RAW
  "hosts":   ["api.github.com"],// see below
  "secrets": ["GITHUB_TOKEN"] } // see below
```
- `service`: the service TYPE id, or absent for a raw connection.
- `hosts`: absent when the service declares exact hosts (derived, no stored copy);
  the pinned subset when the service is wildcard (⊆ its `*.suffix`, path-subset:
  service `*.x.com` admits conn `a.x.com`, not `b.y.com`); required own-anchor for raw.
- `secrets`: the UPPERCASE key names this connection uses. **REQUIRED for raw**
  (answers "which secrets" directly — kills the reverse-index-by-casing hack);
  OMITTED for service-backed (derived from `service.secrets`).
- `connected` + `phantoms` are DERIVED at projection time, NEVER stored.

## 3. service.toml v4 (final)
```toml
# direct (github)
[service]
id = "github"                          # category = the DIRECTORY name, not a toml field
name = "GitHub"
hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]             # top-level: durable stored secrets required for `connected` — uniform for ALL services

# oauth (gmail)
[service]
id = "gmail"
hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]
[oauth2]
provider = "google"                    # -> _providers/google.toml (endpoints, public client)
scopes = ["https://www.googleapis.com/auth/gmail.send", ...]
refresh_token = "GMAIL_REFRESH_TOKEN"  # RFC 6749 response field `refresh_token` → store into THIS vault secret
# id_token = "GMAIL_ID_TOKEN"          # only if a provider returns a STORED id token (OIDC)
```
- `[placeholders]` **DELETED** (was UI-only). If a paste hint is ever wanted:
  optional `secrets_placeholders = ["github_pat_..."]` parallel to `secrets`. Default = omit.
- **No `[oauth2].secret`** — replaced by RFC-named durable-token mappings
  (`refresh_token = "<VAULT_SECRET>"`), unambiguous when `secrets` has >1 entry.
- `access_token` (RFC response field) is **ephemeral, minted per request, never stored**
  → not named; it is what the default phantom resolves to.
- `code` / `code_verifier` (RFC 6749 / 7636 flow temps) are **standard, not per-service**
  → NOT in the toml; they live in `aux.connecting.oauth2` (§4). Objectively: naming them
  per-service is redundant boilerplate; a future non-authcode grant would add a `grant`/`flow`
  marker instead.
- `category` = the service's directory name (`integration` / `llm` / `channel` / `system`),
  reported faithfully.

## 4. aux.connecting — auth-mechanism-scoped  (`aux.connecting[<id>]`)
```jsonc
{ "service": "gmail",
  "hosts": null,                       // pinned FQDNs for a wildcard service, else null
  "oauth2": {                          // auth-mechanism section — mirrors service.toml [oauth2]
    "code": "4/0Ax...",                // RFC 6749 authorization code (loopback redirect)
    "code_verifier": "dBjftJ...",      // RFC 7636 PKCE verifier (browser-generated)
    "error": null } }                  // daemon sets on terminal invalid_grant
```
- Generic identity (`service`, `hosts`) top-level; mechanism handshake state nests under
  the mechanism key. A future mechanism nests under ITS key. Different services can have
  different auth without the schema getting messy.
- **Rename the built field `verifier` → `code_verifier`** (RFC 7636).
- Exchange: daemon POSTs `{grant_type=authorization_code, code, code_verifier, client_id,
  redirect_uri}` → `{access_token, refresh_token, expires_in}` → store `refresh_token` into
  the named vault secret → MOVE the entry into `aux.connections`; drop code/code_verifier.

## 5. OAuth mint cache
- In-memory only (never persisted; wiped on lock), keyed by **`sha256(refresh_token)`** →
  `(access_token, expires_at)`. Key on the INPUT (the refresh token), not `(vault, conn)`:
  the access token is a pure function of the refresh token, so refresh-value keying (a) auto-
  invalidates on reconnect / refresh-token rotation (same conn, NEW refresh → natural cache
  miss → fresh mint; a `(vault,conn)` key would serve the STALE access token until expiry),
  and (b) two accounts never collide for free (different refresh → different key). Hash the
  refresh so map keys are fixed-size and not raw secrets.
- On an oauth phantom: fetch the refresh secret from the in-memory session cache (a cheap
  LOCAL read — needed to compute the key), then look up `sha256(refresh)`: hit + unexpired →
  use the cached access token (mints nothing, never sends the refresh upstream); miss/expired
  → mint at the provider, cache with `expires_at − 60s`, use.
- REWORK: the first build keyed by `(vault, conn)` in `broker_flow.rs` — re-key to
  `sha256(refresh_token)`.

## 6. Registry = TWO separate arrays (kill `category:"connection"`)
`GET /v/{vid}/registry` and `sc status` (shared projection):
```jsonc
{ "version": 4,
  "locked": false,                     // PER-VAULT, scoped to this vault (drop the `vault_` prefix)
  "console_url": "...",
  "services": [                        // 1:1 with service toml — the browse catalog; NO connected/phantoms
    { "id":"github", "name":"GitHub", "category":"integration",
      "hosts":["api.github.com","github.com"], "secrets":["GITHUB_TOKEN"] },
    { "id":"gmail", "name":"Gmail", "category":"integration", "hosts":["gmail.googleapis.com"],
      "secrets":["GMAIL_REFRESH_TOKEN"],
      "oauth2": { "provider":"google", "scopes":[...] },   // PUBLIC half only (no client_secret/token_url — cloud-blind)
      "connect": {...consent params...} }
  ],
  "connections": [                     // 1:1 with aux.connections + DERIVED connected/phantoms
    { "id":"github", "service":"github", "hosts":["api.github.com","github.com"],
      "connected":true, "phantoms":["__sc__github__"] },
    { "id":"gmail_work", "service":"gmail", "hosts":["gmail.googleapis.com"],
      "connected":true, "phantoms":["__sc__gmail_work__"] },
    { "id":"stripe_key", "hosts":["api.stripe.com"], "secrets":["STRIPE_KEY"],
      "connected":true, "phantoms":["__sc__stripe_key__"] }   // RAW: no service, explicit secrets
  ] }
```
- Service rows are the catalog (what's supported); they carry NO `connected`/`phantoms`.
- Connection rows are `aux.connections` faithfully + DERIVED `connected` + `phantoms`.
- **`phantoms` is a LIST, not a map** (`["__sc__gmail_work__gmail_access_token__"]`) — aids
  identification, avoids a key/value inconsistency surface. Agent copies verbatim.
- `?ids=` / `?view=summary` apply to both arrays.
- The old `category:"connection"` conflation is DELETED.

## 7. Phantom form (decision A)
- Sole injectable → short `__sc__<conn>__`. Multiple → role-qualified
  `__sc__<conn>__<role>__` (role = secret key lowercased). Default connection
  (`conn_id == service_id`) → short form. **Do NOT list both forms.**
- oauth: the minted access token is the sole default injectable → `__sc__<conn>__`;
  `exposes` values add role-qualified entries.

## 8. sc status — routing facts (faithful WHAT, no HOW)
- Human `sc status`: a one-line routing summary ("routing: ready" / "routing: not configured").
- `sc status --json` routing block (the agent reads this):
```jsonc
"proxy": { "url":"http://127.0.0.1:23294", "reachable":true },
"routing": {
  "https_proxy": "reaches_safeclaw",   // SELF-EXPLAINING value | "unset" | "reaches_other_proxy" (wrong — traffic intercepted elsewhere)
  "ca_trust": ["SSL_CERT_FILE","NODE_EXTRA_CA_CERTS","CURL_CA_BUNDLE","GIT_SSL_CAINFO","REQUESTS_CA_BUNDLE","DENO_CERT"]
}                        // which resident-CA vars actually point at ca.pem; [] = TLS to intercepted hosts fails
```
- **No `routed` verdict.** Report the parts; the agent composes the judgment and self-queries
  its env for the raw string when it needs it. Values are SELF-EXPLAINING (never a bare `"ok"`):
  `https_proxy` says WHERE traffic goes (`reaches_safeclaw` / `unset` / `reaches_other_proxy`) —
  the value carries the meaning, and the wrong-value case names itself. Don't echo the raw
  proxy string (the agent can `echo $HTTPS_PROXY`); report the JUDGMENT sc status can make and
  the agent can't (does it point at US; which CA vars cover). Skill teaches reading `--json`.

## 9. CLI: sc set vs sc connect  (`connect ⊃ set`)
- `sc set KEY [VALUE] [--host H]` — quick. Store secret KEY (force uppercase). With `--host`,
  also create a RAW single-secret connection: `id = lower(KEY)` (a plain handle — safe now
  that secrets are stored explicitly, no reverse-index coupling), `secrets=[KEY]`, `hosts=[H]`
  (exact FQDN, non-wildcard, non-private/metadata). No service ref. Without `--host`: store the
  secret only (unattached / human-only). `--no-broker` / `--host none` = explicit opt-out
  (also removes any prior raw connection for the key).
- `sc connect <name> [--service SVC] --host H... --secret KEY[=VALUE]...` — full superset:
  - `--service SVC`: service-backed. `--host` optional (derive service exact hosts); if given,
    each host must be ⊆ the service's hosts (exact, or within a `*.suffix`). Secrets = the
    service's; values via `--secret KEY=VALUE`.
  - no `--service`: raw. `--host` + `--secret` required.
- The "two paths" duplication is gone: registry separates services/connections and `connected`
  is per-connection, so a raw `openai_api_key` and a service-backed `openai` connection never
  collide in discovery.

## 10. audit_retention_days
- Core default = `None` = **keep forever** (NOT 30). Console offers 7/30/90/forever
  (forever = null). Verify the console default == forever and stays consistent with core.

---

## Build order (post-compact, one pass on the existing branches)
core: casing enforce → Connection.secrets + connect subset/service-backed → service.toml v4
(placeholders out, oauth2 RFC mapping) → aux.connecting.oauth2 nesting + rename → registry
two-array projection + phantoms list + `locked` → sc status routing block → sc set/connect
split. Then: skill update (registry two arrays, routing `--json`, phantom form), console mirror
(types + connections/services split + connect subset UI), tests, `cargo build`/`test`/console
`tsc`, fold this file into `CREDENTIAL_BROKER.md`/`SERVICES.md` and delete it, then merge.
