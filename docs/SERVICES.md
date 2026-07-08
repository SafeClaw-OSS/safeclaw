# Service TOML reference (v4)

How to write a SafeClaw service definition. Design rationale lives in
[CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md); this page is the authoring
reference only.

A service is a folder `services/{category}/{id}/`:

```
services/integration/github/
  service.toml     # this page
  policy.toml      # per-action rules (each declares a level) — see POLICY.md; rules match (host, path, method)
```

Format: TOML (authored by humans/agents; CI publishes `registry.json`).

## service.toml

```toml
[service]
id = "github"            # required; [a-z0-9_], no "__". category = the {category}/ dir, not a field
name = "GitHub"          # display name
# optional: group, hidden, activation, help, secret_url

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
```

That is a complete service. An optional top-level `setup = """…"""` string
(sibling of `[service]`, not inside it) carries agent-facing setup notes. Add
`[oauth2]` only if the service mints tokens.

### `hosts`

The only destinations this service's secrets may ever be sent to.

- Entry = exact FQDN, or `*.suffix` (`*` leftmost only, matches exactly one
  label: `*.openai.azure.com` matches `foo.openai.azure.com`, not
  `a.b.openai.azure.com`). Bare `*` is rejected.
- Authorities only — no scheme, no path prefix.
- With a wildcard entry, each connection pins its exact host(s) at connect
  time; enforcement always runs against exact FQDNs.
- Do not add routing/transport info anywhere in the file; tool-native hints
  (e.g. npm `--registry`) belong in `setup` prose.

### `secrets`

The durable stored keys a connection of this type holds. Keys are `[A-Z0-9_]`
and are the same list for **every** service — an `[oauth2]` service lists its
refresh-token key here too (whatever `[oauth2].refresh_token` names). Presence of
all of them is what makes a connection "connected".

- **The injectable rule (uniform):** a connection's phantoms resolve to what its
  *production* PRODUCES. No section = pass-through: the products are the declared
  `secrets` themselves. A production section (`[oauth2]`; future `[sigv4]`-class)
  makes its OUTPUT the injectable and marks every secret its fields name (e.g.
  `refresh_token = "…"`) as a production INPUT — stored, never injectable
  (the proxy answers such a phantom with an explicit `403 refresh_forbidden`).
  The registry's per-connection `phantoms` list is the computed projection of
  this rule — agents copy from it, never derive.
- The phantom `__sc__<conn>__` resolves to the sole injectable; if a connection
  has several, agents use `__sc__<conn>__<key>__` (key lowercased).
- Insertion needs no declaration: the value replaces the phantom wherever the
  tool puts it — any header, query param, URL path, body, or inside a decoded
  `Authorization: Basic`. Never in the URL authority.

### `secret_url` (optional)

Where a HUMAN mints/manages this service's secret (e.g.
`https://crates.io/settings/tokens`). Purely auxiliary and display-only: the
console renders it as an "Open … → API tokens" helper link and
`sc connection add --service` prints it ("Get a token: …"). Nothing ever
fetches a secret from it, and it never participates in routing or policy.
Must be `http(s)` when present — it is rendered as a link, so the validator
rejects non-web schemes.

### `[oauth2]`

Declare only when the service authenticates with minted OAuth2 access tokens.

```toml
[service]
# …
secrets = ["GMAIL_REFRESH_TOKEN"]   # the refresh key is listed here too (uniform `secrets`)

[oauth2]
provider = "google"                 # -> services/_providers/<provider>.toml
scopes   = ["https://www.googleapis.com/auth/gmail.send"]
refresh_token = "GMAIL_REFRESH_TOKEN"  # RFC 6749 field name → the vault secret KEY the
                                    #   durable refresh token is stored under
# id_token = "GMAIL_ID_TOKEN"       # only when the provider returns a stored OIDC id token
# exposes = ["account_id"]          # optional extra derived values →
                                    #   __sc__<conn>__account_id__
```

The phantom resolves to the minted access token. Token slots use RFC 6749
response field names: `refresh_token` (required) maps the durable refresh token
to the vault secret KEY it lives under; `id_token` (optional) does the same for a
stored OIDC id token. Naming the durable token explicitly keeps a multi-secret
service unambiguous. The refresh key is internal to the mint — never injectable.
`access_token` (minted, ephemeral, never stored) and the flow temps `code` /
`code_verifier` are NOT in the toml. This is the only auth section; a signing
family (`[sigv4]`, `[web3sign]`) may be added when real. Sections are named by
auth mechanism, never by tool.

### Basic auth — nothing to declare

The proxy decodes `Authorization: Basic` and substitutes phantoms inside it.
Put the phantom where the pair goes:

- git: `https://x:__sc__github__@github.com/owner/repo` (URL userinfo). If the
  service validates the username (e.g. Bitbucket, case-sensitive), type the
  real username there.
- docker: `docker login -u <user> -p __sc__dockerhub__`.
- `sc git-credential` (optional helper): emits `("x", <phantom of the host
  connection's sole injectable secret>)`; declines if none or several.

## Which shape needs what

| Wire shape | Example | toml |
|---|---|---|
| `Authorization: Bearer <token>` | openai, npm | `hosts` + `secrets` |
| custom header | anthropic `x-api-key` | same |
| raw token, no prefix | crates.io | same |
| query param | Gemini `?key=` | same |
| token in URL path | telegram `/bot<token>/` | same |
| Basic pair | github/gitlab git | same |
| OAuth2 mint | gmail; openai-codex (`exposes`) | + `[oauth2]` |

## Out of scope

`services/system/*` and daemon-executed services are not credential brokering
(their upstream is the daemon); this schema does not apply to them.
