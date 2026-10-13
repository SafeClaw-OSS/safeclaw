# Service TOML reference (v4)

How to write a SafeClaw service definition. Design rationale lives in
[credential-broker.md](https://github.com/getsafeclaw/safeclaw/blob/main/design/credential-broker.md); this page is the authoring
reference only.

A service is a folder `services/{id}/` — flat, so the filesystem itself
enforces id uniqueness. Classification is data (`tags`), not layout.

```
services/github/
  service.toml     # this page
  policy.toml      # per-action rules (each declares a level) — see policy.md; rules match (host, path, method)
```

Format: TOML (authored by humans/agents; CI publishes `registry.json`).

## Adding services to a vault: `sc service`

Services outside the built-in catalog live in your vault, added from a
**source**. A source is a folder in the catalog's layout:

- a service folder: `service.toml` + optional `policy.toml`, or
- a collection: `services/<id>/service.toml` + optional `policy.toml`.

| Source | Example |
|---|---|
| Local folder | `./my-api`, `/abs/path/tools` |
| GitHub repository, optional sub-folder | `github:owner/repo`, `github:owner/repo:services/acme` (`git:` works too) |

GitHub only for now; another git host or a URL is refused. `owner/slug`
names the service registry, which is not open yet.

| Command | Does |
|---|---|
| `sc service add <source> [--id <id>] [--ref <ref>]` | Reads the source, checks every definition, stores them with one passkey approval. |
| `sc service update <id\|source> [--all] [--check] [-y] [--ref <ref>]` | Re-reads a source and stores what changed, with one passkey approval. |
| `sc service ls [id]` | Lists the vault's definitions by source, with the pinned commit and loaded / skipped (with the reason). |
| `sc service rm <id\|source>` | Removes one service, or every service of a source. |
| `sc service validate <source> [--ref <ref>]` | Runs the same checks as `add`, without a vault. For authors and CI. |

How it works:

- **Pinned.** A GitHub source is resolved to a full commit (`--ref` takes a
  branch, tag or commit; default: the default branch) and stored with it.
- **Read, never run.** Only `service.toml` and `policy.toml` at those paths
  are read, as regular files: symlinks, links and devices are not followed
  (a local folder is opened one component at a time without following a
  link, macOS and Linux), a GitHub tarball is read in memory (never
  extracted), `..` or an absolute path refuses it, and sizes and entry counts
  are capped. A parse error gives its kind, line and column, never the text.
- **All or nothing.** Every definition passes the same gate the daemon runs at
  unlock; one invalid definition refuses the whole source.
- **One approval.** The card lists each service, every host that receives
  its credentials or OAuth data (declared hosts, the token endpoint, the
  authorization page, a redirect that leaves your device), `PKCE: off` when
  the flow has no PKCE, the rules it applies, and the source with its commit.
  A GitHub source is fetched again on your device at that commit and must
  match, or the request is refused; a local folder, or GitHub out of reach,
  shows the source as stated by the requester. Only the rules that tighten
  apply in a vault.
- **Ids.** A definition is stored under its `[service] id`. It may not be a
  built-in id or one another source already holds; `--id` renames a
  single-service source.
- **Updates.** `update` proposes the remote default branch head (or `--ref`),
  shows what changes, and marks new hosts (`+ NEW HOST`) and what now lets
  requests through more easily (`! LOOSENED`: a rule gone or less strict, a
  longer approval window, a request variable an approval no longer binds,
  PKCE turned off). `--check` only shows; `-y`
  skips the terminal question, never the passkey. A local source is re-read
  only from the path you pass: `sc service update ./my-api`. Services the
  source no longer has are removed.
- **Vaults with members.** Their service definitions must be signed by an
  owner in the browser, so `add`, `update` and `rm` are refused there; add
  services from the console for now.
- **Sync.** If the definitions changed elsewhere before your change reached
  the cloud and the cloud copy cannot be replaced, yours is set aside and not
  applied; `sc service ls` and `sc sync` say so. Re-run the command.
- **Removal.** Connections that use a removed service are kept and listed;
  they stop working until a definition is added again.
- `ls` reads the unlocked vault: no network, no passkey.

## service.toml

```toml
[service]
id = "github"            # required; [a-z0-9_], no "__"; must equal the services/{id}/ dir name
name = "GitHub"          # display name
tags = ["app"]           # classification, multiple allowed — see below
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

### `tags`

Classification, replacing the old `services/{category}/` directory layer.
Lowercase-kebab slugs, several allowed, no duplicates (validator-enforced —
shape only, the vocabulary is open).

- Core vocabulary today: `ai` (model providers), `app` (external apps/SaaS),
  `messaging` (Telegram-class channels). Business-dimension tags (e.g.
  `wallet`) coexist freely in the same list.
- Consumers: the console derives its filter chips and grouping from the tags
  present in the registry (an unknown tag renders verbatim as a chip), and the
  policy engine matches tags against the per-tag default floors — when several
  of a service's tags carry a floor, the most restrictive wins.
- Untagged (typical for per-vault custom services): no tag floor applies —
  only the global floor — and the console buckets the service as an app.

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
provider = "google"                 # display label only ("Connect with Google")
scopes   = ["https://www.googleapis.com/auth/gmail.send"]
refresh_token = "GMAIL_REFRESH_TOKEN"  # RFC 6749 field name → the vault secret KEY the
                                    #   durable refresh token is stored under
authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url         = "https://oauth2.googleapis.com/token"
pkce              = true
client_id         = "499410884315-…apps.googleusercontent.com"  # PUBLIC client, inline
# client_secret only for a non-confidential PUBLIC client (by convention,
# review-enforced; no client_type field). No provider-template layer; every
# [oauth2] is inline-complete.
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
