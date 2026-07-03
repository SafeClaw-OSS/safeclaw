# Service TOML reference (v4)

How to write a SafeClaw service definition. Design rationale lives in
[CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md); this page is the authoring
reference only.

A service is a folder `services/{category}/{id}/`:

```
services/integration/github/
  service.toml     # this page
  policy.toml      # risk-tier rules — see POLICY_RISK_TIERS.md; rules match (host, path, method)
```

Format: TOML (authored by humans/agents; CI publishes `registry.json`).

## service.toml

```toml
[service]
id = "github"            # required; [a-z0-9_], no "__"
name = "GitHub"          # display name
# optional: group, hidden, activation, help

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]

[placeholders]           # optional UI paste hints
GITHUB_TOKEN = "github_pat_..."

setup = """..."""        # optional agent-facing setup notes
```

That is a complete service. Add `[oauth2]` only if the service mints tokens.

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

The stored keys a connection of this type holds. Keys are `[A-Z0-9_]`.

- The phantom `__sc__<conn>__` resolves to the sole injectable secret; if a
  service declares several, agents use `__sc__<conn>__<key>__` (key lowercased).
- Insertion needs no declaration: the value replaces the phantom wherever the
  tool puts it — any header, query param, URL path, body, or inside a decoded
  `Authorization: Basic`. Never in the URL authority.

### `[oauth2]`

Declare only when the service authenticates with minted OAuth2 access tokens.

```toml
[oauth2]
provider = "google"                 # -> services/_providers/<provider>.toml
scopes   = ["https://www.googleapis.com/auth/gmail.send"]
secret   = "GMAIL_REFRESH_TOKEN"    # stored refresh secret feeding the mint
# exposes = ["account_id"]          # optional extra derived values →
                                    #   __sc__<conn>__account_id__
```

The phantom resolves to the minted access token. The refresh secret is
internal automatically (referenced only here). This is the only auth section;
a signing family (`[sigv4]`, `[web3sign]`) may be added when real. Sections are
named by auth mechanism, never by tool.

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
