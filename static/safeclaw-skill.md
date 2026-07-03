# SafeClaw

SafeClaw is a passkey-gated credential broker. You never hold the real
secret. Instead each connected service gives you a **phantom** — a
placeholder like `__sc__github__`. Put the phantom where the credential
belongs (an env var a tool reads, a request header, a config file) and route
your traffic through SafeClaw; SafeClaw swaps the phantom for the real value
on the way out, and only toward that connection's own `hosts`. The user
approves anything sensitive with a passkey tap in a browser tab.

One sentence: *put the phantom where the credential goes; run the command
through SafeClaw.*

## Daemon startup (self-host only)

If `$SAFECLAW_VAULT_URL` points at `localhost` / `127.0.0.1`, the daemon
runs on this machine — make sure it's up before the first call:

```bash
curl -s -o /dev/null --connect-timeout 1 "$SAFECLAW_VAULT_URL/registry" \
  || safeclaw up
```

`sc up` is idempotent — it starts the daemon's user service only if it isn't
already running, and never rewrites config (`sc down` stops it). For a SaaS
vault (host is `api.safeclaw.pro` etc.) skip this: the daemon is hosted, so if
`/registry` is unreachable, just tell the user.

## Auth

SafeClaw expects two env vars in the user's shell:

- **`$SAFECLAW_VAULT_URL`** — the base URL of the user's SafeClaw daemon,
  e.g. `http://localhost:23295/v/abc-def` (the local daemon on this machine).
  If unset, get it from `sc env`. The vault id is baked into the URL.
- **`$SAFECLAW_API_KEY`** — your bearer token, used only for the discovery
  endpoint below. The user provides one from the dashboard's "Connect a new
  agent" flow or `sc agent add`.

```
Authorization: Bearer $SAFECLAW_API_KEY
```

If `$SAFECLAW_VAULT_URL` is unset, stop and ask the user to set it. Don't
guess or hardcode a value. The skill is identical for every user and every
deployment — the user changes vaults by changing the env var, not by
re-installing the skill.

## Discover what's available

```
GET $SAFECLAW_VAULT_URL/registry
Authorization: Bearer $SAFECLAW_API_KEY
```

Filter to save context: `?view=summary` and/or `?ids=a,b`.

```jsonc
{
  "version": 3,
  "vault_locked": false,
  "console_url": "https://.../vault/<your-vault-id>",  // deep link to this vault
  "vault_entries": ["OPENAI_API_KEY", "GMAIL_REFRESH_TOKEN"],  // null when locked
  "services": [
    { "id": "github", "name": "GitHub", "category": "dev",
      "connected": true,
      "hosts": ["api.github.com", "github.com"],
      "phantoms": { "GITHUB_TOKEN": "__sc__github__" } }
  ]
}
```

Each row carries its anchored **`hosts`** and a ready-made **`phantoms`** map
(injectable role → the exact phantom string). Copy phantoms verbatim — never
build one yourself. Use `connected: true` services freely.

If a service is `connected: false` (or absent), the user must add its
credential. **Hand them a link — don't run commands or walk them through
provider menus.** `console_url` points at this vault; send them to its
Connections tab:

```
Connect <service name>: open <console_url>#connections, add your
credential there, approve with your passkey.
```

You never see or handle it. After they confirm, re-GET the registry for
`connected: true`. (Where to *get* the credential is the provider's side —
mention it only if asked.)

Headless fallback, user at the daemon's own terminal (passkey-gated):

```
sc set STRIPE_KEY --host api.stripe.com        # one secret + its host anchor
sc connect myapi --host api.example.com --secret API_TOKEN=<value>
```

Never enter credentials yourself. Never echo one back.

If `vault_locked: true`, run `sc up` — it brings SafeClaw up and unlocks the
vault, printing an approval link; surface that link to the user (they tap
their passkey) and retry once it's done. Don't tell the user to "unlock" or
suggest a browser URL of your own.

## Using a connection

Every connected service in `/registry` carries a ready-made **phantom** — a
placeholder like `__sc__github__`. Put it exactly where the real credential
would go (the env var a tool reads, a header, a config file). SafeClaw swaps
it for the real value on the way out — and only toward that connection's
`hosts`.

Phantoms only work when the traffic passes through SafeClaw. Check first:

    sc status      # routed: true|false, plus each connection's phantom

`routed: false` → run the command through SafeClaw (`sc run -- <cmd>`, or the
service's `setup` hint). Don't send a phantom unrouted — the upstream just
rejects it, indistinguishably from a bad key.

Examples (the phantom goes wherever that tool expects the credential):

```bash
sc run -- curl https://api.stripe.com/v1/charges \
  -H "Authorization: Bearer __sc__stripe__"
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
sc run -- git clone https://__sc__github__@github.com/<owner>/<repo>
```

Multi-account is by phantom VALUE, never by env-var name: switch
`__sc__github__` → `__sc__github_work__`. If a request names an unknown
connection, SafeClaw rejects it with a clear message (it does not forward a
bad phantom to the upstream).

## Configuring a local tool (`setup` hints)

Some services need a **local tool** (a CLI, an SDK) run through SafeClaw so its
traffic is brokered and the credential never enters it. When a service needs
this, its `/registry` entry carries a **`setup`** hint — a goal plus
ready-to-run steps. Read it, **tell the user what you're configuring and why
first**, then apply it (adapt to the user's real config if it differs). The
per-service `setup` hint is the source of truth; nothing tool-specific lives
in this skill.

## Approvals

Some credentials are policy-gated: the first time you route a request that
needs one, SafeClaw doesn't forward it — the command fails and its error output
carries a SafeClaw approval line, e.g.:

```
SafeClaw approval needed to use this credential.
Approve with your passkey:
  https://.../grant/<op_id>
Then re-run the same command.
```

Surface that link to the user on its own line. Do NOT ask them to type "done"
— their browser tap is the signal. Once they've approved, **re-run the exact
same command**; the approval is cached, so it now goes through. A new
destination host you haven't used before is a higher-friction, one-time
*permanent grant* approval — same flow, surface the link.

For a runtime that can't easily re-run, the approval JSON in that output also
carries a `poll_url` (`$SAFECLAW_VAULT_URL/op/<op_id>`); GET it until
`status` is `ok`, then re-run. The op stays valid ~30 min.
