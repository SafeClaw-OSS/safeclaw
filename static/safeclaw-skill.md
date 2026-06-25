# SafeClaw

SafeClaw is a passkey-gated credential broker. Send a request through
it; SafeClaw injects the user's stored credentials server-side and
forwards. The user signs each release with their passkey in a browser
tab.

## Daemon startup (self-host only)

If `$SAFECLAW_VAULT_URL` points at `localhost` / `127.0.0.1`, the daemon
runs on this machine — make sure it's up before the first call:

```bash
curl -s -o /dev/null --connect-timeout 1 "$SAFECLAW_VAULT_URL/registry" \
  || safeclaw up
```

`sc up` is idempotent — it starts the daemon's user service only
if it isn't already running, and never rewrites config. For a SaaS vault
(host is `api.safeclaw.pro` etc.) skip this: the daemon is hosted, so if
`/registry` is unreachable, just tell the user.

## Auth

SafeClaw expects two env vars in the user's shell:

- **`$SAFECLAW_VAULT_URL`** — the base URL of the user's SafeClaw daemon,
  e.g. `http://localhost:23294/v/abc-def` (the local daemon on this
  machine). If unset, get it from `sc env`. Vault id is baked into the URL.
- **`$SAFECLAW_API_KEY`** — your bearer token for this vault (always
  required). The user provides one from the dashboard's "Connect a new
  agent" flow or `sc agent add`. The daemon enforces it on the broker
  plane (`/use`, `/export`).

```
Authorization: Bearer $SAFECLAW_API_KEY
```

If `$SAFECLAW_VAULT_URL` is unset, stop and ask the user to set it.
Don't guess or hardcode a value. The skill is identical for every user
and every deployment — the user changes vaults by changing the env
var, not by re-installing the skill.

## Discover what's available

```
GET $SAFECLAW_VAULT_URL/registry
Authorization: Bearer $SAFECLAW_API_KEY
```

```jsonc
{
  "version": 2,
  "vault_locked": false,
  "console_url": "https://.../vault/<your-vault-id>",  // deep link to this vault
  "vault_entries": ["openai_api_key", "gmail_refresh_token"],  // null when locked
  "services": [
    { "id": "openai", "name": "OpenAI", "category": "llm",
      "connected": true,
      "endpoints": [{ "method": "ANY", "path": "/use/openai", "wildcard": true }],
      "vault_fields": [{ "name": "openai_api_key", "kind": "secret" }] }
  ]
}
```

Use `connected: true` services freely.

If a service is `connected: false` (or absent from `services`), the user
needs to add its credential. **Hand them a link — don't run commands and
don't walk them through provider menus.** Use `console_url` from the registry
(it points at this exact vault) and send them to its Connections tab:

```
To connect <service name>, open:  <console_url>#connections
— find <service name>, paste your credential, and approve with your passkey.
```

You never see or handle the credential; the user pastes it straight into the
web console. After they confirm, re-GET the registry — the service will show
`connected: true`. (If they ask where to GET the credential, you can briefly
point at the provider's side — e.g. a GitHub token at github.com → Settings →
Developer settings — but keep the SafeClaw step to just: open the link, paste,
approve. Don't reproduce the provider's whole UI unless asked.)

Headless / power-user alternative (only when the user is on the daemon's own
machine and prefers the terminal): `sc set <vault_fields[n].name> <value>`
seals it via a passkey gesture. Prefer the link for everyone else.

Never offer to enter credentials yourself. Never echo a credential back.

If `vault_locked: true`, run `sc up` — it brings SafeClaw up and unlocks
the vault, printing an approval link; surface that link to the user (they
tap their passkey) and retry once it's done. Don't tell the user to
"unlock" or suggest a browser URL of your own.

## Call shape

Use `proxy_base` from the registry response as the base URL — it is
already set to the correct host and path for your deployment.

```
<METHOD> <proxy_base>/<service>[/<path>]
Authorization: Bearer $SAFECLAW_API_KEY
```

Use the **upstream's natural HTTP method** — `GET` for reads
(`GET <proxy_base>/openai/v1/models`), `POST`/`PUT`/`PATCH`/`DELETE` for
writes. The daemon forwards your method, path, and body verbatim to the
upstream. `<path>` is optional — services that catch any path work with
or without one. Multi-segment paths (`v1/chat/completions`) pass straight
through.

Every response (initial call and follow-up polls) has the same shape:

```jsonc
{ "status": "ok" | "pending" | "rejected", ... }
```

| HTTP | status | extra fields | meaning |
|------|--------|--------------|---------|
| 200 | `ok` | `value` | done; use `value` |
| 202 | `pending` | `approval: {id, approve_url, poll_url, expires_at}` | needs user approve |
| 403 | `rejected` | — | user denied; do not retry |
| 404 | (none) | — | expired or unknown |

(HTTP 410 is reserved for a future single-use semantic; the daemon does
not emit it today.)

`value` for a Use call is the upstream's full response:
`{ status, headers, body, body_base64? }`. `body` is a string — JSON-parse
it if you need structured fields.

**Critical:** after a `pending` reply, NEVER re-POST the original URL —
that mints a fresh approval each time. Use `approval.poll_url` instead.

## Raw secret export (high-risk)

`/use/<service>` is the default — broker injects credentials server-side,
agent never holds them. Only reach for `/export/<key>` when no
`/use/<service>` route fits the task.

```
POST $SAFECLAW_VAULT_URL/export/<key>
```

`<key>` is a `vault_entries` item from `/registry`. Same `pending` → `ok`
lifecycle as `/use/`. On `ok`, `value` is the plaintext secret as a string —
the agent becomes its custodian. Treat every successful export as the
user deliberately handing you raw material.

## Polling

Two patterns. Try A first; fall back to B if your runtime can't hold a
long shell command.

### A — Auto-poll

Surface `approval.approve_url` to the user on its own line. Do NOT ask
them to type "done" — their browser tap is the signal. Then:

```bash
POLL_URL="<approval.poll_url from the 202 body>"
for i in $(seq 1 100); do
  RESP=$(curl -sS -H "Authorization: Bearer $SAFECLAW_API_KEY" "$POLL_URL")
  STATUS=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))')
  case "$STATUS" in
    ok)         echo "$RESP"; break;;
    rejected)   echo "ended: $STATUS"; exit 0;;
    pending|*)  sleep 3;;
  esac
done
```

If poll returns HTTP 404, the op expired or the daemon restarted. Do NOT keep polling — re-POST the original request to get a fresh op.

### B — 2-step (runtimes that can't block, e.g. Telegram cron-style)

Surface `approval.approve_url` and ask the user to reply "done" once
they've approved. On their reply, GET `approval.poll_url` once. If still
`pending`, ask them to wait and reply again.
