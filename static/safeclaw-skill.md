# SafeClaw

SafeClaw is a passkey-gated credential broker. Send a request through
it; SafeClaw injects the user's stored credentials server-side and
forwards.

## Daemon startup (self-host only)

If `$SAFECLAW_VAULT_URL` points at `localhost` / `127.0.0.1`, make sure
the daemon is up before the first call (`sc up` is idempotent):

```bash
curl -s -o /dev/null --connect-timeout 1 "$SAFECLAW_VAULT_URL/registry" \
  || safeclaw up
```

## Auth

Two env vars:

- **`$SAFECLAW_VAULT_URL`** — base URL of the user's SafeClaw daemon,
  e.g. `http://localhost:23294/v/abc-def`. If unset, get it from
  `sc env`; don't guess or hardcode a value.
- **`$SAFECLAW_API_KEY`** — your bearer token, from the dashboard's
  "Connect a new agent" flow or `sc agent add`.

```
Authorization: Bearer $SAFECLAW_API_KEY
```

## Discover what's available

```
GET $SAFECLAW_VAULT_URL/registry
Authorization: Bearer $SAFECLAW_API_KEY
```

Filter to save context: `?view=summary` and/or `?ids=a,b`.

```jsonc
{
  "version": 2,
  "vault_locked": false,
  "console_url": "https://.../vault/<your-vault-id>",  // deep link to this vault
  "vault_entries": ["OPENAI_API_KEY", "GMAIL_REFRESH_TOKEN"],  // null when locked
  "services": [
    { "id": "openai", "name": "OpenAI", "category": "llm",
      "connected": true,
      "endpoints": [{ "method": "ANY", "path": "/openai", "wildcard": true }],
      "vault_fields": [{ "name": "OPENAI_API_KEY", "kind": "secret" }] }
  ]
}
```

Use `connected: true` services freely.

If a service is `connected: false` (or absent), the user must add its
credential. **Hand them a link — don't run commands or walk them through
provider menus:**

```
Connect <service name>: open <console_url>#connections, paste your
credential there, approve with your passkey.
```

After they confirm, re-GET the registry for `connected: true`. (Where to
*get* the credential is the provider's side — mention it only if asked.)

Headless fallback, user at the daemon's own terminal: `sc set
<vault_fields[n].name> <value>`.

Never enter credentials yourself. Never echo one back.

If `vault_locked: true`, run `sc up`, surface the approval link it
prints to the user, and retry once they've tapped. Don't tell the user
to "unlock" or suggest a browser URL of your own.

## Call shape

```
<METHOD> $SAFECLAW_VAULT_URL/use/<service>[/<path>]
Authorization: Bearer $SAFECLAW_API_KEY
```

`<service>` is a service `id`; `<path>` is the upstream's own path
(optional for catch-all services). The daemon forwards your method,
path, and body verbatim, with the **upstream's natural method** — e.g.
`GET $SAFECLAW_VAULT_URL/use/gmail/gmail/v1/users/me/messages`,
`POST $SAFECLAW_VAULT_URL/use/openai/v1/chat/completions`.

Every response (initial call and follow-up polls) has the same shape:

```jsonc
{ "status": "ok" | "pending" | "rejected", ... }
```

| HTTP | status | extra fields | meaning |
|------|--------|--------------|---------|
| 200 | `ok` | `value` | done; use `value` |
| 202 | `pending` | `approval: {id, approve_url, poll_url, expires_at, expires_in, interval}` | needs user approve; poll every `interval`s (also sent as `Retry-After`) |
| 403 | `rejected` | — | user denied; do not retry |
| 404 | (none) | — | expired or unknown |

`value` for a Use call is the upstream's full response:
`{ status, headers, body, body_base64? }`. `body` is a string — JSON-parse
it if you need structured fields.

**Critical:** after a `pending` reply, NEVER re-POST the original URL —
that mints a fresh approval each time. Use `approval.poll_url` instead.

## Configuring a local tool (`setup` hints)

Some services need a **local tool** (a CLI, an SDK) pointed at SafeClaw instead
of its real endpoint, so the tool's traffic is brokered and the credential never
enters it. When a service needs this, its `/registry` entry carries a **`setup`**
hint — a goal plus ready-to-run config commands, already filled in for your
deployment. Read it, **tell the user what you're configuring and why first**,
then apply it (adapt to the user's real config if it differs).

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
    ok)         echo "$RESP"; break;;   # done — the result is in `value`
    rejected)   echo "ended: $STATUS"; exit 0;;
    pending|*)  sleep 3;;
  esac
done
```

If the loop finishes and it's still `pending`, don't abandon it — the op
stays valid ~30 min. Switch to B: ask them to reply once they've tapped,
then poll once more.

If poll returns HTTP 404, the op expired or the daemon restarted. Do NOT keep polling — re-POST the original request to get a fresh op.

### B — 2-step (runtimes that can't block, e.g. Telegram cron-style)

Surface `approval.approve_url` and ask the user to reply "done" once
they've approved. On their reply, GET `approval.poll_url` once. If still
`pending`, ask them to wait and reply again.
