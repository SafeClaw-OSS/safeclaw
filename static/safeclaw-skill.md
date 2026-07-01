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
  plane (`/use`).

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
provider menus.** `console_url` points at this vault; send them to its
Connections tab:

```
Connect <service name>: open <console_url>#connections, paste your
credential there, approve with your passkey.
```

You never see or handle it. After they confirm, re-GET the registry for
`connected: true`. (Where to *get* the credential is the provider's side —
mention it only if asked.)

Headless fallback, user at the daemon's own terminal: `sc set
<vault_fields[n].name> <value>` (passkey-gated).

Never enter credentials yourself. Never echo one back.

If `vault_locked: true`, run `sc up` — it brings SafeClaw up and unlocks
the vault, printing an approval link; surface that link to the user (they
tap their passkey) and retry once it's done. Don't tell the user to
"unlock" or suggest a browser URL of your own.

## Call shape

Credential calls go to `$SAFECLAW_VAULT_URL/use/<service>` — the same base as
everything else:

```
<METHOD> $SAFECLAW_VAULT_URL/use/<service>[/<path>]
Authorization: Bearer $SAFECLAW_API_KEY
```

`<service>` is a service `id`; `<path>` is the upstream's own path. The daemon
forwards your method, path, and body verbatim, with the **upstream's natural
method** — e.g. `GET $SAFECLAW_VAULT_URL/use/openai/v1/models`,
`GET $SAFECLAW_VAULT_URL/use/gmail/gmail/v1/users/me/messages`,
`POST $SAFECLAW_VAULT_URL/use/openai/v1/chat/completions`. `<path>` is optional
for catch-all services; multi-segment paths pass straight through.

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

## Configuring a local tool (`setup` hints)

Some services need a **local tool** (a CLI, an SDK) pointed at SafeClaw instead
of its real endpoint, so the tool's traffic is brokered and the credential never
enters it. When a service needs this, its `/registry` entry carries a **`setup`**
hint — a goal plus ready-to-run config commands, already filled in for your
deployment. Read it, **tell the user what you're configuring and why first**,
then apply it (adapt to the user's real config if it differs). The per-service
`setup` hint is the source of truth; nothing tool-specific lives in this skill.

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
