# SafeClaw

SafeClaw is a passkey-gated credential broker. Send a request through
it; SafeClaw injects the user's stored credentials server-side and
forwards. The user signs each release with their passkey in a browser
tab.

## Auth

SafeClaw expects two env vars in the user's shell:

- **`$SAFECLAW_VAULT_URL`** — the base URL for the user's vault, e.g.
  `https://api.safeclaw.pro/v/abc-def` (SaaS) or
  `http://localhost:23294/v/abc-def` (self-host). Vault id is baked
  into the URL.
- **`$SAFECLAW_API_KEY`** — bearer token. Required on SaaS. On a
  self-hosted daemon the user may leave it empty; the daemon ignores
  the Authorization header.

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
  "console_url": "https://.../vault",
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
needs to add credentials. Default to the CLI path:

Look up the service's `vault_fields` array in the registry response —
each entry's `name` is the key to set:

```
sc set <vault_fields[n].name> <value>
# example: sc set github_api_key ghp_xxxxx
```

This opens a browser passkey gesture to seal the value into the vault.
After it succeeds, the service will show `connected: true`.

If `console_url` in the registry response points to `safeclaw.pro`, the
user can alternatively add credentials via the web console there.

Never offer to enter credentials yourself. Never echo a credential back.

If `vault_locked: true`, run `sc unlock` first (or open `console_url` if
on safeclaw.pro).

## Call shape

```
POST $SAFECLAW_VAULT_URL/use/<service>[/<path>]
Authorization: Bearer $SAFECLAW_API_KEY
```

`<path>` is optional — services like `demo` that catch any path work with
or without one. Multi-segment paths (`v1/chat/completions`) pass straight
through to the upstream.

Every response (initial call and follow-up polls) has the same shape:

```jsonc
{ "status": "ok" | "pending" | "rejected" | "consumed", ... }
```

| HTTP | status | extra fields | meaning |
|------|--------|--------------|---------|
| 200 | `ok` | `value` | done; use `value` |
| 202 | `pending` | `approval: {id, approve_url, poll_url, expires_at}` | needs user approve |
| 403 | `rejected` | — | user denied; do not retry |
| 410 | `consumed` | — | already redeemed once |
| 404 | (none) | — | expired or unknown |

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
    ok)                 echo "$RESP"; break;;
    rejected|consumed)  echo "ended: $STATUS"; exit 0;;
    pending|*)          sleep 3;;
  esac
done
```

### B — 2-step (runtimes that can't block, e.g. Telegram cron-style)

Surface `approval.approve_url` and ask the user to reply "done" once
they've approved. On their reply, GET `approval.poll_url` once. If still
`pending`, ask them to wait and reply again.
