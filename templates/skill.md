---
name: safeclaw
description: 'SafeClaw proxy protocol handler. Load when your API calls are routed through SafeClaw (localhost:23295 or remote proxy). Teaches you how to handle vault-locked responses and approval-required flows.'
---

# SafeClaw Proxy

SafeClaw is a local API key vault and proxy. Your calls to the proxy are forwarded to upstream services with credentials injected automatically.

## Vault Locked

If the proxy response contains `safeclaw_unlock_url` (or `safeclaw_buttons` with an unlock action), the vault is locked.

**Do not retry automatically.** Tell the user:

> "SafeClaw is locked — your API keys are unavailable. Please unlock: [safeclaw_unlock_url]"

Wait for the user to confirm they've unlocked before retrying.

## Approval Required (HTTP 202)

Some operations require explicit human approval. You will receive HTTP 202 with:

```json
{
  "id": "<approval-id>",
  "safeclaw_approve_url": "https://...",
  "expires_at": 1711548300
}
```

### Step 1 — Notify the user immediately

Tell the user what you were trying to do and share the approval link.
If the channel supports inline buttons (e.g. Telegram), use a button — otherwise send the URL as text:

> "I need approval to [describe the action — service + what you were doing]. Please review: **[Review & Approve]**(`safeclaw_approve_url`)"

Then end your turn — no need to say "waiting…", the notification above is sufficient.

### Step 2 — Set up a cron watcher (required)

Immediately after notifying the user, you MUST create a background polling job so the user gets real-time feedback when they approve.

**Option A** — If you have a `cron` tool, call it with `action: "add"`:
```json
{
  "action": "add",
  "job": {
    "name": "safeclaw-approval-<id>",
    "schedule": { "kind": "every", "everyMs": 1000 },
    "sessionTarget": "isolated",
    "payload": {
      "kind": "agentTurn",
      "message": "Poll http://localhost:23295/approve/<id>. If pending→HEARTBEAT_OK. If approved→announce response.body, remove this job. If rejected/expired/404→announce, remove job."
    },
    "delivery": { "mode": "announce" }
  }
}
```

**Option B** — If you do NOT have a `cron` tool but have `exec`, use the CLI:
```bash
openclaw cron add --name "safeclaw-approval-<id>" \
  --every 1000 \
  --isolated \
  --message "Poll http://localhost:23295/approve/<id>. If pending→HEARTBEAT_OK. If approved→announce response.body and remove this job via: openclaw cron remove <jobId>. If rejected/expired/404→announce and remove job." \
  --announce
```

**Option C** — If neither cron tool nor CLI is available, tell the user "Let me know when you've approved" and poll once on their reply.

- `everyMs: 1000` = poll every 1 second for responsive UX
- The cron job auto-stops when the isolated agent removes it (on approved/rejected/expired)
- `HEARTBEAT_OK` responses are silently discarded — safe for pending state

**Approved response structure** (when the watcher polls GET /approve/\<id\>):
```json
{
  "status": "approved",
  "response": {
    "status": 200,
    "headers": { ... },
    "body": { ...upstream API response... }
  }
}
```
Use `response.body` as the data, not the whole `response` object.

### Notes

- **Each 202 is independent** — if your task makes multiple API calls, each may trigger its own 202 with its own `id`. Create a separate cron watcher per id.
- **Polling is always GET** regardless of your original request method (POST, PUT, etc.)
- **Streaming requests**: if your original call used `stream: true`, the approved `response` will be a complete buffered JSON — handle it as a regular response
- **Expiry**: `expires_at` is a unix timestamp set by the server. Cron checks it first each run — auto-stops at the exact TTL boundary, however long that is.
- **Not found (404)**: treat same as expired — inform user, remove cron job

## Dummy API Key

Your config may contain a placeholder key like `sk-dummy`. This is intentional — SafeClaw intercepts requests and injects the real key from the encrypted vault. Do not replace it, expose it, or treat it as sensitive.
