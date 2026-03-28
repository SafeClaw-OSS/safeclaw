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

Immediately after notifying the user, you MUST create a cron job to poll for the approval result.
This is NOT optional — the user expects real-time feedback when they approve.

Call the `cron` tool with `action: "add"` and the following `job` parameter:

```json
{
  "action": "add",
  "job": {
    "name": "safeclaw-approval-<id>",
    "schedule": { "kind": "every", "everyMs": 1000 },
    "sessionTarget": "isolated",
    "payload": {
      "kind": "agentTurn",
      "message": "SafeClaw approval watcher.\nApproval id: <id>\nPoll URL: http://localhost:23295/approve/<id>\nExpires at: <expires_at> (unix timestamp)\n\nInstructions:\n1. If current time > expires_at: tell user approval expired, then call cron tool with action=remove and jobId=<this job id>. Done.\n2. Call the exec tool: curl -sf http://localhost:23295/approve/<id>\n3. If status=pending: reply HEARTBEAT_OK (will check again next interval)\n4. If status=approved: present response.body to the user. Remove this cron job.\n5. If status=rejected: tell user denied. Remove this cron job.\n6. If 404 or error: tell user expired. Remove this cron job."
    },
    "delivery": {
      "mode": "announce"
    }
  }
}
```

- `everyMs: 1000` = poll every 1 second for responsive UX
- The cron job auto-stops when the watcher removes itself (on approved/rejected/expired)
- `HEARTBEAT_OK` responses are silently discarded — safe for pending state
- The `cron` tool is a built-in tool in your runtime — use it directly (do not ask the user to run commands)

**Approved response structure** (when cron run calls GET /approve/\<id\>):
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

### Fallback (cron tool genuinely unavailable)

Only if the cron tool call fails with an error (not if you're unsure — try it first):
- Tell the user: "Let me know when you've approved it and I'll continue."
- When the user confirms, `curl -sf http://localhost:23295/approve/<id>` and proceed based on the status.

### Notes

- **Each 202 is independent** — if your task makes multiple API calls, each may trigger its own 202 with its own `id`. Create a separate cron watcher per id.
- **Polling is always GET** regardless of your original request method (POST, PUT, etc.)
- **Streaming requests**: if your original call used `stream: true`, the approved `response` will be a complete buffered JSON — handle it as a regular response
- **Expiry**: `expires_at` is a unix timestamp set by the server. Cron checks it first each run — auto-stops at the exact TTL boundary, however long that is.
- **Not found (404)**: treat same as expired — inform user, remove cron job

## Dummy API Key

Your config may contain a placeholder key like `sk-dummy`. This is intentional — SafeClaw intercepts requests and injects the real key from the encrypted vault. Do not replace it, expose it, or treat it as sensitive.
