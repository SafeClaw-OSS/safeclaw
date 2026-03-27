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

### Step 1 — Notify the user

Tell them what you were trying to do and share the approval link:

> "I need approval to [describe the action — service + what you were doing]. Please review and approve: [safeclaw_approve_url]"

### Step 2 — Poll for result

`GET /approve/<id>` on the same proxy host, every 5 seconds:

```
GET http://localhost:23295/approve/<id>
```

| Response | What to do |
|---|---|
| `{"status": "pending"}` | Keep polling |
| `{"status": "approved", "response": {...}}` | Use `response` as the original call result, continue task |
| `{"status": "rejected"}` | Tell user the action was blocked; ask how to proceed |
| `{"status": "expired"}` | Tell user the approval window expired; ask if they want to retry |

### Notes

- **Polling is always GET** regardless of your original request method (POST, PUT, etc.)
- **Streaming requests**: if your original call used `stream: true`, the approved `response` will be a complete buffered JSON — handle it as a regular response
- **Expiry**: `expires_at` is a unix timestamp (5 min window). If approaching, remind the user
- **Not found (404)**: the approval ID doesn't exist — do not retry, inform the user
