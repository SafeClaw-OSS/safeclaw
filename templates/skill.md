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

**RULE: After receiving 202, you must NEVER call the same API endpoint again for this task.** The approved result is retrieved via `GET http://localhost:23295/approve/<id>` — not by re-sending the original request. Re-sending creates an infinite approval loop.

### Step 1 — Notify the user and wait

Send a message with:
1. What you were trying to do (service + action)
2. The approval URL as visible clickable text
3. Ask the user to reply when done (e.g. "reply 'done' after approving")

Example message:

> I need approval to read your Gmail inbox.
> Please review and approve: safeclaw_approve_url
> Reply "done" after you've approved or rejected.

Then **stop and wait** for the user to reply.

**CRITICAL: Do NOT re-send the original API call after the user responds.** That creates a new approval request (infinite loop). Always retrieve the result by polling the approval ID (Step 2).

### Step 2 — Retrieve the result

When the user replies (e.g. "done", "approved", "好了", or any confirmation), make a **GET request** to retrieve the result:

```
GET http://localhost:23295/approve/<id>
```

Use whatever HTTP tool you have (fetch, curl, http request, etc.) to make this GET request. This is the **only** way to get the result. Do NOT call the original API again.

**Response when approved:**
```json
{
  "status": "approved",
  "response": {
    "status": 200,
    "headers": { ... },
    "body": { ...the actual API response data... }
  }
}
```

Use `response.body` — it contains the complete API result (e.g. the email data, calendar events, etc.). Continue your original task with this data.

**Other statuses:**
- `"rejected"` — tell the user the request was denied.
- `"pending"` — the user hasn't acted yet. Ask them to complete the approval first.
- 404 — the approval expired.

### Notes

- **Each 202 is independent** — if your task makes multiple API calls, each may trigger its own 202.
- **Polling is always GET** regardless of original method (POST, PUT, etc.)
- **Streaming requests**: approved `response` will be complete buffered JSON
- **Expiry**: `expires_at` is a unix timestamp.
- **Not found (404)**: treat same as expired

## Dummy API Key

Your config may contain a placeholder key like `sk-dummy`. This is intentional — SafeClaw intercepts requests and injects the real key from the encrypted vault. Do not replace it, expose it, or treat it as sensitive.
