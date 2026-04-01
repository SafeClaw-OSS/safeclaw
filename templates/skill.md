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

### Step 1 — Notify the user and wait

Send a message with:
1. What you were trying to do (service + action)
2. The approval URL as visible clickable text
3. An inline button labeled "Done" that the user clicks after approving on the web

Example message:

> I need approval to read your Gmail inbox.
> Please review and approve: safeclaw_approve_url
> Tap **Done** below after you've approved or rejected.

Then **stop and wait** for the user to click Done or reply.

**CRITICAL: Do NOT re-send the original API call after the user responds.** That creates a new approval request (infinite loop). Always retrieve the result by polling the approval ID (Step 2).

### Step 2 — Retrieve the result

When the user clicks Done or tells you they've approved/rejected, poll the approval endpoint:

```
curl -sf http://localhost:23295/approve/<id>
```

**Approved response:**
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

- If `status` is `"approved"`: use `response.body` as the API result. Continue the original task.
- If `status` is `"rejected"`: tell the user the request was denied.
- If `status` is `"pending"`: the user hasn't acted yet. Ask them to complete the approval first.
- If 404: the approval expired.

### Notes

- **Each 202 is independent** — if your task makes multiple API calls, each may trigger its own 202.
- **Polling is always GET** regardless of original method (POST, PUT, etc.)
- **Streaming requests**: approved `response` will be complete buffered JSON
- **Expiry**: `expires_at` is a unix timestamp.
- **Not found (404)**: treat same as expired

## Dummy API Key

Your config may contain a placeholder key like `sk-dummy`. This is intentional — SafeClaw intercepts requests and injects the real key from the encrypted vault. Do not replace it, expose it, or treat it as sensitive.
