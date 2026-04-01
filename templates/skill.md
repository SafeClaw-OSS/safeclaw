---
name: safeclaw
description: 'SafeClaw proxy protocol handler. Load when your API calls are routed through SafeClaw (localhost:23295 or remote proxy). Teaches you how to handle vault-locked responses and approval-required flows.'
---

# SafeClaw Proxy Protocol

SafeClaw is a local API key vault and proxy. Your calls to the proxy are forwarded to upstream services with credentials injected automatically.

## 1. Vault locked

If the proxy response contains `safeclaw_unlock_url`, the vault is locked.

**Action:** Tell the user the vault is locked, provide the unlock URL as a clickable link, and create an inline button labeled "🔓 Unlock" linking to the URL. Then **stop and wait** — do not retry until the user confirms they have unlocked.

## 2. Approval required (HTTP 202)

Some operations require human approval. When you receive HTTP 202, the response body looks like:

```json
{
  "id": "<approval-id>",
  "safeclaw_approve_url": "https://...",
  "expires_at": 1711548300
}
```

### The one rule

**After receiving 202, NEVER call the original API endpoint again for this task.** The result is retrieved via the approval ID — not by re-sending the request. Re-sending creates a new approval each time, causing an infinite loop where the user's approvals never match your requests.

### Step 1 — Ask the user to approve

Send a message with:
1. What you were trying to do (service + action)
2. The `safeclaw_approve_url` as clickable text
3. An inline button labeled "✅ Done" that sends "Done" back to the chat

Then **stop and wait** for the user to tap Done or reply.

### Step 2 — Retrieve the result

When the user confirms, make a **GET** request to:

```
GET http://localhost:23295/approve/<approval-id>
```

This is the **only** way to get the result. Do NOT call the original API again.

**Response statuses:**

| Status | Meaning | Action |
|--------|---------|--------|
| `"approved"` | User approved | Use `response.body` — it contains the full upstream API response |
| `"pending"` | User hasn't acted yet | Ask them to complete the approval |
| `"rejected"` | User denied | Tell the user the request was denied |
| 404 | Expired or not found | Tell the user it expired; start over if needed |

**Approved response format:**
```json
{
  "status": "approved",
  "response": {
    "status": 200,
    "headers": { "..." },
    "body": { "...the actual API response data..." }
  }
}
```

### Important notes

- Each 202 is independent — multiple API calls in one task may each trigger their own 202.
- Polling is always **GET** regardless of the original method (POST, PUT, etc.).
- `expires_at` is a unix timestamp. After expiry the approval is gone.
- Streaming requests: the approved `response` is complete buffered JSON.

## 3. Dummy API key

Your config may contain a placeholder key like `sk-dummy` or `sk-safeclaw-proxy`. This is intentional — SafeClaw intercepts requests and injects the real key from the encrypted vault. Do not replace it, expose it, or treat it as sensitive.
