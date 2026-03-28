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

Then proceed to Step 2 immediately (do not wait for user reply).

### Step 2 — Set up an approval watcher (required)

You MUST create an isolated cron job that polls the approval endpoint every second. When approved, the watcher sends a resume signal to your main session via CLI so you can continue automatically.

Create the watcher cron:

```json
{
  "action": "add",
  "job": {
    "name": "safeclaw-approval-<id>",
    "schedule": { "kind": "every", "everyMs": 1000 },
    "sessionTarget": "isolated",
    "payload": {
      "kind": "agentTurn",
      "message": "SafeClaw approval watcher.\nApproval id: <id>\nPoll URL: http://localhost:23295/approve/<id>\nExpires at: <expires_at>\nOriginal task: <one-line description of what the user asked>\n\nInstructions:\n1. Check current time vs expires_at. If expired: send expiry notification via CLI (see step 5), then remove this job.\n2. Run: curl -sf http://localhost:23295/approve/<id>\n3. If status=pending: reply HEARTBEAT_OK\n4. If status=approved: Send resume signal via CLI (see step 5), then remove this watcher job.\n5. If status=rejected or 404: Send rejection notification via CLI (see step 5), then remove this job.\n\nStep 5 — Sending the resume signal:\nIMPORTANT: Do NOT use the cron tool to create a systemEvent. Instead, use the exec tool to run this CLI command:\n\nFor approved:\nexec: openclaw cron add --name safeclaw-resume-<id> --at +1s --delete-after-run --system-event \"SafeClaw approval <id> APPROVED. Original task: <task>. API response: <format response.body as clean readable text, not raw JSON dump>. Continue executing the original task using this data.\"\n\nFor rejected:\nexec: openclaw cron add --name safeclaw-resume-<id> --at +1s --delete-after-run --system-event \"SafeClaw approval <id> REJECTED. Original task: <task>. The user denied this request.\"\n\nFor expired:\nexec: openclaw cron add --name safeclaw-resume-<id> --at +1s --delete-after-run --system-event \"SafeClaw approval <id> EXPIRED. Original task: <task>. The approval timed out.\"\n\nThe CLI command creates a gateway-level systemEvent that reaches the real main session (unlike cron tool calls from isolated sessions which are scoped)."
    },
    "delivery": { "mode": "none" }
  }
}
```

If you do not have a `cron` tool, use `exec` to run `openclaw cron add` for the watcher too.
If neither works, tell the user "Let me know when you've approved" and poll once on their reply.

**Key design points:**
- The isolated watcher polls cheaply (HEARTBEAT_OK = zero cost when pending)
- On approval, it uses `exec` + `openclaw cron add --system-event` CLI to create a gateway-level systemEvent
- This bypasses session scoping — the CLI creates the event at gateway level, reaching your real main session
- Your main session receives the systemEvent with full task context and continues automatically
- The watcher formats `response.body` as clean readable text (not raw JSON dump)

**Approved response structure** (from GET /approve/\<id\>):
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

### Step 3 — Continue on resume

When you receive a systemEvent containing "SafeClaw approval ... APPROVED", this is the resume signal from your watcher. It contains:
- The original task description
- The formatted API response

**Continue the original task immediately.** Do not ask the user — just proceed with the data.

### Notes

- **Each 202 is independent** — if your task makes multiple API calls, each may trigger its own 202. Create a separate watcher per id.
- **Polling is always GET** regardless of original method (POST, PUT, etc.)
- **Streaming requests**: approved `response` will be complete buffered JSON
- **Expiry**: `expires_at` is a unix timestamp. Watcher checks it each run.
- **Not found (404)**: treat same as expired

## Dummy API Key

Your config may contain a placeholder key like `sk-dummy`. This is intentional — SafeClaw intercepts requests and injects the real key from the encrypted vault. Do not replace it, expose it, or treat it as sensitive.
