<!-- SAFECLAW:BEGIN - managed block. Changes inside this block may be overwritten by SafeClaw sync. -->
## SafeClaw Proxy (MANDATORY security rules)

**Required:** Load the `safeclaw` skill (SKILL.md) before making any API calls through SafeClaw.
It defines how to handle vault-locked responses and approval flows.

All HTTP requests to the following services MUST go through the SafeClaw proxy.
Direct calls to these APIs are forbidden.

### How to use
1. Replace the upstream base URL with the proxy URL shown below.
2. Do NOT add an Authorization header — SafeClaw injects credentials automatically.
3. Keep the original API path and query parameters unchanged.

### Services
{{SERVICES}}

### Example
```
# Wrong (direct call — FORBIDDEN):
curl https://api.openai.com/v1/chat/completions ...

# Correct (via SafeClaw proxy):
curl {{PROXY_BASE}}/openai/v1/chat/completions ...
# (no Authorization header needed)
```

Violating these rules is a security incident.

### Approval Required (HTTP 202)

Some operations require human approval. When the proxy returns HTTP 202:

```json
{"id":"<uuid>","safeclaw_approve_url":"https://...","expires_at":1711548300}
```

**Do this:**
1. Tell the user what you were doing and share the approval URL (use inline button if supported).
2. Poll `GET <proxy>/approve/<id>` every 5 seconds.
3. On `{"status":"approved","response":{...}}` — use `response.body` as the upstream API result and continue.
4. On `{"status":"rejected"}` — tell the user the action was blocked.
5. On `{"status":"expired"}` or 404 — tell the user the window expired, ask to retry.

Poll URL: `{{PROXY_BASE}}/approve/<id>`

<!-- SAFECLAW:END -->
