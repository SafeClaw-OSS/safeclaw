<!-- SAFECLAW:GENERATED FILE - DO NOT EDIT. Changes may be overwritten by SafeClaw sync. -->
# SafeClaw Services
Route API calls through the SafeClaw proxy at `{{PROXY_BASE}}`. Do NOT call upstream APIs directly.

## Usage
Replace the upstream base URL with the proxy URL. Do NOT add Authorization headers.
SafeClaw auto-injects credentials (API key / OAuth2 token) before forwarding.

## Service Table
{{SERVICE_TABLE}}

## Example
```
# Call OpenAI via proxy (no Authorization header needed):
curl -X POST {{PROXY_BASE}}/openai/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[...]}'

# Call Gmail via proxy:
curl {{PROXY_BASE}}/gmail/gmail/v1/users/me/messages
```

Vault status: {{VAULT_STATUS}}
