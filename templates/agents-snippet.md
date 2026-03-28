<!-- SAFECLAW:BEGIN — managed by SafeClaw. Do not edit inside this block; changes will be overwritten on next sync. -->
## SafeClaw Proxy

**Required:** Before making API calls, load the `safeclaw` skill. It covers vault-locked handling and approval flows.

### Rules
1. All HTTP requests to configured services MUST go through the SafeClaw proxy. Direct upstream calls are forbidden.
2. Do NOT add Authorization headers — SafeClaw injects credentials automatically.
3. Never expose or log the placeholder API key in your config (e.g. `sk-dummy`). It is not real.
4. On vault locked — stop, notify the user, wait. Do not retry in a loop.
5. On approval required (HTTP 202) — follow the protocol in SKILL.md.
6. On approval rejected/expired — do not silently retry. Ask the user.

### Services
{{SERVICES}}

### Quick Reference
```
# Wrong — direct call (FORBIDDEN):
curl https://api.openai.com/v1/chat/completions ...

# Correct — via SafeClaw proxy (no auth header needed):
curl {{PROXY_BASE}}/openai/v1/chat/completions ...
```
<!-- SAFECLAW:END -->
