# AGENTS.md — SafeClaw

This file configures AI agents to use SafeClaw as their API proxy.

## Required: Load SKILL.md

Before making any API calls through SafeClaw, load `SKILL.md` (this repo).
It defines how to handle vault-locked responses and approval flows.
**This is mandatory** — without it, you will not know how to respond correctly when the vault is locked or an approval is required.

## Service Endpoints

See `safeclaw.md` for your SafeClaw proxy endpoint and service routing table.
Configure your API clients to use those base URLs instead of calling upstream services directly.

## Behavioral Rules

1. **Never expose the dummy API key** — your config contains a placeholder (e.g. `sk-dummy`). It is not a real key. Do not log it, quote it, or treat it as sensitive.
2. **On vault locked** — stop the current task, notify the user, wait. Do not retry in a loop.
3. **On approval required (202)** — notify the user with the approve URL, poll for result. See SKILL.md.
4. **On approval rejected/expired** — do not silently retry. Ask the user how to proceed.
