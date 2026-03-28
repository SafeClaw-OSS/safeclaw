# AGENTS.md — SafeClaw

> If you're an AI agent on a SafeClaw VM, your workspace already has a managed
> SafeClaw block in AGENTS.md and a `safeclaw` skill. Follow those — this file
> is the repo-level reference, not what gets deployed.

## Quick Start

1. **Load the `safeclaw` skill** — it covers vault-locked handling and the approval (HTTP 202) protocol.
2. **Route all API calls through the proxy** — see `safeclaw.md` in your workspace for the service table.
3. **Never add Authorization headers** — SafeClaw injects credentials automatically.

## Behavioral Rules

1. **Never expose the dummy API key** — your config contains a placeholder (e.g. `sk-dummy`). It is not a real key.
2. **On vault locked** — stop the current task, notify the user, wait. Do not retry in a loop.
3. **On approval required (202)** — notify the user with the approve URL, set up a cron watcher. See `templates/skill.md`.
4. **On approval rejected/expired** — do not silently retry. Ask the user.

## Templates

The `templates/` directory is the **single source of truth** for all agent-facing documents deployed to VMs:

| Template | Deployed as | Notes |
|----------|-------------|-------|
| `templates/agents-snippet.md` | Managed block in AGENTS.md | `{{SERVICES}}` filled dynamically |
| `templates/safeclaw.md` | `safeclaw.md` in workspace | `{{SERVICE_TABLE}}`, `{{VAULT_STATUS}}` filled dynamically |
| `templates/skill.md` | `~/openclaw/skills/safeclaw/SKILL.md` | Fully static, deployed as-is |

Edit templates to change what agents see. Rust code (`src/generate.rs`) only handles placeholder substitution.
