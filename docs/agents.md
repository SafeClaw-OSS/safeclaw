# Agents: attribution without possession

To SafeClaw, an agent is an **identity**, not a trust decision. Each agent
gets its own API key; what any agent may *do* is decided elsewhere, by
[policy](approvals.md), per action, at use time.

## The identity

`sc agent add <name>` (or the dashboard's install prompt) mints one env
block:

| Var | Meaning |
|---|---|
| `SAFECLAW_BROKER_URL` | the local broker, e.g. `http://127.0.0.1:23294` |
| `SAFECLAW_VAULT_ID` | which vault its requests resolve against |
| `SAFECLAW_API_KEY` | this agent's bearer identity |

One key per agent keeps the audit trail attributable: every brokered request
and every approval you grant is tied to a named agent, so "which agent did
what, when, with which credential" is a query, not a reconstruction. Don't
share a key across agents; don't re-mint when the env already exists.

## What an agent can do

Discover connections through the registry, place phantoms, route commands
through `sc run`, wait on approvals (`sc op wait`). The full behavioral
contract fits in one file, [the skill](../static/safeclaw-skill.md), and
one habit: **phantoms, not values** ([`sc run` and phantoms](sc-run.md)).

## What an agent can't do

Read a secret (`sc get` is passkey-gated, a human primitive), move a
credential toward a host its connection didn't anchor, approve anything, or
steer *your* CLI: your commands read the active vault from your own config,
never from an agent's env. The worst a fully compromised agent can do is ask
the broker for things, inside policy, under your taps; the accounting of that
is exactly what the audit trail records. Costs and limits in detail:
[Security model](security-model.md).

## Handing it over

The dashboard install prompt delivers pairing, env, and skill in one paste.
Doing it by hand: [For your agent](for-your-agent.md).
