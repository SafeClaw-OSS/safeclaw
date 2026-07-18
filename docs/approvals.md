# Approvals & policy: who decides what runs

Every brokered request gets exactly one decision:

| Level | Behavior |
|---|---|
| `allow` | proceeds, no ceremony |
| `ask` | one passkey approval, then reused for that rule's window |
| `ask-always` | a passkey approval every single time |
| `deny` | refused unconditionally |

When multiple sources have an opinion, **the strictest wins**
(`deny > ask-always > ask > allow`), the same fail-safe family as cloud IAM
systems. Anything nothing matches falls to `ask-always`: undefined never
means yes.

## Where decisions come from

1. **Service rules.** Each catalog service ships human-labeled, per-action
   rules ("Read email content", "Delete a repository") matched
   nginx-style against the request. Written by the recipe, overridable by
   you.
2. **Your overrides.** Per connection, you can re-level any rule or set
   read/write floors.
3. **Floors.** Connection, category, and global read/write defaults, derived
   from an objective fact (the HTTP method), not a vibe.

There are no "risk scores". SafeClaw doesn't grade actions medium-spicy on
your behalf; rules state what an action *is*, and the level states your
decision about it.

`deny` is never a factory default. SafeClaw is a gate, not a block: the point
is to let agents work, with you at the choke point that matters.

## What a tap actually approves

Approvals ride SUDP, a passkey-signed **single-use grant** protocol. The
consent card names the specific action from a curated template; your
signature covers that operation, scope-bound, and nothing else. There is no
session-wide approval token to steal, and an approval can't be replayed into
a different request.

`ask` approvals cache per (connection, rule, method) for the rule's window,
so routine work doesn't nag. `ask-always` never caches.

## Boundaries refuse; they don't prompt

A request outside a connection's hosts, or against a `deny` rule, is refused
loudly and immediately. It does not become an approval popup. Prompts are
reserved for actions you defined as sensitive; violations are not a
negotiation. This is the anti-approval-fatigue stance: the fewer taps you
see, the more each one means.

## For agents

An approval-gated command fails with the approval link in its output. The
agent surfaces the link, backgrounds `sc op wait <op_id>` (exit 0 means
approved), and re-runs the same command. You tap; nobody types "done".
