# Approvals & policy: who decides what runs

This page explains SafeClaw's per-action approval levels, policy sources, and passkey decisions.

Every brokered request gets exactly one decision:

| Level | Behavior |
|---|---|
| `allow` | proceeds, no ceremony |
| `ask` | one passkey approval, then reused for that rule (or floor class) for its window |
| `ask-always` | a passkey approval every single time |
| `deny` | blocked unconditionally |

When multiple sources have an opinion, **the strictest wins**
(`deny > ask-always > ask > allow`), the same fail-safe family as cloud IAM
systems.

Out of the box the read and write floors are `allow`: a key you add is usable
by your agent right away. A service's rules tighten specific actions (sending
email, deleting a repository) to `ask` or `ask-always`. A connection you
define yourself has no rules, so everything on it is allowed until you add
some or set its floors.

## Where decisions come from

1. **Service rules.** Each catalog service ships human-labeled, per-action
   rules ("Read email content", "Delete a repository") matched
   nginx-style against the request. Written by the recipe, overridable by
   you.
2. **Your overrides.** Per connection, you can re-level any rule or set
   read/write floors.
3. **Floors.** Connection, category, and global read/write defaults, derived
   from an objective fact (the HTTP method), not a vibe. `GET`, `HEAD` and
   `OPTIONS` are reads; every other method is a write. They apply when no
   rule matches.

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

What an approval lets through afterwards is stated on its card, from signed
fields. It always covers only the requesting agent, on that connection and
host, and only the unit that asked:

- `ask-always`: this one request; the next identical one asks again.
- `ask` on a request a service scopes by its values (a `[requests]` shape,
  e.g. an amount): this identical request, same values, for the window.
- `ask` from a rule (e.g. "Send email"): later requests that the same rule
  decides, for the rule's window, reads or writes like the approved one. A
  read approved under a rule never lets a write through. Another rule still
  asks.
- `ask` from a read or write floor you set to `ask`: later reads (or writes)
  on that connection that no rule matches, for the floor's window. A read
  approval never lets a write through.

A request your policy allows never needs an approval to be authorized; if
its credential is not loaded yet, approving it loads the credential for
allowed requests only and lets no `ask` request through. Whether a
credential is loaded never decides whether an `ask` request may run.

The daemon refuses an approval whose signed card differs from what it would
grant, so the card is never a guess.

## Boundaries refuse; they don't prompt

A request outside a connection's hosts, or against a `deny` rule, is refused
loudly and immediately. So is a request on a value-scoped path covered by a
connection rule you wrote that decides on something an approval there cannot
pin: the body, or a field outside the path's `[requests]` scope. It does not become an approval popup. Prompts are
reserved for actions you defined as sensitive; violations are not a
negotiation. This is the anti-approval-fatigue stance: the fewer taps you
see, the more each one means.

## For agents

An approval-gated command fails with the approval link in its output. The
agent surfaces the link, backgrounds `sc op wait <op_id>` (exit 0 means
approved), and re-runs the same command. You tap; nobody types "done".
