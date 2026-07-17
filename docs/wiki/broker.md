# Broker: one local egress point

The whole mechanism in one sentence: **SafeClaw is a local proxy; put the
phantom where the credential goes and send that traffic through the proxy.**

## Three questions, three owners

Every brokered request answers exactly three questions, each with one owner:

| Question | Owner | Carried by |
|---|---|---|
| Where does the credential go? | the agent | the phantom's position in the request (header, query, body, path) |
| What value? | the vault | phantom → connection → secret (or the OAuth token it manages) |
| Is it allowed? | the vault | the connection's host anchor + [policy](approvals.md) |

The agent controls placement and nothing else. There is no API for "give me
the value", no endpoint that rewrites base URLs, no special cases: every use
of a credential is "a request with a phantom in it, routed through the
proxy".

## The phantom is the only trigger

`sc run -- <cmd>` runs the command with its traffic egressing through the
proxy on your machine. Inside that stream:

- A request carrying a phantom gets it resolved, host-checked,
  policy-checked, and substituted at the last hop before the wire.
- A request with no phantom is forwarded untouched. The broker never injects
  where it wasn't asked to.

And outside that stream, nothing happens at all: SafeClaw is not a
machine-wide interceptor. A phantom that escapes unrouted (pasted into a
browser, sent by a tool you forgot to route) reaches the upstream as a
literal string and fails with a clean 401. The failure mode of a leak is an
error message.

## Substitution at the last hop

Substitution happens inside the proxy, after policy passes, on the way out to
a host the connection itself declared. The response streams back to the
command; the value does not. Nothing between the agent and the proxy, and
nothing the command spawns, ever observes plaintext.

## Failing loudly

A brokered request that can't proceed says so in the command's own output
with a stable `SafeClaw: <code>` line: vault locked, approval needed (with
the link), host outside the anchor, store unreachable. Every code is
catalogued with its fix in [DIAGNOSTICS.md](../DIAGNOSTICS.md). The broker
never swallows a refusal into a mystery timeout, and never fakes a success.
