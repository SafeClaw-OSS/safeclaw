# Overview: the whole model on one page

SafeClaw gives an agent the **use** of a credential without ever letting it
**hold** the credential.

![One brokered request, end to end: the agent holds only a phantom, the local broker resolves it, checks host and policy, and swaps in the real value at the last hop; the vault stays sealed under your passkey, and the cloud syncs only sealed data it cannot decrypt](assets/architecture.svg)

## The problem

Agents need your API keys to do real work, and today they get them the worst
possible way: pasted into an env file. From that moment the key sits in
plaintext inside a process that reads untrusted input all day. One prompt
injection, one rogue skill, one over-chatty log line, and the key is gone,
along with everything it unlocks.

Rationing what the agent may do doesn't require rationing what it may *know*.
The key never needed to be in the agent at all.

## The three moves

**1. The phantom.** Each connected service gives the agent a placeholder like
`__sc__github__` instead of a value. The agent puts it exactly where the
credential would go: an env var, a request header, a config file, a URL path.
The phantom is worthless everywhere except one place.

**2. The broker.** That place is a local proxy on your machine. Commands
routed through `sc run --` egress through it; it resolves the phantom to a
connection, checks the destination against that connection's own hosts,
substitutes the real value at the last hop, and forwards. The response comes
back; the value never does. Traffic you don't route is untouched.

**3. The passkey.** Every brokered request is policy-checked. Routine calls
flow; sensitive ones pause until you approve them with a passkey tap, and one
tap authorizes exactly one operation. The same passkey seals the vault
itself: no password exists anywhere in the system.

## What SafeClaw is not

- **Not a machine-wide interceptor.** Only `sc run` traffic is brokered; the
  phantom is the only trigger.
- **Not cloud custody.** The cloud syncs the vault sealed under your passkey
  and cannot decrypt it. Plaintext exists only in the daemon's memory, on
  your machine, while unlocked.
- **Not an approval treadmill.** Policy is a gate, not a nag: reads flow,
  boundaries refuse loudly, and only defined-sensitive actions ask.

## Where to go deeper

[Vault](vault.md) for where values live ·
[Connections](connections.md) for how a secret becomes a phantom ·
[Broker](broker.md) for the egress mechanics ·
[Approvals & policy](approvals.md) for who decides ·
[Agents](agents.md) for identity and audit ·
[Quickstart](quickstart.md) to just try it.
