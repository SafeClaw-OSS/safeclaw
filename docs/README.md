# SafeClaw Docs

A systematic tour of SafeClaw, one module per page. Concepts explain how the
product thinks; guides get a task done; security answers the questions that
decide trust. `reference/` and `internals/` hold the deep layers. Pages are
deliberately short and will deepen over time.

New here? Read [Overview](overview.md), then do the
[Quickstart](quickstart.md).

## Concepts

| Page | The module |
|---|---|
| [Overview](overview.md) | The whole model on one page: phantoms, the broker, passkey approvals |
| [Vault](vault.md) | Where credentials live: sealed under your passkey, synced blind |
| [Connections](connections.md) | The catalog, host anchors, and how a secret becomes a phantom |
| [Broker](broker.md) | `sc run`: one local egress point that swaps phantoms for values |
| [Approvals & policy](approvals.md) | Who decides what runs: levels, rules, single-use grants |
| [Agents](agents.md) | Agent identities: attribution without possession |

## Guides

| Page | The task |
|---|---|
| [Quickstart](quickstart.md) | Zero to first brokered call in five minutes |
| [`sc run` and phantoms](sc-run.md) | The patterns, and the `sc get` anti-pattern |
| [For your agent](for-your-agent.md) | Handing SafeClaw to an agent: skill file, paste-ready prompt |

## Security

| Page | The question |
|---|---|
| [Design principles](design-principles.md) | The rules the whole system is built on |
| [Security model](security-model.md) | Where keys live, what the cloud sees, what compromise costs |

## Reference

For users and service authors, in [`reference/`](reference/):
[services.md](reference/services.md) (writing a `service.toml`),
[policy.md](reference/policy.md) (per-action decisions),
[diagnostics.md](reference/diagnostics.md) (every error code, with fixes),
[consent-templates.md](reference/consent-templates.md) (approval-copy grammar).

## Internals

For contributors reading the source, in [`internals/`](internals/):
[protocol.md](internals/protocol.md) (SUDP cryptographic profile),
[credential-broker.md](internals/credential-broker.md) (the broker architecture),
[connection-schema.md](internals/connection-schema.md) (vault data shapes),
[sync.md](internals/sync.md) / [sse-sync.md](internals/sse-sync.md) (cloud sync),
[request-scope.md](internals/request-scope.md) (approval scope binding),
[stores-and-items.md](internals/stores-and-items.md) (stores and vault content model).
