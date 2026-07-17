# SafeClaw Wiki

A systematic tour of SafeClaw, one module per page. Concepts explain how the
product thinks; guides get a task done; security answers the questions that
decide trust. Pages are deliberately short and will deepen over time.

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

Engineering detail lives beside this wiki in `docs/`:
[PROTOCOL.md](../PROTOCOL.md) (the cryptographic protocol),
[SERVICES.md](../SERVICES.md) (declarative service definitions),
[CONNECTION_SCHEMA.md](../CONNECTION_SCHEMA.md) (connection data schema),
[DIAGNOSTICS.md](../DIAGNOSTICS.md) (every error code, with fixes).
