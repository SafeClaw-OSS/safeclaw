---
name: safeclaw
description: Use for any task that calls an external API or service needing a credential (API key, token, OAuth). SafeClaw holds the secret; you run the command through `sc run` with a placeholder in its place.
---

# SafeClaw

SafeClaw holds credentials and lends them to requests. Each connection has a
**phantom**, a placeholder like `__sc__github__`. Put the phantom where the
credential goes (an env var, a header, a config file) and run the command through
`sc run --`; any tool works. The broker swaps in the real value, only toward that
connection's hosts. Traffic not run through `sc run` is untouched, so an unrouted
phantom just fails with a 401.

## Setup

Your agent env holds two non-secret values: `SAFECLAW_BROKER_URL` (the broker, the
daemon's endpoint for your requests) and `SAFECLAW_AGENT_IDENTITY`. If they are
unset, load your agent env file (its path is in your always-loaded instructions).
Don't run `sc agent add` again: each run registers another agent.

Before the first call:

```bash
curl -s -o /dev/null --connect-timeout 1 "$SAFECLAW_BROKER_URL/health" || sc up
```

`sc help` and `sc <command> --help` have every command's syntax.

## Connections

- `sc connection ls` lists the connections you can use, with hosts and phantoms
  (`--json` adds each one's `setup` hint). Copy phantoms exactly.
- `sc status` shows whether the vault is locked, its console URL, and any vault
  change that was not applied, with the reason.
- `sc registry` is the catalog of supported services.
- The user adds connections, with their credentials, on the console's Connections
  page (`<console_url>/connections`); a new one then appears in `sc connection ls`.
  Keep any credential value you see out of your replies.
- `sc secret ls` lists the names of secrets already in the vault. One can back a
  connection you propose with `sc connection add ... --from-secret`, so no value
  passes through you.
- An API outside the catalog is a custom connection: its host and key. A service
  (`sc service --help`) adds named rules for an API from a third-party source; an
  owner must first allow third-party services in the vault's Settings, and the
  user approves each install. The user can also install one from that page.
- A vault is a security boundary, and each connection belongs to one. Target it
  with `--vault` to use its connections; resolve a name with `sc vault ls`, and ask
  when it is ambiguous.

## Using a connection

```bash
sc run -- curl https://api.stripe.com/v1/charges \
  -H "Authorization: Bearer __sc__stripe__"
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

- Two accounts of one service differ by phantom (`__sc__github__`,
  `__sc__github_work__`). One request carries one connection's phantoms.
- A connection with a `setup` hint brokers a local tool: tell the user what you are
  configuring, then apply its steps.
- On a 401 or 403, first check the command ran under `sc run --` with the exact
  phantom.

## Approvals

A request that needs approval stops and prints a `/grant/<op_id>` link and
`sc op wait <op_id>`. Background the wait; its exit code says what comes next
(`sc op wait --help`). After an approval, re-run the same command.

Where the user approves:

- `/grant/<op_id>`: one request, no sign-in.
- `/approvals` in the console, signed in: every pending request; the ticked ones
  are approved together, one passkey tap per vault.
- The bell in the console's top bar counts pending requests and opens `/approvals`.

One request: send its `/grant` link. Several at once for a signed-in user: start
them together and send `/approvals`.

`agent_not_authorized` means you are not turned on for this vault; its message
links the vault's Agent access page for the user.

A locked vault: `sc up` prints an unlock link for the user.

## Updates

`sc upgrade` updates `sc` and restarts the daemon, which locks the vault until the
user taps their passkey. Upgrade when a command asks for it or the user agrees, then
run `sc up` and send the unlock link.
