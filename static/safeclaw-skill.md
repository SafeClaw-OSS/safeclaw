---
name: safeclaw
description: Use for any task that calls an external API or service needing a credential (API key, token, OAuth). SafeClaw holds the secret; you run the command through `sc run` with a placeholder in its place.
---

# SafeClaw

SafeClaw holds credentials and lends them to requests. Each connection has a
**phantom**, a placeholder like `__sc__github__`. Put the phantom where the
credential goes (an env var, a header, a config file) and run the command through
`sc run --`. SafeClaw swaps in the real value, only toward that connection's hosts.
Traffic not run through `sc run` is untouched, so an unrouted phantom just fails
with a 401.

## Setup

Your agent env holds two non-secret values, `SAFECLAW_BROKER_URL` and
`SAFECLAW_AGENT_IDENTITY`. If they are unset, load your agent env file (its path is
in your always-loaded instructions). Don't run `sc agent add` again: each run
registers another agent.

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
- Credentials come from the user: in the console (`<console_url>/connections`), or
  at this machine's terminal (`sc set`). Keep any value you see out of your
  replies.
- A secret already in the vault (`sc secret ls`) can back a connection you propose
  with `sc connection add ... --from-secret`; no value passes through you.
- An API outside the catalog is a custom connection: its host and key. Installing
  a service (`sc service --help`) adds named rules for an API; it comes from a third
  party and the user approves it.
- A vault is a security boundary: target one with `--vault`, resolve a name with
  `sc vault ls`, and ask when it is ambiguous.

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

When a command says SafeClaw needs an update, run `sc upgrade`. It restarts the
daemon and locks the vault until the user taps their passkey, so tell them, then
run `sc up` and send the link.
