# For your agent

This page explains how an agent gets the SafeClaw skill, runs setup, loads its identity, and uses SafeClaw without handling credential values.

## The skill

The skill lives at [`skills/safeclaw/SKILL.md`](https://github.com/getsafeclaw/safeclaw/blob/main/skills/safeclaw/SKILL.md) in Agent Skills format. It is the source of truth for discovery, phantom placement, `sc run`, approvals, and setup.

The installer adds it with `sc skill install`. `sc upgrade` runs the skill
install again, so the installed copy stays current. An agent without `sc` can
add it with:

```bash
npx skills add getsafeclaw/safeclaw
```

Install only from [safeclaw.pro](https://safeclaw.pro) or
[github.com/getsafeclaw/safeclaw](https://github.com/getsafeclaw/safeclaw).

## Set up

If `sc` is not installed, run:

```bash
curl -fsSL https://safeclaw.pro/install.sh | sh
```

The installer verifies the download's SHA256, puts `sc` in `~/.local/bin`,
installs this skill, and continues straight into `sc setup` when an agent runs
it. In a terminal, it prints the next step. Run:

```bash
sc setup
```

`--name <a short name for the agent>` is optional and defaults to the agent's
product name, such as `claude-code` or `codex`.
`sc setup` never prompts. Read its status and follow the loop until it reports
`done`:

- `action_required`: relay the `say` sentence exactly. It tells the person to
  open the `/pair` address and type the code shown, or open a link and approve
  with a passkey. Then run the printed `next_step`.
- `waiting`: run the printed `next_step` again.
- `done`: if it has a `next_step`, run it. After the machine and agent are
  approved, this unlocks the vault: `sc unlock` prints a link for the person and
  the `sc op wait` command. Run that wait command and continue after approval.
- `error`: apply the printed `fix`, then run setup again as directed.

The browser sequence is: the person signs in or creates an account, creates a
passkey, and approves the machine; approves the agent and chooses which vaults
it may use. Under the hood, setup runs `sc login` and `sc agent add` when needed,
writes `~/.safeclaw/agents/<name>/agent.env`, and installs the skill. It is safe
to re-run.

Never ask the person to paste a key or a code into chat. Relay the sentence
that setup prints and run the next command it prints.

## Per-agent identity

Each agent has its own identity under `~/.safeclaw/agents/<name>/`. If
`SAFECLAW_AGENT_IDENTITY` is unset, the agent loads its own env file before
running `sc`: `set -a; . ~/.safeclaw/agents/<name>/agent.env; set +a`. With one
directory there, that one is the agent's; with several, it uses the name it set up
with. `sc setup` prints this line when it reports `done`. The file sets:

| Variable | Meaning |
|---|---|
| `SAFECLAW_BROKER_URL` | The local broker, for example `http://127.0.0.1:23294` |
| `SAFECLAW_AGENT_IDENTITY` | The agent identity file used to sign requests; it is not a credential |

The env file is non-secret. Do not share an identity file between agents.

## What your agent can propose

Changes to the vault come from you, but an agent may ask for one: a new host on a connection (`sc connection add-host`), or a new connection that uses a secret already in your vault (`sc connection add <id> --service <svc> --from-secret ROLE=KEY`). Each is an approval request; nothing changes until you approve it with your passkey, and the card lists every key and host involved.
For an API that is not in the catalog, add #custom to that link; it opens the custom connection form.

## Terminal commands for people

People can still run `sc login` to pair a machine and `sc agent add <name>` to
register an agent at a terminal. `sc setup` runs whichever command is still
needed, then handles the env file and skill.
