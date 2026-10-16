# Quickstart

This page explains how to install SafeClaw, run agent-driven setup, approve the browser steps, and make the first brokered call.

## 1. Install

```bash
curl -fsSL https://safeclaw.pro/install.sh | sh
```

The installer uses no sudo, verifies the download's SHA256, puts `sc` in
`~/.local/bin`, and installs the skill at `skills/safeclaw/SKILL.md`. When run by
an agent, it continues straight into `sc setup`; in a terminal it prints one
next step. It also installs the skill with `sc skill install`. Official sources
are [safeclaw.pro](https://safeclaw.pro) and
[github.com/getsafeclaw/safeclaw](https://github.com/getsafeclaw/safeclaw).
Supported platforms: [Platform support](reference/platform-support.md).

## 2. Run setup

Run this as the person or as their agent:

```bash
sc setup
```

`--name <a short name for the agent>` is optional and defaults to the agent's
product name, such as `claude-code` or `codex`.
`sc setup` never prompts. It prints one sentence for the agent to relay and the
next command. The agent repeats this loop until setup reports `done`:

- `action_required`: relay `say` exactly, then run `next_step`. The sentence
  tells the person to open the `/pair` address and type the code shown, or open
  a link and approve with a passkey.
- `waiting`: run the same `next_step` again.
- `done`: continue to the next section.
- `error`: run `fix`, then continue the loop.

In the browser, the person signs in or creates an account the first time,
creates a passkey, and approves the machine. The passkey also creates the
first vault. They then approve the agent and choose which vaults it may use.
Under the hood, setup runs `sc login` if the machine is not paired and `sc agent
add` if the agent is not registered. It writes
`~/.safeclaw/agents/<name>/agent.env` and installs the skill. It is safe to run
again.

At a terminal, a person can still use `sc login` to pair a machine or `sc agent
add <name>` to add an agent by hand, such as a second agent. `sc setup` runs
whichever of those is still needed and also handles the env file and skill.

## 3. Add a credential

Two doors, same result: a **connection** with hosts and a **phantom**.

**Console** (recommended for OAuth services like GitHub or Gmail): open your
vault's Connections tab, pick the service, sign in or paste the key. Values
you type there are encrypted in your browser before upload.

**Terminal**, for any bare API key:

```bash
sc set HF_TOKEN --host huggingface.co
```

Prompts for the value, asks for one passkey approval, and mints the phantom
`__sc__hf_token__` anchored to `huggingface.co`. Entered this way the value
never leaves your machine.

## 4. First use

If the vault is locked, run `sc unlock`; it prints an unlock link and the
`sc op wait` command, like an approval.

## 5. First brokered call

Put the phantom where the credential belongs and route the command through
`sc run --`:

```bash
HF_TOKEN=__sc__hf_token__ sc run -- huggingface-cli whoami
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

The proxy swaps the phantom for the real value on the way out, only toward
that connection's own hosts. The command gets the API response; the
environment, the shell history, and the agent hold only the phantom.

## 6. When an approval is needed

Policy-gated uses don't fail silently: the command's error output carries an
approval link. Open it, tap your passkey, re-run the same command. Agents can
block on `sc op wait <op_id>` instead of asking you to say "done". Approvals
are cached per policy, so routine calls don't nag.

## 7. Daily rhythm

```bash
sc up      # start of day: daemon up + vault unlocked, one passkey tap
sc lock    # done for the day: wipe keys from the daemon's memory
sc doctor  # something's off: health + reachability checks
```

Next: teach the agent the full patterns in
[`sc run` and phantoms](sc-run.md), or hand it the skill directly via
[For your agent](for-your-agent.md).
