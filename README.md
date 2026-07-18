<p align="center">
  <img src="docs/logo.png" alt="SafeClaw" width="80" />
</p>

<h1 align="center">SafeClaw</h1>

<p align="center"><b>Let your AI agent use your API keys. It never holds them.</b></p>

<p align="center">
  <a href="https://github.com/SafeClaw-OSS/safeclaw/releases"><img src="https://img.shields.io/github/v/release/SafeClaw-OSS/safeclaw?label=release&color=2ea44f" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-blue" alt="license"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-555" alt="platforms">
</p>

<p align="center">
  <a href="https://safeclaw.pro">safeclaw.pro</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="docs/README.md">Docs</a>
</p>

<!-- demo GIF goes here once recorded: see demo/README.md -->

Pasting an API key into an agent's env hands it to every prompt injection, rogue skill, and log line downstream. SafeClaw takes the key out of the agent's hands entirely:

```bash
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

`__sc__github__` is a **phantom**: a placeholder the agent uses instead of the credential. SafeClaw's local proxy swaps it for the real token at the network edge, only toward that service's own hosts. The agent gets the API response, never the key. Sensitive calls pause until you approve them with a passkey tap (Touch ID, Windows Hello, or a security key).

## Why

- **The agent never sees a secret.** It writes phantoms; the proxy injects real values at egress, pinned to each service's own hosts.
- **No plaintext at rest, anywhere.** Keys are sealed under your passkey. The cloud syncs the sealed blob and cannot decrypt it. Plaintext exists only in the daemon's memory while unlocked; `sc lock` wipes it.
- **You approve what matters.** Every brokered call is policy-checked; sensitive ones wait for your passkey tap. A compromised agent can't spend your keys unsupervised, and can't exfiltrate what it never held.
- **No passwords.** Passkeys only (WebAuthn).
- **One ~5 MB static binary.** No runtime deps.

## How it works

```
AI agent ──── sc run -- gh pr list ────► SafeClaw proxy ── real token ──► api.github.com
 holds only                               (localhost)
 __sc__github__                                │
                                               ├─ vault: sealed under your passkey;
                                               │  plaintext only in daemon memory
                                               └─ sensitive calls wait for your
                                                  passkey tap
```

`safeclaw` and `sc` are the same binary. The daemon runs on your machine; the control plane at [safeclaw.pro](https://safeclaw.pro) handles encrypted vault backup, cross-device sync, and web approvals, and this binary is its open client.

Only traffic routed through `sc run` is touched. A phantom sent anywhere else reaches the upstream as a literal string and fails with a clean 401: nothing to leak.

GitHub, OpenAI, Anthropic, Gemini, Gmail, Google Drive, GCP, Supabase, Railway, GitLab, npm, crates.io, Telegram and more ship in [the catalog](docs/reference/services.md); any other HTTPS API works as a custom connection.

## Quickstart

**1. Install.** Downloads the prebuilt binary for your platform to `~/.local/bin` and verifies its `SHA256SUMS`; no sudo, no system changes. (Or `cargo build --release`.)

```bash
curl -fsSL https://raw.githubusercontent.com/SafeClaw-OSS/safeclaw/main/install.sh | sh
```

Each release also carries a sigstore build-provenance attestation: `gh attestation verify ~/.local/bin/sc --repo SafeClaw-OSS/safeclaw`.

**2. Create your vault** at [safeclaw.pro](https://safeclaw.pro): sign in and register a passkey. No password to invent, nothing to remember.

**3. Connect your agent.** The console's "Connect a new agent" mints a one-time pair token and an install prompt you paste to your agent. Under the hood it runs:

```bash
sc login --pair-token spt_…   # pair this machine; brings the daemon up + unlocks
sc agent add my-agent         # mint the agent's env (BROKER_URL / VAULT_ID / API_KEY)
```

**4. Add a credential.** In the console's Connections tab (values are encrypted in your browser before upload), or at your terminal:

```bash
sc set HF_TOKEN --host huggingface.co   # prompts for the value; one passkey approval
                                        # mints the phantom __sc__hf_token__
```

Entered this way, the value never leaves your machine.

**5. Use it.** The agent puts the phantom where the credential belongs and routes the command through the proxy:

```bash
HF_TOKEN=__sc__hf_token__ sc run -- python train.py
```

Full walkthrough: [docs/quickstart.md](docs/quickstart.md).

## Teach your agent

Agents learn SafeClaw from one file: [safeclaw-skill.md](static/safeclaw-skill.md). The console's install prompt already includes it; to hand it to an agent yourself, see [docs/for-your-agent.md](docs/for-your-agent.md). The one habit that matters: **phantoms, not values**. An agent never needs `sc get`; see [docs/sc-run.md](docs/sc-run.md).

## CLI

```text
Setup         sc login · logout · up · down · restart · status
Secrets       sc set · get · ls · rm              (aliases of sc secret …)
Connections   sc connection add|ls|rm · sc run -- <cmd> · sc registry · sc store
Account       sc agent · sc device · sc passkey · sc vault
Maintenance   sc unlock · lock · sync · logs · doctor · upgrade · proxy · op
```

`sc --help` shows the grouped list; `sc <cmd> --help` for details. Ports default to `23293` (control) and `23294` (the proxy `sc run` routes through); state lives under `~/.safeclaw/`.

## FAQ

**Where do my keys actually live?** Sealed under a key derived from your passkey. The cloud stores and syncs the sealed blob and cannot decrypt it. Plaintext exists in exactly one place: the daemon's memory on your machine, while unlocked. Details: [docs/security-model.md](docs/security-model.md).

**Can't the agent just run `sc get`?** Every `sc get` is passkey-gated; it exists for you at a terminal, not for agents. An agent never needs the raw value: the phantom + `sc run` path uses a credential without revealing it. Patterns and anti-patterns: [docs/sc-run.md](docs/sc-run.md).

**What about traffic I don't route through `sc run`?** Untouched. SafeClaw is not a machine-wide MITM; only commands you deliberately route are brokered, and a phantom sent unrouted is a worthless string.

**What can a compromised agent do?** Spend credentials only through the proxy, only toward each connection's own hosts, under your policy, with sensitive actions blocked on your passkey. It cannot read the values, and outside the proxy its phantoms are inert.

## Docs

| | |
|---|---|
| [Docs](docs/README.md) | The product, module by module: concepts, guides, security |
| [Reference](docs/reference/) | Service definitions, policy, error codes, consent templates |
| [Design docs](design/) | For contributors: protocol, broker architecture, schemas, sync |

## License

[Functional Source License 1.1 (Apache-2.0 future)](LICENSE), **FSL-1.1-ALv2**. Download, run, study, modify, and self-host freely for any purpose except a Competing Use: offering SafeClaw (or a derivative) to others as a commercial substitute. Each release converts to Apache-2.0 two years after it ships. This repo is the open client of a cloud-connected product; the cloud service stays proprietary.
