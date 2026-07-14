<p align="center">
  <img src="docs/logo.png" alt="SafeClaw" width="72" />
</p>

<h1 align="center">SafeClaw</h1>
<p align="center">Protect your API keys with passkeys. Your AI agent uses your credentials — without ever holding them.</p>

SafeClaw is a local daemon + credential proxy for AI agents. Your keys are
encrypted under your passkey (WebAuthn). The agent never sees them: it writes a
**phantom** — a placeholder like `__sc__github__` — where the credential belongs,
and runs the command through `sc run --`. The proxy swaps the phantom for the
real value at egress, only toward that connection's own hosts, and sensitive
uses wait for your passkey approval. A compromised agent or skill can't
exfiltrate a key it never held.

```
Your AI Agent ──► SafeClaw proxy (localhost) ──► OpenAI / Anthropic / GitHub / …
  sc run --             │
  __sc__github__        ├─ swaps the phantom for the real credential from your encrypted vault
                        └─ sensitive uses wait for your passkey approval
```

`safeclaw` and `sc` are the **same binary** (two names). The daemon runs on your
machine; the control plane (encrypted vault backup, cross-device sync, web-based
approvals, multi-vault) lives at **[safeclaw.pro](https://safeclaw.pro)**, which
this binary is the open client of.

## Why

- **No plaintext keys** — encrypted at rest; decrypted only in the daemon's memory while unlocked.
- **No passwords** — approve with Touch ID, Windows Hello, or a security key (WebAuthn).
- **The agent never holds secrets** — it writes a phantom; the proxy injects the real key at egress, pinned to that service's own hosts.
- **You approve what matters** — every brokered call is policy-checked; sensitive ones wait for your passkey tap. A compromised agent still can't spend your keys unsupervised.
- **Single static binary** — ~5 MB, no runtime deps.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/SafeClaw-OSS/safeclaw/main/install.sh | sh
```

Installs the `sc` binary to `~/.local/bin`. It only downloads the prebuilt
release binary for your platform and verifies its `SHA256SUMS`; no sudo, no system
changes. Each release also carries a sigstore build-provenance attestation
(`gh attestation verify ~/.local/bin/sc --repo SafeClaw-OSS/safeclaw`).

Or build from source: `cargo build --release` (binaries at `target/release/{sc,safeclaw}`).

## Connect an agent

From the **[safeclaw.pro](https://safeclaw.pro)** dashboard, "Connect a new agent"
mints a one-time pair token and an install prompt you paste to your agent. The
flow the agent runs on your machine:

```bash
sc login --pair-token spt_…   # pair this machine; brings the daemon up + unlocks
                              #   (prints a passkey-approval link you open in a browser)
sc agent add my-agent         # mint the agent's env — BROKER_URL / VAULT_ID / API_KEY
                              #   (the install prompt covers both steps)
```

The agent then follows the **skill**
([static/safeclaw-skill.md](static/safeclaw-skill.md)): list what's connected
(`sc connection ls` or `GET $SAFECLAW_BROKER_URL/v/$SAFECLAW_VAULT_ID/registry`),
put the phantom where the credential belongs, and route the command through the
proxy:

```bash
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

The proxy substitutes the real credential on the way out; the agent gets the
response, never the key. Only traffic routed through `sc run` is touched — a
phantom sent anywhere else reaches the upstream as a literal string (a clean
401), never a leak.

## Daily use

- **Up** (`sc up`) — get the daemon running and the vault unlocked (one passkey tap). Idempotent.
- **Work** — the agent runs its commands through `sc run --`; you approve the sensitive ones.
- **Lock** (`sc lock`) — wipe keys from the daemon's memory (or `sc down` to stop it).

## CLI

```bash
sc login --pair-token <spt>   # pair this machine (then brings the daemon up + unlocks)
sc logout                     # unpair this machine; revokes its device key cloud-side too
sc up | down | restart        # daemon lifecycle (Linux systemd / macOS launchd); up re-unlocks
sc status | logs | doctor     # status, daemon logs, health + reachability checks
sc run -- <cmd…>              # run a command through the credential proxy
sc connection add | ls | rm   # connections: secret(s) + host anchor → phantom
sc registry                   # the service catalog
sc set | get | ls | rm        # native secrets in the active vault
sc agent add | ls | rm        # agent identities (API keys; one per agent, account-level)
sc vault ls | use | create    # multi-vault selection
sc unlock | lock              # decrypt / wipe the vault in the daemon's memory
sc upgrade                    # self-update to the latest release
```

`sc --help` shows the full grouped list; `sc <cmd> --help` for details.

## Configuration

State lives under `~/.safeclaw/` (config, device key, vault state, crypto keys).
The three env vars an agent uses — minted as one block by `sc agent add` (or the
dashboard's install prompt):

| Env var | Meaning |
|---------|---------|
| `SAFECLAW_BROKER_URL` | The local broker, e.g. `http://127.0.0.1:23294`. |
| `SAFECLAW_VAULT_ID`   | Which vault this agent's requests resolve against. |
| `SAFECLAW_API_KEY`    | The agent's bearer token (one per agent, account-level). |

Ports default to `23293` (control plane: CLI, approvals, events) and `23294`
(the credential proxy `sc run` routes traffic through). See `sc serve --help`
for the full set (`SAFECLAW_PORT`, `SAFECLAW_PROXY_PORT`, `SAFECLAW_LISTEN`, …).

### Env vs config — who picks the vault

Those env vars belong to the **agent process**. The `sc` CLI (you) reads its
active vault from `~/.safeclaw/config.toml` — set by `sc login` / `sc vault use`,
overridable per-command with `--vault` — never from the agent's env, so a stale
agent env can't hijack your CLI commands. The daemon hosts **all** your vaults
at once: which vault a request hits is the `/v/<id>` in that request (a
per-request choice), not daemon state, and one `SAFECLAW_API_KEY` works for any
of your vaults.

## How it works

The approval surfaces speak **SUDP**, a passkey-signed single-use-grant
protocol: a brokered call that needs consent registers a pending op, you sign
the approval with your passkey, and only then does the daemon inject the
credential and forward the call. The vault blob is sealed client-side under your
passkey-derived key — the cloud stores and syncs it blind.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the cryptographic protocol,
[docs/SERVICES.md](docs/SERVICES.md) for the declarative service definitions
(`services/*/service.toml`), [docs/CONNECTION_SCHEMA.md](docs/CONNECTION_SCHEMA.md)
for the connection data schema, and [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md)
for every error the broker can surface and what to do about it.

## Remote / self-host

WebAuthn requires HTTPS for non-localhost origins. To run the daemon behind TLS,
set `--origin https://your.host` and `--rp-id your.host` (they must match the URL
your browser sees). The managed control plane is safeclaw.pro; the daemon here is
its open client.

## License

[Functional Source License 1.1 (Apache-2.0 future)](LICENSE) — **FSL-1.1-ALv2**.

You can download, run, study, modify, and self-host SafeClaw freely for any
purpose **except a Competing Use** — offering it (or a derivative) to others as a
commercial product that substitutes for SafeClaw. Each release converts to
Apache-2.0 two years after it ships. SafeClaw is the open **client** of a
cloud-connected product; the cloud service stays proprietary.
