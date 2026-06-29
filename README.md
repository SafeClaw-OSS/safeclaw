<p align="center">
  <img src="docs/logo.png" alt="SafeClaw" width="72" />
</p>

<h1 align="center">SafeClaw</h1>
<p align="center">Protect your API keys with passkeys. Your AI agent uses your credentials — without ever holding them.</p>

SafeClaw is a local daemon + proxy for AI agents. Your API keys are encrypted with
your passkey (WebAuthn). Your agent doesn't get the keys — it routes its calls
through a local SafeClaw proxy that injects the credential, and **every use is
gated by a passkey approval from you**. The agent never sees a raw secret, and it
can't exfiltrate one even if its instructions are compromised.

```
Your AI Agent ──► SafeClaw daemon (localhost) ──► OpenAI / Anthropic / GitHub / …
                        │
                        ├─ injects the credential from your encrypted vault
                        └─ each call waits for your passkey approval
```

`safeclaw` and `sc` are the **same binary** (two names). The daemon runs on your
machine; the control plane (encrypted vault backup, cross-device sync, web-based
approvals, multi-vault) lives at **[safeclaw.pro](https://safeclaw.pro)**, which
this binary is the open client of.

## Why

- **No plaintext keys** — encrypted at rest; decrypted only in the daemon's memory while unlocked.
- **No passwords** — unlock with Touch ID, Windows Hello, or a security key (WebAuthn).
- **The agent never holds secrets** — it calls a local proxy; the daemon injects the key server-side.
- **Every use is approved by you** — a compromised agent or skill still can't spend your keys.
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
eval "$(sc env)"              # exports SAFECLAW_VAULT_URL (your local daemon)
```

The agent's own key is `SAFECLAW_API_KEY` (also from the dashboard / `sc agent add`).
With `SAFECLAW_VAULT_URL` + `SAFECLAW_API_KEY` set, the agent follows the **skill**
([`/skill.md`](https://safeclaw.pro/skill.md)) to make calls:

```
POST $SAFECLAW_VAULT_URL/use/<service>/<path>
Authorization: Bearer $SAFECLAW_API_KEY
```

The daemon injects the real credential and holds the call until you approve it with
your passkey. The agent gets the response, never the key.

## Daily use

- **Up** (`sc up`) — get the daemon running and the vault unlocked (one passkey tap). Idempotent.
- **Work** — your agent calls services through the proxy; you approve each use.
- **Lock** (`sc vault lock`) — wipe keys from the daemon's memory (or `sc down` to stop it).

## CLI

```bash
sc login --pair-token <spt>   # pair this machine (then brings the daemon up + unlocks)
sc logout [--keep-remote]     # unpair this machine (inverse of login); revokes the device-key cloud-side too
sc up                         # get the daemon running + vault unlocked (idempotent)
sc down | restart | logs      # daemon lifecycle (`restart` re-unlocks; Linux user-systemd)
sc serve                      # run the daemon in the foreground (Docker / dev)
sc vault unlock | lock        # decrypt / wipe the vault (passkey-gated; `sc up` unlocks for you)
sc env                        # print `export SAFECLAW_VAULT_URL=…` for your shell
sc agent add | ls | rm        # manage agent keys (one per agent, account-level)
sc ls | get | set | rm        # native secrets in the active vault
sc vault ls | use | create    # multi-vault selection
sc status | sc doctor         # status + reachability checks
sc upgrade                    # self-update to the latest release
```

`sc <cmd> --help` for details. Daemon lifecycle: `sc up | down | restart | logs | serve`.

## Configuration

State lives under `~/.safeclaw/` (config, device key, vault state, crypto keys).
The two env vars an agent uses:

| Env var | Meaning |
|---------|---------|
| `SAFECLAW_VAULT_URL` | Your local daemon's vault URL, e.g. `http://localhost:23294/v/<id>` (from `sc env`). |
| `SAFECLAW_API_KEY`   | The agent's bearer token for that vault (`sc agent add` or the dashboard). |

Daemon ports default to `23294` (API) and `23295` (HTTPS proxy). See
`sc serve --help` for the full set (`SAFECLAW_PORT`, `SAFECLAW_LISTEN`, …).

### Env vs config — who picks the vault

Those two env vars belong to the **agent process**. They are *not* how the `sc`
CLI decides which vault you're working in:

- **Agent** → reads `SAFECLAW_VAULT_URL` + `SAFECLAW_API_KEY` from its env; the
  vault it touches is the `/v/<id>` in that URL.
- **`sc` CLI (you)** → reads the active vault from `~/.safeclaw/config.toml`
  (set by `sc login` / `sc vault use`) plus an explicit `--vault` flag. It does
  **not** read `$SAFECLAW_VAULT_URL`, so a stale agent env can never hijack your
  CLI commands.

The rule: **env = process config** (daemon-serve params, the agent's broker
URL); **active vault = user state → `config.toml`**.

Two facts that follow:

- `SAFECLAW_API_KEY` is **account-level** — orthogonal to vaults. One key works
  for any of your vaults; the vault is chosen by the URL, not the key.
- The daemon hosts **all** your vaults at once — there is no global "active
  vault" on the daemon. Which vault a request hits is the `/v/<id>` in that
  request (a per-request choice), not daemon state.

## How it works

The agent→daemon and daemon→cloud surfaces speak **SUDP**, a passkey-signed
single-use-grant protocol: the agent requests a credential *use*, the daemon
registers a pending op, you sign an approval with your passkey, and only then does
the daemon inject the credential and forward the call. The vault blob is sealed
client-side under your passkey-derived key — the cloud stores and syncs it blind.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the cryptographic protocol,
[docs/SERVICES.md](docs/SERVICES.md) for the declarative service definitions
(`services/*/service.toml`), and [docs/CONNECTION_SCHEMA.md](docs/CONNECTION_SCHEMA.md)
for the connection data schema (`aux.connections`, namespaced secrets, routing).

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
