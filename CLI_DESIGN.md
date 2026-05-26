# SafeClaw CLI — Design

**Target:** `v1/crypto-redesign` daemon. The CLI ships in the same `safeclaw` binary.

**Scope:** Self-host / OSS users who run their own daemon. The CLI manages the **vault** (the daemon's stored state) — setup, unlock/lock, read/write secrets, list services, run-and-inject for shell commands. **Agent-side integration (skill install URL, broker forwards) is out of scope** — that's frontend territory, the CLI doesn't touch it.

**Status:** Design only. Implementation queued.

---

## 1. Goals & non-goals

### Goals

- One binary (`safeclaw`) does everything — daemon mode and CLI mode. Same artifact, no separate client install.
- A new OSS user can go from `cargo install` to "my agent is calling OpenAI through my locally-sealed vault" in three commands.
- Vault ops are passkey-gated end-to-end. The CLI never sees plaintext credentials except where it's intrinsic to the operation (e.g., `write` reads the value off stdin, sends to daemon under passkey-bound op).
- Multi-tenant aware. Defaults are coherent for the 1-user-1-vault case; extra flags let power users address specific vaults.
- Mainstream conventions: subcommand UX (`docker`, `git`, `gh`), `--help` at every level, machine-readable `--json` output, config from `~/.config/safeclaw/`.

### Non-goals

- No new "API client library" — the CLI is the only first-party client. If users want a library, they wrap the daemon HTTP.
- No agent-side primitives in the CLI (no skill install, no `/api/use/*` invocation). OSS users wire those manually in their agent of choice.
- No SaaS-specific features (Supabase auth, account/billing). OSS daemon has no concept of an account beyond the vault.
- No GUI launcher / tray app. Just a CLI.

---

## 2. Architecture

### Single binary, two modes

```
safeclaw serve [--state-dir ...]    # daemon mode (today's main.rs)
safeclaw <command> [--daemon URL]   # CLI mode (talks to a running daemon)
```

- `safeclaw serve` is what's running today — `main.rs` already does this. Add a `serve` subcommand wrapper so `safeclaw` alone prints help instead of starting the daemon.
- CLI mode talks to the daemon over HTTP, default `http://127.0.0.1:23294`. Override with `--daemon <URL>` flag or `SAFECLAW_DAEMON` env var.

### State layout (CLI side)

```
~/.config/safeclaw/
  config.toml          # default daemon URL, default vault id
  contexts.toml        # named (daemon, vault_id) pairs, kubectl-style
```

`config.toml`:
```toml
default_daemon = "http://127.0.0.1:23294"
default_vault  = "<vault-id-uuid>"
default_context = "local"

[contexts.local]
daemon = "http://127.0.0.1:23294"
vault  = "<uuid>"

[contexts.work]
daemon = "https://vault.work.example.com"
vault  = "<uuid>"
```

Default context is `local`. `safeclaw context use work` switches sticky. Most users never touch this.

### State layout (daemon side, unchanged)

`SAFECLAW_STATE_DIR` (today: `./state`), with `tenants/<vault-id>/vault.dat` per the existing multi-tenant model.

---

## 3. Subcommand vocabulary

### Setup

```
safeclaw setup
  ↳ creates a new vault, enrolls a passkey, prints the vault id
  ↳ writes ~/.config/safeclaw/config.toml with this vault as default
```

Flags:
- `--vault-id <uuid>` — explicit id (default: generate). Useful for restoring a known id.
- `--daemon <URL>` — point at non-local daemon.
- `--label <name>` — friendly label stored in vault metadata.

### Vault state

```
safeclaw unlock          # passkey ceremony, brings vault to Unlocked
safeclaw lock            # locks
safeclaw status          # prints vault id, locked/unlocked, last activity
```

### Secrets

```
safeclaw write <key>                # value from stdin (echo "..." | safeclaw write openai_api_key)
safeclaw write <key> --value <v>    # value inline (discouraged — shell history)
safeclaw read <key>                 # prints value to stdout, passkey-gated
safeclaw ls                         # lists key names + sources (native / external)
safeclaw delete <key>
```

### Run-and-inject (the killer feature for headless users)

```
safeclaw run -- <command…>
  ↳ unlocks vault if needed, derives env vars from the catalog
    (openai_api_key → OPENAI_API_KEY etc.), execs <command> with them
    in the environment, then locks again.
```

Like `doppler run`, `aws-vault exec`. This is the **broker analog for shells** — same "agent never holds the raw value" property except scoped to a single process tree.

Hidden simple version: `safeclaw export-env` prints `export FOO=...` lines for shell eval. Power users only — `run` is the safer default.

### Stores (external resolution sources, optional)

```
safeclaw stores ls
safeclaw stores add gcp --project-id ... --sa-json @path/to/sa.json
safeclaw stores remove <id>
```

### Multi-tenant (power users)

```
safeclaw vaults ls
safeclaw vaults create [--label ...]
safeclaw vaults delete <id>
safeclaw context use <name>
safeclaw context current
```

Almost all OSS users run one vault, so `vaults` and `context` are advanced commands; the default flow doesn't touch them.

### Daemon mode

```
safeclaw serve [flags...]    # what main.rs does today, but explicit
```

### Misc

```
safeclaw version
safeclaw doctor              # checks daemon reachability, passkey-auth flow, key permissions
```

---

## 4. Passkey ceremony from CLI

Two paths. Default is browser-callback. Copy-paste is the fallback.

### A. Browser-callback (default)

1. CLI opens an HTTP listener on a random localhost port (e.g., `127.0.0.1:53921`).
2. CLI opens user's default browser to `https://<daemon-host>/cli/auth?callback=http://127.0.0.1:53921/done&op_id=<id>` — this is a **new page** in the SafeClaw frontend that does the WebAuthn ceremony and POSTs the signed grant back to the callback URL.
3. CLI waits up to 90 s. On callback receipt, it has the grant in hand and submits to daemon.

**When this works:** anywhere a desktop browser can reach `127.0.0.1` on the CLI's machine. That's most workstations.

**Daemon discovery for the page URL:** the daemon serves the auth page off its own origin (`SAFECLAW_ORIGIN`). For local OSS, that's `http://localhost:23294/cli/auth`. For SaaS-style deploys, it's the configured public origin. CLI just composes `<origin>/cli/auth?...`.

### B. Copy-paste base64 (fallback)

For SSH-only environments, remote dev boxes, anywhere the CLI can't open a browser.

1. CLI prints a URL: `https://<daemon-host>/cli/auth?op_id=<id>&mode=paste`
2. User opens it on any device (laptop with their passkey).
3. The page runs the WebAuthn ceremony, then **renders the signed grant as a base64 blob** with a "Copy" button.
4. User pastes back into the CLI prompt.
5. CLI submits to daemon.

Same trust model as `claude login` paste flow, `gh auth --device`, etc.

**Mode selection:** CLI tries browser-callback first; on failure (`xdg-open` errors, callback timeout) falls back to paste. `--paste` flag forces paste mode for known-headless environments.

### Why not a "device code flow" like OAuth?

We considered the OAuth device-code pattern (browser shows code, user types code on second device). It works but adds a round-trip and an UX wart. The base64 paste is simpler and the user is already pasting from the same device half the time. Skip device-code.

---

## 5. Multi-tenant behavior

**Default behavior matches single-tenant intuition.**

- `safeclaw setup` creates one vault and writes it as default in config.
- All subsequent `safeclaw <op>` commands target the default vault, no flag needed.
- Adding a second vault: `safeclaw vaults create`. To use it, either `--vault <id>` per-command or `safeclaw context use <name>` to switch sticky.

**Why not auto-detect "this user has N vaults" and prompt?**

Friction. Power users who actually run N vaults will explicitly set context; single-vault users get a clean default. Auto-detection introduces an "is your context right?" question on every command that 95% of users don't need.

---

## 6. Examples — what the README will show

### First-time setup
```bash
$ safeclaw serve &                                # one-time, daemon backgrounded
$ safeclaw setup
  → opening browser for passkey enrollment…
  → vault sealed: 3f8a-...-d1e2
  → config written: ~/.config/safeclaw/config.toml

$ echo "sk-..." | safeclaw write openai_api_key
  → wrote openai_api_key

$ safeclaw run -- curl https://api.openai.com/v1/models \
    -H "Authorization: Bearer $OPENAI_API_KEY"
  → unlocked, exec'd, locked.
```

### Returning user
```bash
$ safeclaw unlock           # one passkey gesture
$ safeclaw ls
  openai_api_key       (native)
  github_pat           (native)
  stripe_key           (gcp-prod)

$ safeclaw read openai_api_key | pbcopy   # local clipboard
```

### Headless via SSH
```bash
$ ssh remote-box safeclaw run --paste -- npm test
  → visit: https://vault.example.com/cli/auth?op_id=...&mode=paste
  → paste grant: <user pastes from local laptop>
  → unlocked, exec'd, locked.
```

---

## 7. Implementation order (if you greenlight)

| Phase | What | Why |
|---|---|---|
| 1 | Refactor `main.rs` so `safeclaw serve` is explicit, bare `safeclaw` prints help | Lowest risk, enables everything else |
| 2 | `safeclaw setup` + `safeclaw status` + `safeclaw unlock`/`lock` over HTTP, **paste-only first** | Core flow, paste-mode avoids the page-design rabbit hole |
| 3 | New `/cli/auth` page in frontend (passkey ceremony + base64 grant renderer) | Reuses existing WebAuthn code from `lib/vault-grant.ts`, ~half-day |
| 4 | Browser-callback mode in CLI (random local port + 90s wait) | Bigger UX win; build on top of paste once it works |
| 5 | `write` / `read` / `ls` / `delete` | Day-to-day usage |
| 6 | `run` / `export-env` | Killer-feature parity with `doppler run` |
| 7 | `stores`, `vaults`, `context` — power user surfaces | Last |

Phases 1-5 = MVP. 6 is the differentiator. 7 only when someone actually asks.

---

## 8. Decisions needing user review

(Marked **REVIEW** in priority order. The rest of the doc bakes in mainstream-OSS-convention answers; these are where the convention doesn't dictate.)

1. **REVIEW — `safeclaw run` semantics.** Does it auto-unlock-and-lock around each invocation (current proposal), or expect a pre-unlocked vault? Auto-unlock is more `aws-vault exec`-like; pre-unlock is more `doppler run`-like. Today's draft picks auto, but it means an extra passkey gesture per `run` — annoying for tight test loops.

2. **REVIEW — passkey storage on the daemon side, OSS deployment.** Today the SaaS deployment stores passkey public keys in Supabase (`passkeys` table). OSS doesn't have Supabase. Options:
   - (a) Add a SQLite-backed `passkeys` table inside the daemon, alongside audit log. Cleanest.
   - (b) Stuff passkey records into the existing `vault.dat` aux. Already encrypted, no new dep.
   - (c) Per-tenant `passkeys.json` on disk. Simple.
   I lean (a) — it's the only one that handles "list passkeys before unlock" cleanly, which `safeclaw setup`/`enroll` paths need.

3. **REVIEW — naming for the headless paste mode page.** `/cli/auth` is what I drafted. Other candidates: `/cli/grant`, `/grant`, `/authorize-cli`. The page exists on the SaaS frontend AND in the OSS-self-host frontend (or do OSS users not get a frontend?). Which brings us to:

4. **REVIEW — does OSS ship a frontend at all?** Two extremes:
   - (a) **Yes, full frontend** — `safeclaw serve` also serves the `/vault` UI on the same port. Single binary, single artifact. Heavier dep on Node build artifacts.
   - (b) **No frontend, CLI only** — OSS = headless. The `/cli/auth` page only lives in SaaS. OSS users either run the SaaS frontend themselves (separate repo) or use paste-mode against any SaaS daemon they trust.
   - (c) **Minimal frontend** — only the `/cli/auth` page (essentially a single HTML file with WebAuthn JS). Tiny static bundle the daemon serves. Compromise; cleanest OSS story.
   I lean (c).

5. **REVIEW — `safeclaw doctor` scope.** Useful but unbounded; ship a minimal version (daemon reachable + passkey ceremony works) and grow from feedback.

6. **REVIEW — config file format.** TOML matches Cargo/our service files. Anyone else here would say JSON or YAML; TOML is fine for OSS Rust audience.

7. **REVIEW — should `safeclaw run` proxy the upstream call**, or just inject env vars and exec? Drafted "just inject env vars". The alternative ("CLI talks to broker, broker forwards") gives policy enforcement and audit but couples CLI to broker plane and conflicts with "the broker is an agent-facing concept" framing. Stick with env-inject.

---

## Open follow-ups (not blocking design lock-in)

- Cross-machine sync. If a user runs daemon on a NAS but uses CLI on their laptop, that's already supported via `--daemon URL`. No new design needed; works out of the box.
- Auto-updates. `cargo install --force` is fine for OSS day-1; revisit if needed.
- Shell completions. Add via `clap_complete`; mechanical when implementing.
