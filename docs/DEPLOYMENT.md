# SafeClaw Daemon — Deployment

Where the daemon's state lives and how to deploy it on each platform.
The state path question has ONE answer per platform; this doc is the
single source of truth.

## Configuration model

The daemon reads `SAFECLAW_STATE_DIR` (env var) at startup and writes
each tenant's vault to `<state-dir>/tenants/<tenant-id>/vault.dat`.
Override order: CLI flag (`--state-dir`) > env var > code default
(`./state`, cwd-relative — testing only). Platform deployments override
via env.

The daemon runs as a non-root container user (`safeclaw`, uid 10001).
`entrypoint.sh` chowns the state directory at startup before dropping
privileges, so any persistent volume mounted by the platform (which
typically lands as root-owned) is normalised without manual setup.

## Canonical state paths

| Deployment | `SAFECLAW_STATE_DIR` | Set in |
|---|---|---|
| Local `./dev.sh` (bare cargo binary) | `./.state/safeclaw-daemon` (cwd-relative) | `dev.sh:32` |
| `docker-compose` | `/var/lib/safeclaw/state` | `docker-compose.yml` |
| Bare `docker run` (no overrides) | `/var/lib/safeclaw/state` | `Dockerfile` ENV |
| Railway / Fly / k8s | platform-managed mount path (commonly `/data`) | platform service env |
| systemd on VM | `/var/lib/safeclaw/state` | unit `Environment=` |

All platforms map vault data to `<state-dir>/tenants/<id>/vault.dat`.

## Per-platform recipes

### Local dev (`./dev.sh`)

Already wired. State lives at `./.state/safeclaw-daemon/tenants/` under
the workspace root. To wipe and re-enroll a fresh vault:

```bash
rm -rf ./.state/safeclaw-daemon/tenants
```

### docker-compose

Build context is the workspace ROOT (not `safeclaw/`) because the
daemon's Cargo.toml depends on the sibling sudp crate via a relative
path:

```bash
cd ~/projects/safeclaw
docker compose up --build daemon
```

Vault data lives in the named volume `daemon-state`; wipe with
`docker compose down -v` to start fresh.

### Railway

Two pieces of platform setup, both one-time:

1. **Volume.** Create a Railway Volume on the daemon service and mount
   it at `/data` (or any path you like — pick something stable).
2. **Env var.** Set `SAFECLAW_STATE_DIR=/data` on the daemon service so
   the binary writes vault data into the mounted volume. Also set
   `SAFECLAW_RP_ID` and `SAFECLAW_ORIGIN` to match your public domain.

Build configuration:

- Set the Railway service's build to **Dockerfile**, pointing at
  `safeclaw/Dockerfile` with root directory `safeclaw/`. `sudp` is
  pulled from crates.io, so the safeclaw repo alone is sufficient at
  build time — no submodule or workspace gymnastics required.
- The image is multi-stage, runtime is `debian:bookworm-slim` with
  `gosu` + `ca-certificates`. ~80MB.

Volume ownership is handled by `entrypoint.sh`: container starts as
root, chowns `$SAFECLAW_STATE_DIR` to uid 10001, then `gosu`-drops to
the `safeclaw` user before binding ports. Works whether the volume is
freshly initialised or already populated.

### Bare VM + systemd

```ini
# /etc/systemd/system/safeclaw-daemon.service
[Unit]
Description=SafeClaw custodian daemon
After=network.target

[Service]
Type=simple
User=safeclaw
Group=safeclaw
WorkingDirectory=/var/lib/safeclaw
Environment=SAFECLAW_STATE_DIR=/var/lib/safeclaw/state
Environment=SAFECLAW_BIND=127.0.0.1
Environment=SAFECLAW_PORT=23294
Environment=SAFECLAW_PROXY_PORT=23295
Environment=SAFECLAW_RP_ID=safeclaw.pro
Environment=SAFECLAW_ORIGIN=https://safeclaw.pro
ExecStart=/usr/local/bin/safeclaw
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Make sure the directory exists and is owned by the daemon user before
starting the unit:

```bash
sudo useradd -r -d /var/lib/safeclaw -s /usr/sbin/nologin safeclaw
sudo install -d -o safeclaw -g safeclaw -m 0750 /var/lib/safeclaw/state
```

Front with Caddy / nginx for TLS — the daemon does not terminate TLS
itself.

## Migration notes

- Existing v2 vaults (pre-`1.0.0-demo.4`) hard-fail on first unlock
  under v3 binaries with `vault plaintext version X (expected 3)`. Pre-
  launch policy: wipe state, re-enroll. See
  `safeclaw/docs/SMOKE_TEST_GCP.md` for the wipe command per platform.
- Schema-version negotiation lives in
  `safeclaw/src/storage/plaintext.rs` (constant `PLAINTEXT_VERSION`).
  Bumping it = breaking change; bump `Cargo.toml` package version in
  the same commit so the frontend can detect the mismatch via
  `/health`.
