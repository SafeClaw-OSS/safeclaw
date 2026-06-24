# Multi-stage build for the SafeClaw daemon.
#
# Build context = the safeclaw/ crate directory. `sudp` is pulled from
# crates.io so no sibling source tree is required at build time. See
# `safeclaw/docs/DEPLOYMENT.md` for the per-platform recipe.

FROM rust:1.94-bookworm AS builder
WORKDIR /usr/src/safeclaw
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./build.rs
COPY services ./services
COPY src ./src
RUN cargo build --release --bin safeclaw

FROM debian:bookworm-slim

# `gosu` lets the entrypoint run as root long enough to chown the state
# directory (Railway / k8s volumes mount as root by default) then drops
# privileges to `safeclaw` before exec'ing the daemon. Designed exactly
# for this pattern; lighter than su / sudo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates gosu \
 && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. `-m` materialises `/var/lib/safeclaw` as $HOME
# so the daemon has a writable place for non-state side-effects (caches,
# sockets) without polluting the state volume.
RUN useradd -r -u 10001 -m -d /var/lib/safeclaw safeclaw

WORKDIR /var/lib/safeclaw

COPY --from=builder /usr/src/safeclaw/target/release/safeclaw /usr/local/bin/safeclaw
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Defaults that make `docker run` work without env overrides.
# `SAFECLAW_STATE_DIR` is set to a docker-compose-friendly path; every
# real deployment (compose / k8s / Railway / fly) overrides this to the
# platform-managed persistent-volume mount path.
ENV SAFECLAW_BIND=0.0.0.0 \
    SAFECLAW_PORT=23294 \
    SAFECLAW_PROXY_PORT=23295 \
    SAFECLAW_STATE_DIR=/var/lib/safeclaw/state

EXPOSE 23294 23295

# Entrypoint runs as root, chowns the state dir to the safeclaw uid,
# then `exec gosu safeclaw` drops privileges before the daemon ever
# binds a port.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["safeclaw"]
