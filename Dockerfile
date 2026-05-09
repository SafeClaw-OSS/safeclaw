# Multi-stage build for the SafeClaw daemon.
FROM rust:1.83-bookworm AS builder
WORKDIR /usr/src/safeclaw
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin safeclaw

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 -m -d /var/lib/safeclaw safeclaw
WORKDIR /var/lib/safeclaw
COPY --from=builder /usr/src/safeclaw/target/release/safeclaw /usr/local/bin/safeclaw
USER safeclaw
ENV SAFECLAW_STATE_DIR=/var/lib/safeclaw/state \
    SAFECLAW_BIND=0.0.0.0 \
    SAFECLAW_PORT=23294 \
    SAFECLAW_PROXY_PORT=23295
EXPOSE 23294 23295
ENTRYPOINT ["/usr/local/bin/safeclaw"]
