# syntax=docker/dockerfile:1
FROM rust:1.85-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY src ./src

# Build release binaries with bounded concurrency
RUN nice -n 19 cargo build --release -j 2

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    msmtp-mta \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/lib/nymserv
RUN mkdir -p /var/lib/nymserv/data /var/lib/nymserv/keys /etc/nymserv

COPY --from=builder /app/target/release/nymservd /usr/local/bin/nymservd
COPY --from=builder /app/target/release/nymserv-lda /usr/local/bin/nymserv-lda
COPY --from=builder /app/target/release/nymserv-ctl /usr/local/bin/nymserv-ctl

VOLUME ["/var/lib/nymserv"]
ENTRYPOINT ["/usr/local/bin/nymservd"]
CMD ["--config", "/etc/nymserv/nymserv.toml"]
