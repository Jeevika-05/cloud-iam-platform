# ── Build stage ──────────────────────────────
FROM rust:1-bookworm AS builder

WORKDIR /app

# Cache dependency compilation
COPY Cargo.toml ./
RUN mkdir src && echo "fn main(){}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Build real binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── Runtime stage ────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/cloudshield-attacker /usr/local/bin/attacker

RUN mkdir -p /reports

CMD ["attacker"]
