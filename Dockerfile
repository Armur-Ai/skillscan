# syntax=docker/dockerfile:1
#
# Multi-stage build:
#   1. `builder` compiles a release binary against tree-sitter (C deps).
#   2. final stage runs on distroless/cc as a non-root user, ~30 MB total.
#
# Usage:
#   docker run --rm -v "$PWD:/work" ghcr.io/armur-ai/skillscan scan /work/my-skill

FROM rust:1.95-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY LICENSE README.md ./

RUN cargo build --release --locked \
    && strip target/release/skillscan

FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/Armur-Ai/skillscan"
LABEL org.opencontainers.image.description="Security scanner for Claude Skills"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="skillscan"

COPY --from=builder /build/target/release/skillscan /usr/local/bin/skillscan

USER nonroot
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/skillscan"]
CMD ["--help"]
