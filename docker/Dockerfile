# syntax=docker/dockerfile:1.7

# Multi-stage build for pgroles binaries from source.
# Used for local builds and CI paths that build images directly from the repo.

# ---------------------------------------------------------------------------
# Stage 1: Shared build base
# ---------------------------------------------------------------------------
FROM rust:1.94-alpine@sha256:ef7b340d4201444fa2757dfddfd4c03be9d2bde468de7b7a68b0e9fabb794334 AS base

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build

# Copy the real workspace source.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

ENV SQLX_OFFLINE=true

FROM base AS builder-cli
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --package pgroles-cli && \
    install -Dm755 /build/target/release/pgroles /out/pgroles

FROM base AS builder-operator
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --package pgroles-operator && \
    install -Dm755 /build/target/release/pgroles-operator /out/pgroles-operator

# ---------------------------------------------------------------------------
# Stage 2: Runtime — CLI
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/static@sha256:d6a97eb401cbc7c6d48be76ad81d7899b94303580859d396b52b67bc84ea7345 AS cli

COPY --from=builder-cli /out/pgroles /usr/local/bin/pgroles

USER 65534
ENTRYPOINT ["pgroles"]

# ---------------------------------------------------------------------------
# Stage 3: Runtime — Operator
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/static@sha256:d6a97eb401cbc7c6d48be76ad81d7899b94303580859d396b52b67bc84ea7345 AS operator

COPY --from=builder-operator /out/pgroles-operator /usr/local/bin/pgroles-operator

USER 65534
ENTRYPOINT ["pgroles-operator"]
