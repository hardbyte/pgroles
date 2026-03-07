# syntax=docker/dockerfile:1.7

# Multi-stage build for pgroles binaries from source.
# Used for local builds and CI paths that build images directly from the repo.

# ---------------------------------------------------------------------------
# Stage 1: Shared build base
# ---------------------------------------------------------------------------
FROM rust:1.89-alpine@sha256:4b800f2e72e04be908e5f634c504c741bd943b763d1d8ad7b096cc340e1b5b46 AS base

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build

# Copy workspace manifests first for dependency caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/pgroles-core/Cargo.toml crates/pgroles-core/Cargo.toml
COPY crates/pgroles-inspect/Cargo.toml crates/pgroles-inspect/Cargo.toml
COPY crates/pgroles-cli/Cargo.toml crates/pgroles-cli/Cargo.toml
COPY crates/pgroles-operator/Cargo.toml crates/pgroles-operator/Cargo.toml

# Create stub lib.rs files so cargo can resolve the workspace.
RUN mkdir -p crates/pgroles-core/src \
    && echo "pub fn _stub() {}" > crates/pgroles-core/src/lib.rs \
    && mkdir -p crates/pgroles-inspect/src \
    && echo "pub fn _stub() {}" > crates/pgroles-inspect/src/lib.rs \
    && mkdir -p crates/pgroles-cli/src \
    && echo "fn main() {}" > crates/pgroles-cli/src/main.rs \
    && echo "pub fn _stub() {}" > crates/pgroles-cli/src/lib.rs \
    && mkdir -p crates/pgroles-operator/src \
    && echo "fn main() {}" > crates/pgroles-operator/src/main.rs \
    && echo "pub fn _stub() {}" > crates/pgroles-operator/src/lib.rs \
    && mkdir -p crates/pgroles-operator/src/bin \
    && echo "fn main() {}" > crates/pgroles-operator/src/bin/crdgen.rs

# Pre-build dependency graph per binary target.
ENV SQLX_OFFLINE=true

FROM base AS deps-cli
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --package pgroles-cli 2>/dev/null || true

FROM base AS deps-operator
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --package pgroles-operator 2>/dev/null || true

FROM deps-cli AS builder-cli
COPY crates/ crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --package pgroles-cli && \
    install -Dm755 /build/target/release/pgroles /out/pgroles

FROM deps-operator AS builder-operator
COPY crates/ crates/
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
