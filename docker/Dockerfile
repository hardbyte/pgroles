# Multi-stage build for pgpolicy binaries.
# Produces a statically-linked musl binary in a minimal container.

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM rust:1.89-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build

# Copy workspace manifests first for dependency caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/pgpolicy-core/Cargo.toml crates/pgpolicy-core/Cargo.toml
COPY crates/pgpolicy-inspect/Cargo.toml crates/pgpolicy-inspect/Cargo.toml
COPY crates/pgpolicy-cli/Cargo.toml crates/pgpolicy-cli/Cargo.toml
COPY crates/pgpolicy-operator/Cargo.toml crates/pgpolicy-operator/Cargo.toml

# Create stub lib.rs files so cargo can resolve the workspace.
RUN mkdir -p crates/pgpolicy-core/src \
    && echo "pub fn _stub() {}" > crates/pgpolicy-core/src/lib.rs \
    && mkdir -p crates/pgpolicy-inspect/src \
    && echo "pub fn _stub() {}" > crates/pgpolicy-inspect/src/lib.rs \
    && mkdir -p crates/pgpolicy-cli/src \
    && echo "fn main() {}" > crates/pgpolicy-cli/src/main.rs \
    && echo "pub fn _stub() {}" > crates/pgpolicy-cli/src/lib.rs \
    && mkdir -p crates/pgpolicy-operator/src \
    && echo "fn main() {}" > crates/pgpolicy-operator/src/main.rs \
    && echo "pub fn _stub() {}" > crates/pgpolicy-operator/src/lib.rs \
    && mkdir -p crates/pgpolicy-operator/src/bin \
    && echo "fn main() {}" > crates/pgpolicy-operator/src/bin/crdgen.rs

# Pre-build dependencies (cached layer).
ENV SQLX_OFFLINE=true
RUN cargo build --release --workspace 2>/dev/null || true

# Copy real source.
COPY crates/ crates/

# Touch source files so cargo knows to rebuild them.
RUN find crates -name "*.rs" -exec touch {} +

# Build release binaries.
RUN cargo build --release --workspace

# ---------------------------------------------------------------------------
# Stage 2: Runtime — CLI
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/static:latest AS cli

COPY --from=builder /build/target/release/pgpolicy /usr/local/bin/pgpolicy

ENTRYPOINT ["pgpolicy"]

# ---------------------------------------------------------------------------
# Stage 3: Runtime — Operator
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/static:latest AS operator

COPY --from=builder /build/target/release/pgpolicy-operator /usr/local/bin/pgpolicy-operator

USER 65534
ENTRYPOINT ["pgpolicy-operator"]
