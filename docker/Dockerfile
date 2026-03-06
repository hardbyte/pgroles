# Multi-stage build for pgroles binaries.
# Produces a statically-linked musl binary in a minimal container.

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM rust:1.89-alpine AS builder

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

COPY --from=builder /build/target/release/pgroles /usr/local/bin/pgroles

USER 65534
ENTRYPOINT ["pgroles"]

# ---------------------------------------------------------------------------
# Stage 3: Runtime — Operator
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/static:latest AS operator

COPY --from=builder /build/target/release/pgroles-operator /usr/local/bin/pgroles-operator

USER 65534
ENTRYPOINT ["pgroles-operator"]
