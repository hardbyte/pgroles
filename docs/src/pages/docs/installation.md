---
title: Installation
description: How to install the pgroles CLI tool.
---

## Compatibility

- **PostgreSQL 16+**: Full support including `GRANT ... WITH INHERIT`/`WITH ADMIN` syntax
- **PostgreSQL 14–15**: Supported with automatic fallback to legacy grant syntax (`WITH ADMIN OPTION`)
- CI integration tests run against PostgreSQL **16, 17, and 18**
- pgroles detects the server version at runtime and adapts SQL generation accordingly

## From source

pgroles is written in Rust. Build and install with Cargo:

```shell
cargo install --git https://github.com/hardbyte/pgroles pgroles-cli
```

This compiles the `pgroles` binary and places it in your Cargo bin directory (usually `~/.cargo/bin/`).

## From crates.io

```shell
cargo install pgroles-cli
```

## From a local clone

```shell
git clone https://github.com/hardbyte/pgroles.git pgroles
cd pgroles
cargo build --release
```

The binary will be at `target/release/pgroles`.

## From GitHub Releases

Download pre-built binaries from the [releases page](https://github.com/hardbyte/pgroles/releases).

## Docker

```shell
docker run --rm ghcr.io/hardbyte/pgroles --help
```

Published container images are multi-arch for `linux/amd64` and `linux/arm64`.
The release workflow builds the Linux binaries first and then assembles the
runtime images from those artifacts, so published images do not recompile Rust
inside the Docker publish jobs.

## Local Docker validation

To reproduce the live CLI tests against a local PostgreSQL:

```shell
docker run --rm --name pgroles-pg18 \
  -e POSTGRES_PASSWORD=testpassword \
  -e POSTGRES_DB=pgroles_test \
  -p 5432:5432 \
  postgres:18
```

In another shell:

```shell
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
cargo test -p pgroles-cli --test cli live_db::diff_against_live_db -- --ignored --exact
cargo test -p pgroles-cli --test cli live_db::diff_summary_format -- --ignored --exact
```

Use `postgres:16` or `postgres:17` if you want to reproduce the full CI matrix locally.

## Contributor notes

- `docker/Dockerfile` is the source-build path used for local builds and E2E-style flows.
- `docker/Dockerfile.runtime` is the release assembly path used in GitHub Actions.
- BuildKit cache mounts are used in `docker/Dockerfile` for Cargo registry, git, and target caches.
- The release workflow does not need Cargo cache mounts in the Docker step because it consumes prebuilt Linux binaries from the earlier build job.

## Verify installation

```shell
pgroles --version
pgroles --help
```
