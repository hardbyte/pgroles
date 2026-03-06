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
docker run --rm ghcr.io/hardbyte/pgroles:0.1.1 --help
```

## Local Docker validation

To reproduce the live CLI tests against a local PostgreSQL:

```shell
docker run --rm --name pgroles-pg16 \
  -e POSTGRES_PASSWORD=testpassword \
  -e POSTGRES_DB=pgroles_test \
  -p 5432:5432 \
  postgres:16
```

In another shell:

```shell
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
cargo test -p pgroles-cli --test cli live_db::diff_against_live_db -- --ignored --exact
cargo test -p pgroles-cli --test cli live_db::diff_summary_format -- --ignored --exact
```

Use `postgres:17` or `postgres:18` to mirror the CI matrix.

## Verify installation

```shell
pgroles --version
pgroles --help
```
