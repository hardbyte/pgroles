---
title: Installation
description: How to install the pgroles CLI tool.
---

## Compatibility

- pgroles requires PostgreSQL **16+**
- CI integration tests run against PostgreSQL **16, 17, and 18**
- PostgreSQL 15 and earlier are not supported

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
docker run --rm ghcr.io/hardbyte/pgroles:0.1.0 --help
```

## Verify installation

```shell
pgroles --version
pgroles --help
```
