---
title: Installation
description: How to install the pgroles CLI tool.
---

## Compatibility

- **PostgreSQL 16, 17, 18**: Supported and tested in CI, including per-membership `INHERIT` and `ADMIN` options
- **Earlier PostgreSQL releases**: Unsupported

## Released binaries

Download the binary for your platform from the [latest stable release](https://github.com/thepartly/pgroles/releases/latest). Keep the CLI version aligned with the release documentation and any scripts that consume its JSON output.

## From source

pgroles is written in Rust. Build and install with Cargo:

```shell
cargo install --git https://github.com/thepartly/pgroles pgroles-cli
```

This compiles the `pgroles` binary and places it in your Cargo bin directory (usually `~/.cargo/bin/`).

## From crates.io

```shell
cargo install pgroles-cli
```

## From a local clone

```shell
git clone https://github.com/thepartly/pgroles.git pgroles
cd pgroles
cargo build --release
```

The binary will be at `target/release/pgroles`.

## From GitHub Releases

Download pre-built binaries from the [releases page](https://github.com/thepartly/pgroles/releases).

## Docker

```shell
docker run --rm ghcr.io/thepartly/pgroles --help
```

Published container images are multi-arch for `linux/amd64` and `linux/arm64`.
The release workflow builds the Linux binaries first and then assembles the
runtime images from those artifacts, so published images do not recompile Rust
inside the Docker publish jobs.

## Verify installation

```shell
pgroles --version
pgroles --help
```
