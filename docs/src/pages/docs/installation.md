---
title: Installation
description: How to install the pgroles CLI tool.
---

## From source

pgroles is written in Rust. Build and install with Cargo:

```shell
cargo install --git https://github.com/hardbyte/pgroles pgroles-cli
```

This compiles the `pgroles` binary and places it in your Cargo bin directory (usually `~/.cargo/bin/`).

## From a local clone

```shell
git clone https://github.com/hardbyte/pgroles.git pgroles
cd pgroles
cargo build --release
```

The binary will be at `target/release/pgroles`.

## Verify installation

```shell
pgroles --version
pgroles --help
```
