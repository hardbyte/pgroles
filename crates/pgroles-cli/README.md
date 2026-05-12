# pgroles-cli

CLI package for `pgroles`.

Installing this crate provides the `pgroles` binary for declarative PostgreSQL
role management.

## Install

```bash
cargo install pgroles-cli
```

## Commands

- `pgroles validate`
- `pgroles diff`
- `pgroles plan`
- `pgroles apply`
- `pgroles inspect`
- `pgroles generate`

## Operational Notes

- Best with PostgreSQL 16+, with adaptive support for PostgreSQL 14+
- `diff` can be used as a CI drift gate via `--exit-code`
- `generate` is intended for brownfield adoption of existing databases
- Destructive role drops should use explicit `retirements`

## Documentation

- Project README: <https://github.com/hardbyte/pgroles>
- CLI docs: <https://github.com/hardbyte/pgroles/tree/main/docs/src/pages/docs/cli.md>
- Manifest reference: <https://github.com/hardbyte/pgroles/tree/main/docs/src/pages/docs/manifest-reference.md>
