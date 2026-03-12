# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-12

### Added

- **Reconciliation modes** (`--mode` flag for CLI, `reconciliation_mode` field for Kubernetes operator):
  - `authoritative` (default): full convergence — anything not in the manifest is revoked or dropped. This is the existing behavior, now explicitly named.
  - `additive`: only grant, never revoke — safe for incremental adoption on existing databases.
  - `adopt`: manage declared roles fully (including revoking excess grants), but never drop undeclared roles.
- `ReconciliationMode` enum and `filter_changes()` post-filter in `pgroles-core` for library consumers.
- **Operator plan mode** via `spec.mode: plan`, including planned SQL in status without mutating PostgreSQL.
- **Password-backed roles** with `password` sources and optional `password_valid_until` support for CLI and operator workflows.
- `pgroles generate --output` for direct brownfield manifest export to a file.
- Live-database integration tests covering all three reconciliation modes.
- Documentation for reconciliation modes in CLI reference, operator guide, and CI/CD guide.

### Changed

- Wildcard relation grants and revokes are now scoped by object subtype, so table wildcards do not accidentally touch views or materialized views.
- The docs site, README, and operator guidance now reflect the current production-focused controller model more accurately.

## [0.1.5] - 2026-03-06

Initial public release.
