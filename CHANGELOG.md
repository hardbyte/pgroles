# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Structured connection parameters** — the operator now supports `connection.params` with individual fields for host, port, dbname, username, password, and sslMode. Each field accepts either a literal value or a `*Secret` reference (SecretKeySelector). This integrates natively with Zalando postgres-operator, CloudNativePG, and CrunchyData PGO without requiring an ExternalSecret intermediary. The existing `secretRef` + `secretKey` (DATABASE_URL) mode is unchanged. (#86)

### Fixed

- **Wildcard grant convergence on empty schemas** — wildcard grants (`name: "*"`) on sequences, functions, and other types now converge correctly when a schema contains no objects of that type. Previously the operator re-issued the grant on every reconcile, causing unbounded plan creation. (#84)
- **Missing-object SQL errors classified as non-transient** — errors like `schema "etl" does not exist` (SQLSTATE 3F000, 42P01, 42883, 42704) are now classified as `Slow` retry with a `MissingDatabaseObject` reason instead of hot-looping with exponential backoff. (#79)
- **Pre-flight schema validation** — the operator validates that every schema referenced by the policy exists in the target database before issuing DDL, surfacing a clear `MissingDatabaseObject` status condition. (#80)
- **Plan resource deduplication** — recently-failed plans with the same SQL hash are deduplicated within a 120-second window to prevent accumulation during fast retries. (#81)
- **MemberSpec defaults removed from CRD** — `inherit` and `admin` fields on membership entries are now `Option<bool>` with defaults applied at resolution time, avoiding perpetual ArgoCD diffs when using ServerSideApply. (#83)

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
