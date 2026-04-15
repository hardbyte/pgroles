# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-04-15

### Added

- **PostgresPolicyPlan CRD** — reconciliation plans are now separate Kubernetes resources with their own lifecycle. Plans can be reviewed, approved, rejected, or auto-approved before execution. Includes manual approval via annotations, plan superseding on policy changes, and operator-restart safety. (#74)
- **Operator password management** — the operator can generate random passwords and store them in Kubernetes Secrets with ownerReferences, or sync passwords from existing Secrets. Passwords are sent to PostgreSQL as SCRAM-SHA-256 verifiers (cleartext never crosses the wire). Includes secret rotation detection via resourceVersion tracking. (#65)
- **Structured connection parameters** — `connection.params` supports individual fields for host, port, dbname, username, password, and sslMode. Each field accepts a literal value or a `*Secret` SecretKeySelector reference. Integrates natively with Zalando postgres-operator, CloudNativePG, and CrunchyData PGO without requiring an ExternalSecret intermediary. (#87)
- **Pre-flight schema validation** — the operator validates that every schema referenced by the policy exists in the target database before issuing DDL, surfacing a clear `MissingDatabaseObject` status condition instead of failing mid-transaction. (#80)
- **Plan visibility improvements** — plans include SQL preview annotations, change summary annotations, SQL statement count (post-wildcard expansion), and printer columns for the SQL ConfigMap name and hash (`kubectl get pgplan -o wide`).
- **Printer columns for PostgresPolicy** — `kubectl get pgr` now shows Ready, Mode, Drift, Changes, and Last Reconcile columns.
- **CLI accepts Kubernetes CR manifests** — `pgroles diff/apply/validate` can read `PostgresPolicy` YAML directly (extracts the `spec` from the CR wrapper). (#71)
- **Manifest optional for inspect** — `pgroles inspect` can connect to a database without a manifest file to show the current role state. (#69)
- **Staged adoption guide** — new documentation page covering brownfield adoption patterns and PUBLIC privilege caveats. (#70)

### Fixed

- **Wildcard grant convergence on empty schemas** — wildcard grants on sequences, functions, and other types now converge correctly when no objects of that type exist. Previously re-issued on every reconcile, causing unbounded plan creation. (#84)
- **Missing-object SQL errors classified as non-transient** — SQLSTATE codes 3F000, 42P01, 42883, 42704 are now classified as `Slow` retry with `MissingDatabaseObject` reason instead of exponential transient backoff. (#79)
- **Plan resource deduplication** — recently-failed plans with the same SQL hash are deduplicated within a 120-second window, preventing accumulation during fast retries. (#81)
- **MemberSpec defaults removed from CRD** — `inherit` and `admin` fields are now `Option<bool>` with defaults applied at resolution time, avoiding perpetual ArgoCD diffs when using ServerSideApply. (#83)
- **TLS support for PostgreSQL connections** — the operator and CLI now support TLS connections to PostgreSQL, required for Cloud SQL and other managed services. (#67)

### Changed

- **E2E tests split into 3 parallel suites** — operator scenarios, load tests, and plan lifecycle run concurrently in separate kind clusters, reducing CI wall clock from ~20 min to ~10 min. Shared setup extracted into a composite action. (#85)
- **SCRAM-SHA-256 verifiers** — passwords are always hashed client-side before being sent to PostgreSQL. The verifier is stored alongside the cleartext in generated Secrets. Verified against RFC 7677 known vectors.
- **GitHub Actions updated to Node 24 runtimes.** (#66)

## [0.4.1] - 2026-04-08

### Fixed

- Enable TLS for PostgreSQL connections. (#67)

## [0.4.0] - 2026-04-08

### Added

- Printer columns for `PostgresPolicy` CRD (Ready, Mode, Drift, Changes, Last Reconcile, Age). (#68)

## [0.3.0] - 2026-03-26

### Added

- `pgroles graph` command for role visualization in tree, JSON, dot, and mermaid formats. (#60)

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
