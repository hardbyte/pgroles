# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-05-06

### Added

- **`pgroles generate --suggest-profiles`** — deterministically refactor flat brownfield manifests into reusable profiles, with live database inventory checks before wildcard collapse so generated profiles do not broaden privileges. (#96)
- **`pgroles_core::suggest` public API** and `pgroles_inspect::fetch_object_inventory` for callers building their own brownfield profile-suggestion pipelines. (#96)

### Fixed

- **Large operator plan SQL previews no longer exceed Kubernetes ConfigMap limits.** Small redacted SQL previews remain inline, large previews are stored as gzip-compressed ConfigMap `binaryData`, and exceptionally large incompressible previews fall back to a truncated inline preview while apply continues to render executable SQL from the in-memory change set. (#98)
- **Status-less `PostgresPolicyPlan` resources and orphaned plan SQL ConfigMaps are cleaned up defensively.** The operator persists SQL artifacts before making plans visible, cleans stale status-less plans and orphaned SQL ConfigMaps before and after reconcile, and also collects stale policy-labeled SQL ConfigMaps left behind by older versions. (#99)
- **Plan storage correctness is modeled in TLA+.** The model covers persistence failure, the invariant that plans are not visible before their SQL artifact is ready, at-most-one actionable plan safety, and eventual cleanup of stale status-less plans and orphan SQL artifacts. (#98, #99)

### Changed

- **BREAKING: `PolicyManifest.profiles` is now `BTreeMap<String, Profile>`** (was `HashMap<String, Profile>`). YAML serialization is now deterministic — two `pgroles generate` runs against the same database produce byte-identical output. Library consumers that construct `PolicyManifest` directly will need to update their map type. The CLI and operator are unaffected. (#96)

## [0.7.0-beta.2] - 2026-05-06

### Fixed

- **Large operator plan SQL previews no longer exceed Kubernetes ConfigMap limits.** Small redacted SQL previews remain inline, large previews are stored as gzip-compressed ConfigMap `binaryData`, and exceptionally large incompressible previews fall back to a truncated inline preview while apply continues to render executable SQL from the in-memory change set. (#98)
- **Status-less `PostgresPolicyPlan` resources and orphaned plan SQL ConfigMaps are cleaned up defensively.** The operator persists SQL artifacts before making plans visible, cleans stale status-less plans and orphaned SQL ConfigMaps before and after reconcile, and also collects stale policy-labeled SQL ConfigMaps left behind by older versions. (#99)
- **Plan storage correctness is modeled in TLA+.** The new model covers persistence failure, the invariant that plans are not visible before their SQL artifact is ready, at-most-one actionable plan safety, and eventual cleanup of stale status-less plans and orphan SQL artifacts. (#98, #99)

## [0.7.0-beta.1] - 2026-05-05

### Added

- **`pgroles generate --suggest-profiles`** — deterministically refactor a flat brownfield manifest into reusable profiles. The suggester clusters roles whose grants share an identical *schema-relative signature* across multiple schemas, picks a uniform role-name pattern (`{schema}-{profile}` / `{schema}_{profile}` / `{profile}-{schema}` / `{profile}_{schema}`) so role names are preserved verbatim, and verifies round-trip equivalence against the flat manifest before committing. Re-runs on databases where a suggested manifest has already been applied are idempotent (auto-generated profile-role comments are recognised and ignored). (#96)
- **Live-DB inventory required for safe wildcard collapse** — the suggester only collapses per-name grants into wildcards (`name: "*"`) when given a complete object inventory from `pgroles_inspect::fetch_object_inventory`. The CLI fetches this automatically. A grant-only view would treat ungranted objects as nonexistent and could broaden privileges; the suggester now refuses to collapse if the provided inventory is missing any object that already appears in input grants. (#96)
- **`pgroles_core::suggest` module** — new public API: `suggest_profiles`, `SuggestOptions`, `SuggestReport`, `SuggestedProfile`, `SkipReason` (with variants `MultiSchema`, `SchemaNotDeclared`, `OwnerMismatch`, `UniqueAttributes`, `UnrepresentableGrant`, `SoleSchema`, `NoUniformPattern`, `SchemaPatternConflict`, `RoundTripFailure`, `IncompleteFullInventory`), `Inventory`, `inventory_from_manifest_grants`, `expand_wildcard_grants`. (#96)
- **`pgroles_inspect::fetch_object_inventory`** re-exported at the crate root for callers building their own suggester pipelines. (#96)

### Changed

- **BREAKING: `PolicyManifest.profiles` is now `BTreeMap<String, Profile>`** (was `HashMap<String, Profile>`). YAML serialization is now deterministic — two `pgroles generate` runs against the same database produce byte-identical output. Library consumers that construct `PolicyManifest` directly will need to update their map type. The CLI and operator are unaffected. (#96)

## [0.6.0] - 2026-04-30

### Added

- **Schema management** — declared schemas (`schemas[].owner`) are now first-class state. pgroles creates missing schemas, converges `OWNER TO`, and filters implicit owner ACLs from inspection/export so plan and apply round-trip cleanly. Plan/apply summaries report schema creations and owner alterations. Generated SQL includes `CREATE SCHEMA` and `ALTER SCHEMA … OWNER TO`. (#90)
- **Profile-level `inherit`** — profiles can set `inherit` on generated roles (already existed for `login`); threaded through to the operator CRD as well. (#95)

### Fixed

- **Additive mode no longer rewrites brownfield role attributes or comments.** Previously a pre-existing role like `accounts_editor LOGIN NOINHERIT` could trigger `ALTER ROLE … NOLOGIN INHERIT` under additive mode, which contradicts incremental adoption semantics. Additive mode now leaves attributes and comments unchanged on pre-existing roles. (#95)
- **CLI execution sticks to a single backend.** When a hostname resolves to multiple PostgreSQL servers, one-shot commands could inspect one backend and execute mutations against another. Connection identity is now pinned for the lifetime of a CLI invocation, and SQL execution failures include the backend identity. (#95)

### Changed

- **Documentation** — README and docs updated with schema-management semantics, examples, operator guidance, additive-brownfield behavior, and generated-role attributes. (#90, #95)
- **Dependency bumps** — `next` 16.2.0 → 16.2.3 in `/docs` (#75); `rand` 0.9.2 → 0.9.3 (#82).

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
