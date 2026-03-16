# pgroles Roadmap

## Product direction

pgroles is a declarative PostgreSQL access-control tool with two delivery paths:

- a CLI for explicit, reviewed change workflows
- a Kubernetes operator for continuous reconciliation

The core diff/apply model, safety checks, and operator reconciliation safety (serialized locking, conflict detection, failure-aware retry, transactional apply) are stable on `main`. The roadmap is now about API stability, scale validation, test coverage gaps (especially password management), and broadening compatibility — the work that separates "safe controller" from "production-grade platform".

## Current state

pgroles already provides:

- convergent `diff` / `apply` workflow with transactional execution
- profile-based manifest expansion across schemas
- default privileges with explicit owner context
- brownfield `generate` for existing databases
- managed-provider detection for RDS, Aurora, Cloud SQL, AlloyDB, and Azure Database for PostgreSQL
- password management for login roles with redacted output and `VALID UNTIL`
- safety preflight for destructive role retirement workflows
- PostgreSQL-version-aware SQL generation (PG 14+)
- a production-focused Kubernetes operator with:
  - plan mode
  - per-database serialization
  - advisory locking
  - failure-aware retry behavior
  - OTLP metrics, health probes, and Kubernetes Events
  - CI coverage for conflict detection, secret rotation, insufficient privileges, and scheduled fairness/load runs

## Prior art comparison

| Capability | pgbedrock | TF cyrilgdn | pgroles |
|---|---|---|---|
| Plan/apply workflow | Partial (check/live) | Yes (via TF) | **Yes** (diff/apply) |
| Fine-grained privileges | No (read/write binary) | Yes | **Yes** (all PG privs) |
| Default privileges | Broken | Broken | **Correct** (per-owner, per-schema) |
| Role inheritance graph | Partial | No graph model | **Yes** (BTreeMap/BTreeSet) |
| Convergent model | Yes | Yes (per resource) | **Yes** (whole-graph) |
| Profile/template system | No | No | **Yes** (profiles × schemas) |
| Role retirement lifecycle | No | No | **Yes** (reassign/drop/terminate) |
| Brownfield `generate` | Yes | N/A | **Yes** |
| PG version adaptation | No | Broken | **Yes** (PG 14+ via `SqlContext`) |
| K8s operator | No | No | **Yes** (`v1alpha1` CRD) |
| Transactional apply | No | No | **Yes** |
| Safety preflight checks | No | No | **Yes** (owned objects, sessions, blockers) |
| Idempotent diff | Broken (spurious changes) | Broken (dirty state) | **Yes** (deterministic graph + live inventory) |
| Cloud-managed PG detection | No | No | **Yes** (RDS, Cloud SQL, AlloyDB, Azure) |
| Password management | No | Partial | **Yes** (CLI env + operator Secret sources) |

## Recently completed

The following landed recently and shape the next release line:

- **Operator plan mode** — `spec.mode: plan` computes drift and publishes planned SQL without mutating PostgreSQL.
- **Reconciliation modes** — `authoritative`, `additive`, and `adopt` are now available in the CLI and operator.
- **Password support** — login roles can declare a password source and optional `password_valid_until` timestamp.
- **`generate --output`** — brownfield export can write manifests directly to a file.
- **Subtype-safe wildcard relation grants** — wildcard `table`, `view`, and `materialized_view` privileges no longer bleed across relation subtypes.
- **Docs and branding refresh** — the docs site, README, and operator guidance now reflect the current product model more accurately.

## Near-term roadmap

### 1. Tighten semantic validation

- Broaden manifest validation for privilege/object combinations before connecting to PostgreSQL.
- Validate default privilege declarations more aggressively, especially owner/schema relationships.
- Keep destructive retirement planning precise about warnings vs hard blockers.
- Broaden function grant coverage, especially overloaded signatures and inspect/render parity.

### 2. Make the declarative boundary more explicit

- Introduce a clearer managed scope model:
  - managed roles
  - managed schemas
  - managed ownership transitions
  - whether revokes/drops are authoritative inside that scope
- Keep the current reconciliation modes aligned across the CLI, operator, and future CRD/API revisions.

### 3. Operator API evolution

- Carry the current controller semantics into the next CRD revision instead of leaving them as implementation-only conventions.
- Promote beyond `v1alpha1` only once compatibility, upgrade, and rollback expectations are explicit.
- Keep status, Events, and OTLP metrics aligned as the CRD evolves.

### 4. Compatibility and validation

- Keep expanding compatibility coverage across supported PostgreSQL versions and managed providers.
- Maintain the scheduled fairness/load workflow as the operator surface changes.
- Add longer-running and higher-scale validation without making normal PR CI heavy or flaky.

### 5. CLI/operator UX

- Improve plan-review ergonomics without weakening the transactional apply model.
- Make `inspect` and generated exports easier to use as normalized graph/debugging surfaces.
- Continue documenting privilege bundles and common application patterns so table/sequence/function access is less error-prone.

## Longer-term differentiators

### Row-level security

Unique differentiator vs most existing tools — declarative management for PostgreSQL RLS policies.

Potential shape:

- `rls_policies` manifest section with table, schema, policy name, command, permissive/restrictive mode, roles, `USING`, and `WITH CHECK`
- new `Change` variants such as `EnableRls`, `CreatePolicy`, `AlterPolicy`, `DropPolicy`
- introspection from `pg_policies` and table row-security flags
- SQL generation for `CREATE POLICY`, `ALTER POLICY`, `DROP POLICY`, and `ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY`

### Cloud auth and integrations

- richer runtime support for IAM-mapped roles where the provider metadata is already modeled
- export-oriented integrations for external secret/password systems rather than trying to subsume them

## Architecture principles

The current architecture should stay intact:

```text
YAML -> PolicyManifest -> ExpandedManifest -> RoleGraph (desired)
                                               ↓ diff()
DB   -> pg_catalog queries -> RoleGraph (current) -> Vec<Change> -> SQL
```

New features should plug into that pipeline without restructuring it:

- RLS extends `RoleGraph`, `Change`, introspection, and SQL generation
- reconciliation modes are a post-filter on `Vec<Change>`
- version detection is a context parameter to SQL generation
- export is `RoleGraph -> PolicyManifest` (the reverse of `from_expanded`)

The 4-crate split remains correct:

- `pgroles-core`: pure, no I/O, testable without a database
- `pgroles-inspect`: database-dependent, async
- `pgroles-cli`: binary, thin orchestration layer
- `pgroles-operator`: Kubernetes-specific

## Non-goals

- GUI / web dashboard — pgroles is a CLI/operator tool
- Schema DDL management — pgroles manages authorization, not schema
- Multi-database orchestration in a single manifest — one manifest = one database connection
- Full password lifecycle management (rotation, distribution, external secret orchestration)
- LDAP/SCIM sync — enterprise feature, out of scope for v0.x
