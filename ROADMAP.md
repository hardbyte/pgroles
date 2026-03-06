# pgroles Roadmap

## Goals

- Make the current CLI/operator behavior safe and actually convergent.
- Tighten the declarative contract so the manifest expresses intent, not just SQL-shaped inputs.
- Harden the operator only after the core reconciliation model is reliable.

## Prior Art Comparison

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
| PG version adaptation | No | Broken | **Yes** (PG 14+ via SqlContext) |
| K8s operator | No | No | **Yes** (alpha CRD) |
| Transactional apply | No | No | **Yes** |
| Safety preflight checks | No | No | **Yes** (owned objects, sessions) |
| Idempotent diff | Broken (spurious changes) | Broken (dirty state) | **Yes** (BTreeMap determinism) |
| Cloud-managed PG detection | No | No | **Yes** (RDS, Cloud SQL, Azure) |

## Recently Completed

The following features have been implemented:

- **`generate` command** — Introspects all non-system roles and emits a flat manifest for brownfield adoption. Round-trip invariant: generated manifest applied back produces zero diff.
- **`--format json`** — Machine-readable JSON output for `diff`/`plan`, suitable for CI/CD pipelines.
- **Drift exit code** — `diff` exits with code 2 when changes are detected (`--exit-code`, default on).
- **PG version detection** — `SqlContext` adapts SQL generation based on server version. PG 16+ uses `WITH INHERIT`/`WITH ADMIN`; PG 14–15 falls back to legacy `WITH ADMIN OPTION`.
- **Cloud provider detection** — Detects `rds_superuser`, `cloudsqlsuperuser`, `azure_pg_admin` memberships and validates planned changes against privilege level.
- **Cloud auth provider schema** — `auth_providers` manifest field for declaring Cloud SQL IAM, RDS IAM, and Azure AD providers (informational metadata).

## Phase 1: Safety and Semantic Validation

- Extend the current live destructive-operation preflight:
  - ownership, privilege-dependency, and active-session checks are implemented now
  - current reports also distinguish current-db/shared cleanup from other-database cleanup
  - next add broader unmanaged dependency detection before destructive changes
  - next surface likely blockers more precisely as warnings vs hard blockers in dry-run output
- Harden the new role-retirement path:
  - explicit `retirements` with `REASSIGN OWNED` / `DROP OWNED` are implemented now
  - next decide whether session termination should ever be an explicit opt-in workflow
  - next document the current single-database boundary for retirement cleanup more clearly
- Expand manifest semantic validation:
  - top-level default privileges must declare `grant.role`
  - object target combinations should be checked for required/forbidden fields
  - unsupported default privilege object types should be rejected
  - privilege/object combinations should be validated early
  - validate that declared default privilege owners have CREATE privileges on the schema
- Keep transactional apply as the default execution model.
- Keep membership flag changes covered by regression tests; the current remove-then-add behavior is acceptable because apply is transactional.
- Broaden function grant coverage, especially for overloaded signatures and inspect/render parity.

## Phase 2: Test Coverage

- Add live PostgreSQL tests for:
  - wildcard table/sequence/function grants
  - function grants with arguments
  - membership option changes
  - default privilege validation and reconciliation
  - destructive preflight checks for owned objects and unsafe drops
- Add operator tests for:
  - Secret rotation
  - degraded status on failure
  - reconcile recovery after failure
  - safe failure reporting for blocked destructive changes

## Phase 3: Declarative Boundary & Reconciliation Modes

- Introduce an explicit managed scope:
  - managed roles
  - managed schemas
  - managed ownership transitions
  - whether revokes/drops are authoritative inside that scope
- Add reconcile modes:
  - `authoritative` (current behavior, default): full convergence
  - `additive`: only create/grant, never revoke/drop — filter out `Revoke`, `RevokeDefaultPrivilege`, `RemoveMember`, `DropRole` from the diff output
  - `adopt`: like authoritative, but only manage roles that already exist in the DB or are declared in the manifest
- Implementation: `ReconcileMode` enum and a post-filter on `diff()` output. The diff engine stays pure; filtering happens in the CLI/operator layer.
- Treat selectors like "all tables in schema X" as first-class intent, not a string convention.
- Make owner context for default privileges explicit instead of relying on fallbacks.

## Phase 4: Scope and UX

- Keep the current contract explicit: one manifest reconciles one database connection.
- Decide whether multi-database manifests are a non-goal or a later orchestration feature.
- If multi-database support is added, model it above the current single-database diff engine rather than overloading one manifest with ambiguous scope.
- Make `inspect` emit a detailed normalized graph, not just counts.

## Phase 5: Row-Level Security

Unique differentiator vs all prior art — no other tool manages RLS policies declaratively.

- **RLS data model**: `rls_policies` manifest section with table, schema, policy name, command, permissive/restrictive, roles, USING/WITH CHECK expressions. Extends `RoleGraph` with `rls_policies: BTreeMap<RlsPolicyKey, RlsPolicyState>` and `rls_enabled_tables`.
- **RLS diff engine**: New `Change` variants — `EnableRls`, `DisableRls`, `CreatePolicy`, `AlterPolicy`, `DropPolicy`. Ordering: `EnableRls` before `CreatePolicy`, `DropPolicy` before `DisableRls`.
- **RLS introspection**: Query `pg_tables` (rowsecurity) and `pg_policies` for current state.
- **RLS SQL generation**: `CREATE POLICY`, `ALTER POLICY`, `DROP POLICY`, `ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY`.

## Phase 6: Operator Hardening

- Cache pools by Secret resource version and watch for Secret updates.
- Surface `Ready`, `Reconciling`, and `Degraded` conditions consistently.
- Add rate-limited retries and clearer failure summaries.
- Add policy around deletion behavior instead of relying on implicit defaults.

## Future: Cloud Auth & Integrations

- **Cloud auth provider runtime**: Auto-detect IAM-mapped role names, validate role naming conventions, set `rds_iam` attribute on RDS IAM roles. (Manifest schema is already in place.)
- **Vault integration**: Generate Vault-compatible creation statement templates from the manifest (export format, not runtime integration).
- **LDAP/SCIM adapter**: Enterprise feature, out of scope for v0.x.

## Architecture Principles

The current architecture is clean and should be preserved:

```
YAML → PolicyManifest → ExpandedManifest → RoleGraph (desired)
                                                ↓ diff()
DB   → pg_catalog queries → RoleGraph (current) → Vec<Change> → SQL
```

All new features should plug into this pipeline without restructuring it:
- **RLS** extends `RoleGraph`, `Change`, introspection, and SQL generation
- **Reconciliation modes** are a post-filter on `Vec<Change>`
- **Version detection** is a context parameter to SQL generation
- **Export** is `RoleGraph → PolicyManifest` (the reverse of `from_expanded`)

The 4-crate split is correct:
- `pgroles-core`: Pure, no IO, testable without a database
- `pgroles-inspect`: Database-dependent, async
- `pgroles-cli`: Binary, thin orchestration layer
- `pgroles-operator`: Kubernetes-specific

### Non-goals

- GUI / web dashboard — pgroles is a CLI/operator tool
- Schema DDL management — pgroles manages authorization, not schema
- Multi-database orchestration in a single manifest — one manifest = one database connection
- Password management — Vault handles this better
- LDAP/SCIM sync — enterprise feature, out of scope for v0.x

## Declarative Direction

Today, pgroles is declarative at the manifest surface but still partly operational internally. The next step is to make the core model intent-based:

- desired selectors and edges in
- normalized current state over the same managed boundary
- diff between those two graphs
- SQL only as an execution backend

That makes the tool more predictable for both the CLI and the operator.
