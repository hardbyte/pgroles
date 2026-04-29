---
title: CLI commands
description: Reference for all pgroles CLI commands and options.
---

The `pgroles` CLI provides six commands for managing PostgreSQL role policies. {% .lead %}

---

## Global options

Commands that operate on desired state accept either:

- `-f` / `--file` for a single manifest file
- `--bundle` for a composed bundle root file

If omitted, manifest-based commands default to `pgroles.yaml` in the current directory.

Commands that connect to a database accept `--database-url` or read from the `DATABASE_URL` environment variable.

## validate

Parse and validate a manifest file or composed bundle without connecting to a database.

```shell
pgroles validate
pgroles validate -f path/to/policy.yaml
pgroles validate --bundle path/to/pgroles.bundle.yaml
```

Reports the number of roles, grants, default privileges, and memberships after profile expansion.

## diff / plan

Show the SQL changes needed to converge the database to the manifest or bundle. `plan` is an alias for `diff`.

```shell
pgroles diff --database-url postgres://localhost/mydb
pgroles plan --database-url postgres://localhost/mydb
pgroles diff --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path (default: `pgroles.yaml`) |
| `--bundle` | Bundle root file path |
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `--format` | Output format: `sql` (default), `summary`, or `json` |
| `--mode` | Reconciliation mode: `authoritative` (default), `additive`, or `adopt` |
| `--exit-code` | Exit with code 2 when drift is detected (default: `true`) |

The `sql` format prints the full SQL script. The `summary` format shows counts of each change type.

For single-manifest mode, the `json` format outputs the change list as a JSON array. For bundle mode, the `json` format returns a typed object with:

- `schema_version`
- `managed_scope`
- per-change ownership annotations (`document` plus managed key details)

### CI drift detection

By default, `diff` exits with code **2** when structural changes are detected and **0** when the database is in sync. Password-only changes are excluded from drift detection because PostgreSQL does not expose password hashes for comparison — they always appear in the plan but will not trigger a non-zero exit. Command failures still use a normal error exit code. This makes it suitable for CI gates and SRE runbooks:

```shell
if pgroles diff --database-url postgres://localhost/mydb; then
  echo "database is in sync"
else
  case $? in
    2) echo "drift detected" ;;
    *) echo "pgroles failed" >&2; exit 1 ;;
  esac
fi
```

Disable this with `--no-exit-code` if you only want the output without a non-zero exit on drift.

If the plan includes role drops, `diff` also runs a live safety check and splits the result into:

- cleanup warnings that the planned retirement steps are expected to handle
- residual blockers that still prevent a safe apply

For intentional removals, declare a `retirements` block in the manifest so pgroles can inspect the soon-to-be-dropped role even though it is absent from the desired role list:

```yaml
roles:
  - name: app_owner

retirements:
  - role: legacy_app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
```

That causes the generated plan to insert session termination, `REASSIGN OWNED BY`, `DROP OWNED BY`, and then `DROP ROLE`.

`REASSIGN OWNED` and `DROP OWNED` only clean the current database plus shared objects. If the safety report mentions other databases, repeat the cleanup there before expecting the final drop to succeed.

## apply

Apply changes to bring the database in sync with the manifest or bundle.

```shell
pgroles apply --database-url postgres://localhost/mydb
pgroles apply --database-url postgres://localhost/mydb --dry-run
pgroles apply --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path (default: `pgroles.yaml`) |
| `--bundle` | Bundle root file path |
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `--mode` | Reconciliation mode: `authoritative` (default), `additive`, or `adopt` |
| `--dry-run` | Print the SQL without executing it |

`apply` executes the plan inside a single database transaction. Individual changes may still render to multiple SQL statements internally, but the whole apply either commits or rolls back together.

Before executing changes, `apply` detects the connecting role's privilege level — true superuser, cloud provider superuser (for the explicitly supported providers), or regular user — and warns about any planned changes that exceed the detected privileges (for example setting `SUPERUSER` or `BYPASSRLS` through a managed-service admin role).

Provider-aware warning logic currently recognizes `rds_superuser`, `cloudsqlsuperuser`, `alloydbsuperuser`, and `azure_pg_admin`. Other PostgreSQL-compatible managed services, including Supabase and PlanetScale PostgreSQL, may still work, but privilege warnings will be generic rather than provider-specific.

### Insufficient privileges

There are two common cases:

1. pgroles can predict the limitation up front
2. PostgreSQL rejects a statement during inspect or apply

For explicitly recognized managed-service admin roles, pgroles warns before apply when the plan requests unsupported attributes such as `SUPERUSER`, `REPLICATION`, or `BYPASSRLS`.

If PostgreSQL still rejects a query or DDL statement, `apply` fails, the transaction is rolled back, and pgroles exits non-zero. No partial changes from that run are committed.

Typical outcomes:

- `diff` may still succeed if the connecting role can inspect the required catalog state
- `diff` fails non-zero if the connecting role cannot inspect the database state needed for planning
- `apply` fails non-zero if the connecting role cannot execute one of the planned statements

Example of an apply-time failure:

```text
Warning: Cannot create role "app_admin" with SUPERUSER — cloud superuser lacks this privilege
Error: failed to execute: CREATE ROLE "app_admin" LOGIN SUPERUSER ...
Caused by:
    error returned from database: permission denied to create role
```

{% callout type="note" title="Transactional apply" %}
If any statement fails during `apply`, the transaction is rolled back and earlier changes from that run are not committed.
{% /callout %}

{% callout type="warning" title="Residual blockers stop apply" %}
If pgroles still sees unhandled role-drop hazards after accounting for the declared retirement steps, `apply` refuses the change by default instead of attempting a `DROP ROLE`.
{% /callout %}

## inspect

Show the current database state for roles and privileges.

```shell
pgroles inspect --database-url postgres://localhost/mydb
pgroles inspect -f pgroles.yaml --database-url postgres://localhost/mydb
pgroles inspect --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb
```

Without `-f` or `--bundle`, `inspect` shows all non-system roles and visible privileges. With `-f`, it scopes inspection to the manifest's managed roles and referenced schemas. With `--bundle`, it scopes inspection to the composed managed ownership boundary and prints a managed-scope summary before the role graph summary.

## generate

Generate a YAML manifest from the current database state. This is the primary tool for brownfield adoption — it introspects all non-system roles, their grants, default privileges, and memberships, then emits a flat manifest (no profiles) that faithfully reproduces the current state.

```shell
pgroles generate --database-url postgres://localhost/mydb
pgroles generate --database-url postgres://localhost/mydb > policy.yaml
pgroles generate --database-url postgres://localhost/mydb --output policy.yaml
```

The generated manifest uses no profiles — all roles, grants, default privileges, and memberships are emitted as top-level entries. When applied back to the same database, it should produce zero diff.

### Options

| Flag | Description |
|---|---|
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `-o`, `--output` | Write the generated manifest to a file instead of stdout |

{% callout type="note" title="Starting point for refinement" %}
The generated manifest is a flat snapshot of the current state. After generating it, you can reorganize roles into profiles and schemas to take advantage of pgroles' template system.
{% /callout %}

{% callout type="warning" title="Treat generated manifests as authoritative input" %}
`generate` is best used as a starting point for brownfield adoption. Before applying the generated manifest in production, review it like any other infrastructure policy because once committed it becomes the desired state.
{% /callout %}

## graph

Render the role graph as a terminal tree or machine-readable graph.

```shell
pgroles graph desired -f pgroles.yaml --format tree
pgroles graph desired --bundle path/to/pgroles.bundle.yaml --format json
pgroles graph current --database-url postgres://localhost/mydb --scope all --format tree
pgroles graph current --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb --scope managed --format json
```

### desired

Build the graph from a manifest or bundle.

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path |
| `--bundle` | Bundle root file path |
| `--format` | `tree` (default), `json`, `dot`, or `mermaid` |
| `-o`, `--output` | Write the rendered graph to a file |

### current

Build the graph from a live database.

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path |
| `--bundle` | Bundle root file path |
| `--database-url` | PostgreSQL connection string |
| `--scope` | `managed` (default) or `all` |
| `--format` | `tree` (default), `json`, `dot`, or `mermaid` |
| `-o`, `--output` | Write the rendered graph to a file |

`graph current --scope managed` requires either `-f` or `--bundle` so pgroles knows which roles or bundle scope are considered managed.

Bundle-aware graph JSON includes:

- top-level `schema_version`
- the normal graph payload
- `meta.managed_scope` describing bundle-managed roles and schema facets

## Reconciliation modes

The `--mode` flag controls how aggressively pgroles converges the database. Both `diff` and `apply` accept this flag.

### authoritative (default)

Full convergence. Anything not in the manifest is revoked or dropped. This is the standard GitOps model — the manifest is the single source of truth.

```shell
pgroles apply --database-url postgres://localhost/mydb --mode authoritative
```

### additive

Only grant, never revoke. New roles, grants, memberships, and default privileges are created, but nothing is removed. This is the safest mode for incremental adoption — start managing roles without risking disruption to existing access.

```shell
pgroles apply --database-url postgres://localhost/mydb --mode additive
```

Additive mode filters out: `ALTER ROLE`, `COMMENT ON ROLE`, `REVOKE`, `REVOKE DEFAULT PRIVILEGE`, `REMOVE MEMBER`, `ALTER SCHEMA ... OWNER TO ...`, `DROP ROLE`, `DROP OWNED`, `REASSIGN OWNED`, and `TERMINATE SESSIONS`.

If additive mode skips a schema ownership transfer, pgroles also defers owner-bound follow-up steps such as schema-owner privilege repair and `ALTER DEFAULT PRIVILEGES FOR ROLE ...` for that owner context.

For brownfield roles that already exist, additive mode intentionally leaves role attributes and comments unchanged. That means a pre-existing `LOGIN NOINHERIT` role can stay that way during adoption even if a minimal manifest would otherwise imply `NOLOGIN INHERIT`.

### adopt

Manage declared roles fully (including revoking excess grants within their scope), but never drop undeclared roles. This is the middle ground — you get full convergence for roles in the manifest, but roles outside the manifest are left untouched.

```shell
pgroles apply --database-url postgres://localhost/mydb --mode adopt
```

Adopt mode filters out: `DROP ROLE`, `DROP OWNED`, `REASSIGN OWNED`, and `TERMINATE SESSIONS`. Revokes and membership removals for managed roles still apply.

{% callout type="note" title="Adoption path" %}
A common adoption path is: start with `--mode additive` to verify the manifest produces the right grants, then move to `--mode adopt` to start revoking excess grants within managed roles, and finally switch to `--mode authoritative` when you're confident the manifest is complete.
{% /callout %}

## Change ordering

pgroles applies changes in dependency order:

1. Create roles
2. Set passwords (immediately after each role creation, or appended for existing roles)
3. Alter role attributes
4. Grant privileges
5. Set default privileges
6. Remove memberships
7. Add memberships
8. Revoke default privileges
9. Revoke privileges
10. Terminate sessions for retired roles
11. Reassign owned objects for retired roles
12. Drop owned objects / revoke remaining privileges for retired roles
13. Drop roles

This ensures roles exist before they're granted privileges, membership flag changes can be re-applied safely, and retired roles can be drained and cleaned up before the final drop.
