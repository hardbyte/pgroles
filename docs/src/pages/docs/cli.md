---
title: CLI commands
description: Reference for all pgroles CLI commands and options.
---

The `pgroles` CLI provides five commands for managing PostgreSQL role policies. {% .lead %}

---

## Global options

All commands accept `-f` / `--file` to specify the manifest path. If omitted, it defaults to `pgroles.yaml` in the current directory.

Commands that connect to a database accept `--database-url` or read from the `DATABASE_URL` environment variable.

## validate

Parse and validate a manifest file without connecting to a database.

```shell
pgroles validate
pgroles validate -f path/to/policy.yaml
```

Reports the number of roles, grants, default privileges, and memberships after profile expansion.

## diff / plan

Show the SQL changes needed to converge the database to the manifest. `plan` is an alias for `diff`.

```shell
pgroles diff --database-url postgres://localhost/mydb
pgroles plan --database-url postgres://localhost/mydb
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path (default: `pgroles.yaml`) |
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `--format` | Output format: `sql` (default), `summary`, or `json` |
| `--mode` | Reconciliation mode: `authoritative` (default), `additive`, or `adopt` |
| `--exit-code` | Exit with code 2 when drift is detected (default: `true`) |

The `sql` format prints the full SQL script. The `summary` format shows counts of each change type. The `json` format outputs the change list as a JSON array, suitable for CI/CD pipelines and programmatic consumption.

### CI drift detection

By default, `diff` exits with code **2** when changes are detected and **0** when the database is in sync. Command failures still use a normal error exit code. This makes it suitable for CI gates and SRE runbooks:

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

Apply changes to bring the database in sync with the manifest.

```shell
pgroles apply --database-url postgres://localhost/mydb
pgroles apply --database-url postgres://localhost/mydb --dry-run
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path (default: `pgroles.yaml`) |
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

Show the current database state for roles and privileges managed by the manifest.

```shell
pgroles inspect --database-url postgres://localhost/mydb
```

This connects to the database, inspects the current roles/grants/memberships that are relevant to the manifest, and prints a summary.

## generate

Generate a YAML manifest from the current database state. This is the primary tool for brownfield adoption — it introspects all non-system roles, their grants, default privileges, and memberships, then emits a flat manifest (no profiles) that faithfully reproduces the current state.

```shell
pgroles generate --database-url postgres://localhost/mydb
pgroles generate --database-url postgres://localhost/mydb > policy.yaml
```

The generated manifest uses no profiles — all roles, grants, default privileges, and memberships are emitted as top-level entries. When applied back to the same database, it should produce zero diff.

{% callout type="note" title="Starting point for refinement" %}
The generated manifest is a flat snapshot of the current state. After generating it, you can reorganize roles into profiles and schemas to take advantage of pgroles' template system.
{% /callout %}

{% callout type="warning" title="Treat generated manifests as authoritative input" %}
`generate` is best used as a starting point for brownfield adoption. Before applying the generated manifest in production, review it like any other infrastructure policy because once committed it becomes the desired state.
{% /callout %}

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

Additive mode filters out: `REVOKE`, `REVOKE DEFAULT PRIVILEGE`, `REMOVE MEMBER`, `DROP ROLE`, `DROP OWNED`, `REASSIGN OWNED`, and `TERMINATE SESSIONS`.

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
2. Alter role attributes
3. Grant privileges
4. Set default privileges
5. Remove memberships
6. Add memberships
7. Revoke default privileges
8. Revoke privileges
9. Terminate sessions for retired roles
10. Reassign owned objects for retired roles
11. Drop owned objects / revoke remaining privileges for retired roles
12. Drop roles

This ensures roles exist before they're granted privileges, membership flag changes can be re-applied safely, and retired roles can be drained and cleaned up before the final drop.
