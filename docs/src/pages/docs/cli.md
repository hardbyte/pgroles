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
| `--exit-code` | Exit with code 2 when drift is detected (default: `true`) |

The `sql` format prints the full SQL script. The `summary` format shows counts of each change type. The `json` format outputs the change list as a JSON array, suitable for CI/CD pipelines and programmatic consumption.

### CI drift detection

By default, `diff` exits with code **2** when changes are detected and **0** when the database is in sync. This makes it easy to use as a CI gate:

```shell
pgroles diff --database-url postgres://localhost/mydb || echo "Drift detected!"
```

Disable this with `--no-exit-code` if you only want the output without a non-zero exit.

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
| `--dry-run` | Print the SQL without executing it |

`apply` executes the plan inside a single database transaction. Individual changes may still render to multiple SQL statements internally, but the whole apply either commits or rolls back together.

Before executing changes, `apply` detects the connecting role's privilege level — true superuser, cloud provider superuser (e.g., `rds_superuser`, `cloudsqlsuperuser`, `azure_pg_admin`), or regular user — and warns about any planned changes that exceed the detected privileges (e.g., setting `SUPERUSER` or `BYPASSRLS` via a cloud admin role).

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
