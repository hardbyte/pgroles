# pgpolicy

Declarative PostgreSQL role graph manager. Define roles, memberships, object privileges, and default privileges in YAML — pgpolicy diffs against live databases and applies changes.

Requires **PostgreSQL 16+** (uses `GRANT ... WITH INHERIT` syntax).

## Components

- **pgpolicy-core** — Manifest parsing, profile expansion, diff engine, SQL generation. No database dependencies.
- **pgpolicy-inspect** — Live database introspection via `pg_catalog` queries (sqlx + tokio).
- **pgpolicy-cli** — Command-line tool for validating manifests, planning changes, and applying them.
- **pgpolicy-operator** — *(work in progress)* Kubernetes operator that reconciles `PostgresPolicy` custom resources against PostgreSQL databases.

## Quick Start

```bash
# Validate a manifest (no database needed)
pgpolicy validate -f policy.yaml

# Show the SQL needed to converge the database to the manifest
pgpolicy diff -f policy.yaml --database-url postgres://...

# Same thing — "plan" is an alias for "diff"
pgpolicy plan -f policy.yaml --database-url postgres://...

# Preview as a summary instead of raw SQL
pgpolicy diff -f policy.yaml --database-url postgres://... --format summary

# Apply changes
pgpolicy apply -f policy.yaml --database-url postgres://...

# Dry run — print the SQL without executing
pgpolicy apply -f policy.yaml --database-url postgres://... --dry-run

# Inspect current database state for managed roles
pgpolicy inspect -f policy.yaml --database-url postgres://...
```

If `-f` is omitted, it defaults to `pgpolicy.yaml` in the current directory. The `--database-url` flag can also be set via the `DATABASE_URL` environment variable.

## Manifest Format

A manifest defines roles, grants, default privileges, and memberships. Profiles let you define reusable privilege templates that expand across schemas.

```yaml
default_owner: pgloader_pg

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table

  viewer:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT]
        on: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: ibody
    profiles: [editor, viewer]
  - name: catalog
    profiles: [viewer]

roles:
  - name: app-service
    login: true
    comment: "Application service account"

grants:
  - role: app-service
    privileges: [CONNECT]
    on: { type: database, name: mydb }

memberships:
  - role: ibody-editor
    members:
      - name: app-service
```

This expands into roles `ibody-editor`, `ibody-viewer`, `catalog-viewer`, and `app-service`, with grants and default privileges scoped to each schema.

### Profile expansion

Each `schema × profile` combination generates a role named `{schema}-{profile}` by default. Override the naming pattern per-schema with `role_pattern`:

```yaml
schemas:
  - name: legacy_data
    profiles: [viewer]
    role_pattern: "legacy-{profile}"  # produces "legacy-viewer" instead of "legacy_data-viewer"
```

### Role attributes

Roles support: `login`, `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls`, `connection_limit`, and `comment`. Unspecified attributes use PostgreSQL defaults.

### Object types

Supported object types for grants: `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, `type`.

### Convergent model

pgpolicy is convergent: the manifest is the entire truth. Roles, grants, and memberships present in the database but absent from the manifest will be dropped/revoked.

## License

MIT
