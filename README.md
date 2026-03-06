# pgroles

Declarative PostgreSQL role graph manager. Define roles, memberships, object privileges, and default privileges in YAML — pgroles diffs against live databases and applies changes.

Requires **PostgreSQL 16+** (uses `GRANT ... WITH INHERIT` syntax).

## Components

- **pgroles-core** — Manifest parsing, profile expansion, diff engine, SQL generation. No database dependencies.
- **pgroles-inspect** — Live database introspection via `pg_catalog` queries (sqlx + tokio).
- **pgroles-cli** — Command-line tool for validating manifests, planning changes, and applying them.
- **pgroles-operator** — *(work in progress)* Kubernetes operator that reconciles `PostgresPolicy` custom resources against PostgreSQL databases.

## Quick Start

```bash
# Validate a manifest (no database needed)
pgroles validate -f policy.yaml

# Show the SQL needed to converge the database to the manifest
pgroles diff -f policy.yaml --database-url postgres://...

# Same thing — "plan" is an alias for "diff"
pgroles plan -f policy.yaml --database-url postgres://...

# Preview as a summary instead of raw SQL
pgroles diff -f policy.yaml --database-url postgres://... --format summary

# Apply changes
pgroles apply -f policy.yaml --database-url postgres://...

# Dry run — print the SQL without executing
pgroles apply -f policy.yaml --database-url postgres://... --dry-run

# Inspect current database state for managed roles
pgroles inspect -f policy.yaml --database-url postgres://...
```

If `-f` is omitted, it defaults to `pgroles.yaml` in the current directory. The `--database-url` flag can also be set via the `DATABASE_URL` environment variable.

## Manifest Format

A manifest defines roles, grants, default privileges, and memberships. Profiles let you define reusable privilege templates that expand across schemas.

```yaml
default_owner: app_owner

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
  - name: inventory
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
  - role: inventory-editor
    members:
      - name: app-service
```

This expands into roles `inventory-editor`, `inventory-viewer`, `catalog-viewer`, and `app-service`, with grants and default privileges scoped to each schema.

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

pgroles is convergent within the scope it manages today: the manifest is treated as the desired truth for the roles, grants, default privileges, and memberships it inspects. Roles, grants, and memberships present in the database but absent from the manifest will be dropped or revoked.

Dry-run detection for dangerous destructive operations such as dropping roles that still own objects is still on the roadmap.

## License

MIT
