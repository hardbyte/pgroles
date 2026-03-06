# pgroles

Stop managing PostgreSQL roles with ad-hoc SQL. Define them in YAML, diff against live databases, apply the changes.

pgroles treats your manifest as the **entire desired state** — roles, grants, and memberships not in the manifest get revoked or dropped. This is the same convergent model used by Terraform and Kubernetes, applied to PostgreSQL access control.

> **Best with PostgreSQL 16+**. Supports PostgreSQL 14+ with version-adaptive SQL generation.

## Compatibility

- **PostgreSQL 16+**: Full support including `GRANT ... WITH INHERIT`/`WITH ADMIN` syntax
- **PostgreSQL 14–15**: Supported with automatic fallback to legacy grant syntax (`WITH ADMIN OPTION`)
- CI integration tests run against PostgreSQL **16, 17, and 18**
- Provider-aware privilege warnings currently recognize **AWS RDS/Aurora**, **Google Cloud SQL**, **AlloyDB**, and **Azure Database for PostgreSQL**.
- Manifest metadata also supports **Supabase** and **PlanetScale PostgreSQL**, but those variants are currently informational only.

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

# Generate a manifest from an existing database (brownfield adoption)
pgroles generate --database-url postgres://...

# Output the diff as JSON (for CI/CD pipelines)
pgroles diff -f policy.yaml --database-url postgres://... --format json

# Use as a CI drift gate (exits with code 2 when drift is detected)
pgroles diff -f policy.yaml --database-url postgres://... --exit-code
```

If `-f` is omitted, it defaults to `pgroles.yaml` in the current directory. The `--database-url` flag can also be set via the `DATABASE_URL` environment variable.

If you are adopting an existing database rather than starting greenfield, begin with `pgroles generate` and then refine the generated flat manifest into profiles and schema bindings.

Example `pgroles diff` output:

```sql
CREATE ROLE "inventory-editor"
  NOLOGIN NOSUPERUSER INHERIT;
COMMENT ON ROLE "inventory-editor"
  IS 'Generated from profile editor';

GRANT USAGE ON SCHEMA "inventory"
  TO "inventory-editor";
GRANT SELECT, INSERT, UPDATE, DELETE
  ON ALL TABLES IN SCHEMA "inventory"
  TO "inventory-editor";

REVOKE ALL ON SCHEMA "legacy"
  FROM "old-reader";
DROP ROLE "old-reader";
```

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

Before applying planned role drops, pgroles now performs a live preflight check for owned objects, privilege dependencies, policy/init-privilege references, and active sessions. It reports hazards the declared retirement workflow will clean up as warnings, and refuses apply only when residual blockers remain.

Use `retirements` to make planned role removal explicit and to declare how pgroles should clean up ownership before the final `DROP ROLE`:

```yaml
roles:
  - name: app_owner

retirements:
  - role: legacy_app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
```

That expands the inspection scope to include `legacy_app` even though it is no longer in the desired role set, then executes session termination, `REASSIGN OWNED`, `DROP OWNED`, and `DROP ROLE` in that order when those steps are declared.

Cleanup is still scoped to the current database plus shared objects. If the preflight reports dependencies in other databases, run the same cleanup against those databases before the final drop.

## Operational Boundaries

- One manifest converges one PostgreSQL connection target.
- `pgroles` is authoritative within the roles, grants, default privileges, and memberships it inspects for that manifest.
- Retirement cleanup (`REASSIGN OWNED` / `DROP OWNED`) only covers the current database plus shared objects.
- Managed PostgreSQL is supported at the PostgreSQL protocol/DDL level, but provider-specific warning logic is only explicit for RDS/Aurora, Cloud SQL, AlloyDB, and Azure today. Other services, including Supabase and PlanetScale PostgreSQL, are not yet special-cased.

## CI/CD

`pgroles diff` is designed to work as a drift gate:

- Exit code `0`: database is in sync
- Exit code `2`: drift detected
- Any other non-zero exit: command or connectivity failure

```bash
if pgroles diff -f policy.yaml --database-url "$DATABASE_URL"; then
  echo "database is in sync"
else
  case $? in
    2) echo "drift detected" ;;
    *) echo "pgroles failed" >&2; exit 1 ;;
  esac
fi
```

## Installation

### From source

```bash
cargo install --git https://github.com/hardbyte/pgroles pgroles-cli
```

### From crates.io

```bash
cargo install pgroles-cli
```

### From GitHub Releases

Download pre-built binaries from the [releases page](https://github.com/hardbyte/pgroles/releases). Archives are available for Linux (x86_64, aarch64) and macOS (x86_64, aarch64).

### Docker

```bash
docker run --rm ghcr.io/hardbyte/pgroles:0.1.0 --help
```

## Local Testing

```bash
# Unit + non-ignored tests
cargo test --workspace

# Full integration suite (requires PostgreSQL)
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
cargo test --workspace -- --include-ignored
```

### Local Docker Repro

```bash
docker run --rm --name pgroles-pg16 \
  -e POSTGRES_PASSWORD=testpassword \
  -e POSTGRES_DB=pgroles_test \
  -p 5432:5432 \
  postgres:16
```

In another shell:

```bash
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test

# Reproduce the CLI live-db tests locally
cargo test -p pgroles-cli --test cli live_db::diff_against_live_db -- --ignored --exact
cargo test -p pgroles-cli --test cli live_db::diff_summary_format -- --ignored --exact
```

Swap the image tag to `postgres:17` or `postgres:18` to mirror the CI integration matrix.

### Kubernetes Operator *(work in progress)*

Install via Helm:

```bash
helm repo add pgroles https://hardbyte.github.io/pgroles
helm install pgroles-operator pgroles/pgroles-operator
```

## Components

- **pgroles-core** — Manifest parsing, profile expansion, diff engine, SQL generation, and manifest export. No database dependencies. Includes version-aware SQL rendering via `SqlContext`.
- **pgroles-inspect** — Live database introspection via `pg_catalog` queries (sqlx + tokio). Includes PostgreSQL version detection, cloud provider detection (RDS, Cloud SQL, Azure), and privilege level assessment.
- **pgroles-cli** — Command-line tool for validating manifests, planning changes, applying them, and generating manifests from existing databases.
- **pgroles-operator** — *(work in progress)* Kubernetes operator that reconciles `PostgresPolicy` custom resources against PostgreSQL databases.

## License

MIT
