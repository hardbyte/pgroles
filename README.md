<p align="center">
  <img alt="pgroles logo" src="https://raw.githubusercontent.com/hardbyte/pgroles/main/docs/public/logo.svg" width="140" />
</p>

# pgroles

<div align="center">

[![CI](https://github.com/hardbyte/pgroles/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hardbyte/pgroles/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardbyte/pgroles?sort=semver)](https://github.com/hardbyte/pgroles/releases)
[![Docs](https://img.shields.io/badge/docs-github_pages-blue)](https://hardbyte.github.io/pgroles/)
[![crates.io - pgroles-cli](https://img.shields.io/crates/v/pgroles-cli)](https://crates.io/crates/pgroles-cli)
[![crates.io - pgroles-core](https://img.shields.io/crates/v/pgroles-core)](https://crates.io/crates/pgroles-core)
[![crates.io - pgroles-inspect](https://img.shields.io/crates/v/pgroles-inspect)](https://crates.io/crates/pgroles-inspect)
[![Helm Chart OCI](https://img.shields.io/badge/helm-ghcr.io%2Fhardbyte%2Fcharts-informational)](https://github.com/hardbyte/pgroles/pkgs/container/charts%2Fpgroles-operator)

</div>

Declarative PostgreSQL access control. Define roles, grants, and memberships in YAML — pgroles diffs against your live database and generates the exact SQL to converge it.

Anything not in the manifest gets revoked or dropped. Same model as Terraform, applied to PostgreSQL.

## How it works

Define a policy. Profiles are reusable privilege templates that expand across schemas:

```yaml
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

schemas:
  - name: inventory
    profiles: [editor, viewer]
  - name: catalog
    profiles: [viewer]

roles:
  - name: app-service
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: app-service
```

This generates roles `inventory-editor`, `inventory-viewer`, and `catalog-viewer`, each scoped to their schema. `app-service` gets `inventory-editor` membership.

Run `pgroles diff` to see exactly what SQL will be executed:

```sql
CREATE ROLE "inventory-editor"
  NOLOGIN NOSUPERUSER INHERIT;

GRANT USAGE ON SCHEMA "inventory"
  TO "inventory-editor";
GRANT SELECT, INSERT, UPDATE, DELETE
  ON ALL TABLES IN SCHEMA "inventory"
  TO "inventory-editor";

-- Roles removed from the manifest get cleaned up:
REVOKE ALL ON SCHEMA "legacy"
  FROM "old-reader";
DROP ROLE "old-reader";
```

Then `pgroles apply` to execute it.

## Quick start

```bash
# Already have a database with roles? Generate a manifest from it:
pgroles generate --database-url postgres://... > pgroles.yaml

# See what SQL pgroles would run:
pgroles diff -f pgroles.yaml --database-url postgres://...

# Apply the changes:
pgroles apply -f pgroles.yaml --database-url postgres://...
```

`--database-url` can also be set via the `DATABASE_URL` environment variable.

## Install

**Pre-built binaries** from [GitHub Releases](https://github.com/hardbyte/pgroles/releases) (Linux x86_64/aarch64, macOS x86_64/aarch64).

**Cargo CLI:**
```bash
cargo install pgroles-cli
```

**Rust crates:**
- [`pgroles-cli`](https://crates.io/crates/pgroles-cli) — end-user CLI
- [`pgroles-core`](https://crates.io/crates/pgroles-core) — manifest model, diff engine, SQL rendering
- [`pgroles-inspect`](https://crates.io/crates/pgroles-inspect) — database inspection and managed-provider detection
- `pgroles-operator` — operator crate in this repository; see the [operator docs](https://hardbyte.github.io/pgroles/docs/operator/) for source consumption

**Docker:**
```bash
docker run --rm ghcr.io/hardbyte/pgroles --help
```

## Features

- **Convergent** — the manifest is the desired state. Missing roles get created, extra roles get dropped, drifted grants get fixed.
- **Profiles** — define privilege templates once, apply them across schemas. Each `schema x profile` pair becomes a role.
- **Brownfield adoption** — `pgroles generate` introspects an existing database and produces a manifest you can refine.
- **Drift detection** — `pgroles diff --exit-code` returns exit code 2 on drift, designed for CI gates.
- **Safe role removal** — preflight checks for owned objects, active sessions, and dependencies before dropping roles. Explicit `retirements` declare cleanup steps.
- **Managed PostgreSQL** — works with RDS, Aurora, Cloud SQL, AlloyDB, and Azure Database for PostgreSQL. Detects provider-specific reserved roles and warns about privilege limitations.
- **Kubernetes operator** — reconcile `PostgresPolicy` custom resources continuously. Install via Helm:
  ```bash
  helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
  ```

## Documentation

Full documentation is published at [hardbyte.github.io/pgroles](https://hardbyte.github.io/pgroles/).

- [Quick start](https://hardbyte.github.io/pgroles/docs/quick-start/)
- [Installation](https://hardbyte.github.io/pgroles/docs/installation/)
- [Manifest format](https://hardbyte.github.io/pgroles/docs/manifest-format/)
- [CLI reference](https://hardbyte.github.io/pgroles/docs/cli/)
- [Kubernetes operator](https://hardbyte.github.io/pgroles/docs/operator/)
- [Operator architecture](https://hardbyte.github.io/pgroles/docs/operator-architecture/)

## License

MIT
