<p align="center">
  <img alt="pgroles logo" src="https://raw.githubusercontent.com/hardbyte/pgroles/main/docs/public/logo.svg" width="140" />
</p>

# pgroles

<div align="center">

[![CI](https://github.com/hardbyte/pgroles/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hardbyte/pgroles/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardbyte/pgroles?sort=semver)](https://github.com/hardbyte/pgroles/releases)
[![Docs](https://img.shields.io/badge/docs-github_pages-blue)](https://hardbyte.github.io/pgroles/)
[![Helm Chart OCI](https://img.shields.io/badge/helm-ghcr.io%2Fhardbyte%2Fcharts-informational)](https://github.com/hardbyte/pgroles/pkgs/container/charts%2Fpgroles-operator)

</div>

Declarative PostgreSQL access control. Define roles, schema ownership, grants, and memberships in YAML — pgroles diffs against your live database and generates the exact SQL to converge it.

For simple setups, use a single manifest. For larger teams, the CLI also supports bundle composition: shared profiles plus multiple scoped policy fragments merged into one desired plan with conflict checks before any database diff or apply.

By default, anything not in the manifest gets revoked or dropped. Same model as Terraform, applied to PostgreSQL. For incremental adoption, use `--mode additive` to only grant and never revoke, or `--mode adopt` to manage declared roles fully without dropping undeclared ones. In additive mode, pgroles also leaves attributes and comments unchanged on pre-existing roles.

## How it works

Define a policy. Profiles are reusable privilege templates that expand across schemas:

```yaml
profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        object: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        object: { type: sequence, name: "*" }
      - privileges: [EXECUTE]
        object: { type: function, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        on_type: table
      - privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - privileges: [EXECUTE]
        on_type: function

  viewer:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT]
        object: { type: table, name: "*" }

schemas:
  - name: inventory
    owner: app_owner
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

This generates roles `inventory-editor`, `inventory-viewer`, and `catalog-viewer`, each scoped to their schema. pgroles will create `inventory` if it is missing and keep it owned by `app_owner`. `app-service` gets `inventory-editor` membership.

Run `pgroles diff` to see exactly what SQL will be executed:

```sql
CREATE ROLE "inventory-editor"
  NOLOGIN NOSUPERUSER INHERIT;

GRANT USAGE ON SCHEMA "inventory"
  TO "inventory-editor";
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER
  ON TABLE "inventory"."orders"
  TO "inventory-editor";
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER
  ON TABLE "inventory"."customers"
  TO "inventory-editor";
GRANT USAGE, SELECT, UPDATE
  ON SEQUENCE "inventory"."orders_id_seq"
  TO "inventory-editor";
GRANT EXECUTE
  ON FUNCTION "inventory"."refresh_inventory_cache"()
  TO "inventory-editor";

-- Roles removed from the manifest get cleaned up:
REVOKE ALL ON SCHEMA "legacy"
  FROM "old-reader";
DROP ROLE "old-reader";
```

For wildcard relation grants, pgroles expands the current objects of the requested
type safely, so table grants do not accidentally touch views or materialized
views.

Then `pgroles apply` to execute it.

## Quick start

```bash
# Already have a database with roles? Generate a manifest from it:
pgroles generate --database-url postgres://... > pgroles.yaml

# See what SQL pgroles would run:
pgroles diff -f pgroles.yaml --database-url postgres://...

# Apply the changes:
pgroles apply -f pgroles.yaml --database-url postgres://...

# Write the generated manifest directly to a file:
pgroles generate --database-url postgres://... --output pgroles.yaml
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
- [`pgroles-operator`](https://crates.io/crates/pgroles-operator) — Kubernetes operator crate, controller runtime, and CRD types

**Docker:**
```bash
docker run --rm ghcr.io/hardbyte/pgroles --help
```

## Features

- **Convergent** — the manifest is the desired state. Missing roles get created, extra roles get dropped, drifted grants get fixed.
- **Reconciliation modes** — `--mode authoritative` (default) for full convergence, `--mode additive` to only grant and never revoke, `--mode adopt` to manage declared roles without dropping undeclared ones. Additive mode is the safest way to start using pgroles on an existing database.
- **Profiles** — define privilege templates once, apply them across schemas. Each `schema x profile` pair becomes a role, and profiles can set generated-role `login` and `inherit` attributes.
- **Bundle composition** — compose shared profiles plus multiple scoped policy fragments in the CLI, with duplicate/conflict detection and managed-scope enforcement before diff or apply.
- **Schema management** — declared schemas can be created and have ownership converged, while undeclared referenced schemas must already exist.
- **Safer privilege bundles** — common application profiles can pair table, sequence, and function privileges so identity columns and trigger-driven routines are covered together.
- **Brownfield adoption** — `pgroles generate` introspects an existing database and produces a manifest you can refine. Add `--suggest-profiles` to deterministically refactor roles that share a privilege shape across schemas into reusable profiles, with a built-in round-trip check that guarantees the suggested manifest doesn't widen privileges.
- **Reproducible export** — `pgroles generate --output` writes the current database state directly to a manifest file.
- **Drift detection** — `pgroles diff --exit-code` returns exit code 2 on drift, designed for CI gates.
- **Password management** — login roles can set passwords from environment variables (CLI) or Kubernetes Secrets (operator), with `VALID UNTIL` expiration and redacted output.
- **Safe role removal** — preflight checks for owned objects, active sessions, and dependencies before dropping roles. Explicit `retirements` declare cleanup steps.
- **Managed PostgreSQL** — works with RDS, Aurora, Cloud SQL, AlloyDB, and Azure Database for PostgreSQL. Detects provider-specific reserved roles and warns about privilege limitations.
- **Kubernetes operator** — reconcile `PostgresPolicy` custom resources continuously. Install via Helm:
  ```bash
  helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
  ```
  Use `spec.mode: plan` to inspect drift without executing SQL.

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
