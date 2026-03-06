---
title: Architecture
description: How pgroles is structured internally as a Rust workspace.
---

pgroles is a Rust workspace with four crates, each with a clear responsibility. {% .lead %}

---

## Crate overview

### pgroles-core

The core library with no database dependencies. Contains:

- **Manifest parsing** (`manifest.rs`) -- YAML deserialization, profile expansion, validation. Includes `AuthProvider` model for cloud IAM provider declarations.
- **Role graph model** (`model.rs`) -- normalized representation of roles, grants, default privileges, and memberships
- **Diff engine** (`diff.rs`) -- compares two `RoleGraph` instances and produces an ordered list of `Change` operations. Changes are `serde::Serialize` for JSON output.
- **SQL generation** (`sql.rs`) -- renders `Change` operations into PostgreSQL DDL statements. Uses `SqlContext` for version-dependent rendering (PG 14/15 legacy syntax vs PG 16+ `WITH INHERIT`/`WITH ADMIN`).
- **Export** (`export.rs`) -- converts a `RoleGraph` back into a flat `PolicyManifest` for brownfield adoption (`generate` command).

All types use `BTreeMap` and `BTreeSet` for deterministic output ordering.

### pgroles-inspect

Database introspection via `pg_catalog` queries. Connects to a live PostgreSQL database and builds a `RoleGraph` representing the current state. Uses `sqlx` with tokio for async database access.

Inspects:
- Role attributes (`pg_roles`)
- Object privileges (`information_schema.role_table_grants`, etc.)
- Default privileges (`pg_default_acl`)
- Memberships (`pg_auth_members`)

Also provides:
- **Version detection** (`version.rs`) -- queries `server_version_num` to determine PG major version for syntax adaptation
- **Cloud provider detection** (`cloud.rs`) -- detects whether the connecting role is a true superuser, cloud provider superuser (`rds_superuser`, `cloudsqlsuperuser`, `azure_pg_admin`), or regular user. Validates planned changes against detected privilege level.
- **Unscoped introspection** (`inspect_all`) -- discovers all non-system roles for the `generate` command

### pgroles-cli

The command-line interface. Thin wrapper that:
1. Reads and validates the manifest (via core)
2. Inspects the database (via inspect)
3. Computes a diff (via core)
4. Renders and/or applies the changes

### pgroles-operator

*(Work in progress)* A Kubernetes operator that reconciles `PostgresPolicy` custom resources against PostgreSQL databases.

## Data flow

```
YAML manifest
    |
    v
parse_manifest() --> PolicyManifest
    |
    v
expand_manifest() --> ExpandedManifest  (profiles x schemas resolved)
    |
    v
RoleGraph::from_expanded() --> RoleGraph (desired state)

Database
    |
    v
inspect() --> RoleGraph (current state)

diff(current, desired) --> Vec<Change>
    |
    v
sql::render_all() --> SQL script
```

## Convergent diff model

The diff engine treats the manifest as the **entire truth**. It produces changes in dependency order:

1. **Creates** before grants (roles must exist first)
2. **Alters** for attribute changes on existing roles
3. **Grants** for new privileges
4. **Default privileges** for new default rules
5. **Membership removes**
6. **Membership adds**
7. **Default privilege revocations**
8. **Revocations** for removed privileges
9. **Drops** after revocations (roles must have no privileges first)

`apply` then executes the rendered plan inside a single transaction so the database does not commit a partially-applied change set.
