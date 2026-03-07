---
title: pgroles & Terraform
description: How pgroles complements Terraform for PostgreSQL role management.
---

Terraform is great at creating infrastructure — the database instance, VPC, IAM bindings. pgroles is purpose-built for what lives inside the database: roles, grants, default privileges, and memberships. Most teams benefit from using both. {% .lead %}

---

## The complementary pattern

Use Terraform for infrastructure, pgroles for access control:

```hcl
# Terraform — create the database and management role
resource "google_sql_database_instance" "main" { ... }
resource "google_sql_database" "app" { ... }
resource "google_sql_user" "pgroles_admin" {
  name     = "pgroles-admin"
  instance = google_sql_database_instance.main.name
}
```

```yaml
# pgroles — manage roles, grants, memberships inside it
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

schemas:
  - name: inventory
    profiles: [editor, viewer]
  - name: catalog
    profiles: [editor, viewer]
  - name: analytics
    profiles: [viewer]
```

This is the same split teams use elsewhere: Terraform creates the Kubernetes cluster, Helm/ArgoCD manages the workloads. Terraform creates the database, Flyway/Alembic manages the schema. Terraform creates the database, pgroles manages access control.

## Where they differ

### Convergence

Terraform manages what's in your `.tf` files. If someone manually adds a `GRANT` or creates a role via psql, Terraform doesn't know about it and won't revoke it.

pgroles treats the manifest as the entire desired state. Roles, grants, and memberships present in the database but absent from the manifest get revoked or dropped. This catches drift from manual changes, scripts, or other tools.

### Profiles vs combinatorial resources

A setup with 3 schemas and 2 profiles (editor, viewer) requires in Terraform:

- 6 `postgresql_role` resources
- 6+ `postgresql_grant` resources (one per privilege-type per schema)
- 6 `postgresql_default_privileges` resources
- Careful `depends_on` wiring between them

In pgroles, the same setup is the YAML above — define the profiles once, bind them to schemas. Each `schema × profile` pair expands automatically.

### Default privileges

Terraform's `postgresql_grant` with an empty objects list grants on all *existing* tables at plan time. Tables created after the apply don't get grants. You need a separate `postgresql_default_privileges` resource and must remember to pair them.

pgroles profiles naturally pair wildcard grants with default privileges — when you declare `on: { type: table, name: "*" }` alongside `default_privileges`, both existing and future tables are covered.

### Role removal

Terraform's `postgresql_role` can't cleanly drop a role that owns objects. The workaround is `skip_drop_role = true` and manual cleanup.

pgroles has explicit [retirements](/docs/manifest-format) that declare the cleanup sequence: `reassign_owned_to`, `drop_owned`, `terminate_sessions`, then `DROP ROLE`.

### Managed PostgreSQL awareness

Terraform's PostgreSQL provider doesn't know about cloud provider limitations. pgroles detects `rds_superuser`, `cloudsqlsuperuser`, `alloydbsuperuser`, and `azure_pg_admin` and warns when your manifest requests attributes (like `SUPERUSER` or `BYPASSRLS`) that the provider doesn't allow.

## When Terraform alone is enough

If you manage a handful of roles with straightforward grants and no schema-based profile patterns, the Terraform PostgreSQL provider works fine. The overhead of a second tool isn't worth it for simple setups.

pgroles becomes valuable when:

- You have multiple schemas with repeating privilege patterns
- You need convergent enforcement (drift gets revoked, not just detected)
- Role lifecycle management matters (retirements, preflight safety checks)
- You're on managed PostgreSQL and want provider-aware warnings
- You want a dedicated CI drift gate for database access control
