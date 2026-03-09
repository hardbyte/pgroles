---
title: Related tools
description: How pgroles compares to other PostgreSQL role management approaches.
---

An honest look at other tools in this space and when you might choose them instead. {% .lead %}

---

## Terraform

Terraform is great at creating infrastructure — the database instance, VPC, IAM bindings. pgroles is purpose-built for what lives *inside* the database: roles, grants, default privileges, and memberships. Most teams benefit from using both.

**The complementary pattern:** Terraform creates the database and a management role, pgroles manages what those roles are allowed to do. This is the same split teams use elsewhere — Terraform creates the Kubernetes cluster, Helm/ArgoCD manages the workloads.

**Where they differ:**

- **Convergence** — Terraform manages what's in your `.tf` files. If someone manually adds a `GRANT` via psql, Terraform doesn't know about it and won't revoke it. pgroles treats the manifest as the entire desired state and revokes anything not declared.
- **Profiles vs combinatorial resources** — 3 schemas × 2 profiles requires 18+ Terraform resources with `depends_on` wiring. In pgroles, define profiles once and bind them to schemas.
- **Default privileges** — Terraform's `postgresql_grant` only covers *existing* tables at plan time. pgroles pairs wildcard grants with default privileges so future tables are covered too.
- **Role removal** — Terraform's `postgresql_role` can't cleanly drop a role that owns objects. pgroles has explicit [retirements](/docs/manifest-format) with `reassign_owned_to`, `drop_owned`, and `terminate_sessions`.
- **Managed PostgreSQL awareness** — Terraform's PostgreSQL provider doesn't know about cloud provider limitations. pgroles detects `rds_superuser`, `cloudsqlsuperuser`, and `azure_pg_admin` and warns when your manifest requests unsupported attributes.

**Choose Terraform alone if:** you manage a handful of roles with straightforward grants and no repeating schema patterns.

**Choose both if:** you have multiple schemas with repeating privilege patterns, need convergent enforcement, or want a CI drift gate for database access control.

## ldap2pg

[ldap2pg](https://github.com/dalibo/ldap2pg) by Dalibo is the most established tool in this space — actively maintained, well-documented, and battle-tested in enterprise environments. It syncs PostgreSQL roles and privileges from LDAP/Active Directory or static YAML definitions.

**How it compares:**

Both pgroles and ldap2pg are convergent — they treat the config as desired state and revoke anything not declared. Both use YAML. Both manage roles, grants, and privileges.

The key difference is focus. ldap2pg is built around enterprise directory integration. If your organisation uses LDAP or Active Directory to manage who gets database access, ldap2pg is purpose-built for that workflow and pgroles is not.

pgroles is built around the **profile × schema** expansion model — define privilege templates once, bind them across schemas, and let the tool generate the concrete roles. It also has a Kubernetes operator, managed PostgreSQL detection (RDS, Cloud SQL, AlloyDB, Azure), brownfield adoption via `pgroles generate`, and safe role retirement with preflight checks.

**Choose ldap2pg if:** your roles are sourced from LDAP/AD and you need directory sync.

**Choose pgroles if:** your roles are defined in code (YAML manifests), you want profile-based templating across schemas, or you run on Kubernetes.

## CloudNativePG managed roles

[CloudNativePG](https://cloudnative-pg.io/documentation/current/declarative_role_management/) includes declarative role management as part of its PostgreSQL operator. You define roles in the `Cluster` spec and CNPG ensures they exist with the right attributes and passwords.

However, CNPG's role management covers **role attributes only** — it does not manage grants, privileges, default privileges, or memberships. If you use CNPG for your PostgreSQL clusters, you'd still need pgroles (or another tool) for access control.

The two work well together: CNPG manages the database cluster lifecycle and role passwords, pgroles manages what those roles are allowed to do.

## pgbedrock

[pgbedrock](https://github.com/Squarespace/pgbedrock) by Squarespace is a Python tool with a very similar philosophy — YAML specs, convergent enforcement, wildcard grants, default privileges. It was built for real internal use and proves the concept works at scale.

Development effectively stopped around 2018. If you're starting fresh, pgroles covers the same ground with active maintenance, a Kubernetes operator, and managed PostgreSQL support.

## SQL migration scripts

The most common approach is no dedicated tool at all — teams write `CREATE ROLE` and `GRANT` statements in migration files (Flyway, Alembic, plain SQL) or run them ad-hoc.

This works for simple setups but breaks down as complexity grows:

- **No convergence** — migrations are additive. Removing a grant from a migration file doesn't revoke it from the database.
- **No drift detection** — if someone runs a manual `GRANT` in production, nothing catches it.
- **No templating** — the same privilege pattern repeated across 10 schemas means 10 copies of the same SQL.
- **Ordering headaches** — role drops require careful dependency management that migration tools don't help with.

pgroles' `generate` command can bootstrap a manifest from an existing database managed this way, making adoption incremental.
