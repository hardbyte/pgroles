---
title: Related tools
description: How pgroles compares to other PostgreSQL role management approaches.
---

An honest look at other tools in this space and when you might choose them instead. For the Terraform comparison specifically, see [pgroles & Terraform](/docs/terraform). {% .lead %}

---

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
