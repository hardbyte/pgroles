---
title: Limitations
description: What pgroles does not manage today, and what happens if you rely on those features anyway.
---

What pgroles does not cover, so you know where the edges of the declared-state model are before you hit them. {% .lead %}

---

## Column-level grants

`GRANT SELECT (col) ON table` is invisible to pgroles. Column-level grants are not inspected, not diffed, not revoked, and `pgroles generate` does not export them — manifests only describe table-level access. If a column-level grant exists in the database, pgroles will not report it and will not touch it; there is no error, it simply never appears. Detection and warning for column-level grants is planned but not yet implemented.

## Per-database role settings

`ALTER ROLE ... IN DATABASE ... SET` entries are not managed. pgroles only manages the cluster-wide role settings in `pg_roles.rolconfig` via `roles[].config` — see [role configuration defaults](/docs/manifest-reference#role-configuration-defaults). A per-database `SET` is left untouched by diff and apply, silently, in every reconciliation mode. If you need per-database overrides, set them manually outside pgroles.

## Server configuration

pgroles does not touch server-level configuration. `ALTER SYSTEM`, `postgresql.conf`, and the PostgreSQL 15+ `GRANT SET`/`GRANT ALTER SYSTEM ON PARAMETER` privilege are all out of scope. Use your infrastructure-as-code tool or PostgreSQL operator for server configuration; pgroles only manages roles, schemas, and privileges within a database.

## Extensions

`CREATE EXTENSION` and objects owned directly by an extension are not managed — pgroles does not install, upgrade, or drop extensions, and it does not track extension ownership. Wildcard grants (`name: "*"`) do cover tables and functions an extension creates inside a schema pgroles manages, so extension-installed objects still pick up the schema's standard grants; the extension lifecycle itself is just not something pgroles reasons about.

## Row-level security

RLS policies (`CREATE POLICY`, `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`) are not modeled, inspected, or applied. This is on the roadmap — see [ROADMAP.md](https://github.com/hardbyte/pgroles/blob/main/ROADMAP.md) on GitHub — but there is no current workaround beyond managing policies with raw SQL outside pgroles.

## Unmodeled grant object types

pgroles' grant model covers `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, and `type`. Domains, foreign data wrappers, foreign servers, languages, tablespaces, large objects, and publications/subscriptions are not modeled object types. Grants on these are ignored by `diff` (they never appear as drift, in either direction) and are silently dropped from the manifest by `generate` — a brownfield export will not round-trip a `GRANT USAGE ON FOREIGN SERVER ...`, for example. Manage privileges on these object types with raw SQL.

## Password drift

PostgreSQL does not expose password hashes for comparison, so pgroles cannot detect when a password has been changed directly in the database outside of pgroles. Passwords are re-applied on every `apply` from the configured source (CLI environment variable or operator Secret), and password-only changes are excluded from `diff --exit-code` drift detection since they always appear in the plan. See [passwords and drift detection](/docs/manifest-reference#roles) in the manifest reference.

## Databases themselves

pgroles grants privileges *on* a database (`CONNECT`, `CREATE`, `TEMPORARY`) but does not create, drop, or rename databases, and does not manage database ownership (`ALTER DATABASE ... OWNER TO`). Provision the database itself with your migration tooling or infrastructure-as-code before pointing a pgroles manifest at it.
