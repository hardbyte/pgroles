---
title: Limitations
description: What pgroles does not manage today, and what happens if you rely on those features anyway.
---

What pgroles does not cover, so you know where the edges of the declared-state model are before you hit them. {% .lead %}

---

## Column-level grants

`GRANT SELECT (col) ON table` remains unmanaged by pgroles: column-level grants are not diffed, not revoked, and `pgroles generate` does not export them — manifests only describe table-level access. pgroles does, however, detect column-level grants during `diff` and `apply` — in schemas whose privileges it manages (schemas referenced by grants or default privileges in the manifest): if any are found, it prints a warning (schema, table, grantee, affected columns, and privileges) so the gap is visible instead of silent. The warning does not block `diff`/`apply` and the grants themselves are still not managed — you must review and, if needed, revoke them manually.

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

## Policy names are limited to 63 characters

A `PostgresPolicy` name must be at most 63 characters. The operator links a policy to its plans and plan-SQL ConfigMaps through the `pgroles.io/policy` label, and Kubernetes caps label values at 63 characters, so a longer name could not be represented without truncation. The CRD rejects longer names at admission with an explanatory message.

Two upgrade notes if you are adopting this on an existing installation:

- **A policy created before this limit existed keeps its long name until you next write to it.** On Kubernetes 1.30 and later, [validation ratcheting](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-ratcheting) allows updates that leave the offending name unchanged, so such a policy keeps reconciling normally. On Kubernetes versions before 1.30 there is no ratcheting, and *every* write is rejected — including the operator's own status updates — so the policy stops making progress with no status change to explain it. Rename affected policies (delete and recreate under a shorter name) before upgrading on those clusters. `kubectl get pgr -A -o name | awk 'length($0) > 67'` lists candidates.
- **Deleting a policy with `--cascade=orphan` now leaks its plans.** Plans and plan-SQL ConfigMaps are matched to their policy by owner UID rather than by name, so orphaned objects are no longer re-adopted by a recreated policy of the same name. Because `--cascade=orphan` also strips the owner references that garbage collection relies on, those objects persist until deleted by hand. Prefer the default cascading delete; if you have already orphaned some, delete leftover `pgplan` objects and `*-sql` ConfigMaps explicitly.
