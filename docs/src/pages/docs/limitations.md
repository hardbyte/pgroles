---
title: Limitations
description: What pgroles does not manage today, and what happens if you rely on those features anyway.
---

What pgroles does not cover, so you know where the edges of the declared-state model are before you hit them. {% .lead %}

---

## Column-level grants

`GRANT SELECT (col) ON table` remains unmanaged by pgroles: column-level grants are not diffed, not revoked, and `pgroles generate` does not export them — manifests only describe table-level access. pgroles does, however, detect column-level grants during `diff` and `apply` — in schemas whose privileges it manages (schemas referenced by grants or default privileges in the manifest): if any are found, it prints a warning (schema, table, grantee, affected columns, and privileges) so the gap is visible instead of silent. The warning does not block `diff`/`apply` and the grants themselves are still not managed — you must review and, if needed, revoke them manually.

## Membership SET option

PostgreSQL 16 separates `INHERIT`, `SET`, and `ADMIN` on each role-membership edge. pgroles models and converges `inherit` and `admin`, but does not inspect or manage `pg_auth_members.set_option`. A membership created by pgroles gets PostgreSQL's default `SET TRUE`. An existing `SET FALSE` edge can appear to match, but converging a changed `inherit` or `admin` value revokes and recreates the edge without a `SET` clause, restoring `SET TRUE`. Do not place a `SET FALSE` security boundary on a pgroles-managed membership.

## Grant options and effective access

The manifest does not model `WITH GRANT OPTION` for application grantees. pgroles performs a separate executor-grantability preflight for wildcard safety, but it does not converge who may delegate an object privilege onward.

Delegated grants also limit what a planned `REVOKE` can do: PostgreSQL only removes ACL entries whose grantor is a role the executor can act as, and a `REVOKE` that matches none of them **succeeds silently without changing anything** — no error, no warning. A privilege granted onward by a delegate therefore cannot be revoked by the pgroles executor, and the same drift is planned again on the next run. The operator detects this (a plan whose exact effects were just applied yet still diff) and reports `Ready=False` with reason `NonConvergentPlan` instead of re-applying it in a loop; with the CLI, an `apply` that leaves `diff` unchanged means the same thing. The fix is to revoke the delegating grant option (with `CASCADE`) or run the revoke as a role that can act as the grantor.

More generally, pgroles converges managed direct ACLs; it does not claim that absence from a manifest means absence of effective access. Membership, ownership, `PUBLIC`, column grants, row security, or unmodeled object types may change the answer. Use PostgreSQL's `has_*_privilege` and `pg_has_role` functions to verify the effective path. Work through [The permission chain](/docs/postgresql-access-model) and [The security review](/docs/postgresql-security-review) to test those paths interactively.

## Predefined roles

PostgreSQL’s predefined roles (`pg_read_all_data`, `pg_write_all_data`, `pg_monitor`, and friends) grant access through special-cased permission checks, not ACL entries, so they never appear in the grants pgroles diffs. Their **memberships** are manageable, though: a membership stanza may name a `pg_*` role directly, declared members converge, and `exclusive: true` asserts the complete member list — see [memberships](/docs/memberships#predefined-and-external-granted-roles). What stays out of scope: the role objects themselves are never created, altered, or dropped, and undeclared members are never revoked without an explicit `exclusive` assertion, so provider-granted memberships survive adoption. `pgroles inspect` reports all `pg_*` memberships informationally, and `pgroles generate` exports them. [The security review](/docs/postgresql-security-review#the-predefined-master-keys) shows why they matter.

## PUBLIC inspection is deliberately scoped

pgroles can reconcile a declared `PUBLIC` object or default-privilege rule, including `ensure: absent`, and it supports both schema and global default scopes. It does not treat every undeclared `PUBLIC` privilege as drift: only an explicit rule opts that target into desired-state management. `pgroles generate` does not emit `PUBLIC` or absence rules.

`pgroles inspect` also reports `PUBLIC` grants on the current database and its non-system schemas as informational output. That report is useful evidence, but it is not a complete inventory of every object type or every effective-access path.

## Per-database role settings

`ALTER ROLE ... IN DATABASE ... SET` entries are not managed. pgroles only manages the cluster-wide role settings in `pg_roles.rolconfig` via `roles[].config` — see [role configuration defaults](/docs/manifest-reference#role-configuration-defaults). A per-database `SET` is left untouched by diff and apply, silently, in every reconciliation mode. If you need per-database overrides, set them manually outside pgroles.

## Server configuration

pgroles does not touch server-level configuration. `ALTER SYSTEM`, `postgresql.conf`, and the PostgreSQL 15+ `GRANT SET`/`GRANT ALTER SYSTEM ON PARAMETER` privilege are all out of scope. Use your infrastructure-as-code tool or PostgreSQL operator for server configuration; pgroles only manages roles, schemas, and privileges within a database.

## Extensions

`CREATE EXTENSION` and objects owned directly by an extension are not managed — pgroles does not install, upgrade, or drop extensions, and it does not track extension ownership. Wildcard grants (`name: "*"`) do cover tables and functions an extension creates inside a schema pgroles manages, so extension-installed objects still pick up the schema's standard grants; the extension lifecycle itself is just not something pgroles reasons about.

## Row-level security

RLS policies (`CREATE POLICY`, `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`) are not modeled, inspected, or applied. This is on the roadmap — see [ROADMAP.md](https://github.com/thepartly/pgroles/blob/main/ROADMAP.md) on GitHub — but there is no current workaround beyond managing policies with raw SQL outside pgroles.

## Unmodeled grant object types

pgroles' grant model covers `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, and `type`. Domains, foreign data wrappers, foreign servers, languages, tablespaces, large objects, and publications/subscriptions are not modeled object types. Grants on these are ignored by `diff` (they never appear as drift, in either direction) and are silently dropped from the manifest by `generate` — a brownfield export will not round-trip a `GRANT USAGE ON FOREIGN SERVER ...`, for example. Manage privileges on these object types with raw SQL.

## Password drift

PostgreSQL does not expose password hashes for comparison, so pgroles cannot detect when a password has been changed directly in the database outside of pgroles. Passwords are re-applied on every `apply` from the configured source (CLI environment variable or operator Secret), and password-only changes are excluded from `diff --exit-code` drift detection since they always appear in the plan. See [passwords and drift detection](/docs/manifest-reference#roles) in the manifest reference.

## Databases themselves

pgroles grants privileges *on* a database (`CONNECT`, `CREATE`, `TEMPORARY`) but does not create, drop, or rename databases, and does not manage database ownership (`ALTER DATABASE ... OWNER TO`). Provision the database itself with your migration tooling or infrastructure-as-code before pointing a pgroles manifest at it.
