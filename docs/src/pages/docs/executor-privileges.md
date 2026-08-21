---
title: Executor privileges
description: The exact PostgreSQL privileges the role running pgroles needs, and why superuser is not one of them.
---

pgroles does not require superuser. It needs `CREATEROLE` plus a handful of scoped grants, and the exact set depends on whether the roles you manage are new or already exist. {% .lead %}

---

## What pgroles actually needs

This table was verified against a live PostgreSQL 16 server. `CREATEROLE` is the load-bearing attribute; everything else is either automatic (for roles the executor created itself) or a narrow, explicit grant.

| pgroles operation | Requires |
|---|---|
| `CREATE ROLE` | `CREATEROLE` attribute |
| `ALTER ROLE` / `COMMENT ON ROLE` / passwords / `ALTER ROLE ... SET` config | `CREATEROLE` + `ADMIN OPTION` on the target role (automatic for roles the executor created itself) |
| `GRANT`/`REVOKE` role memberships | `ADMIN OPTION` on the granted (group) role — automatic for roles the executor created |
| `GRANT`/`REVOKE` predefined (`pg_*`) role memberships | `ADMIN OPTION` on the predefined role — never automatic: a superuser must run `GRANT pg_read_all_data TO executor WITH ADMIN OPTION` (or the executor must be superuser). The plan preflight warns and apply blocks when this is missing |
| `DROP ROLE` | `CREATEROLE` + `ADMIN OPTION` on the role |
| `CREATE SCHEMA` | `CREATE` privilege on the database |
| `ALTER SCHEMA ... OWNER TO` | ownership of the schema plus membership in the new owner role |
| `GRANT`/`REVOKE` on tables/sequences/functions | ownership of the objects, directly or via membership in the owning role |
| `ALTER DEFAULT PRIVILEGES FOR ROLE x` | membership (privileges) of role `x` — `ADMIN OPTION` alone is **not** enough |
| `REASSIGN OWNED BY a TO b` (retirements) | membership (privileges) of **both** `a` and `b`. The executor has `ADMIN OPTION` on roles it created, so it can `GRANT a TO executor` itself first — pgroles does not do this automatically |
| `DROP OWNED BY a` (retirements) | membership (privileges) of `a` |
| `terminate_sessions` (retirements) | membership in `pg_signal_backend` (cannot terminate superuser sessions) |
| inspection (`diff`/`plan`/`generate`) | none beyond `CONNECT` — `pg_roles`, `pg_shdescription`, and ACL columns are readable by any role |

## Why greenfield is nearly free and brownfield has friction

PostgreSQL 16 changed `CREATEROLE` semantics: a role with `CREATEROLE` automatically receives `ADMIN OPTION` on any role it creates. That collapses most of the table above into a single attribute for a **greenfield** executor — one that creates every role it will later alter, grant, or drop. A fresh executor needs only:

- `CREATEROLE`
- `CREATE` on the target database (to create schemas)
- membership in the schema-owner role(s) it manages default privileges for

There is one greenfield exception: `ADMIN OPTION` is not membership. A
non-superuser cannot create a new owner role and run `ALTER DEFAULT PRIVILEGES
FOR ROLE owner` in the same pgroles transaction. For owner-bound defaults,
pre-create the owner and grant the executor membership, bootstrap in two stages,
or use a superuser for the atomic first apply.

The friction also shows up in **brownfield** adoption. `CREATEROLE` does not retroactively grant `ADMIN OPTION` on roles that already existed before the executor was created. For every pre-existing role pgroles needs to alter, drop, or manage memberships on, a superuser or existing admin must explicitly grant the executor admin rights:

```sql
GRANT adopted_role TO executor WITH ADMIN TRUE;
```

Without this, pgroles can still create new roles and manage grants on objects the executor owns, but altering or dropping the adopted role, or changing its memberships, fails with a permission error. See the [staged adoption guide](/docs/adoption) for the broader brownfield rollout sequence.

## Bootstrap SQL

Run once, by a superuser or an existing admin (RDS `rds_superuser` member, Cloud SQL `cloudsqlsuperuser` member, AlloyDB `alloydbsuperuser` member, etc.), before pointing pgroles at a database for the first time:

```sql
-- Run once as superuser / cloud admin user.

-- 1. The role pgroles connects as.
CREATE ROLE pgroles_executor WITH LOGIN PASSWORD '...' CREATEROLE;

-- 2. Let it create schemas in the target database.
GRANT CREATE ON DATABASE mydb TO pgroles_executor;

-- 3. If pgroles will manage default privileges owned by an existing
--    schema-owner role, give the executor membership in that role.
GRANT app_owner TO pgroles_executor;

-- 4. Brownfield only: for each pre-existing role pgroles must alter,
--    drop, or manage memberships on, grant explicit admin rights.
GRANT some_preexisting_role TO pgroles_executor WITH ADMIN TRUE;
```

Steps 1–2 cover a greenfield executor only when the first plan does not alter
defaults for an owner it also creates. Step 3 is required for every existing
default-privilege owner. For an owner created by the policy, use the two-stage
or superuser bootstrap described above. Step 4 is brownfield-only.

## Cloud providers

None of RDS, Cloud SQL, AlloyDB, or Azure Database for PostgreSQL expose true superuser. The bootstrap above is run by the provider's admin user instead — `rds_superuser` member on RDS/Aurora, `cloudsqlsuperuser` member on Cloud SQL, `alloydbsuperuser` member on AlloyDB. See the [AWS RDS & Aurora](/docs/aws-rds) and [Google Cloud SQL](/docs/google-cloud-sql) pages for the specific attributes those admin roles lack and how pgroles adapts around them.

For Cloud SQL IAM authentication, the operator can authenticate as a low-privilege IAM identity and `SET ROLE` to a privileged parent role on every connection via `connection.params.setRole` — see the [operator connection docs](/docs/operator-connections#gke-workload-identity-for-cloud-sql-iam) for the full pattern.

## The superuser shortcut

Running pgroles as superuser works and satisfies every row in the table above automatically — there is nothing to grant, adopt, or troubleshoot. The cost is the one every DBA already weighs: the connection can do anything to the cluster, not just what pgroles' manifest describes. Scoped `CREATEROLE` privileges are the recommended default; superuser is a pragmatic fallback for small or throwaway environments.
