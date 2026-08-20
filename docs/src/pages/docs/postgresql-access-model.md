---
title: How PostgreSQL access works
description: Follow one query through PostgreSQL roles, memberships, schemas, object privileges, default privileges, PUBLIC, and row security in a real browser database.
---

PostgreSQL access is not one grant. It is a path from the identity that opened a connection, through role membership and namespace checks, to an object's privileges and any row policy. The fastest way to understand that path is to watch one query fail, repair it, and then change the rules around it. {% .lead %}

## Follow one access request

Alice needs to read an `orders` table. The example uses three roles with deliberately different jobs:

| Role | Job | Logs in? |
|---|---|---|
| `alice` | Represents a human or workload identity | Yes |
| `reporting` | Bundles the privileges needed by readers | No |
| `app_owner` | Owns the schema and its objects | No |

The guided story below keeps that cast and database state from beginning to end. Each checkpoint asks one question, runs real PostgreSQL SQL in your browser, and explains the result before continuing. Complete the story to unlock a free-form SQL playground over the finished database.

{% postgres-permission-lab /%}

## Use the model outside the lab

The seven checkpoints reduce to four ideas: **who PostgreSQL is checking, which gates the operation must pass, where the privilege came from, and whether another authorization layer narrows the result.**

### Separate identity, capability, and ownership

PostgreSQL has one primitive called a **role**. `LOGIN` makes a role eligible to begin a session; it does not create a separate user object type.

```sql
CREATE ROLE alice LOGIN;
CREATE ROLE reporting NOLOGIN;
CREATE ROLE app_owner NOLOGIN;
```

Keeping those responsibilities separate creates a stable production shape:

```text
human / workload login
          |
          v
   capability role          migration login
   (read or write)                 |
          |                        | SET ROLE
          v                        v
 table / sequence ACLs        NOLOGIN owner
                                  |
                                  v
                            schemas and objects
```

The runtime identity does not own tables. The owner does not log in. Ownership carries authority beyond an ACL entry: an owner can alter or drop the object and grant its privileges, and a table owner normally bypasses row security. Migration automation deliberately becomes the owner while running DDL, so ownership and default privileges remain stable when login credentials rotate.

After a connection opens, these two names explain whose authority is active:

```sql
SELECT session_user, current_user;
```

- `session_user` is normally the role that authenticated.
- `current_user` is the effective identity PostgreSQL uses for permission checks and new-object ownership.

`SET ROLE reporting` changes `current_user`, not `session_user`. It is a switch, not an accumulation: the session begins using privileges held or inherited by `reporting` rather than retaining every privilege held only by the previous effective identity.

Role attributes such as `LOGIN`, `CREATEDB`, `CREATEROLE`, `REPLICATION`, and `BYPASSRLS` are not ordinary object privileges. They are not inherited simply because one role is a member of another; the session normally has to become that role to use them.

### Trace every gate

For an ordinary `SELECT app.orders`, ask the questions in order:

1. **Who authenticated?** `pg_hba.conf`, certificates, cloud IAM, or another provider maps the client to a login role. Authentication does not create object privileges.
2. **Can that role connect?** `CONNECT` is checked when the database session opens. Revoking it blocks new connections but does not terminate existing sessions.
3. **Who is effective now?** Start with `current_user`, then include privileges available through `INHERIT TRUE` membership paths.
4. **Can PostgreSQL reach the namespace?** A qualified name still requires `USAGE` on its schema.
5. **Does an authorization path allow the operation?** A direct ACL, inherited role, ownership, or `PUBLIC` can provide the table privilege.
6. **Does another layer narrow the answer?** Row security can filter rows after the table operation is allowed.

The common object gates answer different questions:

| Privilege | What it allows | What it does not imply |
|---|---|---|
| Database `CONNECT` | Open a session to the database | Access to schemas or objects |
| Schema `USAGE` | Resolve objects in the namespace | `SELECT`, `INSERT`, or `EXECUTE` inside it |
| Schema `CREATE` | Create objects in the namespace | Ownership of existing objects |
| Table `SELECT` | Read rows from a table or view | Schema `USAGE` |
| Table `INSERT` | Insert rows | Sequence access for a default value |
| Sequence `USAGE` | Use `currval` and `nextval` as PostgreSQL defines them | `INSERT` on a consuming table |
| Routine `EXECUTE` | Call a function or procedure | Access used by an invoker-security routine |

The `search_path` changes name resolution but grants nothing. PostgreSQL also has no general `DENY` ACL that overrides every authorization path. Revoking Alice's direct grant does not remove access if she can still reach it through `reporting`, ownership, or `PUBLIC`.

### Read membership as a directed edge

Read `GRANT reporting TO alice` as:

> Alice is a member of reporting, so Alice may use reporting according to the options on that edge.

On PostgreSQL 16 and later, those options answer three independent questions:

| Option | Question |
|---|---|
| `INHERIT` | Are the granted role's ordinary privileges usable automatically? |
| `SET` | May the session run `SET ROLE` to the granted role through this path? |
| `ADMIN` | May the member grant or revoke membership in the granted role? |

```sql
SELECT
  pg_has_role('alice', 'reporting', 'MEMBER') AS is_member,
  pg_has_role('alice', 'reporting', 'USAGE')  AS inherits_now,
  pg_has_role('alice', 'reporting', 'SET')    AS can_set_role;
```

This is why `MEMBER = true` does not necessarily mean the role's privileges are active. Capability roles can themselves be members of other roles, and PostgreSQL follows nested membership paths while rejecting cycles.

### Cover both existing and future objects

This statement changes only tables that exist when it runs:

```sql
GRANT SELECT ON ALL TABLES IN SCHEMA app TO reporting;
```

A pgroles wildcard behaves similarly during reconciliation: it expands over matching objects that exist at that moment. pgroles will discover a later table on its next run, but there can be a gap between creation and reconciliation.

Default privileges stamp an ACL onto a new object at creation time:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner
  IN SCHEMA app
  GRANT SELECT ON TABLES TO reporting;
```

Three rules prevent most surprises:

1. **Defaults are future-only.** They do not repair existing objects.
2. **Defaults belong to the creator role.** The example applies only when `current_user` is `app_owner` as the object is created. Membership in `app_owner` is not enough unless the creator actually uses `SET ROLE app_owner`.
3. **Global and schema defaults are layered.** A schema-scoped revoke cannot subtract a privilege supplied by a global default.

Pair both halves in pgroles:

```yaml
default_owner: app_owner

grants:
  - role: reporting
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }

default_privileges:
  - owner: app_owner
    schema: app
    grant:
      - role: reporting
        privileges: [SELECT]
        on_type: table
```

### Treat PUBLIC and row security as separate paths

`PUBLIC` is a pseudo-role in which every role implicitly participates. PostgreSQL commonly supplies `CONNECT` and `TEMPORARY` on databases, `EXECUTE` on routines, and privileges on some languages, types, and schemas through `PUBLIC`. Actual defaults vary with object type, PostgreSQL version, upgrades, and prior administration, so inspect the database rather than assuming a pristine cluster.

```sql
SELECT has_database_privilege('public', current_database(), 'CONNECT');
SELECT has_schema_privilege('public', 'app', 'USAGE');
SELECT has_function_privilege('public', 'app.some_function()', 'EXECUTE');
```

Revoking from `PUBLIC` affects every role. Treat it as a deliberate database baseline, not a cleanup side effect of one application's policy.

Row-level security answers a later question. A role may have `SELECT` on a table and still see only rows allowed by a policy:

```sql
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_orders ON app.orders
  FOR SELECT
  USING (account_name = current_user);
```

If RLS is enabled and no applicable policy exists, rows are denied by default. Table owners normally bypass RLS unless the table uses `FORCE ROW LEVEL SECURITY`; superusers and roles with `BYPASSRLS` bypass it too.

## Debug a real denial

Start with identity instead of adding grants:

```sql
SELECT
  session_user,
  current_user,
  current_database(),
  current_schemas(true);
```

Then ask PostgreSQL the same questions its permission system answers:

```sql
SELECT has_database_privilege(current_user, current_database(), 'CONNECT');
SELECT has_schema_privilege(current_user, 'app', 'USAGE');
SELECT has_table_privilege(current_user, 'app.orders', 'SELECT');
SELECT has_sequence_privilege(current_user, 'app.orders_id_seq', 'USAGE');
SELECT row_security_active('app.orders');

SELECT
  pg_has_role(current_user, 'reporting', 'MEMBER') AS is_member,
  pg_has_role(current_user, 'reporting', 'USAGE')  AS inherits_now,
  pg_has_role(current_user, 'reporting', 'SET')    AS can_set_role;
```

Use `psql` to inspect the stored state:

```text
\du+ alice
\drg reporting
\dn+ app
\dp app.orders
\ddp
```

`has_*_privilege` reports effective answers. ACLs and membership catalogs explain the path that produced them. Keep both views: a catalog row alone can miss ownership, inheritance, or `PUBLIC`; an effective Boolean alone does not tell you why it is true.

When pgroles is involved, compare four evidence levels:

1. **Declared:** what the manifest says pgroles should manage.
2. **Observed:** what `pgroles inspect` and PostgreSQL report now.
3. **Planned:** the exact SQL from `pgroles diff` or `pgroles plan`.
4. **Verified:** the application operation and negative access tests after apply.

## What pgroles manages

pgroles is intentionally narrower than PostgreSQL's entire authorization system.

| Area | pgroles behavior |
|---|---|
| Named roles and supported attributes | Managed |
| Named-role memberships | `INHERIT` and `ADMIN` managed; PostgreSQL 16 `SET` not managed |
| Supported object ACLs | Managed at object level; column grants and application grant options are not managed |
| Schema-scoped default ACLs for named roles | Managed |
| Global defaults and defaults for `PUBLIC` | Not managed |
| Current-database and schema `PUBLIC` ACLs | Reported informationally, not reconciled |
| Row-level security and routine definitions | Not managed |
| Authentication and provider identity lifecycle | External; provider-owned roles can be declared `external: true` |

{% callout type="warning" title="Desired ACLs are not the same as effective access" %}
pgroles converges the direct roles, memberships, and ACLs in its managed graph. An omitted grant does not prove that a role has no effective access: another membership path, ownership, `PUBLIC`, row-policy behavior, or an unmodeled privilege can still matter.
{% /callout %}

pgroles does not currently inspect or converge the PostgreSQL 16 membership `SET` option. A membership it creates receives PostgreSQL's default `SET TRUE`; changing `inherit` or `admin` revokes and recreates the edge, which can turn a manually hardened `SET FALSE` back into `SET TRUE`.

For defaults, pgroles manages schema-scoped privileges granted to named roles. It does not manage global default ACLs or defaults granted to `PUBLIC`. This is especially important for routines because PostgreSQL grants `EXECUTE` to `PUBLIC` by default, and a schema-only revoke cannot subtract that global default.

Read [Grants & privileges](/docs/grants), [Default privileges](/docs/default-privileges), [Memberships](/docs/memberships), and [Limitations](/docs/limitations) for the exact pgroles surface.

## About the browser database

The lesson runs an isolated PostgreSQL 18.3 database in WebAssembly. Nothing connects to your systems, and **Reset lesson** discards the entire database.

{% callout type="note" title="Why this uses PGlite rather than pgrust today" %}
We reviewed [pgrust](https://github.com/malisper/pgrust) first. A single-click lesson needs a callable browser API, but its hosted cross-origin terminal does not expose one to the parent page. Its current browser build also does not enforce separate login identities or RLS accurately enough for this complete story. The lab therefore uses [PGlite](https://pglite.dev/), which compiles upstream PostgreSQL to WebAssembly and exposes a same-page execution API.

The browser has one bootstrap session as `postgres` and uses `SET ROLE` to demonstrate effective identities. It teaches authorization, not `pg_hba.conf`, login authentication, or concurrent sessions. Verify production decisions against a supported PostgreSQL server.
{% /callout %}

## PostgreSQL references

The authoritative references are [Database roles](https://www.postgresql.org/docs/current/user-manag.html), [Role membership](https://www.postgresql.org/docs/current/role-membership.html), [Privileges](https://www.postgresql.org/docs/current/ddl-priv.html), [Schemas and privileges](https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PRIV), [ALTER DEFAULT PRIVILEGES](https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html), and [Row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
