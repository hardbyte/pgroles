---
title: How PostgreSQL access works
description: A teaching guide to roles, memberships, ownership, schemas, object privileges, default privileges, PUBLIC, and row security — with an interactive access lab.
---

PostgreSQL access is not one grant. It is a path from the identity that opened a connection, through role membership and namespace checks, to an object's privileges and any row policy. This guide builds that path one gate at a time. {% .lead %}

---

## What you will learn

By the end, you should be able to answer five questions without guessing:

- Which role authenticated, and which role is PostgreSQL checking *now*?
- Is a privilege direct, inherited, implicit through ownership, or available to every role through `PUBLIC`?
- Does a failure come from the database, schema, object, sequence, or row-policy layer?
- Will a grant cover objects created tomorrow, and whose defaults decide that?
- Which parts of the answer pgroles manages, observes, or deliberately leaves outside its model?

We will keep one cast throughout: `alice` is a login role, `reporting` is a capability role, `app_owner` owns objects, and the objects live in schema `app`.

{% postgres-permission-lab /%}

{% callout type="note" title="Why this uses PGlite rather than pgrust today" %}
We reviewed [pgrust](https://github.com/malisper/pgrust) and first embedded its hosted terminal. A single-click lesson needs a callable browser API, but the hosted cross-origin page does not expose one to its parent. More importantly, its current browser build does not yet enforce separate login identities or RLS accurately enough for those lessons. The lab therefore uses [PGlite](https://pglite.dev/), which compiles upstream PostgreSQL to WebAssembly and exposes a same-page execution API. We ran this complete sequence against PGlite's PostgreSQL 18.3 build. The browser has one bootstrap session as `postgres` and uses `SET ROLE` to demonstrate effective identities; it teaches authorization, not `pg_hba.conf`, login authentication, or concurrent sessions. Verify production decisions against a supported server and the inspection queries later in this guide.
{% /callout %}

## Start with one primitive: the role

PostgreSQL does not have separate "user" and "group" object types. It has **roles**. A role with `LOGIN` can begin a session; a role without `LOGIN` is usually used as an owner or a reusable bundle of privileges.

```sql
CREATE ROLE alice LOGIN;
CREATE ROLE reporting NOLOGIN;
CREATE ROLE app_owner NOLOGIN;
```

Those three roles are cluster-wide: they are visible to every database in the PostgreSQL cluster. Most things they can access — schemas, tables, sequences, routines, and their ACLs — belong to one database.

This is why a common design separates responsibilities:

| Role kind | Typical purpose | Usually logs in? |
|---|---|---|
| Login identity | A human, workload, or automation connection | Yes |
| Capability role | `app_read`, `app_write`, `app_admin` | No |
| Owner role | Stable ownership for a schema and its objects | No |

`LOGIN`, `CREATEDB`, `CREATEROLE`, `REPLICATION`, and `BYPASSRLS` are role attributes. They are not ordinary object privileges, and they are not inherited merely because one role is a member of another. To use an attribute on a granted role, the session must normally `SET ROLE` to it.

In pgroles, all three are declared under `roles`; `login: true` is what makes the first one a login identity:

```yaml
roles:
  - name: alice
    login: true
  - name: reporting
  - name: app_owner
```

## The two names in every session

After login, ask PostgreSQL who authenticated and whose permissions are active:

```sql
SELECT session_user, current_user;
```

- `session_user` is normally the role that authenticated. It stays `alice` after `SET ROLE`.
- `current_user` is the effective execution identity. PostgreSQL uses it for permission checks and for ownership of newly created objects.

```sql
GRANT reporting TO alice WITH INHERIT FALSE, SET TRUE;

SET ROLE reporting;
SELECT session_user, current_user;
-- alice | reporting

RESET ROLE;
SELECT session_user, current_user;
-- alice | alice
```

`SET ROLE` is a switch, not an accumulation. After becoming `reporting`, the session uses the privileges held or inherited by `reporting`; it does not keep every privilege held only by `alice`.

`SECURITY DEFINER` routines also change `current_user` while they execute: the effective identity becomes the routine owner. That can be useful, but it makes secure ownership and a safe `search_path` essential. pgroles can manage `EXECUTE` on routines, but it does not define routine bodies or their security mode.

## Access is a chain of gates

For an ordinary `SELECT app.orders`, use this decision path:

1. **Authentication maps the client to a login role.** `pg_hba.conf`, a cloud IAM integration, certificates, or another provider performs this step. Authentication does not create object privileges.
2. **The database accepts the connection.** The role needs `CONNECT` on the database. PostgreSQL commonly grants this to `PUBLIC` by default. The check happens when a connection is established: revoking `CONNECT` blocks new sessions but does not terminate sessions that are already connected.
3. **PostgreSQL chooses the effective identity.** Start with `current_user`, then include privileges available through `INHERIT TRUE` membership paths.
4. **An authorization path supplies the privilege.** A direct ACL, an inherited role, ownership, or `PUBLIC` can provide it. Superusers bypass ordinary permission checks.
5. **The schema is reachable.** A qualified name such as `app.orders` still requires `USAGE` on schema `app`.
6. **The object allows the operation.** The role normally needs `SELECT` on the table. Column-level `SELECT` can instead authorize a query limited to the granted columns; pgroles detects but does not manage those column ACLs. A different operation or object type has a different privilege vocabulary.
7. **Row security may narrow the result.** If RLS is active, policies decide which rows an otherwise permitted command can see or change.

PostgreSQL has no general `DENY` ACL that overrides every grant. Access is additive. Revoking a direct grant from `alice` does not remove access if `alice` can still reach the privilege through `reporting`, ownership, or `PUBLIC`.

{% callout type="warning" title="Desired ACLs are not the same as effective access" %}
pgroles converges the direct roles, memberships, and ACLs in its managed graph. An omitted grant does not prove that a role has no effective access: another membership path, ownership, `PUBLIC`, row-policy behavior, or an unmodeled privilege can still matter.
{% /callout %}

## Database, schema, and object privileges do different jobs

Create the example as a privileged bootstrap role:

```sql
CREATE DATABASE appdb OWNER app_owner;
\c appdb

SET ROLE app_owner;
CREATE SCHEMA app AUTHORIZATION app_owner;
CREATE TABLE app.orders (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  account_name text NOT NULL,
  total_cents bigint NOT NULL
);
RESET ROLE;
```

Now give `reporting` only a table privilege:

```sql
GRANT SELECT ON app.orders TO reporting;
GRANT reporting TO alice;
```

Alice can still fail at the schema boundary. The complete read path is:

```sql
GRANT CONNECT ON DATABASE appdb TO reporting;
GRANT USAGE ON SCHEMA app TO reporting;
GRANT SELECT ON app.orders TO reporting;
```

Think of the three grants this way:

| Privilege | Question it answers | What it does not imply |
|---|---|---|
| Database `CONNECT` | May this role open a session to this database? | Access to schemas or objects |
| Schema `USAGE` | May this role resolve objects in this namespace? | `SELECT`, `INSERT`, or `EXECUTE` inside it |
| Schema `CREATE` | May this role create objects in this namespace? | Ownership of existing objects |
| Table `SELECT` | May this role read rows from this table or view? | Schema `USAGE` or sequence access |
| Table `INSERT` | May this role insert rows? | Permission to call a sequence used by a default |
| Sequence `USAGE` | May this role use `currval`/`nextval` as PostgreSQL defines them? | `INSERT` on a table that consumes the value |
| Routine `EXECUTE` | May this role call the function or procedure? | Access to objects used by an invoker-security routine |

The `search_path` only changes how an unqualified name is resolved. It grants nothing. A role can have `app` in its search path and still lack `USAGE` on it.

The corresponding pgroles policy keeps every gate visible:

```yaml
roles:
  - name: alice
    login: true
  - name: reporting

grants:
  - role: reporting
    privileges: [CONNECT]
    object: { type: database, name: appdb }
  - role: reporting
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: reporting
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }

memberships:
  - role: reporting
    members:
      - name: alice
```

## Membership is a directed edge

Read `GRANT reporting TO alice` as:

> Alice is a member of reporting, so Alice may use reporting according to the membership options.

The privilege flows from the granted role to the member, not the other way around. Capability roles can themselves be members of other roles, and PostgreSQL follows nested membership paths. It rejects cycles.

On PostgreSQL 16 and later, one membership edge has three independent options:

| Option | Question |
|---|---|
| `INHERIT` | Are the granted role's ordinary privileges immediately usable? |
| `SET` | May the session run `SET ROLE` to the granted role through this path? |
| `ADMIN` | May the member grant or revoke membership in the granted role? |

This creates useful combinations:

```sql
-- Privileges are active automatically; SET ROLE is also allowed by default.
GRANT reporting TO alice WITH INHERIT TRUE;

-- Privileges are dormant until Alice deliberately becomes reporting.
GRANT reporting TO alice WITH INHERIT FALSE, SET TRUE;

-- Privileges are inherited, but Alice cannot become reporting.
GRANT reporting TO alice WITH INHERIT TRUE, SET FALSE;
```

pgroles models `inherit` and `admin` on a membership. It does not currently inspect or converge the PostgreSQL 16 `SET` option. A membership created by pgroles gets PostgreSQL's default `SET TRUE`. Changing `inherit` or `admin` also makes pgroles revoke and recreate the edge, which can turn a manually hardened `SET FALSE` back into `SET TRUE`. Do not rely on `SET FALSE` remaining intact on a pgroles-managed membership.

Use PostgreSQL itself to distinguish the three questions:

```sql
SELECT
  pg_has_role('alice', 'reporting', 'MEMBER') AS is_member,
  pg_has_role('alice', 'reporting', 'USAGE')  AS inherits_now,
  pg_has_role('alice', 'reporting', 'SET')    AS can_set_role;
```

## Ownership is more than an ACL entry

The owner is the role with authority over an object. Owners can alter or drop their objects and inherently hold all grant options for them. An ACL display can look as though an owner's ordinary privileges were revoked, but ownership still carries powers that a plain grantee does not have.

That is why a stable, `NOLOGIN` owner role is a strong default:

```sql
ALTER SCHEMA app OWNER TO app_owner;
ALTER TABLE app.orders OWNER TO app_owner;
GRANT app_owner TO migration_job WITH INHERIT FALSE, SET TRUE;
```

The migration job can `SET ROLE app_owner` while running DDL. Runtime identities receive only the object privileges they need and do not own the objects they use.

`WITH GRANT OPTION` is another, narrower kind of delegation: it lets a grantee pass an object privilege onward. pgroles checks whether its own executor can grant missing wildcard privileges, but grant options for application roles are not part of the manifest's desired state and are not converged.

## Existing objects and future objects are separate problems

This SQL touches only tables that exist when it runs:

```sql
GRANT SELECT ON ALL TABLES IN SCHEMA app TO reporting;
```

Likewise, a pgroles wildcard is reconciled against current matching objects. pgroles will discover a later table on its next run, but there can be a gap between object creation and reconciliation.

Default privileges change the ACL stamped onto a new object:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner
  IN SCHEMA app
  GRANT SELECT ON TABLES TO reporting;
```

Three rules prevent most default-privilege surprises:

1. **They are future-only.** They do not repair existing objects.
2. **They belong to the creator role.** Defaults for `app_owner` apply only when `current_user` is `app_owner` at creation time. Membership in `app_owner` is not enough unless the creator actually uses `SET ROLE app_owner`.
3. **Global and per-schema defaults are layered.** Schema defaults add to global defaults. A schema-scoped revoke cannot subtract a privilege supplied by a global default.

Pair the two halves in pgroles:

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

pgroles currently manages schema-scoped defaults granted to named roles. It does not manage global default ACLs or default privileges granted to `PUBLIC`. This matters especially for routines because PostgreSQL grants `EXECUTE` to `PUBLIC` by default; removing that global default cannot be expressed as a schema-only revoke.

## PUBLIC means every role

`PUBLIC` is a pseudo-role, not a row in `pg_roles`, and every role implicitly participates in it. PostgreSQL commonly supplies these built-in defaults:

- `CONNECT` and `TEMPORARY` on databases
- `EXECUTE` on functions and procedures
- `USAGE` on languages and types
- `USAGE` on the `public` schema in a new database

Defaults can vary with object type, PostgreSQL version, upgrades, and previous administration. Inspect the actual database instead of assuming a pristine cluster.

`pgroles inspect` reports selected `PUBLIC` grants on the current database and its non-system schemas as **informational** output. pgroles does not model or reconcile `PUBLIC`, and that report is not a complete inventory of every object, routine, or default ACL granted to `PUBLIC`.

```sql
SELECT has_database_privilege('public', current_database(), 'CONNECT');
SELECT has_schema_privilege('public', 'app', 'USAGE');
SELECT has_function_privilege('public', 'app.some_function()', 'EXECUTE');
```

Revoking from `PUBLIC` affects every role. Treat it as a deliberate database baseline, not as a cleanup side effect of one application's policy.

## Row security is a second authorization system

An object grant answers whether a statement may operate on the table. Row-level security can then restrict which rows the statement sees or changes:

```sql
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_orders ON app.orders
  FOR SELECT
  USING (account_name = current_user);
```

With `SELECT` on `app.orders`, Alice's query can succeed and return only Alice's rows. If RLS is enabled and no applicable policy exists, PostgreSQL uses default deny for rows.

Table owners normally bypass RLS unless the table uses `FORCE ROW LEVEL SECURITY`; superusers and roles with `BYPASSRLS` bypass it. This is another reason not to make an application runtime the owner of its tables.

pgroles manages the surrounding roles and ACLs, but it does not model, inspect, or apply RLS policies. Keep policies in migrations or another SQL workflow and test the combined result.

## Debug a denial with evidence

Start with identity. Do not begin by adding grants:

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

Use `psql` for the stored state:

```text
\du+ alice
\drg reporting
\dn+ app
\dp app.orders
\ddp
```

`has_*_privilege` reports effective answers, while ACLs and membership catalogs help explain the path that produced them. Keep both views: a catalog row alone can miss ownership, inheritance, or `PUBLIC`; an effective Boolean alone does not tell you why it is true.

When pgroles is in the loop, compare four evidence levels:

1. **Declared:** what the manifest says should be managed.
2. **Observed:** what `pgroles inspect` and PostgreSQL report now.
3. **Planned:** the exact SQL from `pgroles diff` or `pgroles plan`.
4. **Verified:** the application operation and negative access tests after apply.

## A production role shape

A practical application often ends up with this graph:

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

The owner does not log in. The runtime does not own objects. Human and workload identities receive capability roles. Migration automation deliberately changes to the owner while creating objects, so ownership and default privileges remain stable through credential rotation.

Before calling the design complete, test all of these:

- The intended login can connect.
- A reader can select but cannot write.
- A writer can perform sequence-backed inserts if the schema uses them.
- A runtime role cannot alter or drop the table.
- A migration identity creates objects as the intended owner.
- A newly created table has the expected ACL immediately.
- An unrelated role is denied.
- `PUBLIC`, RLS, column grants, and grant options do not create an unreviewed path.

## Where pgroles stops

pgroles is intentionally narrower than PostgreSQL's entire authorization system.

| Area | pgroles behavior |
|---|---|
| Named roles and supported attributes | Managed |
| Named-role memberships | `INHERIT` and `ADMIN` managed; PG16 `SET` not managed |
| Supported object ACLs | Managed at object level; column grants and application grant options are not managed |
| Schema-scoped default ACLs for named roles | Managed |
| Global defaults and defaults for `PUBLIC` | Not managed |
| Current-database and schema `PUBLIC` ACLs | Reported informationally, not reconciled |
| Row-level security and routine definitions | Not managed |
| Authentication and provider identity lifecycle | External; provider-owned roles can be declared `external: true` |

Read [Grants & privileges](/docs/grants), [Default privileges](/docs/default-privileges), and [Memberships](/docs/memberships) for pgroles syntax. Use [Limitations](/docs/limitations) before treating a manifest as a complete account of effective access.

The authoritative PostgreSQL references are [Database roles](https://www.postgresql.org/docs/current/user-manag.html), [Role membership](https://www.postgresql.org/docs/current/role-membership.html), [Privileges](https://www.postgresql.org/docs/current/ddl-priv.html), [Schemas and privileges](https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PRIV), [ALTER DEFAULT PRIVILEGES](https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html), and [Row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
