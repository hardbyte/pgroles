---
title: Application and migration tools
description: How pgroles fits beside ORMs, SQL migration tools, and PostgreSQL client libraries.
---

Use pgroles as the access-control layer next to your existing schema and application tooling. {% .lead %}

Most PostgreSQL stacks already have something that creates tables, indexes, functions, and application metadata. Keep using that tool for schema changes. Let pgroles own roles, memberships, grants, default privileges, and role retirement.

---

## The boundary

pgroles is intentionally not a schema migration framework. It does not create tables, rewrite indexes, manage row-level security policies, or replace an ORM's migration history.

The clean split is:

| Layer | Typical tools | Owner |
| --- | --- | --- |
| Infrastructure | Terraform, Pulumi, cloud consoles | Database instances, networking, IAM |
| Schema migrations | Alembic/SQLAlchemy | Tables, views, functions, types, extensions |
| Access control | pgroles | Roles, memberships, grants, default privileges, passwords, retirements |
| Runtime queries | SQLAlchemy, PostgreSQL client connections | Application reads and writes |

This avoids the common failure mode where every migration tool, app bootstrap script, and operator tries to issue `GRANT` statements independently.

## Recommended order

For each environment, run access control after the database exists and before application traffic relies on new privileges:

```shell
# 1. Apply schema migrations
alembic upgrade head

# 2. Apply role and privilege policy
pgroles diff -f pgroles.yaml --database-url "$DATABASE_URL"
pgroles apply -f pgroles.yaml --database-url "$DATABASE_URL"

# 3. Deploy or restart application workloads
```

If a migration creates new tables in an already-managed schema, pgroles usually has two safety nets:

- wildcard grants cover objects that already exist when pgroles runs
- default privileges cover future objects created by the configured owner

If a migration needs a brand-new schema, either declare that schema in pgroles so pgroles creates it and converges its PostgreSQL owner, or run the migration first and then apply the pgroles policy that grants access to the existing schema.

## Migration tools

### Validated DDL-owning tools

Some PostgreSQL libraries run DDL even though they are not ORMs. Treat these like schema owners, not like ordinary application clients.

Concrete DDL-owning patterns:

| Pattern | Behavior | pgroles guidance |
| --- | --- | --- |
| pg-boss queue schema | pg-boss can create a custom schema and queue through an installer role. A separate worker role can run with `migrate: false` after receiving schema/table/sequence/function grants. | Run pg-boss schema setup with an installer role, then use pgroles for worker access. Disable runtime migrations for narrow worker credentials. |
| Graphile Worker schema install | `graphile-worker --schema-only` creates the `graphile_worker` schema, tables, sequences, functions, and `jobs` view. A naive split worker with ordinary grants is not enough because Graphile applies its own row-level security policy to private tables such as `_private_tasks`. | Let Graphile Worker own and migrate its schema. Do not assume ordinary grants are enough for a separate runtime role; use the owner role or validate Graphile's restricted-role setup yourself. |
| Webhook-style table triggers | PostgreSQL table triggers and trigger functions are schema DDL. In `supabase/postgres`, a trigger function can call `net.http_post(...)` and be attached to a table trigger. | Install trigger functions and triggers through the migration/admin path. Use pgroles for the roles that access the source tables and any approved helper functions. |
| Logical-replication publication | PostgreSQL accepts publication DDL for application tables, but actual logical replication requires server WAL configuration such as `wal_level=logical`. | Manage publication setup outside pgroles. Use pgroles for replication/read roles only after validating the server's WAL configuration. |
| PostgREST-style cache reload trigger | A `ddl_command_end` event trigger can run a function that emits `NOTIFY pgrst, 'reload schema'`. | Event triggers are DDL and should be installed by an admin/migration path, not by pgroles. |
| Supabase pgmq | In `supabase/postgres`, `pgmq` is available, must be installed in schema `pgmq`, and can create queues that send and read messages. | Treat `pgmq` as extension-owned. Use pgroles for consumer access after the extension and queues exist. |
| Supabase pg_net | In `supabase/postgres`, `pg_net` is available and trigger functions can call `net.http_post(...)`. | Treat `pg_net` webhook triggers as migration-owned DDL. Use pgroles for surrounding privileges, not trigger creation. |

The safe pattern is:

1. Give the tool's installer or migrator role enough privilege to create and upgrade its own objects.
2. Let the tool create or migrate its schema.
3. Use pgroles to grant narrower runtime roles access to those objects.
4. Include default privileges for the tool-owned schema if future upgrades create new tables, sequences, or functions.

For example, a pg-boss deployment can use a schema installed by `queue_migrator`, while workers connect as `queue_worker`:

```yaml
default_owner: queue_migrator

schemas:
  - name: queue_demo
    owner: queue_migrator

roles:
  - name: queue_migrator
    login: true
  - name: queue_worker
    login: true

grants:
  - role: queue_migrator
    privileges: [CONNECT]
    object: { type: database, name: appdb }
  - role: queue_migrator
    privileges: [SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER]
    object: { type: table, schema: queue_demo, name: "*" }
  - role: queue_migrator
    privileges: [USAGE, SELECT, UPDATE]
    object: { type: sequence, schema: queue_demo, name: "*" }
  - role: queue_migrator
    privileges: [EXECUTE]
    object: { type: function, schema: queue_demo, name: "*" }
  - role: queue_worker
    privileges: [CONNECT]
    object: { type: database, name: appdb }
  - role: queue_worker
    privileges: [USAGE]
    object: { type: schema, name: queue_demo }
  - role: queue_worker
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: queue_demo, name: "*" }
  - role: queue_worker
    privileges: [USAGE, SELECT, UPDATE]
    object: { type: sequence, schema: queue_demo, name: "*" }
  - role: queue_worker
    privileges: [EXECUTE]
    object: { type: function, schema: queue_demo, name: "*" }

default_privileges:
  - owner: queue_migrator
    schema: queue_demo
    grant:
      - role: queue_migrator
        privileges: [SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER]
        on_type: table
      - role: queue_migrator
        privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - role: queue_migrator
        privileges: [EXECUTE]
        on_type: function
      - role: queue_worker
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
      - role: queue_worker
        privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - role: queue_worker
        privileges: [EXECUTE]
        on_type: function
```

Do not point pgroles at a tool-managed schema and expect it to understand that tool's internal invariants. pgroles manages privileges around those objects; the tool still owns its upgrade path.

If the installer role is managed by pgroles in `authoritative` mode, declare the privileges that role should keep on its own schema too. Otherwise pgroles may correctly identify those owner-visible privileges as undeclared drift and plan revocations.

### Alembic and SQLAlchemy

Use a migrator role such as `app_migrator` for Alembic schema changes, then let pgroles grant narrower application roles such as `app_runtime` and `app_readonly`. The runtime role should receive the table, sequence, and function privileges it needs; the read-only role should receive only read privileges.

Alembic creates a version table. If your migrator role does not have `CREATE` on `public`, configure Alembic to put that version table in the application schema, or create a dedicated migration metadata schema. Avoid granting broad `CREATE` on `public` just to satisfy the default.

## Runtime client libraries

Runtime clients should connect as application roles managed by pgroles, not as migration or installer roles.

Prefer separate roles for distinct duties:

| Role | Purpose |
| --- | --- |
| `app_migrator` | Runs schema migrations and owns created objects |
| `app_runtime` | Serves normal application traffic |
| `app_readonly` | Read-only workers, analytics jobs, or support tools |
| `pgroles_admin` | Runs pgroles with enough grant/admin authority |

This makes privilege boundaries visible in one manifest instead of scattering them across connection strings and migration scripts.

## Anti-patterns

- Do not run pgroles before migrations that create referenced schemas or objects, unless pgroles is responsible for creating those schemas.
- Do not grant broad privileges to the application runtime role just because migrations need them. Split migrator and runtime credentials.
- Do not forget that authoritative mode revokes undeclared bootstrap privileges. If a migrator needs permanent `CREATE ON DATABASE`, declare it explicitly; otherwise use it only for initial schema creation and let pgroles remove it.
- Do not keep permanent `GRANT` policy in old migration files and also manage the same grants with pgroles. Pick pgroles as the source of truth once adopted.
- Do not depend on `PUBLIC` grants for application access. pgroles does not manage `PUBLIC`, so those privileges stay outside the manifest.
- Do not give CI or code generation jobs superuser access when read-only catalog/schema access is sufficient.
