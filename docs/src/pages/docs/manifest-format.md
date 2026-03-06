---
title: Manifest format
description: Complete reference for the pgroles YAML manifest schema.
---

A pgroles manifest is a YAML file that declares the desired state of your PostgreSQL roles, grants, default privileges, and memberships. {% .lead %}

---

## Top-level fields

```yaml
default_owner: pgloader_pg       # Owner for ALTER DEFAULT PRIVILEGES
profiles: {}                      # Reusable privilege templates
schemas: []                       # Schema-profile bindings
roles: []                         # Role definitions
grants: []                        # Object privilege grants
default_privileges: []            # Default privilege rules
memberships: []                   # Role membership edges
```

All fields are optional. A minimal manifest might only define `roles` and `grants`.

## default_owner

The `default_owner` field specifies which role is used as the owner context for `ALTER DEFAULT PRIVILEGES` statements. This is typically the role that creates objects in your database (e.g. a migration runner or loader role).

```yaml
default_owner: pgloader_pg
```

Individual schemas can override this with their own `owner` field.

## roles

Each role definition specifies a PostgreSQL role and its attributes:

```yaml
roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"
  - name: app-service
    login: true
    createdb: false
    connection_limit: 10
```

### Supported attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `name` | string | *required* | Role name |
| `login` | bool | `false` | Can the role log in? |
| `superuser` | bool | `false` | Superuser privileges |
| `createdb` | bool | `false` | Can create databases |
| `createrole` | bool | `false` | Can create other roles |
| `inherit` | bool | `true` | Inherits privileges of granted roles |
| `replication` | bool | `false` | Can initiate replication |
| `bypassrls` | bool | `false` | Bypasses row-level security |
| `connection_limit` | int | `-1` (unlimited) | Max concurrent connections |
| `comment` | string | *none* | Comment on the role |

Unspecified attributes use PostgreSQL defaults.

## grants

Grants define object privileges:

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    on: { type: table, schema: public, name: "*" }
  - role: analytics
    privileges: [USAGE]
    on: { type: schema, name: public }
  - role: analytics
    privileges: [CONNECT]
    on: { type: database, name: mydb }
```

### Object target

The `on` field specifies the grant target:

| Field | Description |
|---|---|
| `type` | Object type (see below) |
| `schema` | Schema name (required for most types except `schema` and `database`) |
| `name` | Object name, `"*"` for all objects, or omit for schema-level grants |

### Object types

Supported values for `type`: `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, `type`.

### Wildcard grants

Use `name: "*"` to grant on all objects of a type in a schema. This generates `GRANT ... ON ALL TABLES IN SCHEMA` style SQL.

## default_privileges

Default privileges configure what happens when new objects are created:

```yaml
default_privileges:
  - owner: pgloader_pg
    schema: public
    grant:
      - role: analytics
        privileges: [SELECT]
        on_type: table
      - role: analytics
        privileges: [USAGE, SELECT]
        on_type: sequence
```

If `owner` is omitted, the top-level `default_owner` is used.

## memberships

Memberships declare which roles are members of other roles:

```yaml
memberships:
  - role: editors
    members:
      - name: "user@example.com"
        inherit: true
      - name: "admin@example.com"
        admin: true
```

| Field | Default | Description |
|---|---|---|
| `inherit` | `true` | Member inherits the role's privileges |
| `admin` | `false` | Member can administer the role (grant it to others) |

## Convergent model

{% callout type="warning" title="pgroles is convergent" %}
The manifest represents the **entire desired state**. Roles, grants, default privileges, and memberships that exist in the database but are absent from the manifest will be dropped or revoked. Only declare roles that pgroles should manage.
{% /callout %}

## retirements

When removing a role that owns objects, declare a retirement workflow so pgroles can safely clean up before dropping it:

```yaml
retirements:
  - role: legacy_app
    reassign_owned_to: app_owner
    drop_owned: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `role` | string | *required* | The role to retire and ultimately drop |
| `reassign_owned_to` | string | *none* | Successor role for `REASSIGN OWNED BY ... TO ...` |
| `drop_owned` | bool | `false` | Run `DROP OWNED BY` before dropping the role |

Retired roles are included in the inspection scope even though they are absent from the desired role list. The generated plan inserts `REASSIGN OWNED` and/or `DROP OWNED` immediately before the `DROP ROLE` statement.

A retirement entry cannot reference a role that is also listed in `roles` (that would be contradictory), and a role cannot reassign ownership to itself.
