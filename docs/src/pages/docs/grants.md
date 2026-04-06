---
title: Grants & privileges
description: How pgroles manages object privileges via GRANT and REVOKE statements.
---

Grants define what privileges a role has on database objects. pgroles supports granting on specific objects, all objects of a type in a schema, schemas themselves, and databases. {% .lead %}

---

## Grant syntax

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object:
      type: table
      schema: public
      name: "*"
```

The preferred key is `object`. pgroles still accepts a quoted legacy `"on"` key when parsing older manifests, but new manifests should use `object` to avoid YAML 1.1 boolean coercion.

## Privilege types

| Privilege | Applies to |
|---|---|
| `SELECT` | tables, views, sequences |
| `INSERT` | tables |
| `UPDATE` | tables, sequences |
| `DELETE` | tables |
| `TRUNCATE` | tables |
| `REFERENCES` | tables |
| `TRIGGER` | tables |
| `EXECUTE` | functions |
| `USAGE` | schemas, sequences, types |
| `CREATE` | schemas, databases |
| `CONNECT` | databases |
| `TEMPORARY` | databases |

## Grant targets

### Schema-level

Grant privileges on the schema itself (e.g. `USAGE` to allow accessing objects within it):

```yaml
grants:
  - role: analytics
    privileges: [USAGE]
    object: { type: schema, name: public }
```

Generates: `GRANT USAGE ON SCHEMA "public" TO "analytics";`

### Database-level

```yaml
grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
```

Generates: `GRANT CONNECT ON DATABASE "mydb" TO "analytics";`

### Wildcard (all objects of a type in schema)

Use `name: "*"` to grant on all existing objects of a type:

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
```

pgroles expands wildcard relation grants against the current objects of the
requested type in that schema. That keeps `table`, `view`, and
`materialized_view` grants scoped correctly instead of letting one subtype
touch the others.

### Specific object

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: users }
```

Generates: `GRANT SELECT ON TABLE "public"."users" TO "analytics";`

## Privilege merging

If multiple grant entries target the same role and object, their privileges are merged:

```yaml
grants:
  - role: app
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
  - role: app
    privileges: [INSERT, UPDATE]
    object: { type: table, schema: public, name: "*" }
```

This is equivalent to granting `SELECT, INSERT, UPDATE` on all tables.

## Convergent revocation

Privileges present in the database but absent from the manifest are revoked. If a role currently has `DELETE` on a table but your manifest only grants `SELECT`, pgroles will generate a `REVOKE DELETE` statement.
