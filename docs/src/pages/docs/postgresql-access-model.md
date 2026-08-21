---
title: How PostgreSQL access works
description: Run the same table query as Alice and Mallory, then watch one schema grant change PostgreSQL's decision.
---

Alice and Mallory run the same query. One gets rows; the other gets an error. {% .lead %}

{% postgres-permission-lab /%}

## The rule to remember

**PostgreSQL must be able to reach the schema and authorize the table operation.**

The login role changes who PostgreSQL evaluates. Schema `USAGE` makes `app.orders` reachable; table `SELECT` authorizes reading its rows. Neither grant implies the other.

## Make the access path durable

Direct grants make the first lesson easy to see. In production, repeating them for every person and workload becomes difficult to review and easy to drift. A capability role gives the permissions one name, then membership decides who receives them.

{% production-role-shape-diagram /%}

The reader path and owner are explicit in pgroles policy:

```yaml
default_owner: app_owner

roles:
  - name: alice
    login: true
  - name: mallory
    login: true
  - name: orders_reader
  - name: app_owner

grants:
  - role: orders_reader
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: orders_reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: orders }

memberships:
  - role: orders_reader
    members:
      - name: alice
```

This policy replaces the direct teaching grants from the lesson. Alice moves behind `orders_reader`; Mallory's direct `SELECT` becomes undeclared drift. pgroles can show the exact SQL needed to converge that intent and keep the reusable access path intact.

## Continue from here

The next lesson replaces direct grants with a nested hierarchy, then changes `INHERIT`, uses `SET ROLE`, and delegates membership administration.

{% quick-links %}
{% quick-link title="Build a role hierarchy" description="Compose reusable roles and control how their privileges flow." icon="presets" href="/docs/postgresql-role-hierarchy" /%}
{% quick-link title="Grants & privileges" description="See the complete pgroles object-grant model." icon="plugins" href="/docs/grants" /%}
{% quick-link title="Default privileges" description="Cover objects that will be created later." icon="installation" href="/docs/default-privileges" /%}
{% quick-link title="Limits and boundaries" description="Understand PUBLIC, row security, authentication, and unmanaged access paths." icon="lightbulb" href="/docs/limitations" /%}
{% /quick-links %}

For PostgreSQL's authoritative model, see [Database roles](https://www.postgresql.org/docs/current/user-manag.html), [Privileges](https://www.postgresql.org/docs/current/ddl-priv.html), and [Schemas and privileges](https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PRIV).
