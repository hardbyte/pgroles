---
title: 1. The permission chain
description: Meet Acme, grant Alice the smallest working path to orders, and watch PostgreSQL evaluate schema and table privileges.
---

Alice needs Acme’s first orders report. You are the database administrator who must make it work without opening anything else. {% .lead %}

{% postgres-permission-lab /%}

## Meet the cast

- **Priya**, Acme’s founder, owns the original `app` schema and `orders` table.
- **Alice**, the first analyst, needs to read orders.
- **deploy**, Acme’s migration login, will matter when the schema starts changing.
- **reporting_app** will arrive in the next chapter.

## Keep one rule

**PostgreSQL must be able to reach the schema and authorize the object operation.**

For `SELECT * FROM app.orders`, schema `USAGE` makes the name reachable and table `SELECT` authorizes the read. `search_path` changes name lookup, not privileges. A table grant does not imply schema access, and schema access does not imply a table operation.

## The policy so far

This is the small team’s literal state: Alice receives both grants directly.

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: alice
    login: true

grants:
  - role: alice
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: alice
    privileges: [SELECT]
    object: { type: table, schema: app, name: orders }
```

It works, but every new reader would duplicate those ACL entries. The next chapter gives the permission bundle a reusable name.

{% quick-links %}
{% quick-link title="Continue: capability roles" description="Give Alice and an application the same access without copying grants." icon="presets" href="/docs/postgresql-capability-roles" /%}
{% quick-link title="Grants reference" description="See every object type and privilege pgroles manages." icon="plugins" href="/docs/grants" /%}
{% /quick-links %}
