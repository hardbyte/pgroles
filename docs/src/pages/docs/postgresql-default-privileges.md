---
title: 5. Future objects
description: Break the report with a new table, then align the creating role, ownership, existing grants, and default privileges.
---

Refunds launches. Deploy creates `app.refunds`, but the report immediately fails. Nothing removed the working grants on `orders`; the new object simply never received them. {% .lead %}

{% postgres-default-privileges-lab /%}

## Existing objects and future objects are separate problems

- A wildcard object grant covers matching objects that exist when reconciliation runs.
- A default privilege changes what a particular owner grants when that owner creates a future object.
- The migration must create the object as the same owner named by the default privilege.

The policy now pairs both halves:

```yaml {% schema="pgroles-manifest" %}
default_owner: app_owner

grants:
  - role: orders_reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }

default_privileges:
  - owner: app_owner
    scope: { type: schema, schema: app }
    grant:
      - role: orders_reader
        privileges: [SELECT]
        on_type: table
```

The wildcard repairs and maintains existing tables. The default covers tables created later by `app_owner`. Neither substitutes for the other.

**Default privileges belong to the creating role, not to the schema and not to the login that happens to run the migration.**

{% quick-links %}
{% quick-link title="Continue: offboarding" description="Use the durable owner to remove Priya without deleting her objects." icon="lightbulb" href="/docs/postgresql-offboarding" /%}
{% quick-link title="Default privileges reference" description="See schema and global scopes, PUBLIC defaults, and object types." icon="installation" href="/docs/default-privileges" /%}
{% /quick-links %}
