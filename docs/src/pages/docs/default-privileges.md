---
title: Default privileges
description: Configure privileges that are automatically granted on newly created objects.
---

Default privileges control what privileges are automatically granted when new objects are created. This ensures that roles get access to tables, sequences, and functions created after the initial grant. {% .lead %}

---

## Why default privileges?

Wildcard grants like `GRANT SELECT ON ALL TABLES IN SCHEMA` only apply to objects that exist **right now**. When a migration creates a new table, existing roles won't have access to it unless you re-run the grant.

`ALTER DEFAULT PRIVILEGES` solves this by configuring automatic grants for future objects.

## Syntax

```yaml
default_owner: app_owner

default_privileges:
  - owner: app_owner
    schema: public
    grant:
      - role: analytics
        privileges: [SELECT]
        on_type: table
      - role: analytics
        privileges: [USAGE, SELECT]
        on_type: sequence
```

This generates:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE "app_owner"
  IN SCHEMA "public"
  GRANT SELECT ON TABLES TO "analytics";

ALTER DEFAULT PRIVILEGES FOR ROLE "app_owner"
  IN SCHEMA "public"
  GRANT SELECT, USAGE ON SEQUENCES TO "analytics";
```

## Owner context

The `owner` field specifies which role's object creation triggers the default grant. This is typically the role that runs migrations or creates tables (e.g. `pgloader_pg`, `app_owner`).

If `owner` is omitted on a default privilege entry, the top-level `default_owner` is used. If neither is set, it falls back to `postgres`.

## Default privileges in profiles

When using profiles, default privileges are expanded automatically:

```yaml
profiles:
  viewer:
    grants:
      - privileges: [SELECT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [viewer]
```

This generates a default privilege rule for `inventory-viewer` on tables in the `inventory` schema, using the `default_owner` as the owner context.

{% callout title="Pair wildcards with defaults" %}
It's good practice to pair wildcard grants (`name: "*"`) with matching default privileges. The wildcard covers existing objects; the default privilege covers future ones.
{% /callout %}

{% callout title="Tables are not enough" %}
If a role writes to tables created by migrations, check whether it also needs sequence and function defaults. Identity/serial-backed inserts typically need sequence access, and trigger-driven schemas often need `EXECUTE` on functions too.
{% /callout %}
