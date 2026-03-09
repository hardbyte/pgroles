---
title: Profiles & schemas
description: Use profiles to define reusable privilege templates that expand across multiple schemas.
---

Profiles are the key abstraction in pgroles for managing privileges at scale. Instead of writing grants for every role-schema combination, define a profile once and bind it to multiple schemas. {% .lead %}

---

## Defining profiles

A profile is a reusable template that defines what grants and default privileges a role should have on a schema:

```yaml
profiles:
  editor:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        on: { type: sequence, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
      - privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence

  viewer:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT]
        on: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table
```

Note that the schema name is **not specified** in profile grants -- it gets filled in during expansion.

## Common application bundles

For application writer roles, table privileges rarely stand alone. If the application inserts into identity or serial-backed tables, it usually also needs sequence privileges. If the schema has trigger-driven routines, it often needs `EXECUTE` on functions too.

This is a good default bundle for an application writer profile:

```yaml
profiles:
  app_writer:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        on: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        on: { type: sequence, name: "*" }
      - privileges: [EXECUTE]
        on: { type: function, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        on_type: table
      - privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - privileges: [EXECUTE]
        on_type: function
```

Use a narrower profile if you know the role does not need writes, sequence access, or function execution. The important point is to make the bundle explicit instead of granting tables and forgetting the related object types.

## Binding profiles to schemas

The `schemas` section binds profiles to schemas:

```yaml
schemas:
  - name: inventory
    profiles: [editor, viewer]
  - name: catalog
    profiles: [viewer]
```

## What gets generated

Each `schema x profile` combination produces:

1. **A role** named `{schema}-{profile}` (e.g. `inventory-editor`, `catalog-viewer`)
2. **Grants** from the profile, scoped to the schema
3. **Default privileges** from the profile, scoped to the schema

The example above generates four roles: `inventory-editor`, `inventory-viewer`, `catalog-viewer`, plus all their associated grants and default privileges.

## Custom role naming

Override the default `{schema}-{profile}` pattern per-schema:

```yaml
schemas:
  - name: legacy_data
    profiles: [viewer]
    role_pattern: "legacy-{profile}"
```

This produces `legacy-viewer` instead of `legacy_data-viewer`.

The pattern **must** contain `{profile}`. The `{schema}` placeholder is optional.

## Profile login attribute

Profiles can specify a `login` attribute that applies to generated roles:

```yaml
profiles:
  service:
    login: true
    grants:
      - privileges: [USAGE]
        on: { type: schema }
```

By default, profile-generated roles have `login: false` (NOLOGIN).

## Owner overrides

Each schema binding can override the `default_owner` for its default privileges:

```yaml
default_owner: app_owner

schemas:
  - name: inventory
    profiles: [editor]
  - name: legacy
    profiles: [editor]
    owner: legacy_admin
```

Here, `inventory`'s default privileges use `app_owner`, while `legacy`'s use `legacy_admin`.

## Combining profiles with one-off definitions

Profile-generated roles and one-off roles coexist in the same manifest. You can then reference profile-generated roles in memberships:

```yaml
profiles:
  editor:
    grants:
      - privileges: [USAGE]
        on: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on: { type: table, name: "*" }

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: app-service
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: app-service
```

{% callout title="Duplicate role names" %}
If a profile expansion produces a role name that matches a one-off role definition, pgroles will report an error. Each role name must be unique across both profile-generated and one-off roles.
{% /callout %}
