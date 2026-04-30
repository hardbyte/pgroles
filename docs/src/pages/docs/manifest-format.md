---
title: Manifest format
description: Complete reference for the pgroles YAML manifest schema.
---

A pgroles manifest is a YAML file that declares the desired state of your PostgreSQL roles, schemas, grants, default privileges, and memberships. {% .lead %}

---

## Top-level fields

```yaml
default_owner: pgloader_pg       # Owner for ALTER DEFAULT PRIVILEGES
auth_providers: []                # Cloud IAM provider declarations
profiles: {}                      # Reusable privilege templates
schemas: []                       # Managed schemas and schema-profile bindings
roles: []                         # Role definitions
grants: []                        # Object privilege grants
default_privileges: []            # Default privilege rules
memberships: []                   # Role membership edges
```

All fields are optional. A minimal manifest might only define `roles` and `grants`.

## Bundle mode

The CLI can also compose a **bundle** from one root file plus multiple scoped policy documents:

```yaml
# pgroles.bundle.yaml
shared:
  default_owner: app_owner
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
sources:
  - file: platform.yaml
  - file: app.yaml
```

Each source file is a `PolicyFragment`:

```yaml
# platform.yaml
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]

roles:
  - name: app_owner

schemas:
  - name: inventory
    owner: app_owner
```

```yaml
# app.yaml
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]

schemas:
  - name: inventory
    profiles: [editor]
```

Bundle composition is currently a CLI/core feature. The Kubernetes operator still reconciles a single `PostgresPolicy` resource.

### Shared bundle fields

| Field | Description |
|---|---|
| `shared.default_owner` | Default owner context shared across source documents |
| `shared.auth_providers` | Shared auth provider metadata |
| `shared.profiles` | Shared profile registry used by source documents |
| `sources` | Relative file paths to policy documents that will be composed together |

### Policy fragment fields

Each source document adds two fields on top of the normal manifest content:

| Field | Description |
|---|---|
| `policy.name` | Human-readable source label used in conflict and plan output |
| `scope` | The ownership boundary this document is allowed to manage |

### Scoped schema facets

Schema scope is split into explicit facets:

| Facet | Description |
|---|---|
| `owner` | Manage schema creation and ownership convergence |
| `bindings` | Manage profile expansion, grants, and default privileges tied to the schema |

Two source documents may reference the same schema only when they manage disjoint facets. If two documents claim the same role, grant, default-privilege rule, membership selector, or schema facet, composition fails before any database inspection begins.

## auth_providers

Declare cloud authentication providers to document how IAM-mapped roles connect to the database. This is currently informational metadata used for validation and documentation purposes.

```yaml
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
  - type: alloydb_iam
    project: my-gcp-project
    cluster: analytics-prod
  - type: rds_iam
    region: us-east-1
  - type: azure_ad
    tenant_id: "00000000-0000-0000-0000-000000000000"
  - type: supabase
    project_ref: abcd1234
  - type: planet_scale
    organization: my-org
```

Supported provider types:

| Type | Description |
|---|---|
| `cloud_sql_iam` | Google Cloud SQL IAM authentication. Optional `project` field. |
| `alloydb_iam` | Google AlloyDB IAM authentication. Optional `project` and `cluster` fields. |
| `rds_iam` | AWS RDS/Aurora IAM authentication. Optional `region` field. |
| `azure_ad` | Azure Active Directory authentication. Optional `tenant_id` field. |
| `supabase` | Supabase PostgreSQL metadata. Optional `project_ref` field. |
| `planet_scale` | PlanetScale PostgreSQL metadata. Optional `organization` field. |

{% callout type="note" title="Managed service metadata is intentionally narrow" %}
The `auth_providers` block models the provider types listed above, but not every variant has provider-specific runtime behavior yet. Today the privilege-warning path has explicit detection for RDS/Aurora, Cloud SQL, AlloyDB, and Azure. Supabase and PlanetScale PostgreSQL entries are currently documentation and validation metadata.
{% /callout %}

## default_owner

The `default_owner` field specifies which role is used as the owner context for `ALTER DEFAULT PRIVILEGES` statements. This is typically the role that creates objects in your database (e.g. a migration runner or loader role).

```yaml
default_owner: pgloader_pg
```

Individual schemas can override this with their own `owner` field.

## profiles

Profiles are reusable templates that expand into concrete roles, grants, and default privileges when bound to schemas.

```yaml
profiles:
  editor:
    login: false
    inherit: false
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
```

### Profile fields

| Field | Type | Default | Description |
|---|---|---|---|
| `login` | bool | `false` | Login attribute for generated roles |
| `inherit` | bool | `true` | Inherit attribute for generated roles |
| `grants` | list[grant template] | `[]` | Grants expanded into each bound schema |
| `default_privileges` | list[default privilege template] | `[]` | Default privileges expanded into each bound schema |

The generated role attributes apply only to roles created from `schema x profile` expansion. One-off roles under `roles:` still declare their own attributes directly.

## schemas

The `schemas` section serves two related purposes:

- declare schemas pgroles should manage
- bind profiles to those schemas so profile-generated roles and grants are expanded

```yaml
schemas:
  - name: inventory
    owner: app_owner
    profiles: [editor, viewer]

  - name: cdc
    owner: cdc_owner
    profiles: []
```

### Schema fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | *required* | Schema name |
| `profiles` | list[string] | `[]` | Profiles to expand for this schema |
| `owner` | string | `default_owner` | Desired schema owner; if omitted and `default_owner` is unset, pgroles only ensures the schema exists |
| `role_pattern` | string | `"{schema}-{profile}"` | Naming pattern for profile-generated roles |

### Schema ownership and creation

When a schema is declared under `schemas:`:

- pgroles can create it if it does not exist
- pgroles can converge its owner with `ALTER SCHEMA ... OWNER TO ...`
- pgroles does not manage dropping schemas
- pgroles does not reassign ownership of objects inside the schema

If a schema is only referenced from top-level `grants:` or `default_privileges:` and is not declared under `schemas:`, it must already exist.

{% callout type="note" title="Additive mode and schema bindings" %}
In `additive` mode, pgroles still creates missing generated roles and grants, but it does not rewrite attributes or comments on pre-existing roles. If a generated role already exists with different attributes, additive mode leaves it unchanged until you switch to a mode that allows full convergence.
{% /callout %}

### Declared vs referenced example

```yaml
schemas:
  - name: app_managed
    owner: app_owner
    profiles: []

grants:
  - role: reporting
    privileges: [USAGE]
    object: { type: schema, name: app_managed }

  - role: reporting
    privileges: [SELECT]
    object: { type: table, schema: existing_warehouse, name: "*" }
```

In this example:

- `app_managed` is declared under `schemas:`, so pgroles can create it and set its owner.
- `existing_warehouse` is only referenced from a top-level grant, so it must already exist before `apply` runs.

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
    password:
      from_env: APP_SERVICE_PASSWORD
    password_valid_until: "2026-12-31T00:00:00Z"
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
| `password` | object | *none* | Password source (see below) |
| `password_valid_until` | string | *none* | Password expiration (ISO 8601) |

Unspecified attributes use PostgreSQL defaults.

### Passwords

Roles with `login: true` can declare a password source. The password value is never stored in the manifest — it is resolved at apply time from an environment variable (CLI) or a Kubernetes Secret (operator).

```yaml
roles:
  - name: app-service
    login: true
    password:
      from_env: APP_SERVICE_PASSWORD   # CLI: read from this env var
    password_valid_until: "2026-12-31T00:00:00Z"
```

- `password.from_env` — the environment variable name containing the password (CLI mode).
- `password_valid_until` — an ISO 8601 timestamp (e.g. `"2025-12-31T00:00:00Z"`) that sets the PostgreSQL `VALID UNTIL` attribute on the role. The timestamp must include a date, time, and timezone indicator.

Only `login: true` roles may have a password. Declaring a password on a non-login role is a validation error.

{% callout type="note" title="Passwords and drift detection" %}
Because PostgreSQL does not expose password hashes for comparison, password changes always appear in the plan. The `diff --exit-code` flag treats password-only changes as non-structural — they will **not** trigger exit code 2.
{% /callout %}

{% callout type="warning" title="Password values are never logged" %}
pgroles redacts password values in all log output, dry-run SQL, and operator status fields. The actual password is only used in the `ALTER ROLE ... PASSWORD` statement sent to PostgreSQL inside the apply transaction.
{% /callout %}

## grants

Grants define object privileges:

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
  - role: analytics
    privileges: [USAGE]
    object: { type: schema, name: public }
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
```

### Object target

The `object` field specifies the grant target:

| Field | Description |
|---|---|
| `type` | Object type (see below) |
| `schema` | Schema name (required for most types except `schema` and `database`) |
| `name` | Object name, `"*"` for all objects, or omit for schema-level grants |

pgroles also accepts a quoted legacy `"on"` key when parsing older manifests, but `object` is the supported spelling for new manifests and generated output.

### Object types

Supported values for `type`: `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, `type`.

### Wildcard grants

Use `name: "*"` to grant on all current objects of a type in a schema. pgroles
expands relation wildcards safely by object type, so `table`, `view`, and
`materialized_view` privileges do not bleed across each other.

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
| `inherit` | `true` | Member inherits the role's privileges (optional, omit for default) |
| `admin` | `false` | Member can administer the role (optional, omit for default) |

## Convergent model

{% callout type="warning" title="pgroles is convergent" %}
The manifest represents the **entire desired state**. Roles, grants, default privileges, and memberships that exist in the database but are absent from the manifest will be dropped or revoked. Declared schemas are created and their owner may be converged, but schemas are not dropped automatically. Only declare roles and schemas that pgroles should manage.
{% /callout %}

## retirements

When removing a role that owns objects, declare a retirement workflow so pgroles can safely clean up before dropping it:

```yaml
retirements:
  - role: legacy_app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `role` | string | *required* | The role to retire and ultimately drop |
| `reassign_owned_to` | string | *none* | Successor role for `REASSIGN OWNED BY ... TO ...` |
| `drop_owned` | bool | `false` | Run `DROP OWNED BY` before dropping the role |
| `terminate_sessions` | bool | `false` | Terminate other active sessions for the role before dropping it |

Retired roles are included in the inspection scope even though they are absent from the desired role list. The generated plan inserts session termination, `REASSIGN OWNED`, and/or `DROP OWNED` immediately before the `DROP ROLE` statement.

A retirement entry cannot reference a role that is also listed in `roles` (that would be contradictory), and a role cannot reassign ownership to itself.
