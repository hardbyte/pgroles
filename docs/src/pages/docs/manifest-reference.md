---
title: Manifest reference
description: Complete reference for the pgroles YAML manifest schema.
---

Complete field reference for pgroles manifests and CLI bundle files. {% .lead %}

---

## Top-level fields

All top-level manifest fields are optional:

```yaml
default_owner: app_migrator      # Owner for ALTER DEFAULT PRIVILEGES
auth_providers: []                # Cloud IAM provider declarations
profiles: {}                      # Reusable privilege templates
schemas: []                       # Managed schemas and schema-profile bindings
roles: []                         # Role definitions
grants: []                        # Object privilege grants
default_privileges: []            # Default privilege rules
memberships: []                   # Role membership edges
retirements: []                   # Safe role removal workflows
```

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

The `default_owner` field specifies which role is used as the owner context for `ALTER DEFAULT PRIVILEGES` statements. This is typically the role that creates objects in your database.

```yaml
default_owner: app_migrator
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

| Field | Type | Default | Description |
|---|---|---|---|
| `login` | bool | `false` | Login attribute for generated roles |
| `inherit` | bool | `true` | Inherit attribute for generated roles |
| `grants` | list[grant template] | `[]` | Grants expanded into each bound schema |
| `default_privileges` | list[default privilege template] | `[]` | Default privileges expanded into each bound schema |

The generated role attributes apply only to roles created from `schema x profile` expansion. One-off roles under `roles:` still declare their own attributes directly.

## schemas

The `schemas` section declares schemas pgroles should manage and binds profiles to those schemas.

```yaml
schemas:
  - name: inventory
    owner: app_owner
    profiles: [editor, viewer]
```

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | *required* | Schema name |
| `profiles` | list[string] | `[]` | Profiles to expand for this schema |
| `owner` | string | `default_owner` | Desired schema owner; if omitted and `default_owner` is unset, pgroles only ensures the schema exists |
| `role_pattern` | string | `"{schema}-{profile}"` | Naming pattern for profile-generated roles |

When a schema is declared under `schemas:`, pgroles can create it if it does not exist and can converge its owner with `ALTER SCHEMA ... OWNER TO ...`. pgroles does not drop schemas or reassign ownership of objects inside the schema.

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
| `password` | object | *none* | Password source |
| `password_valid_until` | string | *none* | Password expiration (ISO 8601) |

Roles with `login: true` can declare a password source. The password value is never stored in the manifest; it is resolved at apply time from an environment variable in CLI mode or from a Kubernetes Secret in operator mode.

Only `login: true` roles may have a password. Declaring a password on a non-login role is a validation error.

{% callout type="note" title="Passwords and drift detection" %}
Because PostgreSQL does not expose password hashes for comparison, password changes always appear in the plan. The `diff --exit-code` flag treats password-only changes as non-structural; they do not trigger exit code 2.
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

The `object` field specifies the grant target:

| Field | Description |
|---|---|
| `type` | Object type |
| `schema` | Schema name; required for most types except `schema` and `database` |
| `name` | Object name, `"*"` for all objects, or omit for schema-level grants |

Supported object `type` values: `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, `type`.

pgroles also accepts a quoted legacy `"on"` key when parsing older manifests, but `object` is the supported spelling for new manifests and generated output.

## default_privileges

Default privileges configure what happens when new objects are created:

```yaml
default_privileges:
  - owner: app_migrator
    schema: app
    grant:
      - role: app_migrator
        privileges: [SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER]
        on_type: table
      - role: app_migrator
        privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - role: analytics
        privileges: [SELECT]
        on_type: table
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
| `inherit` | `true` | Member inherits the role's privileges; omit for PostgreSQL default behavior |
| `admin` | `false` | Member can administer the role |

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

## Bundle mode

The CLI can compose a bundle from one root file plus multiple scoped policy documents. Use this when different teams own different parts of the same database policy.

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

| Field | Description |
|---|---|
| `policy.name` | Human-readable source label used in conflict and plan output |
| `scope` | The ownership boundary this document is allowed to manage |

Schema scope is split into explicit facets:

| Facet | Description |
|---|---|
| `owner` | Manage schema creation and ownership convergence |
| `bindings` | Manage profile expansion, grants, and default privileges tied to the schema |

Two source documents may reference the same schema only when they manage disjoint facets. If two documents claim the same role, grant, default-privilege rule, membership selector, or schema facet, composition fails before any database inspection begins.
