---
title: Memberships
description: Manage role membership and inheritance with pgroles.
---

Memberships declare which roles are members of other roles, allowing privilege inheritance and role-based access patterns. {% .lead %}

---

## Syntax

```yaml
memberships:
  - role: inventory-editor
    members:
      - name: app-service
      - name: "deploy@example.com"
        admin: true
```

## Member options

| Field | Default | Description |
|---|---|---|
| `name` | *required* | The member role name |
| `inherit` | `true` | Whether the member inherits the role's privileges (omit for default) |
| `admin` | `false` | Whether the member can grant the role to others (omit for default) |

Both `inherit` and `admin` can be omitted entirely — they default to `true` and `false` respectively. Omitting default values is recommended because it keeps the Kubernetes resource minimal and avoids perpetual diffs in GitOps tools like ArgoCD.

## Generated SQL

pgroles generates version-appropriate membership syntax. On PostgreSQL 16+:

```sql
GRANT "inventory-editor" TO "app-service" WITH INHERIT TRUE;
GRANT "inventory-editor" TO "deploy@example.com" WITH INHERIT TRUE, ADMIN TRUE;
```

On PostgreSQL 14–15, pgroles uses the legacy syntax:

```sql
GRANT "inventory-editor" TO "app-service";
GRANT "inventory-editor" TO "deploy@example.com" WITH ADMIN OPTION;
```

{% callout type="note" title="Version-adaptive SQL" %}
pgroles detects the PostgreSQL server version at runtime and generates the appropriate grant syntax automatically. The `WITH INHERIT TRUE/FALSE` syntax is only available on PostgreSQL 16+. On earlier versions, the role-level `INHERIT` attribute controls inheritance behavior instead of per-membership options.
{% /callout %}

## Flag changes

If a membership exists but the `inherit` or `admin` flags differ from the manifest, pgroles generates a `REVOKE` followed by a new `GRANT` with the correct flags. Because `apply` is transactional, that temporary remove-and-re-add sequence does not leave the database half-updated if execution fails.

## Convergent behavior

Memberships in the database that are not declared in the manifest will be revoked. Only declare memberships that pgroles should manage.

## Common patterns

### Service account inherits a profile role

```yaml
roles:
  - name: app-service
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: app-service
```

### Blue/green login roles sharing an owner role

For zero-downtime password rotation, two login roles alternate as the application credential while a shared NOLOGIN role owns all objects. Combining membership with a [`config.role` setting](/docs/manifest-reference#role-configuration-defaults) makes PostgreSQL `SET ROLE` at connect time, so objects created under either credential are owned by the shared role:

```yaml
roles:
  - name: combined
  - name: blue
    login: true
    config:
      role: combined
  - name: green
    login: true
    config:
      role: combined

memberships:
  - role: combined
    members:
      - name: blue
      - name: green
```

Without the membership, PostgreSQL would reject the `role` setting at login — pgroles validates the pair at manifest-validation time. See [examples/blue-green-rotation.yaml](https://github.com/hardbyte/pgroles/blob/main/examples/blue-green-rotation.yaml) for a complete manifest.

### Email-based roles (e.g. IAM authentication)

PostgreSQL roles can have names like email addresses. pgroles handles quoting automatically:

```yaml
memberships:
  - role: inventory-editor
    members:
      - name: "alice@company.com"
      - name: "bob@company.com"
        admin: true
```
