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
| `inherit` | `true` | Whether the member inherits the role's privileges |
| `admin` | `false` | Whether the member can grant the role to others |

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
