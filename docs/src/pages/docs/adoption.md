---
title: Staged adoption
description: How to adopt pgroles incrementally in an existing database, including app-owned schema lifecycles and PUBLIC privilege caveats.
---

Guide to rolling out pgroles against existing databases without disruption. {% .lead %}

---

## Brownfield vs greenfield

If your database already has roles, grants, and schemas, you are in a **brownfield** scenario. pgroles is designed for this — use `additive` mode to layer managed roles on top of existing state without revoking anything.

For new databases where pgroles owns everything from the start, `authoritative` mode is appropriate.

## Recommended rollout

### 1. Generate a baseline manifest

Start by capturing what already exists:

```shell
pgroles generate --database-url $DATABASE_URL > pgroles.yaml
```

This produces a flat manifest you can refine into profiles and schema bindings.

### 2. Plan mode first

Deploy with `mode: plan` to see what pgroles *would* do without executing any SQL:

```yaml
spec:
  mode: plan
  reconciliation_mode: additive
```

The operator will report planned changes in the CRD status, including the full SQL.

### 3. Validate with diff

Run `pgroles diff` locally to review changes before enabling apply:

```shell
pgroles diff --database-url $DATABASE_URL -f pgroles.yaml --mode additive
```

If the output is `-- No changes needed`, the manifest matches the database and apply will be a no-op.

### 4. Enable additive apply

Switch to `mode: apply` with `reconciliation_mode: additive`. This only adds grants and memberships — it never revokes existing privileges or drops roles.

```yaml
spec:
  mode: apply
  reconciliation_mode: additive
```

### 5. Progress to authoritative (optional)

Once the manifest covers all roles and grants you want managed, switch to `reconciliation_mode: authoritative` to enable full convergence. Review the planned revocations carefully before switching — in a typical brownfield database, this may include thousands of existing grants to roles not yet in the manifest.

## App-owned schemas

Applications that create their own schemas via migrations (e.g. `awa`, `analytics`) require a **two-stage** manifest:

1. **Bootstrap** — create login roles and database-level grants *before* migrations run
2. **Full** — add schema-level grants, object grants, and default privileges *after* migrations have created the schema

This is necessary because `GRANT USAGE ON SCHEMA foo` fails if `foo` does not exist yet.

```yaml
# Stage 1: bootstrap (pre-migration)
roles:
  - name: app_runtime
    login: true
grants:
  - role: app_runtime
    privileges: [CONNECT]
    object:
      type: database
```

```yaml
# Stage 2: full (post-migration)
schemas:
  - name: app_schema
    profiles: [editor, viewer]
```

{% callout type="note" title="Schema existence" %}
pgroles does not create schemas. If a schema referenced in grants or profiles does not exist, the apply will fail. Ensure your application migrations run before applying schema-level grants.
{% /callout %}

## PUBLIC privilege caveats

PostgreSQL grants certain default privileges to the `PUBLIC` pseudo-role on every database (e.g. `CONNECT`, `TEMPORARY`). pgroles **does not inspect or manage PUBLIC grants**.

This means:

- A role may have effective privileges not visible in `pgroles inspect` output
- A manifest that omits `TEMPORARY` does not guarantee the role lacks `TEMPORARY` — it may still inherit it from `PUBLIC`
- `additive` mode showing "no changes needed" does not mean effective privileges match the manifest exactly

If least-privilege enforcement is important, you may need to manually revoke unwanted `PUBLIC` grants:

```sql
REVOKE TEMPORARY ON DATABASE mydb FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

{% callout type="warning" title="PUBLIC is outside pgroles scope" %}
pgroles intentionally excludes PUBLIC from inspection and management. Revoking PUBLIC grants is a manual, database-level decision that should be made carefully — it affects all roles, not just those managed by pgroles.
{% /callout %}
