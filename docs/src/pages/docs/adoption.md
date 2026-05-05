---
title: Staged adoption
description: How to adopt pgroles incrementally in an existing database, including app-owned schema lifecycles and PUBLIC privilege caveats.
---

Guide to rolling out pgroles against existing databases without disruption. {% .lead %}

---

## Brownfield vs greenfield

If your database already has roles, grants, and schemas, you are in a **brownfield** scenario. pgroles is designed for this — use `additive` mode to layer managed roles on top of existing state without revoking anything or rewriting pre-existing role attributes during the first rollout.

For new databases where pgroles owns everything from the start, `authoritative` mode is appropriate.

## Recommended rollout

### 1. Generate a baseline manifest

Start by capturing what already exists:

```shell
pgroles generate --database-url $DATABASE_URL > pgroles.yaml
```

This produces a flat manifest you can refine into profiles and schema bindings.

For databases where multiple schemas share the same access pattern (a `*_reader`, `*_editor`, `*_app` role per schema), add `--suggest-profiles` to skip the manual refactoring step:

```shell
pgroles generate --database-url $DATABASE_URL --suggest-profiles > pgroles.yaml
```

The suggester extracts reusable [profiles](/docs/profiles) deterministically and only commits to them when round-trip equivalence with the flat manifest is verified. Roles that don't fit a uniform pattern stay flat. See the [CLI reference](/docs/cli#refining-with---suggest-profiles) for details.

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

Switch to `mode: apply` with `reconciliation_mode: additive`. This applies all non-destructive changes — creating roles and declared schemas, adding grants and memberships, and setting default privileges when their owner context is already valid — but never revokes existing privileges, rewrites attributes/comments on pre-existing roles, transfers schema ownership, removes memberships, or drops roles. If a schema's desired `owner` differs from the current owner, pgroles defers owner-bound follow-up steps such as `ALTER DEFAULT PRIVILEGES FOR ROLE <owner> ...` until a mode that allows the ownership transfer.

```yaml
spec:
  mode: apply
  reconciliation_mode: additive
```

### 5. Progress to authoritative (optional)

Once the manifest covers all roles and grants you want managed, switch to `reconciliation_mode: authoritative` to enable full convergence. Review the planned revocations carefully before switching — in a typical brownfield database, this may include thousands of existing grants to roles not yet in the manifest.

## Multi-team adoption with bundles

If platform and application teams need separate ownership boundaries, use CLI bundle mode instead of forcing everyone into one large manifest.

- put shared profiles and `default_owner` in the bundle root
- let one source document manage schema `owner` facets
- let another source document manage schema `bindings` facets
- run `validate`, `diff`, and `apply` against the bundle so pgroles rejects overlapping ownership before any database work begins

This split is especially useful when platform owns schema creation/ownership, while application teams own the profile bindings and memberships that sit on top of those schemas.

## App-owned schemas

Applications that create their own schemas via migrations (e.g. `awa`, `analytics`) now have two viable patterns:

1. **Let pgroles manage the schema** — declare it under `schemas:` with an optional `owner`, and pgroles can create it before grants/default privileges are applied.
2. **Let the application manage the schema** — keep using a two-stage manifest where migrations create the schema first, then pgroles applies schema/object grants afterward.

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
      name: myapp
```

```yaml
# Stage 2: full (pgroles manages schema)
schemas:
  - name: app_schema
    owner: app_owner
    profiles: [editor, viewer]
```

{% callout type="note" title="Declared vs referenced schemas" %}
pgroles can create schemas that are explicitly declared under `schemas:`. Schemas that are only referenced from top-level `grants:` or `default_privileges:` must still exist before apply.
{% /callout %}

## PUBLIC privilege caveats

PostgreSQL grants certain default privileges to the `PUBLIC` pseudo-role on every database (e.g. `CONNECT`, `TEMPORARY`). pgroles **does not inspect or manage PUBLIC grants**.

This means:

- A role may have effective privileges not visible in `pgroles inspect` output
- A manifest that omits `TEMPORARY` does not guarantee the role lacks `TEMPORARY` — it may still inherit it from `PUBLIC`
- `additive` mode showing "no changes needed" does not mean effective privileges or existing role attributes match the manifest exactly

If least-privilege enforcement is important, you may need to manually revoke unwanted `PUBLIC` grants:

```sql
REVOKE TEMPORARY ON DATABASE mydb FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

{% callout type="warning" title="PUBLIC is outside pgroles scope" %}
pgroles intentionally excludes PUBLIC from inspection and management. Revoking PUBLIC grants is a manual, database-level decision that should be made carefully — it affects all roles, not just those managed by pgroles.
{% /callout %}
