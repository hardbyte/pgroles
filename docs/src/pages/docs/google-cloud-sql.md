---
title: Google Cloud SQL
description: Running pgroles against Cloud SQL for PostgreSQL.
---

What you need to know about pgroles on Cloud SQL — auto-detection, attribute restrictions, IAM authentication, and the Docker image interface. {% .lead %}

For general usage, see the [quick start](/docs/quick-start). For CI pipeline patterns, see [CI/CD integration](/docs/ci-cd). For the Kubernetes operator, see the [operator docs](/docs/operator).

---

## Auto-detection

pgroles auto-detects Cloud SQL when the connecting role is a member of `cloudsqlsuperuser`. You don't need to configure anything — it adjusts behaviour automatically.

## Attribute restrictions

Cloud SQL doesn't expose the PostgreSQL `SUPERUSER` attribute. The default `postgres` user is a member of `cloudsqlsuperuser`, which has most administrative capabilities but cannot grant:

- `SUPERUSER`
- `BYPASSRLS`

If your manifest includes these, pgroles warns during `diff` and `apply`.

## Connection string

However you connect to Cloud SQL — [Auth Proxy](https://cloud.google.com/sql/docs/postgres/sql-proxy), private IP, or the [built-in connector](https://cloud.google.com/sql/docs/postgres/connect-run) — pass the connection string as `DATABASE_URL`:

```shell
# Auth Proxy (localhost)
export DATABASE_URL='postgres://postgres:PASSWORD@127.0.0.1:5432/mydb'

# Private IP
export DATABASE_URL='postgres://postgres:PASSWORD@10.x.x.x:5432/mydb'

# Built-in connector (Cloud Run / App Engine)
export DATABASE_URL='postgres://postgres:PASSWORD@/mydb?host=/cloudsql/PROJECT:REGION:INSTANCE'
```

## Docker image

The published image (`ghcr.io/hardbyte/pgroles:latest`) has `WORKDIR /work` and `ENTRYPOINT ["pgroles"]`. This means:

- **Volume mount:** `docker run -v ./:/work ghcr.io/hardbyte/pgroles:latest diff -f pgroles.yaml`
- **Derived image:** `FROM ghcr.io/hardbyte/pgroles:latest` then `COPY pgroles.yaml .`
- **Secret Manager mount:** use `--set-secrets /work/pgroles.yaml=secret-name:latest` in Cloud Run to mount the manifest directly — no custom image needed

For Cloud Run, Cloud Build, GKE, or any other compute — use whichever pattern fits. The container needs `DATABASE_URL` set and the manifest file available at the path you pass to `-f`.

## IAM database authentication

Cloud SQL supports [IAM database authentication](https://cloud.google.com/sql/docs/postgres/iam-authentication) for individual users, service accounts, and groups. Declare the provider in your manifest:

```yaml
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
```

### Role naming conventions

Cloud SQL maps IAM principals to PostgreSQL roles with specific naming rules:

| IAM principal | PostgreSQL role name | Example |
| --- | --- | --- |
| User | Full email address | `"kai@example.com"` |
| Service account | Email without `.gserviceaccount.com` | `"my-sa@my-project.iam"` |
| Group | Full group email address | `"editors@example.com"` |

### Service accounts

```yaml
roles:
  - name: "my-sa@my-project.iam"
    external: true
```

### IAM groups

[IAM group authentication](https://cloud.google.com/sql/docs/postgres/add-manage-iam-users) lets you grant database privileges to a Cloud Identity group. All group members inherit the grants automatically on first login — you don't need to add individual members to your manifest.

```yaml
roles:
  - name: "backend-team@example.com"
    external: true

grants:
  - role: "backend-team@example.com"
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: "backend-team@example.com"
    privileges: [SELECT, INSERT, UPDATE]
    object: { type: table, schema: app, name: "*" }
```

When a group member logs in for the first time, Cloud SQL creates their individual PostgreSQL role automatically and grants them the group's privileges.

Use `external: true` for Cloud SQL IAM users and groups that are created through Cloud SQL IAM APIs, Terraform `google_sql_user`, or another platform owner. That keeps pgroles from changing the role's `LOGIN` attribute or revoking provider-managed role memberships while still allowing grants and ownership references.

{% callout type="note" title="Group membership propagation" %}
Changes to Cloud Identity group membership take about 15 minutes to propagate. However, changes to the group's database privileges take effect immediately.
{% /callout %}

## Granting on objects owned by other roles

On Cloud SQL, object owners you did not create — `cloudsqlexternalsync` (Datastream), roles created by other tooling, legacy loaders — are typically already **members of `cloudsqlsuperuser`**. That creates a trap when a pgroles [wildcard grant](/docs/executor-privileges#granting-on-objects-owned-by-other-roles) needs to touch their objects.

The instinct is to make `cloudsqlsuperuser` (the role pgroles usually runs as) a member of each owner so it can grant on their behalf. **PostgreSQL rejects this** — the owners are already members of `cloudsqlsuperuser`, and role membership must be acyclic:

```
ERROR: role "legacy_owner" is a member of role "cloudsqlsuperuser"
```

Because pgroles issues a single `SET ROLE` per connection, you cannot switch owners mid-run to work around it. Instead, run pgroles as a **dedicated delegated-admin role** that sits *below* the owners in the membership graph. A fresh role has no incoming memberships, so granting it membership in the owners is cycle-free:

```sql
-- Run once as the postgres / cloudsqlsuperuser admin user.
CREATE ROLE pgroles_executor WITH NOLOGIN CREATEROLE;   -- attribute set directly
GRANT cloudsqlsuperuser TO pgroles_executor;            -- keep the capabilities pgroles relies on
GRANT legacy_owner      TO pgroles_executor;            -- one GRANT per in-scope object owner
GRANT other_owner       TO pgroles_executor;
-- let the login identity assume it:
GRANT pgroles_executor TO "pgroles-operator@my-project.iam";
```

Then point the operator at it:

```yaml
spec:
  connection:
    params:
      setRole: pgroles_executor
```

Notes:

- **All current Cloud SQL PostgreSQL majors are 16+**, so each `GRANT owner TO pgroles_executor` needs `ADMIN OPTION` on that owner — run the bootstrap as `postgres`. Confirm it actually succeeds for provider-managed roles like `cloudsqlexternalsync`, which the platform may refuse to let you grant at all.
- **`CREATEROLE` is set directly**, not inherited from `cloudsqlsuperuser` — attributes never transfer through membership, and without it pgroles cannot create the roles your profiles declare.
- **Give each `GRANT owner TO pgroles_executor` a single source of truth**, matched to who manages the owner role. For provider- or legacy-owned roles you do not manage with pgroles — Datastream's `cloudsqlexternalsync`, cloud-internal roles, a loader you have not adopted — mark them `external: true`; pgroles then ignores their member lists and the IaC-managed grant is never treated as drift. For roles pgroles does manage, declare the executor's membership in the manifest and let pgroles own it; bootstrap the grant once (as `postgres`) so the membership already exists. Either way, do not manage the same grant in both places. pgroles keys the external filter on the *group* role, so marking the executor external — or leaving it undeclared — does **not** suppress the drift.
- This is a *delegated-admin* role, not least-privilege: with `CREATEROLE` plus `cloudsqlsuperuser` membership it is highly privileged. Its value is a single, auditable, reversible entry point — drop the role or revoke the memberships to undo it.

## Kubernetes operator on GKE

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator

kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@127.0.0.1:5432/mydb'
```

With [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity), the operator can authenticate directly to Cloud SQL IAM without a Cloud SQL Auth Proxy sidecar:

```yaml
spec:
  connection:
    params:
      host: 10.0.0.5
      port: 5432
      dbname: mydb
      username: pgroles-operator@my-project.iam
      auth:
        type: gcp_workload_identity
```

The operator fetches a short-lived Cloud SQL login token from the GKE metadata server and uses it as the PostgreSQL password. If `sslMode` is omitted, the operator uses `require`. A Cloud SQL Auth Proxy sidecar or standalone Deployment is still supported when you prefer proxy-managed connectivity. See the [operator docs](/docs/operator) for the full `PostgresPolicy` CRD reference.
