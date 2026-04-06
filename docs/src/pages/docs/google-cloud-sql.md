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
    login: true
    comment: "IAM-authenticated service account"
```

### IAM groups

[IAM group authentication](https://cloud.google.com/sql/docs/postgres/add-manage-iam-users) lets you grant database privileges to a Cloud Identity group. All group members inherit the grants automatically on first login — you don't need to add individual members to your manifest.

```yaml
roles:
  - name: "backend-team@example.com"
    login: false
    comment: "Cloud Identity group — members authenticate individually"

grants:
  - role: "backend-team@example.com"
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: "backend-team@example.com"
    privileges: [SELECT, INSERT, UPDATE]
    object: { type: table, schema: app, name: "*" }
```

When a group member logs in for the first time, Cloud SQL creates their individual PostgreSQL role automatically and grants them the group's privileges.

{% callout type="note" title="Group membership propagation" %}
Changes to Cloud Identity group membership take about 15 minutes to propagate. However, changes to the group's database privileges take effect immediately.
{% /callout %}

## Kubernetes operator on GKE

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator

kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@127.0.0.1:5432/mydb'
```

With [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity), run the [Cloud SQL Auth Proxy](https://cloud.google.com/sql/docs/postgres/sql-proxy) as a sidecar or standalone Deployment in the same namespace. See the [operator docs](/docs/operator) for the full `PostgresPolicy` CRD reference.
