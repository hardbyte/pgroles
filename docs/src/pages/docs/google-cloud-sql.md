---
title: Google Cloud SQL
description: Set up pgroles with Cloud SQL for PostgreSQL — as a Kubernetes operator on GKE, a Cloud Run job, or from CI.
---

Run pgroles against Cloud SQL for PostgreSQL. This guide covers three deployment patterns: the Kubernetes operator on GKE, a scheduled Cloud Run job, and running the CLI from CI pipelines. {% .lead %}

---

## Prerequisites

- A Cloud SQL for PostgreSQL instance (PostgreSQL 14+, 16+ recommended)
- A database user with `cloudsqlsuperuser` membership (the default `postgres` user has this)
- `gcloud` CLI authenticated

pgroles auto-detects Cloud SQL when the connecting role is a member of `cloudsqlsuperuser` and adjusts privilege warnings accordingly — for example, it will warn if your manifest requests `SUPERUSER` or `BYPASSRLS` attributes that Cloud SQL doesn't allow.

## Connection string

Cloud SQL connections typically use one of:

- **Cloud SQL Auth Proxy** — `postgres://user:password@127.0.0.1:5432/mydb`
- **Private IP** — `postgres://user:password@10.x.x.x:5432/mydb`
- **Cloud SQL Connector** (Go/Python/Java) — not applicable for pgroles

For all deployment patterns below, store the connection string in a secret and reference it as `DATABASE_URL`.

## Option 1: Kubernetes operator on GKE

This is the recommended pattern if you already run workloads on GKE. The operator watches `PostgresPolicy` resources and reconciles continuously.

### Install the operator

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
```

### Set up the Cloud SQL Auth Proxy

The simplest approach is to run the [Cloud SQL Auth Proxy](https://cloud.google.com/sql/docs/postgres/sql-proxy) as a sidecar. Add it to the operator deployment via Helm values:

```yaml
# values.yaml
operator:
  env:
    - name: RUST_LOG
      value: "info,pgroles_operator=debug"

  # Additional containers are not directly supported by the chart today,
  # so use the proxy as a separate Deployment or DaemonSet in the namespace,
  # or connect via Private IP.
```

If your GKE cluster has [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) configured, the proxy authenticates automatically without keys.

### Create the database secret

```shell
kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@127.0.0.1:5432/mydb'
```

If using Private IP instead of the proxy:

```shell
kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@PRIVATE_IP:5432/mydb'
```

### Apply a policy

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: myapp-roles
spec:
  connection:
    secretRef:
      name: mydb-credentials

  interval: "5m"

  auth_providers:
    - type: cloud_sql_iam
      project: my-gcp-project

  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          on: { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE]
          on: { type: table, name: "*" }
      default_privileges:
        - privileges: [SELECT, INSERT, UPDATE, DELETE]
          on_type: table

    viewer:
      grants:
        - privileges: [USAGE]
          on: { type: schema }
        - privileges: [SELECT]
          on: { type: table, name: "*" }

  schemas:
    - name: app
      profiles: [editor, viewer]

  roles:
    - name: api-service
      login: true

  memberships:
    - role: app-editor
      members:
        - name: api-service
```

```shell
kubectl apply -f policy.yaml
```

Check reconciliation status:

```shell
kubectl get postgrespolicy myapp-roles -o yaml
```

## Option 2: Cloud Run job (no Kubernetes)

If you don't run Kubernetes, a [Cloud Run job](https://cloud.google.com/run/docs/create-jobs) scheduled via Cloud Scheduler is a lightweight alternative. pgroles runs as a one-shot container, applies the manifest, and exits.

### Build and push the image

Use the published CLI image directly, or build a custom one with your manifest baked in:

```dockerfile
FROM ghcr.io/hardbyte/pgroles:latest

COPY pgroles.yaml /etc/pgroles/pgroles.yaml
ENTRYPOINT ["pgroles", "apply", "-f", "/etc/pgroles/pgroles.yaml"]
```

```shell
gcloud builds submit --tag gcr.io/MY_PROJECT/pgroles-apply
```

### Create the Cloud Run job

```shell
gcloud run jobs create pgroles-apply \
  --image gcr.io/MY_PROJECT/pgroles-apply \
  --set-secrets DATABASE_URL=pgroles-db-url:latest \
  --vpc-connector my-connector \
  --region us-central1
```

{% callout type="note" title="VPC connector required" %}
Cloud Run needs a [Serverless VPC Access connector](https://cloud.google.com/vpc/docs/configure-serverless-vpc-access) or [Direct VPC egress](https://cloud.google.com/run/docs/configuring/vpc-direct-vpc) to reach Cloud SQL via Private IP. Alternatively, use the `--add-cloudsql-instances` flag for the built-in Cloud SQL connector.
{% /callout %}

Using the built-in Cloud SQL connection instead of a VPC connector:

```shell
gcloud run jobs create pgroles-apply \
  --image gcr.io/MY_PROJECT/pgroles-apply \
  --set-secrets DATABASE_URL=pgroles-db-url:latest \
  --add-cloudsql-instances MY_PROJECT:us-central1:my-instance \
  --region us-central1
```

The secret `pgroles-db-url` should be stored in [Secret Manager](https://cloud.google.com/secret-manager) with the connection string. When using `--add-cloudsql-instances`, the Cloud SQL proxy socket is available at `/cloudsql/INSTANCE_CONNECTION_NAME`, so the connection string looks like:

```
postgres://postgres:PASSWORD@/mydb?host=/cloudsql/MY_PROJECT:us-central1:my-instance
```

### Schedule it

```shell
gcloud scheduler jobs create http pgroles-daily \
  --schedule "0 3 * * *" \
  --uri "https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/MY_PROJECT/jobs/pgroles-apply:run" \
  --oauth-service-account-email MY_SA@MY_PROJECT.iam.gserviceaccount.com \
  --location us-central1
```

### Run it manually

```shell
gcloud run jobs execute pgroles-apply --region us-central1
```

### Drift detection only

For a CI-style drift check that alerts but doesn't apply, override the entrypoint:

```shell
gcloud run jobs create pgroles-drift-check \
  --image ghcr.io/hardbyte/pgroles:latest \
  --set-secrets DATABASE_URL=pgroles-db-url:latest \
  --add-cloudsql-instances MY_PROJECT:us-central1:my-instance \
  --command pgroles \
  --args "diff,-f,/etc/pgroles/pgroles.yaml,--exit-code" \
  --region us-central1
```

Exit code 2 means drift was detected.

## Option 3: From CI

Run pgroles directly in a GitHub Actions or Cloud Build pipeline. This works well for teams that treat role changes as part of their deployment process.

### GitHub Actions

```yaml
- name: Set up Cloud SQL Proxy
  uses: google-github-actions/setup-cloud-sql-proxy@v1
  with:
    instance: my-project:us-central1:my-instance

- name: Apply roles
  run: pgroles apply -f pgroles.yaml
  env:
    DATABASE_URL: postgres://postgres:${{ secrets.DB_PASSWORD }}@127.0.0.1:5432/mydb
```

### Cloud Build

```yaml
steps:
  - name: ghcr.io/hardbyte/pgroles:latest
    args: ['apply', '-f', 'pgroles.yaml']
    secretEnv: ['DATABASE_URL']

availableSecrets:
  secretManager:
    - versionName: projects/MY_PROJECT/secrets/pgroles-db-url/versions/latest
      env: DATABASE_URL
```

## Cloud SQL IAM authentication

If your roles use [Cloud SQL IAM database authentication](https://cloud.google.com/sql/docs/postgres/iam-authentication), declare the provider in your manifest:

```yaml
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
```

IAM-authenticated roles in Cloud SQL follow the naming convention `user@project.iam` for service accounts. You can reference these in your manifest:

```yaml
roles:
  - name: "my-sa@my-project.iam"
    login: true
    comment: "IAM-authenticated service account"
```
