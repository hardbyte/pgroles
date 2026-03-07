---
title: Google Cloud SQL
description: Connect pgroles to Cloud SQL for PostgreSQL — connectivity, IAM authentication, and Cloud Run deployment.
---

Platform-specific guidance for running pgroles against Cloud SQL for PostgreSQL. {% .lead %}

For general usage, see the [quick start](/docs/quick-start). For CI pipeline patterns, see [CI/CD integration](/docs/ci-cd). For the Kubernetes operator, see the [operator docs](/docs/operator).

---

## Prerequisites

- A Cloud SQL for PostgreSQL instance (PostgreSQL 14+, 16+ recommended)
- A database user with `cloudsqlsuperuser` membership (the default `postgres` user has this)

pgroles auto-detects Cloud SQL when the connecting role is a member of `cloudsqlsuperuser` and adjusts privilege warnings accordingly — for example, it will warn if your manifest requests `SUPERUSER` or `BYPASSRLS` attributes that Cloud SQL doesn't allow.

## Connecting to Cloud SQL

### Cloud SQL Auth Proxy

The [Cloud SQL Auth Proxy](https://cloud.google.com/sql/docs/postgres/sql-proxy) is the recommended connection method. It handles TLS and IAM-based authentication automatically.

```shell
# Start the proxy
cloud-sql-proxy my-project:us-central1:my-instance --port 5432

# In another shell
export DATABASE_URL='postgres://postgres:PASSWORD@127.0.0.1:5432/mydb'
pgroles diff -f pgroles.yaml
```

In **GKE**, run the proxy as a sidecar or as a standalone Deployment in the same namespace as the operator. With [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) configured, the proxy authenticates automatically without keys.

In **GitHub Actions**, use the [setup-cloud-sql-proxy](https://github.com/google-github-actions/setup-cloud-sql-proxy) action — see the [CI/CD integration](/docs/ci-cd) guide for the full workflow pattern.

### Private IP

If your Cloud SQL instance has a private IP and your workload runs in the same VPC:

```shell
export DATABASE_URL='postgres://postgres:PASSWORD@10.x.x.x:5432/mydb'
```

### Cloud SQL built-in connector (Cloud Run)

Cloud Run and App Engine can use `--add-cloudsql-instances` instead of the proxy. The connector exposes a Unix socket:

```
postgres://postgres:PASSWORD@/mydb?host=/cloudsql/MY_PROJECT:us-central1:my-instance
```

## Cloud Run job

If you don't run Kubernetes, a [Cloud Run job](https://cloud.google.com/run/docs/create-jobs) is a lightweight way to run pgroles on a schedule. Build a custom image with your manifest:

```dockerfile
FROM ghcr.io/hardbyte/pgroles:latest
COPY pgroles.yaml /etc/pgroles/pgroles.yaml
ENTRYPOINT ["pgroles", "apply", "-f", "/etc/pgroles/pgroles.yaml"]
```

```shell
gcloud builds submit --tag gcr.io/MY_PROJECT/pgroles-apply
```

Create the job using the built-in Cloud SQL connector:

```shell
gcloud run jobs create pgroles-apply \
  --image gcr.io/MY_PROJECT/pgroles-apply \
  --set-secrets DATABASE_URL=pgroles-db-url:latest \
  --add-cloudsql-instances MY_PROJECT:us-central1:my-instance \
  --region us-central1
```

The secret `pgroles-db-url` should be stored in [Secret Manager](https://cloud.google.com/secret-manager) with the connection string.

{% callout type="note" title="VPC connector" %}
If connecting via Private IP instead of the built-in connector, Cloud Run needs a [Serverless VPC Access connector](https://cloud.google.com/vpc/docs/configure-serverless-vpc-access) or [Direct VPC egress](https://cloud.google.com/run/docs/configuring/vpc-direct-vpc).
{% /callout %}

### Schedule it

```shell
gcloud scheduler jobs create http pgroles-daily \
  --schedule "0 3 * * *" \
  --uri "https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/MY_PROJECT/jobs/pgroles-apply:run" \
  --oauth-service-account-email MY_SA@MY_PROJECT.iam.gserviceaccount.com \
  --location us-central1
```

### Drift detection

Build a separate image for drift checks (or override the command):

```dockerfile
FROM ghcr.io/hardbyte/pgroles:latest
COPY pgroles.yaml /etc/pgroles/pgroles.yaml
ENTRYPOINT ["pgroles", "diff", "-f", "/etc/pgroles/pgroles.yaml", "--exit-code"]
```

Exit code 2 means drift was detected.

## Cloud Build

Use the published Docker image directly in Cloud Build steps:

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

## IAM database authentication

If your roles use [Cloud SQL IAM database authentication](https://cloud.google.com/sql/docs/postgres/iam-authentication), declare the provider in your manifest:

```yaml
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
```

IAM-authenticated roles in Cloud SQL follow the naming convention `user@project.iam` for service accounts:

```yaml
roles:
  - name: "my-sa@my-project.iam"
    login: true
    comment: "IAM-authenticated service account"
```
