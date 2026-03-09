---
title: AWS RDS & Aurora
description: Running pgroles against Amazon RDS or Aurora PostgreSQL.
---

What you need to know about pgroles on RDS and Aurora — auto-detection, attribute restrictions, IAM authentication, and the Docker image interface. {% .lead %}

For general usage, see the [quick start](/docs/quick-start). For CI pipeline patterns, see [CI/CD integration](/docs/ci-cd). For the Kubernetes operator, see the [operator docs](/docs/operator).

---

## Auto-detection

pgroles auto-detects RDS and Aurora when the connecting role is a member of `rds_superuser`. You don't need to configure anything — it adjusts behaviour automatically.

## Attribute restrictions

RDS and Aurora don't expose the PostgreSQL `SUPERUSER` attribute. The default `postgres` user is a member of `rds_superuser`, which has most administrative capabilities but cannot grant:

- `SUPERUSER`
- `REPLICATION`
- `BYPASSRLS`

If your manifest includes any of these, pgroles warns during `diff` and `apply` rather than failing with a cryptic PostgreSQL error.

## Connection string

```
postgres://postgres:PASSWORD@my-instance.abc123.us-east-1.rds.amazonaws.com:5432/mydb
```

Pass it as `DATABASE_URL`. How you get it to your workload — Secrets Manager, SSM Parameter Store, Kubernetes Secret, CI secret — is up to you. pgroles just reads the environment variable.

## Docker image

The published image (`ghcr.io/hardbyte/pgroles:latest`) has `WORKDIR /work` and `ENTRYPOINT ["pgroles"]`. This means:

- **Volume mount:** `docker run -v ./:/work ghcr.io/hardbyte/pgroles:latest diff -f pgroles.yaml`
- **Derived image:** `FROM ghcr.io/hardbyte/pgroles:latest` then `COPY pgroles.yaml .`
- **S3 sidecar:** fetch the manifest into a shared `/work` volume before pgroles starts

For ECS, Lambda, Step Functions, or any other compute — use whichever pattern fits your infrastructure. The container needs `DATABASE_URL` set and the manifest file available at the path you pass to `-f`.

## Network access

RDS instances are typically in a private VPC. Your pgroles workload needs network connectivity to the database — same VPC, peered VPC, VPN, PrivateLink, or (not recommended) public access. This is no different from any other database client.

## IAM database authentication

If your roles use [RDS IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html), declare the provider in your manifest:

```yaml
auth_providers:
  - type: rds_iam
    region: us-east-1
```

## Kubernetes operator on EKS

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator

kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@my-instance.abc123.us-east-1.rds.amazonaws.com:5432/mydb'
```

See the [operator docs](/docs/operator) for the full `PostgresPolicy` CRD reference.

{% callout type="note" title="Secrets Manager integration" %}
For production, use the [AWS Secrets Store CSI Driver](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html) to sync credentials from Secrets Manager into Kubernetes Secrets, rather than creating them manually.
{% /callout %}
