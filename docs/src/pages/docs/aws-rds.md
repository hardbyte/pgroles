---
title: AWS RDS & Aurora
description: Set up pgroles with Amazon RDS or Aurora PostgreSQL — from ECS, Lambda, CI pipelines, or the Kubernetes operator.
---

Run pgroles against Amazon RDS or Aurora PostgreSQL. This guide covers running the CLI from CI, as a scheduled ECS task, or using the Kubernetes operator on EKS. {% .lead %}

---

## Prerequisites

- An RDS or Aurora PostgreSQL instance (PostgreSQL 14+, 16+ recommended)
- A database user with `rds_superuser` membership (the default `postgres` user has this)

pgroles auto-detects RDS/Aurora when the connecting role is a member of `rds_superuser` and adjusts privilege warnings — for example, it will warn if your manifest requests `SUPERUSER`, `REPLICATION`, or `BYPASSRLS` attributes that RDS doesn't allow.

## Connection string

```
postgres://postgres:PASSWORD@my-instance.abc123.us-east-1.rds.amazonaws.com:5432/mydb
```

Store this in AWS Secrets Manager or SSM Parameter Store rather than hardcoding it.

## Option 1: From CI (GitHub Actions)

The simplest approach. Run pgroles as part of your deployment pipeline:

```yaml
jobs:
  apply-roles:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install pgroles
        run: cargo install pgroles-cli

      - name: Apply roles
        run: pgroles apply -f pgroles.yaml
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

{% callout type="note" title="Network access" %}
Your CI runner needs network access to the RDS instance. Options include a self-hosted runner in the VPC, an AWS VPN/PrivateLink setup, or making the instance publicly accessible (not recommended for production).
{% /callout %}

For drift detection as a PR check:

```yaml
      - name: Check for drift
        run: pgroles diff -f pgroles.yaml --exit-code
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

## Option 2: Scheduled ECS task

Run pgroles on a schedule using an ECS Scheduled Task with Fargate. No infrastructure to manage.

### Task definition

```json
{
  "family": "pgroles-apply",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "pgroles",
      "image": "ghcr.io/hardbyte/pgroles:latest",
      "command": ["apply", "-f", "/etc/pgroles/pgroles.yaml"],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789:secret:pgroles-db-url"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/pgroles",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "apply"
        }
      }
    }
  ],
  "executionRoleArn": "arn:aws:iam::123456789:role/ecsTaskExecutionRole"
}
```

To bake the manifest into the image:

```dockerfile
FROM ghcr.io/hardbyte/pgroles:latest
COPY pgroles.yaml /etc/pgroles/pgroles.yaml
ENTRYPOINT ["pgroles", "apply", "-f", "/etc/pgroles/pgroles.yaml"]
```

### Schedule with EventBridge

```shell
aws events put-rule \
  --name pgroles-daily \
  --schedule-expression "cron(0 3 * * ? *)"

aws events put-targets \
  --rule pgroles-daily \
  --targets '[{
    "Id": "pgroles-apply",
    "Arn": "arn:aws:ecs:us-east-1:123456789:cluster/my-cluster",
    "RoleArn": "arn:aws:iam::123456789:role/ecsEventsRole",
    "EcsParameters": {
      "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789:task-definition/pgroles-apply",
      "LaunchType": "FARGATE",
      "NetworkConfiguration": {
        "awsvpcConfiguration": {
          "Subnets": ["subnet-abc123"],
          "SecurityGroups": ["sg-abc123"]
        }
      }
    }
  }]'
```

## Option 3: Kubernetes operator on EKS

If you run EKS, deploy the operator via Helm:

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
```

Create a Secret with the RDS connection string:

```shell
kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@my-instance.abc123.us-east-1.rds.amazonaws.com:5432/mydb'
```

Then apply a `PostgresPolicy` resource — see the [operator docs](/docs/operator) for the full CRD reference.

{% callout type="note" title="Secrets Manager integration" %}
For production, use the [AWS Secrets Store CSI Driver](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html) to sync credentials from Secrets Manager into Kubernetes Secrets, rather than creating them manually.
{% /callout %}

## RDS IAM authentication

If your roles use [RDS IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html), declare the provider in your manifest:

```yaml
auth_providers:
  - type: rds_iam
    region: us-east-1
```

## Managed service limitations

RDS and Aurora don't expose the PostgreSQL `SUPERUSER` attribute. The default `postgres` user is a member of `rds_superuser`, which has most administrative capabilities but cannot:

- Set `SUPERUSER` on other roles
- Set `REPLICATION` on other roles
- Set `BYPASSRLS` on other roles

pgroles detects this automatically and warns during `diff` and `apply` if your manifest includes these attributes.
