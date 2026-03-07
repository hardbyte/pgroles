---
title: AWS RDS & Aurora
description: Connect pgroles to Amazon RDS or Aurora PostgreSQL — connectivity, secrets, and ECS deployment.
---

Platform-specific guidance for running pgroles against Amazon RDS or Aurora PostgreSQL. {% .lead %}

For general usage, see the [quick start](/docs/quick-start). For CI pipeline patterns, see [CI/CD integration](/docs/ci-cd). For the Kubernetes operator on EKS, see the [operator docs](/docs/operator).

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

## Network access

RDS instances are typically in a private VPC. Your pgroles workload needs network access:

- **ECS / EKS** — run in the same VPC or a peered VPC
- **CI runners** — use a self-hosted runner in the VPC, AWS VPN/PrivateLink, or SSH tunneling
- **Public access** — possible but not recommended for production

## Scheduled ECS task

Run pgroles on a schedule using an ECS Scheduled Task with Fargate. Build a custom image with your manifest baked in:

```dockerfile
FROM ghcr.io/hardbyte/pgroles:latest
COPY pgroles.yaml /etc/pgroles/pgroles.yaml
ENTRYPOINT ["pgroles", "apply", "-f", "/etc/pgroles/pgroles.yaml"]
```

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
      "image": "ECR_REPO/pgroles-apply:latest",
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

## Kubernetes operator on EKS

Deploy the operator via Helm and create a Secret with your RDS connection string:

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator

kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgres://postgres:PASSWORD@my-instance.abc123.us-east-1.rds.amazonaws.com:5432/mydb'
```

See the [operator docs](/docs/operator) for the full `PostgresPolicy` CRD reference.

{% callout type="note" title="Secrets Manager integration" %}
For production, use the [AWS Secrets Store CSI Driver](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html) to sync credentials from Secrets Manager into Kubernetes Secrets, rather than creating them manually.
{% /callout %}

## IAM database authentication

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
