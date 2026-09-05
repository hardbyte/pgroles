---
title: Kubernetes operator
description: Run pgroles as a Kubernetes operator that continuously reconciles PostgreSQL roles against a custom resource.
---

For field types, defaults, and admission constraints, see the [CRD API reference](/docs/operator-api-reference).

Declare your PostgreSQL roles, memberships, and privileges as a Kubernetes resource, and let the operator keep the database matching it. {% .lead %}

---

{% callout type="warning" title="Know what it will do before you apply it" %}
By default a `PostgresPolicy` runs in `mode: apply` with
`reconciliation_mode: authoritative`, which means anything in the database but
not in the policy is revoked or dropped. On an existing database that can be
thousands of grants. Start with `mode: observe`, which executes no mutating SQL, and
read [staged adoption](/docs/adoption) before pointing pgroles at something you
care about.
{% /callout %}

## A first policy

For a copyable install-to-approval walkthrough, start with the
[operator quick start](/docs/operator-quick-start). The shorter example below is
deliberately non-mutating: it inspects the database, computes what it *would*
change, and publishes that for review without executing any DDL.

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: myapp-roles
  namespace: default
spec:
  connection:
    secretRef:
      name: myapp-db-credentials
    secretKey: DATABASE_URL

  mode: observe       # inspect and publish a plan; change nothing
  approval: manual
  interval: 5m

  roles:
    - name: myapp-readonly
      login: false
    - name: myapp-service
      login: true

  memberships:
    - role: myapp-readonly
      members:
        - name: myapp-service

  grants:
    - role: myapp-readonly
      object: { type: database, name: app }
      privileges: [CONNECT]
```

The Secret it references holds the connection string. Read it from a file rather
than passing it as an argument, so the password stays out of shell history and
out of the process list:

```bash
umask 077
read -rsp 'Database URL: ' DATABASE_URL && printf '\n'
printf '%s' "$DATABASE_URL" > db-url
unset DATABASE_URL
kubectl create secret generic myapp-db-credentials -n default \
  --from-file=DATABASE_URL=db-url
rm db-url
```

In production, prefer a secret manager — External Secrets Operator, Vault, or
your cloud provider's CSI driver — over creating the Secret by hand.

Apply it and read the result:

```shell
kubectl apply -f policy.yaml
kubectl get pgr myapp-roles -n default
```

```text
NAME           READY   MODE      DRIFT   CHANGES   LAST RECONCILE   AGE
myapp-roles    True    observe   True    3         2s               2s
```

`DRIFT` is `True` because there are pending changes and `mode: observe` never
applies them. To see the SQL it would run, follow the policy to its plan — see
[plan and approval](/docs/operator-plan-approval).

When you are ready to let it execute, switch to `mode: apply`. Choose
`approval: auto` to apply immediately, or `approval: manual` to require a human
to approve each plan first.

## How it works

The operator watches `PostgresPolicy` resources and reconciles on a configurable
interval, using the same expansion, diff, and SQL engine as the CLI. The policy
sections — roles, profiles, schemas, grants, memberships, retirements — are the
same ones the CLI manifest uses, so the [manifest guide](/docs/manifest-format)
and [manifest reference](/docs/manifest-reference) describe them field by field,
nested under `spec:` rather than at the top level.

- Database credentials come from Kubernetes Secrets
- Every reconcile applies in a single transaction, or not at all
- Reconciliation is serialized per database, in-process and across replicas
- Status conditions and change summaries report what happened
- A finalizer cleans up on deletion — deletion means "stop managing", not "undo"

The custom resources have short names in `kubectl`: `pgr` for `PostgresPolicy`,
`pgplan` for `PostgresPolicyPlan`, `pgeap` for `EphemeralAccessPolicy`, and
`pgear` for `EphemeralAccessRequest`.

## Where to go next

| Page | What it covers |
| --- | --- |
| [Operator quick start](/docs/operator-quick-start) | Install, preview, approve, and verify a safe first policy |
| [Install the operator](/docs/operator-install) | Helm install, chart values, CRD upgrades |
| [The PostgresPolicy resource](/docs/operator-postgrespolicy) | Spec fields, execution and approval modes, role passwords |
| [Database connections](/docs/operator-connections) | Connection URLs, structured parameters, cloud IAM auth |
| [Plan and approval](/docs/operator-plan-approval) | Previewing changes and gating execution behind review |
| [Running the operator](/docs/operator-operations) | Intervals, force reconcile, suspend, reconciliation mode, deletion |
| [Status and telemetry](/docs/operator-status) | Conditions, Events, metrics, what to alert on |
| [Troubleshooting index](/docs/operator-troubleshooting) | Follow status reasons to the failing boundary |
| [RBAC and security](/docs/operator-security) | Permissions the operator needs |
| [Production status](/docs/operator-production-status) | Maturity and known gaps — read before deploying |

Before pointing the operator at a real database, check
[executor privileges](/docs/executor-privileges) for what its database role
needs, and [staged adoption](/docs/adoption) for how to roll it out without
revoking access you meant to keep.

For bounded, request-driven membership on top of a durable policy, see
[ephemeral access](/docs/ephemeral-access). For the internal controller design,
see [operator architecture](/docs/operator-architecture).

{% callout type="note" title="Bundle composition reaches the operator via render-bundle" %}
The operator reconciles a single `PostgresPolicy` per resource — it does not load bundle fragments directly. To get cross-team or cross-environment fragment composition under the operator, compose the bundle in CI with `pgroles render-bundle --bundle pgroles.bundle.yaml --output pgroles.yaml`, then wrap the rendered manifest into a `PostgresPolicy` resource (the manifest fields go under `spec:` alongside `connection:`). Gate the bundle ↔ rendered-manifest relationship with `pgroles render-bundle --bundle … --check pgroles.yaml` in CI. See the [bundle composition guide](/docs/bundle-composition) for the full workflow.
{% /callout %}
