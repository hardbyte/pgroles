---
title: Kubernetes operator
description: Run pgroles as a Kubernetes operator that continuously reconciles PostgreSQL roles against a custom resource.
---

The pgroles operator watches `PostgresPolicy` custom resources and continuously reconciles your PostgreSQL databases to match the declared state. {% .lead %}

---

## Overview

The operator brings the same convergent model as the CLI into Kubernetes. Instead of running `pgroles apply` manually, you declare a `PostgresPolicy` resource and the operator reconciles on a configurable interval.

- Same manifest semantics — profiles, schemas, grants, retirements all work identically
- Database credentials referenced via Kubernetes Secrets
- Status conditions and change summaries on the custom resource
- Finalizer-based cleanup on resource deletion

{% callout title="Work in progress" %}
The operator is functional but still under active development. The CRD schema may change in future releases.
{% /callout %}

## Installation

### Helm

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
```

### crates.io

For local development or custom packaging, the operator crate is also published on crates.io:

```shell
cargo install pgroles-operator
```

If you are embedding the reconciler or CRD types in another Rust project, pin the current release in your `Cargo.toml`:

```toml
[dependencies]
pgroles-operator = "<current-release>"
```

### Configuration

Key values you can override:

```yaml
# values.yaml
installCRDs: true

operator:
  image:
    repository: ghcr.io/hardbyte/pgroles-operator
    tag: ""  # defaults to Chart.appVersion

  env:
    - name: RUST_LOG
      value: "info,pgroles_operator=debug"

  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
```

The operator runs as `nobody` (UID 65534) with a read-only root filesystem, no capabilities, and seccomp enabled by default.

## Operational guidance

- Use one `PostgresPolicy` per database and credential boundary.
- Prefer a dedicated management role rather than an application login for reconciliation.
- Validate and review the manifest with the CLI before handing it to the operator.
- Treat deletion as "stop managing", not "revert the database".

## Production roadmap

The operator is intended to become a production controller, but that requires stricter ownership, observability, and failure-handling semantics than the current `v1alpha1` shape. The near-term roadmap is:

### 1. Safe multi-policy ownership for the same database

- Add a canonical database identity to each policy target so the operator can determine when multiple `PostgresPolicy` resources point at the same database.
- Add explicit management scope so ownership is unambiguous:
  - managed role names
  - managed schema names
  - generated role patterns
- Reject overlapping policies by default rather than allowing last-writer-wins behavior.
- Reconcile multiple policies for the same database only when their managed scopes are provably disjoint.

### 2. Clear invalid-config and conflict handling

- Distinguish invalid spec errors from transient operational failures.
- Surface conflict and validation outcomes through status conditions rather than hot-looping retries.
- Extend status to include:
  - `lastAttemptedGeneration`
  - `lastSuccessfulReconcileTime`
  - `lastError`
  - managed database identity
  - owned role/schema summary

### 3. Per-database serialization and retry discipline

- Serialize reconciliation for the same database target inside the controller.
- Add PostgreSQL advisory locking as a second layer of protection against multi-replica races.
- Replace the fixed retry interval with exponential backoff and jitter for transient failures.
- Avoid aggressive retries for invalid specs or policy conflicts.

### 4. Production probes and metrics

- Add HTTP endpoints for:
  - `/livez`
  - `/readyz`
  - `/metrics`
- Keep readiness tied to controller health rather than the success of any one policy.
- Export Prometheus metrics for:
  - reconcile duration and result
  - database connection failures
  - lock contention
  - change counts by type
  - invalid spec/conflict totals

### 5. More realistic test coverage

- Add E2E coverage for:
  - multiple policies targeting the same database with conflicting ownership
  - multiple non-overlapping policies targeting the same database
  - invalid specs
  - missing or rotated secrets
  - insufficient database privileges
- Add scale and load tests covering large manifests, many roles/grants, and many policies across multiple databases.
- Add reconciliation concurrency tests to prove per-database serialization and backoff behavior.

### 6. API hardening toward production use

- Carry these semantics into the next CRD revision rather than leaving them as controller-only conventions.
- Promote the API only after conflict detection, richer status, probes, metrics, retry behavior, and realistic load tests are all in place.

## Custom resource

A `PostgresPolicy` spec mirrors the CLI manifest format with added Kubernetes-specific fields for connection and scheduling.

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: myapp-roles
  namespace: default
spec:
  connection:
    secretRef:
      name: mydb-credentials
    secretKey: DATABASE_URL  # optional, defaults to DATABASE_URL

  interval: "5m"   # reconciliation interval (supports 5m, 1h, 30s, 1h30m)
  suspend: false   # set true to pause reconciliation

  default_owner: app_owner

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

  schemas:
    - name: inventory
      profiles: [editor]

  roles:
    - name: app-service
      login: true
      comment: "Application service account"

  grants:
    - role: app-service
      privileges: [CONNECT]
      on: { type: database, name: mydb }

  memberships:
    - role: inventory-editor
      members:
        - name: app-service

  retirements:
    - role: legacy_app
      reassign_owned_to: app_owner
      drop_owned: true
```

### Database secret

Create a Secret containing your PostgreSQL connection string:

```shell
kubectl create secret generic mydb-credentials \
  --from-literal=DATABASE_URL='postgresql://user:password@host:5432/database'
```

The operator reads the Secret from the same namespace as the `PostgresPolicy` resource. When the Secret's `resourceVersion` changes (e.g. credential rotation), the operator automatically reconnects with updated credentials.

## Reconciliation

Each reconciliation cycle:

1. Reads the Secret and establishes (or reuses a cached) database connection
2. Converts the CRD spec into a `PolicyManifest` — the same type used by the CLI
3. Expands profiles across schemas into concrete roles and grants
4. Inspects the live database state
5. Computes the diff between current and desired state
6. Applies all changes in a single transaction
7. Updates the resource status with conditions and a change summary

### Interval

The `interval` field controls how often the operator re-reconciles, even when the resource hasn't changed. This catches drift from manual SQL changes. Supports durations like `30s`, `5m`, `1h`, or compound forms like `1h30m`. Defaults to `5m`.

### Suspending

Set `suspend: true` to pause reconciliation without deleting the resource. The operator will skip the resource until `suspend` is set back to `false`.

### Deletion behaviour

When a `PostgresPolicy` resource is deleted, the operator **does not** revoke grants or drop roles. The database is left as-is. This is intentional — resource deletion means "stop managing", not "undo everything".

## Status

The operator reports status on the custom resource:

```yaml
status:
  conditions:
    - type: Ready
      status: "True"
      reason: Reconciled
      message: "Applied 5 changes"
      lastTransitionTime: "2026-03-06T10:30:00Z"
  observedGeneration: 3
  lastReconcileTime: "2026-03-06T10:30:00Z"
  changeSummary:
    rolesCreated: 2
    rolesAltered: 0
    rolesDropped: 0
    grantsAdded: 3
    grantsRevoked: 0
    defaultPrivilegesSet: 2
    defaultPrivilegesRevoked: 0
    membersAdded: 1
    membersRemoved: 0
    total: 8
```

### Conditions

| Type | Meaning |
| --- | --- |
| `Ready` | `True` when the last reconciliation succeeded |
| `Reconciling` | `True` while a reconciliation is in progress |
| `Degraded` | `True` when the last reconciliation failed (includes error detail) |

On failure, the operator requeues after 60 seconds.

## RBAC

The operator requires a ClusterRole with these permissions:

| Resource | Verbs |
| --- | --- |
| `postgrespolicies` | get, list, watch, patch, update |
| `postgrespolicies/status` | get, patch, update |
| `postgrespolicies/finalizers` | update |
| `secrets` | get, list, watch |
| `events` | create, patch |

The Helm chart creates the ClusterRole, ClusterRoleBinding, and ServiceAccount automatically.
