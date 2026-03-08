---
title: Kubernetes operator
description: Run pgroles as a Kubernetes operator that continuously reconciles PostgreSQL roles against a custom resource.
---

The pgroles operator watches `PostgresPolicy` custom resources and continuously reconciles your PostgreSQL databases to match the declared state. {% .lead %}

---

For the internal controller design, see the [operator architecture](/docs/operator-architecture) page.

## Overview

The operator brings the same convergent model as the CLI into Kubernetes. Instead of running `pgroles apply` manually, you declare a `PostgresPolicy` resource and the operator reconciles on a configurable interval.

- Same manifest semantics — profiles, schemas, grants, retirements all work identically
- Database credentials referenced via Kubernetes Secrets
- Status conditions and change summaries on the custom resource
- Finalizer-based cleanup on resource deletion

{% callout title="Production-focused controller" %}
The operator is no longer an experimental proof of concept. It is intended for production use, but the API is still `v1alpha1` and the remaining roadmap items are primarily about broader test coverage and API hardening rather than basic controller viability.
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

The operator is intended to become a production controller, but that still requires stricter retry and test semantics than the current `v1alpha1` shape.

### Implemented foundations

- Canonical database identity and ownership claims let the controller detect overlapping `PostgresPolicy` resources targeting the same database.
- Conflicting policies are rejected instead of allowing last-writer-wins behavior.
- Status records managed database identity, owned role/schema summaries, `lastAttemptedGeneration`, `lastSuccessfulReconcileTime`, and the last error message.
- Reconciliation is serialized per database target:
  - in-process locking prevents concurrent reconciles within one operator replica
  - PostgreSQL advisory locking prevents concurrent reconciles across multiple replicas
- Retry behavior is failure-aware:
  - transient operational failures use exponential backoff with jitter
  - invalid specs, conflicts, and unsafe role-drop workflows fall back to the normal reconcile interval
  - lock contention keeps its own short retry path
- The operator exposes:
  - `/livez`
  - `/readyz`
- Metrics are exported via OpenTelemetry OTLP with the OpenTelemetry Collector as the intended Kubernetes sink.
- Transition-based Kubernetes Events are emitted for notable policy state changes.

### Remaining work

### 1. More realistic test coverage

- CI covers:
  - multiple policies targeting the same database with conflicting ownership
  - multiple non-overlapping policies targeting the same database
  - shared-secret churn across multiple policies targeting the same database
  - invalid specs
  - missing secrets
  - insufficient database privileges
  - rotated secrets and connection recovery after secret repair
- Remaining gaps:
  - broader scale and load tests covering larger manifests, more roles/grants, and more policies across multiple databases
  - reconciliation concurrency tests that prove per-database serialization and backoff behavior under churn

Current validated profile in default CI:

- generated policies spanning 2 databases
- 30 managed schemas total
- 60 generated roles total
- schema, table, and sequence privilege checks on both database targets

### 2. API hardening toward production use

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
          'on': { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE]
          'on': { type: table, name: "*" }
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
      'on': { type: database, name: mydb }

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

The controller also emits Kubernetes Events for notable state transitions. These are intended for `kubectl describe` and quick operational debugging, not as a durable audit trail or alerting mechanism.

## Reconciliation

{% operator-reconciliation-diagram /%}

### Insufficient privileges

If the operator can connect to PostgreSQL but the management role cannot inspect or apply the requested changes, the policy settles to a non-ready state instead of hot-looping as if the failure were transient.

Current behavior:

- `Ready=False`
- reason `InsufficientPrivileges`
- `lastError` contains the PostgreSQL error message, for example `permission denied to create role`
- the policy retries on its normal reconcile interval rather than exponential transient backoff

This is the expected state when the database credential is valid but under-privileged for the requested manifest.

### Interval

The `interval` field controls how often the operator re-reconciles, even when the resource hasn't changed. This catches drift from manual SQL changes. Supports durations like `30s`, `5m`, `1h`, or compound forms like `1h30m`. Defaults to `5m`.

### Suspending

Set `suspend: true` to pause reconciliation without deleting the resource. The operator will skip the resource until `suspend` is set back to `false`.

### Health and telemetry

The operator exposes health probes on its internal HTTP port:

- `/livez`
- `/readyz`

The Helm chart configures these probes automatically. Metrics are exported via OpenTelemetry OTLP when standard OTel endpoint environment variables are set, for example:

```yaml
operator:
  env:
    - name: OTEL_EXPORTER_OTLP_ENDPOINT
      value: http://otel-collector.observability.svc.cluster.local:4317
    - name: OTEL_METRICS_EXPORTER
      value: otlp
```

The intended deployment model is operator -> OpenTelemetry Collector -> your metrics backend.

The operator also emits transition-based Kubernetes Events such as:

- `ConflictDetected`
- `ConflictResolved`
- `Suspended`
- `Reconciled`
- `Recovered`
- `SecretFetchFailed`
- `DatabaseConnectionFailed`
- `InsufficientPrivileges`
- `UnsafeRoleDropsBlocked`

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
  transientFailureCount: 0
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

An insufficient-privilege failure looks more like:

```yaml
status:
  conditions:
    - type: Ready
      status: "False"
      reason: InsufficientPrivileges
      message: "error returned from database: permission denied to create role"
    - type: Degraded
      status: "True"
      reason: InsufficientPrivileges
  lastError: "error returned from database: permission denied to create role"
  transientFailureCount: 0
```

### Conditions

| Type | Meaning |
| --- | --- |
| `Ready` | `True` when the last reconciliation succeeded |
| `Reconciling` | `True` while a reconciliation is in progress |
| `Degraded` | `True` when the last reconciliation failed (includes error detail) |

On failure, the operator chooses a retry path based on the failure mode:

- lock contention: short jittered retry
- transient operational failures: exponential backoff with jitter
- invalid specs, conflicts, and unsafe role-drop blockers: normal reconcile interval

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
