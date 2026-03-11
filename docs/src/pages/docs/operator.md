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
The operator is intended for production use. The current API is still `v1alpha1`, so the remaining work is primarily around API hardening and lifecycle polish rather than basic controller viability.
{% /callout %}

## Installation

### Helm

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
```

### Rust crate

Install from crates.io:

```toml
[dependencies]
pgroles-operator = "<current-release>"
```

If you are embedding the reconciler or CRD types directly from source, depend on the repository in your `Cargo.toml`:

```toml
[dependencies]
pgroles-operator = { git = "https://github.com/hardbyte/pgroles" }
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

The operator now has the production-readiness foundations on `main`. The remaining work is mostly about API evolution and maintaining the stronger validation profile already in CI.

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

### Current validation profile

CI covers:

- multiple policies targeting the same database with conflicting ownership
- multiple non-overlapping policies targeting the same database
- shared-secret churn across multiple policies targeting the same database
- invalid specs
- missing secrets
- insufficient database privileges
- rotated secrets and connection recovery after secret repair
- transition-based Kubernetes Event delivery for warning and recovery states

Default PR CI validates:

- generated policies spanning 2 databases
- 30 managed schemas total
- 60 generated roles total
- schema, table, and sequence privilege checks on both database targets

Scheduled fairness/load coverage on `main` additionally exercises:

- 5 generated policies across 3 databases
- 100 managed schemas total
- 200 generated roles total
- repeated shared-secret churn across 3 same-database policies
- targeted secret churn on a separate database to verify isolation
- latency reporting in the workflow summary for initial convergence and full churn completion

### Remaining work

- Carry the current controller semantics into the next CRD revision rather than leaving them as implementation-only conventions.
- Promote the API beyond `v1alpha1` only after the compatibility and upgrade story is explicit.
- Keep the validation profile current as the manifest surface and operator behavior evolve.

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
  mode: apply      # apply changes, or use plan for non-mutating drift preview

  default_owner: app_owner

  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          'on': { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
          'on': { type: table, name: "*" }
        - privileges: [USAGE, SELECT, UPDATE]
          'on': { type: sequence, name: "*" }
        - privileges: [EXECUTE]
          'on': { type: function, name: "*" }
      default_privileges:
        - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
          on_type: table
        - privileges: [USAGE, SELECT, UPDATE]
          on_type: sequence
        - privileges: [EXECUTE]
          on_type: function

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

### Role passwords

Roles can reference Kubernetes Secrets for their passwords. The operator resolves password values at reconcile time and injects them into the apply transaction:

```yaml
spec:
  roles:
    - name: app-service
      login: true
      password:
        secretRef:
          name: app-passwords
        secretKey: app-service      # optional, defaults to the role name
      password_valid_until: "2026-12-31T00:00:00Z"
```

- `password.secretRef.name` — the Secret containing the password value.
- `password.secretKey` — the key within the Secret. Defaults to the role name if omitted.
- `password_valid_until` — ISO 8601 timestamp for PostgreSQL `VALID UNTIL`.

Password values are redacted in operator logs and the `status.planned_sql` field. If the referenced Secret or key is missing, the operator sets a `SecretMissing` or `SecretFetchFailed` status condition and retries on the normal interval.

The controller also emits Kubernetes Events for notable state transitions. These are intended for `kubectl describe` and quick operational debugging, not as a durable audit trail or alerting mechanism.

## Reconciliation

The operator reconciles on three paths:

- `PostgresPolicy` spec changes
- referenced Secret changes
- the normal periodic `interval`

Each reconcile inspects the current database state, computes a diff from the policy, and then either applies it or publishes a non-mutating plan depending on `spec.mode`. Same-database policies are serialized, and status-only updates do not retrigger the controller.

Use this page for the external behavior and operating model. For the internal controller pipeline and locking model, see the [operator architecture](/docs/operator-architecture) page.

{% operator-reconciliation-diagram /%}

### Insufficient privileges

If the operator can connect to PostgreSQL but the management role cannot inspect or apply the requested changes, the policy settles to a non-ready state instead of hot-looping as if the failure were transient.

Current behavior:

- `Ready=False`
- reason `InsufficientPrivileges`
- `last_error` contains the PostgreSQL error message, for example `permission denied to create role`
- the policy retries on its normal reconcile interval rather than exponential transient backoff

This is the expected state when the database credential is valid but under-privileged for the requested manifest.

### Interval

The `interval` field controls how often the operator re-reconciles, even when the resource hasn't changed. This catches drift from manual SQL changes. Supports durations like `30s`, `5m`, `1h`, or compound forms like `1h30m`. Defaults to `5m`.

### Suspending

Set `suspend: true` to pause reconciliation without deleting the resource. The operator will skip the resource until `suspend` is set back to `false`.

### Plan mode

Set `mode: plan` to let the operator inspect the database, compute the diff, and publish the planned SQL without executing it.

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  mode: plan
  roles:
    - name: preview-user
      login: true
```

Plan mode is useful when you want the operator to stay in-cluster but you are not ready to trust it with mutations yet.

Current behavior in `plan` mode:

- the operator connects to the database and computes the full diff normally
- no SQL is executed
- `status.change_summary` records the pending changes
- `status.planned_sql` stores the rendered SQL, truncated if needed for status size safety
- `Ready=True` with reason `Planned`
- `Drifted=True` when changes are pending, `Drifted=False` when the database is already in sync

Use `suspend` when you want the controller to stop reconciling entirely. Use `plan` when you want it to keep inspecting and showing you what it would do.

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
- `DriftDetected`
- `PlanClean`
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
      last_transition_time: "2026-03-06T10:30:00Z"
  observed_generation: 3
  last_reconcile_time: "2026-03-06T10:30:00Z"
  transient_failure_count: 0
  change_summary:
    roles_created: 2
    roles_altered: 0
    roles_dropped: 0
    grants_added: 3
    grants_revoked: 0
    default_privileges_set: 2
    default_privileges_revoked: 0
    members_added: 1
    members_removed: 0
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
  last_error: "error returned from database: permission denied to create role"
  transient_failure_count: 0
```

### Conditions

| Type | Meaning |
| --- | --- |
| `Ready` | `True` when the last reconciliation succeeded |
| `Drifted` | `True` when `plan` mode found pending changes |
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
