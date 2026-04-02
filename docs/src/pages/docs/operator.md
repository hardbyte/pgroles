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

{% callout title="Maturity" %}
The operator provides serialized reconciliation with conflict detection, failure-aware retry, and observable status reporting. The API is `v1alpha1` — controller semantics are stable but the CRD contract has no documented upgrade path. Review the [production status](#production-status) section before deploying.
{% /callout %}

## Installation

### Helm

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
```

### Rust crate

Add the operator crate from crates.io:

```shell
cargo add pgroles-operator
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

## Production status

The operator's safety model — serialized reconciliation, conflict detection, failure-aware retry, and transactional apply — is stable and tested in CI. The API surface, scale ceiling, and operational guidance have known gaps.

### Stable

**Reconciliation safety:**

- All changes execute in a single PostgreSQL transaction (all-or-nothing).
- Reconciliation is serialized per database target: in-process locking within a replica, PostgreSQL advisory locking across replicas.
- Conflicting policies (overlapping ownership claims) are rejected, not silently merged.

**Failure handling:**

- Transient operational failures use exponential backoff with jitter.
- Invalid specs, conflicts, and unsafe role-drop workflows fall back to the normal reconcile interval without hot-looping.
- Lock contention has its own short retry path.

**Observability:**

- Status conditions (`Ready`, `Drifted`, `Degraded`, `Conflict`, `Paused`) with change summaries and error detail.
- OTLP metrics export via OpenTelemetry Collector.
- Transition-based Kubernetes Events for `kubectl describe` debugging.
- `/livez` and `/readyz` health probes.

### Known gaps

**API stability:**

- The CRD is `v1alpha1`. There is no conversion webhook, no migration tooling, and no documented upgrade path between versions.
- Controller semantics that should be part of the API contract are currently implementation-only conventions.

**Scale and HA:**

- The largest tested workload is 200 roles / 100 schemas / 5 policies (scheduled CI, not PR CI).
- Advisory locks enable multi-replica deployment, but there is no documented HA pattern, replica guidance, or failure-mode analysis.

**Password drift visibility:**

- PostgreSQL does not expose password material in a way pgroles can compare safely. The operator can detect password source Secret changes and re-apply them, but it cannot detect out-of-band manual password changes made directly in the database.

**Managed provider validation:**

- RDS, Cloud SQL, AlloyDB, and Azure detection is implemented but not validated against live managed instances.

**Deployment security:**

- The operator requires a ClusterRole with Secret read access. There is no namespace-scoped deployment option or RBAC hardening guidance.

**Deletion semantics:**

- Deleting a `PostgresPolicy` stops reconciliation but does not revert the database. This is by design (stop managing, not undo) but differs from GitOps conventions where deleting a resource reverts its effects.

### CI coverage

PR CI validates:

- conflicting and non-overlapping same-database policies
- shared-secret churn and recovery
- synced and generated password lifecycle flows
- invalid specs, missing secrets, insufficient privileges
- Kubernetes Event delivery for warning and recovery transitions
- generated policies spanning 2 databases, 30 schemas, 60 roles

Scheduled coverage on `main` additionally exercises:

- 5 policies across 3 databases, 100 schemas, 200 roles
- repeated secret churn with latency reporting

### Path to API stability

- Carry controller semantics into the CRD contract rather than leaving them as implementation conventions.
- Promote beyond `v1alpha1` only after the upgrade and rollback story is explicit.
- Establish a scale validation baseline that reflects real-world deployment sizes.

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
  reconciliation_mode: authoritative  # authoritative | additive | adopt

  default_owner: app_owner

  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
          object: { type: table, name: "*" }
        - privileges: [USAGE, SELECT, UPDATE]
          object: { type: sequence, name: "*" }
        - privileges: [EXECUTE]
          object: { type: function, name: "*" }
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
      object: { type: database, name: mydb }

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

Roles can either sync a password from an existing Kubernetes Secret or ask the operator to generate and manage a per-role Secret. In both cases the password value is resolved at reconcile time and only sent to PostgreSQL inside the apply transaction.

#### Sync from an existing Secret

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

#### Generate and manage a Secret

```yaml
spec:
  roles:
    - name: app-service
      login: true
      password:
        generate:
          length: 48                # optional, must be 16-128
          secretName: app-service-password   # optional
          secretKey: password       # optional, defaults to password
```

- `password.generate.length` — generated password length. Defaults to `32`. Must be between `16` and `128`.
- `password.generate.secretName` — override the generated Secret name. If omitted, the operator derives a Kubernetes-safe name from `{policy}-pgr-{role}`.
- `password.generate.secretKey` — key written into the generated Secret. Defaults to `password`.

Generated Secrets are created in the same namespace as the `PostgresPolicy`, owned by that policy, and include both the cleartext password and a SCRAM verifier. The cleartext password is written at `password.generate.secretKey` (default `password`) and the SCRAM verifier is written at the fixed key `verifier`. `password.generate.secretKey` must not be `verifier`; the CRD rejects that value. Deleting the generated Secret causes the operator to recreate it and rotate the PostgreSQL password on the next reconcile.

#### Validation and reconcile semantics

- Passwords are only allowed on roles with `login: true`.
- Exactly one of `password.secretRef` or `password.generate` must be set.
- Password values are redacted in operator logs and the `status.planned_sql` field.
- If the referenced Secret or key is missing, the operator sets a `SecretMissing` or `SecretFetchFailed` status condition and retries on the normal interval.
- Password updates are driven by password-source Secret changes. After a successful `apply`, unchanged password sources do not create permanent drift in later `plan` reconciles.
- pgroles cannot detect direct password changes made in PostgreSQL outside the operator, because PostgreSQL does not expose comparable password state safely.

The controller also emits Kubernetes Events for notable state transitions. These are intended for `kubectl describe` and quick operational debugging, not as a durable audit trail or alerting mechanism.

## Reconciliation

The operator reconciles on three paths:

- `PostgresPolicy` spec changes
- referenced Secret changes
- the normal periodic `interval`

Each reconcile inspects the current database state, computes a diff from the policy, and then either applies it or publishes a plan depending on `spec.mode`. Plan mode is non-mutating: it does not execute PostgreSQL DDL and it does not create generated password Secrets. Same-database policies are serialized, and status-only updates do not retrigger the controller.

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

Plan mode is useful when you want the operator to stay in-cluster but you are not ready to trust it with PostgreSQL mutations yet.

Current behavior in `plan` mode:

- the operator connects to the database and computes the full diff normally
- no PostgreSQL SQL is executed
- `status.change_summary` records the pending changes
- `status.planned_sql` stores the rendered SQL, truncated if needed for status size safety
- `Ready=True` with reason `Planned`
- `Drifted=True` when changes are pending, `Drifted=False` when the database is already in sync
- for `password.generate`, the controller may still create or recreate the generated Kubernetes Secret while resolving password inputs for the plan
- for password-managed roles, `Drifted=False` is only possible after a prior successful `apply` recorded the password source version; a plan-only policy cannot prove an existing database password already matches its Secret

Use `suspend` when you want the controller to stop reconciling entirely. Use `plan` when you want it to keep inspecting and showing you what it would do.

### Reconciliation mode

The `reconciliation_mode` field controls how aggressively the operator converges the database, independent of `mode` (which controls whether changes are applied or only planned).

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  reconciliation_mode: additive  # only grant, never revoke
```

| Value | Behavior |
| --- | --- |
| `authoritative` (default) | Full convergence — anything not in the manifest is revoked or dropped |
| `additive` | Only grant, never revoke — safe for incremental adoption |
| `adopt` | Manage declared roles fully, but never drop undeclared roles |

This is the same behavior as the CLI `--mode` flag. See the [CLI reconciliation modes](/docs/cli#reconciliation-modes) section for detailed semantics.

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
| `secrets` | get, list, watch, create, update, patch |
| `events` | create, patch |

The Helm chart creates the ClusterRole, ClusterRoleBinding, and ServiceAccount automatically.
