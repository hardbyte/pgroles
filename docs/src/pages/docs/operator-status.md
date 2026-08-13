---
title: Status, conditions and telemetry
description: Reading PostgresPolicy status, the condition vocabulary, Kubernetes Events, and exported metrics.
---

What the operator reports about itself, and what to alert on. {% .lead %}

---

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
  last_successful_reconcile_time: "2026-03-06T10:30:00Z"
  lastHandledReconcileAt: "2026-03-06T10:31:00Z"
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

## Conditions

| Type | Meaning |
| --- | --- |
| `Ready` | `True` when the last reconciliation succeeded |
| `Drifted` | `True` when changes are pending but not applied — in `mode: plan`, and in `mode: apply` with `approval: manual` while a plan awaits a decision |
| `Reconciling` | `True` while a reconciliation is in progress |
| `Degraded` | `True` when the last reconciliation failed (includes error detail) |
| `Conflict` | `True` when another policy targets the same database with overlapping ownership |
| `Paused` | `True` while `spec.suspend` stops reconciliation |
| `ApprovalUnset` | `True` while `spec.approval` is omitted and inferred from `spec.mode` (deprecated) |
| `ApprovalIgnored` | `True` when a plan is approved but `spec.mode: plan` means it will never execute |

`ApprovalUnset` and `ApprovalIgnored` are advisory: they report a configuration
that will not do what it looks like, and neither indicates a failed
reconciliation. Both clear on the next reconcile once the configuration is
corrected.

On failure, the operator chooses a retry path based on the failure mode:

- lock contention: short jittered retry
- transient operational failures: exponential backoff with jitter
- invalid specs, conflicts, and unsafe role-drop blockers: normal reconcile interval

## Health and telemetry

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

| Metric | Labels | Meaning |
| --- | --- | --- |
| `pgroles.reconcile.total` | `result`, `reason` | Reconcile outcomes |
| `pgroles.reconcile.duration` | - | Reconcile wall time |
| `pgroles.reconcile.inflight` | - | Reconciles currently running |
| `pgroles.plan.total` | `result` | Plans computed |
| `pgroles.plan.changes` | - | Changes per plan |
| `pgroles.apply.total` | `result` | Applies attempted |
| `pgroles.apply.statements` | - | SQL statements executed |
| `pgroles.lock_contention.total` | - | Reconciles that lost the per-database lock |
| `pgroles.policy.conflicts` | - | Overlapping-ownership conflicts detected |
| `pgroles.database.connection_failures` | - | Failed database connections |
| `pgroles.invalid_spec.total` | - | Specs rejected as invalid |
| `pgroles.deprecated.approval_unset` | `inferred` | Policies relying on the deprecated `spec.approval` inference |
| `pgroles.inspect.duration` | `phase` | Duration for each inspection phase |
| `pgroles.inspect.items` | `kind` | Counts of inspected objects by kind |
| `pgroles.wildcard.grantability_queries` | - | Wildcard grantability catalog queries issued |
| `pgroles.wildcard.unsatisfied_grants` | - | Wildcard grants missing privileges before grantability checks |
| `pgroles.ephemeral_access.transitions` | `phase`, `reason` | Ephemeral request phase transitions |
| `pgroles.ephemeral_access.failures` | `reason` | Ephemeral activation and revocation failures |
| `pgroles.ephemeral_access.retained_memberships` | - | Memberships kept at expiry because they became durable |
| `pgroles.ephemeral_access.expiry_lag` | - | Seconds between expiry and revocation |
| `pgroles.ephemeral_access.role_retirement_blocked` | - | Role retirements blocked by an in-flight request |

Useful alerting signals: `Degraded=True` for reconcile failure (not bare
`Ready=False`, which is also how a healthy plan-awaiting-approval policy
reports), sustained `Drifted=True` on an auto-applying policy,
`pgroles.lock_contention.total` rising steadily, and
`pgroles.deprecated.approval_unset` as the count of policies still relying on
the deprecated inference.

The operator also emits transition-based Kubernetes Events on the policy.
Status transitions:

- `ConflictDetected`, `ConflictResolved`
- `Suspended`
- `Reconciled`, `Recovered`
- `DriftDetected`, `PlanClean`
- `ApprovalUnset`, `ApprovalIgnored`
- `InvalidSpec`
- `SecretFetchFailed`
- `DatabaseConnectionFailed`
- `GcpAuthFailed`
- `InsufficientPrivileges`
- `UnsafeRoleDropsBlocked`

Plan lifecycle:

- `PlanCreated`, `PlanApproved`, `PlanRejected`
- `ApplyStarted`, `ApplySucceeded`, `ApplyFailed`

Not every failure becomes an Event. `MissingDatabaseObject`,
`InvalidConnectionParams`, and `UnsatisfiableWildcardGrant` are condition
*reasons* only — they appear in `status.conditions[].reason` and never as an
Event, so alert on the condition rather than watching for an Event that will
not arrive.
