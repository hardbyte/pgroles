---
title: Production status
description: What is stable in the pgroles operator, what the known gaps are, and the path to API stability.
---

Maturity of the operator, stated plainly. {% .lead %}

---

## Production status

The operator's safety model — serialized reconciliation, conflict detection, failure-aware retry, and transactional apply — is stable and tested in CI. The API surface, scale ceiling, and operational guidance have known gaps.

## Stable

**Reconciliation safety:**

- All changes execute in a single PostgreSQL transaction (all-or-nothing).
- Reconciliation is serialized per database target: in-process locking within a replica, PostgreSQL advisory locking across replicas.
- Conflicting policies (overlapping ownership claims) are rejected, not silently merged.

**Failure handling:**

- Transient operational failures use exponential backoff with jitter.
- Invalid specs, conflicts, and unsafe role-drop workflows fall back to the normal reconcile interval without hot-looping.
- Unsatisfiable wildcard grants are reported as `Ready=False` and `Degraded=True` with reason `UnsatisfiableWildcardGrant`; the operator does not create a `PostgresPolicyPlan` or SQL ConfigMap for that reconcile.
- Lock contention has its own short retry path.

**Observability:**

- Status conditions (`Ready`, `Drifted`, `Degraded`, `Conflict`, `Paused`) with change summaries and error detail.
- OTLP metrics export via OpenTelemetry Collector.
- Transition-based Kubernetes Events for `kubectl describe` debugging.
- `/livez` and `/readyz` health probes.

## Known gaps

**API stability:**

- The CRD is `v1alpha1`. There is no conversion webhook, no migration tooling. Follow the [upgrade guide](/docs/operator-upgrades) and review each release's compatibility notes.
- Controller semantics that should be part of the API contract are implementation-only conventions.

**Scale and HA:**

- Validate reconcile performance at your target object count before relying on the operator for large role and schema inventories.
- Advisory locks enable multi-replica deployment, but there is no documented HA pattern, replica guidance, or failure-mode analysis.

**Password drift visibility:**

- The operator re-applies passwords when the source Secret changes, but cannot detect a password changed directly in the database. See [password drift](/docs/limitations#password-drift) for why PostgreSQL makes this undetectable.

**Managed provider validation:**

- Treat managed-provider detection as environment-specific. Verify behavior against your target RDS, Cloud SQL, AlloyDB, or Azure PostgreSQL instance before relying on provider-specific SQL planning.

**Deployment security:**

- The operator requires controller RBAC with Secret read access. It is
  cluster-scoped by default; `operator.watchNamespace` scopes every watch and
  the chart's RBAC to a single namespace. Ephemeral request and approval
  hardening is covered in [securing ephemeral access](/docs/ephemeral-access-security).

**Deletion semantics:**

- Deleting a `PostgresPolicy` stops reconciliation but does not revert the database. This is by design (stop managing, not undo) but differs from GitOps conventions where deleting a resource reverts its effects.
- Deleting a policy with `--cascade=orphan` leaves its plans and plan-SQL ConfigMaps behind. They are matched to their policy by owner UID rather than by name, so a recreated policy of the same name does not re-adopt them, and orphan deletion strips the owner references that garbage collection relies on. Prefer the default cascading delete; if you have already orphaned some, delete the leftover `pgplan` objects and `*-sql` ConfigMaps by hand.

## Path to API stability

- Carry controller semantics into the CRD contract rather than leaving them as implementation conventions.
- Promote beyond `v1alpha1` only after the upgrade and rollback story is explicit.
- Establish a scale validation baseline that reflects real-world deployment sizes.
