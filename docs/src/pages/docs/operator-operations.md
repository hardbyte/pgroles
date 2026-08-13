---
title: Running the operator
description: Reconciliation triggers, intervals, force reconcile, suspend, reconciliation mode, and deletion behaviour.
---

Day-to-day operation of a running policy. {% .lead %}

---

## Reconciliation

The operator reconciles on five paths:

- `PostgresPolicy` spec changes
- referenced Secret changes
- force-reconcile annotation changes
- `PostgresPolicyPlan` changes, matched back to the owning policy by controller-owner UID — this is what makes approving or rejecting a plan take effect immediately rather than at the next `interval`
- the normal periodic `interval`

Each reconcile inspects the current database state, computes a diff from the policy, and then either applies it or publishes a plan depending on `spec.mode`. Plan mode is non-mutating: it does not execute PostgreSQL DDL and it does not create generated password Secrets. Same-database policies are serialized, and status-only updates do not retrigger the controller.

Use this page for the external behavior and operating model. For the internal controller pipeline and locking model, see the [operator architecture](/docs/operator-architecture) page.

{% operator-reconciliation-diagram /%}

## Interval

The `interval` field controls how often the operator re-reconciles, even when the resource hasn't changed. This catches drift from manual SQL changes. Supports durations like `30s`, `5m`, `1h`, or compound forms like `1h30m`. Defaults to `5m`.

## Force reconcile

Set `reconcile.pgroles.io/requestedAt` to a new RFC 3339 timestamp to request an immediate reconcile without changing `spec`:

```shell
kubectl annotate postgrespolicy my-policy \
  reconcile.pgroles.io/requestedAt="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --overwrite
```

The same timestamp is idempotent. Re-setting it is a no-op, while setting a newer value bypasses the normal `interval` wait. The operator mirrors successfully handled requests to `status.lastHandledReconcileAt`, which is useful for scripts and runbooks that need to verify the request completed or produced a plan.

The CLI wraps the same annotation flow:

```shell
pgroles reconcile postgrespolicy/my-policy -n platform --wait
```

## Suspending

Set `suspend: true` to pause reconciliation without deleting the resource. The operator will skip the resource until `suspend` is set back to `false`.

## Reconciliation mode

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
| `additive` | Only grant, never revoke — safe for incremental adoption, and it leaves pre-existing role attributes/comments unchanged |
| `adopt` | Manage declared roles fully, but never drop undeclared roles |

This is the same behavior as the CLI `--mode` flag. See the [CLI reconciliation modes](/docs/cli#reconciliation-modes) section for detailed semantics.

## Deletion behaviour

When a `PostgresPolicy` resource is deleted, the operator **does not** revoke grants or drop roles. The database is left as-is. This is intentional — resource deletion means "stop managing", not "undo everything".
