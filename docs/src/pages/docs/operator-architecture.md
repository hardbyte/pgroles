---
title: Operator architecture
description: Internal architecture of the pgroles Kubernetes operator.
---

How the pgroles operator watches Kubernetes resources, talks to PostgreSQL, and enforces safe reconciliation. {% .lead %}

---

## Overview

The operator is a Kubernetes controller around the same core model as the CLI:

1. read desired state from a `PostgresPolicy`
2. inspect live PostgreSQL state
3. compute a convergent diff
4. apply changes in a single transaction
5. write status back to Kubernetes

The important difference is that the operator has to do this continuously, safely, and in the presence of concurrent policy updates, secret changes, and transient infrastructure failures.

## Control-plane diagram

{% operator-architecture-diagram /%}

## Main components

### CRD and policy model

`PostgresPolicy` is the operator-facing API. Its spec mirrors the CLI manifest format, with Kubernetes-specific fields for:

- Secret-based connection lookup
- reconciliation interval
- suspend/pause behavior

The controller converts the CRD into the same manifest types used by the CLI, so both paths share expansion, diffing, and SQL rendering semantics.

### Watch sources

The operator currently reconciles from two primary trigger sources:

- `PostgresPolicy` generation changes
- Secret `resourceVersion` changes for referenced database credentials

Generation filtering matters. The controller intentionally ignores status-only `PostgresPolicy` updates as reconcile triggers, otherwise successful status patches create hot loops and can starve other policies targeting the same database.

### Database connection handling

The operator reads `DATABASE_URL` from a Secret in the same namespace as the policy. It caches `sqlx::PgPool` instances by:

```text
namespace / secret name / secret key
```

When the Secret changes, the controller refetches it and refreshes the cached pool on the next reconcile. This is what enables credential rotation and recovery without restarting the operator.

### Reconcile engine

Each reconcile follows this path:

```text
PostgresPolicy
  -> Secret fetch
  -> PolicyManifest conversion
  -> manifest expansion
  -> live database inspection
  -> diff engine
  -> SQL rendering
  -> transaction apply
  -> status patch
```

The diff/apply behavior is shared with the CLI. The operator is not a separate implementation of role management logic; it is a controller wrapped around the same core engine.

## Safety model

### Ownership and conflict detection

Multiple policies may target the same database only if their ownership claims are disjoint.

The controller derives ownership claims from declared roles and schema/profile expansions, then rejects overlapping policies by setting conflict status instead of letting policies revoke each other's grants.

### Per-database serialization

Reconciliation is serialized per database target in two layers:

1. in-process locking to prevent concurrent reconciles in one operator replica
2. PostgreSQL advisory locking to prevent concurrent reconciles across replicas

This is the core safety boundary for production use. It ensures one database target has one active inspect/diff/apply cycle at a time.

### Retry and backoff

The controller uses different retry behavior depending on failure class:

- invalid specs and ownership conflicts: normal reconcile interval
- secret-missing and other non-transient configuration errors: normal reconcile interval
- transient infrastructure/database failures: exponential backoff with jitter
- lock contention: short dedicated retry path

That keeps the operator from hammering the Kubernetes API or the database during persistent misconfiguration.

## Status model

The operator writes status conditions and summaries back to the `PostgresPolicy`, including:

- `Ready`
- `Reconciling`
- `Degraded`
- `Conflict`
- `Paused`

It also records:

- last attempted generation
- last successful reconcile time
- managed database identity
- owned roles and schemas
- last error
- transient failure count
- change summary

This is the main operator-facing debugging surface for SREs.

## Observability

The operator exposes:

- `/livez`
- `/readyz`

Metrics are exported through OpenTelemetry OTLP. The intended deployment model is:

```text
pgroles-operator -> OpenTelemetry Collector -> metrics backend
```

The operator deliberately does not default to a built-in Prometheus scrape endpoint.

For object-local debugging, the controller also emits transition-based Kubernetes Events for notable status changes such as conflicts, suspend/resume, recovery, secret failures, database connectivity failures, and insufficient privileges. The intended split is:

- status: current state of the policy
- Events: notable transitions visible in `kubectl describe`
- OTLP metrics: fleet-level trends and alerting

## Current CI coverage

CI covers:

- happy-path reconciliation in kind
- same-database disjoint policies
- same-database disjoint policies recovering through shared-secret churn
- same-database conflicting policies
- invalid specs
- missing secrets
- insufficient database privileges
- secret rotation and recovery
- OTLP metrics export through an in-cluster Collector
- generated load policies across 2 databases with 30 schemas / 60 generated roles

Remaining gaps:

- higher-scale reconcile/load coverage
- more explicit fairness/concurrency testing under churn

## Relationship to the CLI

The CLI remains the simplest path for explicit, reviewed role changes. The operator is the continuous control plane version of the same model.

That split is intentional:

- the CLI is the easiest way to validate and review manifests
- the operator is the right place to enforce drift correction continuously inside Kubernetes

For the external user model, see the [operator guide](/docs/operator). For the shared workspace structure, see the general [architecture](/docs/architecture) page.
