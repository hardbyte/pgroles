---
title: Ephemeral access
description: Request, approve, audit, and revoke bounded PostgreSQL role memberships.
---

# Ephemeral PostgreSQL access

Ephemeral access grants an existing PostgreSQL identity one predefined bundle of
role memberships for a bounded duration. `PostgresPolicy` remains the durable
source of truth; an `EphemeralAccessPolicy` defines a requestable bundle, and an
immutable `EphemeralAccessRequest` records one approval and lease lifecycle.

The feature does not issue credentials, implement cloud login, or terminate
existing sessions. Revoking membership prevents a new `SET ROLE`, but a session
which already assumed the role can retain it until it resets or disconnects.

## Define a requestable bundle

```yaml
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessPolicy
metadata:
  name: inventory-incident-editor
  namespace: pgroles-system
spec:
  postgresPolicyRef:
    name: production
  memberships:
    - role: inventory-editor
      inherit: false
    - role: audit-viewer
      inherit: false
  maximumDuration: 1h
  defaultDuration: 30m
  pendingRequestTTL: 15m
  justification:
    required: true
  approval:
    mode: Required
```

The target must be a same-namespace `PostgresPolicy` in `mode: apply`. Roles are
concrete names from its expanded graph. The subject already exists; pgroles does
not create a login identity for a request. Membership never carries `ADMIN
OPTION`. Durations are one or more integer/unit pairs using `s`, `m`, or `h`
(for example `45s` or `1h30m`); unitless values are rejected.

PostgreSQL 16 and later can enforce `inherit` per membership. On PostgreSQL 15,
the requested value must match the subject role's server-wide `INHERIT`
attribute; the request fails before SQL when it does not. This prevents a
set-role-only (`inherit: false`) bundle from becoming implicitly inherited on
servers that cannot encode that option on `GRANT ROLE`.

```yaml
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  generateName: inventory-incident-editor-
  namespace: pgroles-system
spec:
  accessPolicyRef:
    name: inventory-incident-editor
  subject:
    role: alice@example.com
  requestedDuration: 30m
  justification: Investigating INC-1234
```

The request spec is immutable. The operator resolves concrete memberships into
write-once `status.resolvedAccess`, including the target and access-policy UIDs,
a non-secret fingerprint of the resolved host/port/database, a versioned
canonical bundle hash, and the granted duration. The fingerprint is part of the
approved bundle. Credential rotation is allowed, but changing the resolved
host, port, or database blocks activation, durable reconciliation, and
revocation until the original target is restored. This fail-closed rule avoids
revoking an identically named role in a different database.

## Secure `Required` approval with Kyverno

CRDs have no custom `/approval` subresource. Kubernetes RBAC alone cannot
separate approval-condition mutation from other status updates. A `Required`
policy without admission enforcement is therefore only a trusted-status-writer
contract.

The recommended secure installation is in
`k8s/security/ephemeral-access-kyverno.yaml`. Kyverno's CEL
`ValidatingPolicy` enforces decision integrity. Because that CEL environment
does not expose Kubernetes'
`authorizer`, a narrowly scoped Kyverno `ClusterPolicy` performs documented
`SubjectAccessReview` API calls for the logical verbs and enforces ownership of
operator-managed lifecycle status and finalizers. Together they:

- require the logical `use` verb on an access policy to create a request;
- require the logical `approve` verb to change `Approved` or `Denied`;
- require the logical `manage` verb to change operator-owned lifecycle status
  or remove an ephemeral-access finalizer;
- bind a decision to the resolved bundle hash and duration;
- leave approvers able to change only their `Approved`/`Denied` conditions.

The companion `k8s/security/ephemeral-access-rbac.yaml` defines requester and
approver ClusterRoles. Bind those roles to deployment-specific users, groups,
or brokers. The pgroles operator service account deliberately has neither
`use` nor `approve`; its normal controller ClusterRole carries `manage`.
Authorizing lifecycle ownership through a logical verb avoids hard-coding a
namespace or service-account name and remains correct with Helm naming
overrides. The manifest also grants Kyverno's reports controller read-only CRD
discovery through an aggregated role; it does not grant mutation access.

An approver appends a typed decision while preserving operator-owned
conditions. JSON Patch is convenient because it does not replace the condition
array:

```json
[
  {
    "op": "add",
    "path": "/status/conditions/-",
    "value": {
      "type": "Approved",
      "status": "True",
      "reason": "ApprovedByAccessReview",
      "bundleHash": "sha256:...",
      "grantedDuration": "1800s"
    }
  }
]
```

The controller also treats a request-owned activation plan as execution
provenance. `Applying` and `Active` status without a matching controller owner
UID, origin, operation, and bundle hash never enters the effective graph;
revocation likewise cannot execute without that activation record. This is a
defence-in-depth boundary for trusted-writer installations without Kyverno.

## Audit is an external durability requirement

In-cluster policy, request, plan, status, and Event objects are operational
state. They are **not the system of record**: finalizers, retention, garbage
collection, administrators, and etcd lifecycle can all remove or rewrite them.

Enable Kubernetes API auditing and send it to an off-cluster backend with an
independent retention policy. This audit-policy fragment records the request and
response bodies for all security-relevant ephemeral-access mutations:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived
rules:
  - level: RequestResponse
    verbs: [create, update, patch, delete]
    resources:
      - group: pgroles.io
        resources:
          - ephemeralaccesspolicies
          - ephemeralaccessrequests
          - ephemeralaccessrequests/status
          - postgrespolicyplans
          - postgrespolicyplans/status
  - level: Metadata
    resources:
      - group: pgroles.io
        resources: ["*"]
```

`RequestResponse` captures subjects and justifications, so protect the audit
backend accordingly. At minimum, retain request status patches and the
admission decision identifying the authenticated caller.

As belt-and-braces evidence, every request lifecycle transition also emits a
structured `pgroles.ephemeral_access.lifecycle` log event with request UID,
access-policy UID, target-policy UID, bundle hash, subject, old/new phase,
reason, and lifecycle timestamps. When `OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is configured, these events are exported
through OTLP as well as JSON stdout. Route OTLP logs to append-only or otherwise
tamper-resistant off-cluster storage. Configure `OTEL_LOGS_EXPORTER=none` only
when another agent already ships container logs durably.

The same transitions emit Kubernetes Events on the request object. OTLP
metrics include:

- `pgroles.ephemeral_access.transitions`
- `pgroles.ephemeral_access.failures`
- `pgroles.ephemeral_access.expiry_lag`
- `pgroles.ephemeral_access.retained_memberships`
- `pgroles.ephemeral_access.role_retirement_blocked`

Metrics and Events are operational signals, not substitutes for API audit and
off-cluster lifecycle logs.

## Expiry and deletion

Activation persists the absolute expiry before changing PostgreSQL. Expiry and
request deletion use the same database locks and a request-owned scoped plan;
only memberships for the approved bundle may be changed. An edge is removed
only after its final ephemeral owner ends and when the current durable graph
does not own it.

Recovery never resets the absolute deadline. An `Applying` request found after
its deadline is cancelled if SQL never began, or immediately cleaned up if its
activation plan shows that execution may have started. It is never granted a
fresh duration after restart.

Suspending an access policy blocks new activation while active requests run to
their existing expiry. Deleting an access policy deletes and revokes its
requests before the policy finalizer completes. Do not forcibly remove
finalizers: authoritative reconciliation can later heal a stranded edge, but
additive mode may leave it indefinitely.

Deleting a target `PostgresPolicy` first deletes attached access policies and
waits for their request finalizers, keeping the database connection available
until scoped revocation completes. Invalid unresolved requests expose
`Resolved=False`, a reason, and `status.lastError` with a slower retry rather
than remaining silent in `Pending`.

Role retirement is blocked before SQL planning when an active request still
uses the subject or granted role. The target policy error and affected access
policy `RoleRetirementBlocked` condition include the blocking request name and
UID.

## Existing sessions

Revoking membership prevents a fresh `SET ROLE`; it does not terminate a
session which already assumed the capability role. The E2E suite verifies that
an elevated session remains under its current role until `RESET ROLE` or
disconnect, while a subsequent and a newly connected `SET ROLE` are rejected.
Connection pools therefore need their own bounded-lifetime or eviction policy
when wall-clock session termination is required. pgroles does not implicitly
call `pg_terminate_backend`.

Natural terminal requests remain as Kubernetes operational records. Deletion
is currently the garbage-collection mechanism; choose explicit retention and
cleanup automation for the cluster, while keeping Kubernetes audit and OTLP
logs as the durable record.
