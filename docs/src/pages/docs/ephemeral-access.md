---
title: Ephemeral access
description: Request, approve, audit, and revoke bounded PostgreSQL role memberships.
---

# Ephemeral PostgreSQL access

Ephemeral access grants an existing PostgreSQL identity one predefined bundle of
role memberships for a bounded duration. `PostgresPolicy` remains the durable
source of truth; an `EphemeralAccessPolicy` defines a requestable bundle, and an
immutable `EphemeralAccessRequest` records one approval and request lifecycle.

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
not create a login identity for a request. Ephemeral memberships never include
`ADMIN OPTION`: the subject can use the granted role but cannot grant it to
another role. Durations are one or more integer/unit pairs using `s`, `m`, or
`h` (for example `45s` or `1h30m`); unitless values are rejected.

Ephemeral access requires PostgreSQL 16 or later so that `inherit` is enforced
on each membership. Setting `inherit: false` creates set-role-only access:
the subject must explicitly run `SET ROLE`, rather than inheriting the granted
role's privileges immediately.

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
  requestedBy:
    username: alice@example.com
  requestedDuration: 30m
  justification: Investigating INC-1234
```

`requestedBy` is required so every request has an operational identity even in
a trusted-broker installation. In the recommended secure installation,
Kyverno replaces the submitted username, UID, and groups with the authenticated
Kubernetes admission identity. A client therefore cannot choose who the
request appears to come from.

The request spec is immutable. The operator resolves concrete memberships into
write-once `status.resolvedAccess`, including the target and access-policy UIDs,
a non-secret fingerprint of the resolved host/port/database, a versioned
canonical bundle hash, and the granted duration. The fingerprint is part of the
approved bundle. Credential rotation is allowed, but changing the resolved
host, port, or database blocks activation, durable reconciliation, and
revocation until the original target is restored. This fail-closed rule avoids
revoking an identically named role in a different database.

## Secure `Required` approval with Kyverno

{% callout type="warning" title="Admission enforcement is required" %}
For secure `Required` approval, install the supplied Kyverno policies. RBAC
alone cannot protect approval decisions on a custom resource's status.
{% /callout %}

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

- replace `spec.requestedBy` with the authenticated request creator;
- require the logical `use` verb on an access policy to create a request;
- require the logical `approve` verb to change `Approved` or `Denied`;
- record the authenticated approver or denier in write-once
  `status.decidedBy`;
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

Kyverno adds `status.decidedBy` from the authenticated admission identity in
the same update. A trusted broker operating without Kyverno must include that
field itself; the resulting value is useful operational metadata but is not an
independent authentication record.

The controller grants only the exact resolved bundle recorded for the request,
and revokes only memberships proven to have been activated by that request.
Forged lifecycle status cannot create access or authorize revocation. See
[operator architecture](/docs/operator-architecture#ephemeral-access-overlays)
for the ownership and execution-record checks behind this guarantee.
Without Kyverno, `requestedBy` and `decidedBy` are assertions made by the
trusted client or broker; Kubernetes API audit remains the only independent
record of the authenticated caller.

## Bound request-object growth

The CRD limits one access policy to 32 memberships, one actor identity to 64
groups, conditions to small fixed collections, justification and description
text to 2 KiB, and every other user-controlled string or collection to an
explicit maximum. These limits bound each object; they do not bound the number
of objects in a namespace.

Apply a Kubernetes `ResourceQuota` in every namespace where ephemeral access
is enabled. The supplied example permits 50 access policies and 500 retained
requests:

```shell
kubectl apply -f k8s/security/ephemeral-access-resource-quota.yaml
```

Edit its namespace and limits for local request volume and retention. The
quota is an API-server hard stop, so excess objects are rejected before they
enter the controller cache or reconciliation queue. It limits persisted
requests, not simultaneous active grants; keep the quota conservative and
delete terminal request objects according to your retention policy.

## Audit is an external durability requirement

In-cluster policy, request, plan, status, and Event objects are operational
state. They are **not the system of record**: finalizers, retention, garbage
collection, administrators, and etcd lifecycle can all remove or rewrite them.
`spec.requestedBy` and `status.decidedBy` make the current object and lifecycle
logs self-describing, but only an independently retained API audit event proves
which authenticated identity performed each mutation.

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
access-policy UID, target-policy UID, bundle hash, subject, requester,
decision-maker, old/new phase, reason, and lifecycle timestamps. When
`OTEL_EXPORTER_OTLP_ENDPOINT` or
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

Activation records the absolute expiry before changing PostgreSQL. Expiry and
request deletion can change only memberships in the approved bundle. A
membership remains while another active request still needs it or when it has
become part of the durable `PostgresPolicy` configuration.

Recovery never resets the absolute deadline. An `Applying` request found after
its deadline is cancelled if SQL never began, or immediately cleaned up if its
activation plan shows that execution may have started. It is never granted a
fresh duration after restart.

Suspending an access policy blocks new activation while active requests run to
their existing expiry. Deleting an access policy deletes and revokes its
requests before the policy finalizer completes. Do not forcibly remove
finalizers: authoritative reconciliation can later heal a stranded membership, but
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
session which already assumed the granted role. The current session remains
elevated until `RESET ROLE` or disconnect. Further `SET ROLE` attempts,
including from new sessions, are rejected after revocation.
Connection pools therefore need their own bounded-lifetime or eviction policy
when wall-clock session termination is required. pgroles does not implicitly
call `pg_terminate_backend`.

Natural terminal requests remain as Kubernetes operational records. Deletion
is currently the garbage-collection mechanism; choose explicit retention and
cleanup automation for the cluster, while keeping Kubernetes audit and OTLP
logs as the durable record.
