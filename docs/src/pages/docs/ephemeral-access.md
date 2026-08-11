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
OPTION`.

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
a versioned canonical bundle hash, and the granted duration.

## Secure `Required` approval with Kyverno

CRDs have no custom `/approval` subresource. Kubernetes RBAC alone cannot
separate approval-condition mutation from other status updates. A `Required`
policy without admission enforcement is therefore only a trusted-status-writer
contract.

The recommended secure installation is in
`k8s/security/ephemeral-access-kyverno.yaml`. Kyverno's CEL
`ValidatingPolicy` resources enforce decision integrity and finalizer
ownership. Because that CEL environment does not expose Kubernetes'
`authorizer`, a narrowly scoped Kyverno `ClusterPolicy` performs documented
`SubjectAccessReview` API calls for the logical verbs. Together they:

- require the logical `use` verb on an access policy to create a request;
- require the logical `approve` verb to change `Approved` or `Denied`;
- bind a decision to the resolved bundle hash and duration;
- prevent non-operator principals from stripping cleanup finalizers.

The companion `k8s/security/ephemeral-access-rbac.yaml` defines requester and
approver ClusterRoles. Bind those roles to deployment-specific users, groups,
or brokers. The pgroles operator service account deliberately has neither
logical verb. The manifest also grants Kyverno's reports controller read-only
CRD discovery through an aggregated role; it does not grant mutation access.

An approver copies the resolved hash and duration into a typed decision:

```yaml
status:
  conditions:
    - type: Approved
      status: "True"
      reason: ApprovedByAccessReview
      bundleHash: sha256:...
      grantedDuration: 1800s
```

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

## Expiry and deletion

Activation persists the absolute expiry before changing PostgreSQL. Expiry and
request deletion use the same database locks and a request-owned scoped plan;
only memberships for the approved bundle may be changed. An edge is removed
only after its final ephemeral owner ends and when the current durable graph
does not own it.

Suspending an access policy blocks new activation while active requests run to
their existing expiry. Deleting an access policy deletes and revokes its
requests before the policy finalizer completes. Do not forcibly remove
finalizers: authoritative reconciliation can later heal a stranded edge, but
additive mode may leave it indefinitely.
