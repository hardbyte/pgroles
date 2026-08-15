---
title: Ephemeral access
description: Request, approve, and revoke bounded PostgreSQL role memberships.
---

Ephemeral access grants an existing PostgreSQL identity one predefined bundle of
role memberships for a bounded duration. `PostgresPolicy` remains the durable
source of truth; an `EphemeralAccessPolicy` defines a requestable bundle, and an
immutable `EphemeralAccessRequest` records one request lifecycle.

The feature does not issue credentials, implement cloud login, or terminate
existing sessions. Revoking membership prevents a new `SET ROLE`, but a session
which already assumed the role can retain it until it resets or disconnects.

{% callout type="warning" title="Choose a trust model before enabling requests" %}
Direct Kubernetes API access needs admission enforcement; a trusted broker must
authenticate callers and be the only non-controller writer. pgroles ships a
CI-tested Kyverno reference implementation, but Kyverno is not part of the
operator itself. See [securing ephemeral access](/docs/ephemeral-access-security).
{% /callout %}

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
on each membership. Setting `inherit: false` creates set-role-only access: the
subject must explicitly run `SET ROLE`, rather than inheriting the granted
role's privileges immediately.

`pendingRequestTTL` defaults to `15m` when omitted: a request that is not
approved within that window becomes `ApprovalExpired` and cannot be revived.

### Cluster ceilings

Two operator environment variables cap what any access policy may ask for. They
are the only cluster-wide limit on ephemeral access, so set them before enabling
the feature — a namespace `ResourceQuota` bounds how many objects exist, not how
long access lasts.

| Variable | Default | Bounds |
| --- | --- | --- |
| `EPHEMERAL_ACCESS_MAXIMUM_DURATION` | `24h` | `spec.maximumDuration` |
| `EPHEMERAL_ACCESS_MAX_PENDING_TTL` | `1h` | `spec.pendingRequestTTL` |

An access policy exceeding either ceiling is rejected with `Accepted=False` and
reason `DurationExceedsClusterMaximum`, so it never becomes requestable. Set them
through `operator.env` in the Helm chart.

## Create a request

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

`requestedBy` is required so every request is self-describing. It is trustworthy
only when an admission policy derives it from the authenticated Kubernetes
caller or a trusted broker supplies it after authenticating the requester. The
supplied Kyverno reference policy replaces the submitted username, UID, and
groups with admission `userInfo`. Its `use` check authorizes the bundle, not a
mapping from the caller to `subject.role`; restrict requesters accordingly or
add that identity mapping in admission.

The request spec is immutable. The operator resolves concrete memberships into
write-once `status.resolvedAccess`, including the target and access-policy UIDs,
a non-secret fingerprint of the resolved host, port, and database, a versioned
canonical bundle hash, and the granted duration. Credential rotation is allowed,
but changing the resolved host, port, or database blocks activation, durable
reconciliation, and revocation until the original target is restored.

## Approve a request

`approval.mode: Automatic` begins activation after the request resolves. It
removes the decision step, not the need to authenticate and authorize whoever
can create requests.

`approval.mode: Required` waits for one terminal `Approved=True` or
`Denied=True` condition. An approval must attest to the exact resolved bundle
hash and duration. The condition and `status.decidedBy` are recorded together:

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
  },
  {
    "op": "add",
    "path": "/status/decidedBy",
    "value": {
      "username": "approver@example.com",
      "groups": []
    }
  }
]
```

The Kyverno reference policy overwrites `decidedBy` with authenticated admission
`userInfo`. A trusted broker must set it from its authenticated decision maker.
The CRD makes the decision and identity terminal, while the deployment's
security boundary determines whether that identity is authoritative. See
[securing ephemeral access](/docs/ephemeral-access-security) for the required
controls and tested manifests.

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
finalizers: authoritative reconciliation can later heal a stranded membership,
but additive mode may leave it indefinitely.

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
is currently the garbage-collection mechanism. Choose explicit retention and
cleanup automation, and follow the [security guide](/docs/ephemeral-access-security)
for durable audit and resource-exhaustion controls.
