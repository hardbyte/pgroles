---
title: Securing ephemeral access
description: Trust models, admission controls, audit, and abuse resistance for ephemeral PostgreSQL access.
---

The pgroles operator enforces bounded PostgreSQL membership and safe lifecycle
transitions. Your deployment must establish who may request, approve, and
administer that lifecycle, and must retain authenticated evidence outside the
mutable Kubernetes objects.

{% callout type="warning" title="Required approval needs a real trust boundary" %}
RBAC on `EphemeralAccessRequest/status` alone cannot separate approval from
other status management. Use admission enforcement for direct Kubernetes API
access, or restrict request APIs to a trusted broker which authenticates users
and records decisions itself.
{% /callout %}

## Choose a trust model

| Model | Who writes requests and decisions | Identity authority | Deployment requirement |
|---|---|---|---|
| Direct Kubernetes API with admission enforcement | Authenticated Kubernetes users or service accounts | Admission `userInfo` | Enforce every control below. The supplied Kyverno policy is a CI-tested starting point. |
| Trusted broker | Only the broker and pgroles controller | The broker's authentication and audit trail | Deny users direct write access; have the broker populate actor fields and preserve its authenticated human-level audit record. |
| Trusted status writers | Any identity holding request/status RBAC | Writer-supplied assertions | Suitable only where every writer is already trusted to request, approve, and manage lifecycle state. This is not independent approval separation. |

`approval.mode: Automatic` removes the approver but does not change the
requester boundary: whoever can create an accepted request can activate the
bundle. `approval.mode: Required` additionally needs an independently authorized
decision maker.

## Required enforcement contract

An admission implementation or trusted broker must provide all of these
controls:

1. Derive `spec.requestedBy` from the authenticated requester rather than
   trusting submitted identity fields.
2. Define who the requester may name as `spec.subject.role`: derive it from an
   identity mapping, authorize the requester-to-subject relationship, or
   deliberately treat `use` as authority to nominate any concrete subject.
3. Authorize a logical `use` action against the referenced
   `EphemeralAccessPolicy` before admitting a request.
4. Authorize a logical `approve` action before accepting an `Approved` or
   `Denied` condition.
5. Record `status.decidedBy` from the same authenticated decision maker in the
   same update as the terminal condition.
6. Bind approval to the exact write-once bundle hash and granted duration.
7. Let a requester delete only their own request; require lifecycle-management
   authority to delete another request during normal operation, without
   blocking cleanup of a namespace that is already terminating.
8. Prevent requesters and approvers from modifying controller-owned lifecycle
   status or removing finalizers; reserve that authority for a logical `manage`
   action and the operator.
9. Reject client-supplied request finalizers and constrain any other permitted
   metadata according to the deployment's object-size budget.
10. Preserve authenticated create, decision, status, and deletion evidence in an
   independently retained audit system.

The CRD itself enforces immutable request specs, write-once resolution, terminal
decisions, and the required pairing between a decision and `decidedBy`. Those
rules protect object integrity but cannot establish who authenticated to make a
request or decision.

## Why status RBAC is insufficient

Kubernetes custom resources support only the optional `/status` and `/scale`
subresources; a CRD cannot define a separately authorizable `/approval`
subresource. The
[Kubernetes CRD documentation](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#subresources)
describes the available subresources.

Consequently, permission to patch `EphemeralAccessRequest/status` is broad
enough to submit approval conditions as well as ordinary lifecycle status.
Admission enforcement must inspect the actual transition and authorize the
logical operation, or a trusted broker must be the only non-controller status
writer.

## CI-tested Kyverno reference implementation

pgroles ships tested authorization and lifecycle controls for clusters which
already use Kyverno:

- `k8s/security/ephemeral-access-rbac.yaml` defines the logical `use`,
  `approve`, and `manage` roles.
- `k8s/security/ephemeral-access-kyverno.yaml` authenticates actor fields,
  performs `SubjectAccessReview` checks, and protects lifecycle status and
  finalizers. The Helm chart renders the same policies from
  `admissionPolicies.enabled`.
- `k8s/security/plan-decision-kyverno.yaml` does the equivalent for
  `PostgresPolicyPlan` approvals.

The reference profile is tested in CI with Kyverno 1.18.2. Other Kyverno
versions are not currently verified by pgroles. Install Kyverno using the
supported method for your cluster, then apply the pgroles manifests:

```shell
kubectl apply -f k8s/security/ephemeral-access-rbac.yaml
helm upgrade pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --namespace pgroles-system --reuse-values \
  --set admissionPolicies.enabled=true
```

Prefer the chart for the admission policies. `admissionPolicies.enabled`
defaults to `false` — the policies are Kyverno custom resources, so enabling
them without Kyverno present fails the install — but leaving it off means
decisions are unattributed and `approval.mode: Required` is not an approval
boundary. Turn it on as soon as Kyverno is in the cluster. The chart generates
the operator's exemption from `operator.serviceAccount.name` and the release
namespace, so a non-default install cannot silently stall plans on a mismatched
identity. Per-policy flags `admissionPolicies.planDecision.enabled` and
`admissionPolicies.ephemeralAccess.enabled` are on by default under it.

If you are not using the chart, apply the mirrored manifests instead. They are
pinned to the `pgroles-system` namespace and the `pgroles-operator`
ServiceAccount name, and the exemption in `plan-decision-kyverno.yaml` must be
edited to match your install:

```shell
kubectl apply -f k8s/security/ephemeral-access-kyverno.yaml
kubectl apply -f k8s/security/plan-decision-kyverno.yaml
```

Bind the requester and approver ClusterRoles to deployment-specific users,
groups, or brokers. Prefer namespace-scoped `RoleBinding` objects so access to
one namespace does not imply access to every pgroles installation:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: database-access-requesters
  namespace: pgroles-system
subjects:
  - kind: Group
    name: database-users
    apiGroup: rbac.authorization.k8s.io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pgroles-ephemeral-access-requester
```

Create an equivalent namespaced binding to
`pgroles-ephemeral-access-approver` for the approver group. The pgroles operator
service account deliberately has neither `use` nor `approve`; its controller
ClusterRole carries `manage`.

The reference implementation:

- replaces `spec.requestedBy` with the authenticated request creator;
- requires `use` on the referenced access policy;
- lets requesters delete their own requests but requires `manage` to delete
  another caller's request during normal operation;
- allows the namespace controller to complete deletion once the namespace is
  already terminating, without admission blocking pgroles finalizer attempts;
- requires `approve` for terminal decisions;
- replaces `status.decidedBy` with the authenticated decision maker;
- restricts approvers to their decision conditions;
- rejects client-supplied request finalizers and requires `manage` for
  operator-owned status and finalizer changes; and
- validates the decision's bundle hash and duration.

The reference policy deliberately gives a holder of `use` authority to nominate
any concrete PostgreSQL subject accepted by the access policy. It cannot infer a
portable mapping between Kubernetes identities and PostgreSQL roles. Restrict
`Automatic` policies to trusted requesters, or extend the admission policy with
your identity mapping. With `Required`, approvers must verify the named subject
as part of their decision.

Namespace deletion does not guarantee PostgreSQL revocation. Kubernetes may
delete the connection Secret, access policy, target policy, or scoped plan
before a request finalizer can use them. Before deleting a namespace, delete
its ephemeral access requests and access policies, wait for their finalizers to
complete, and verify that active memberships have been revoked. The namespace
termination exception prevents admission deadlock; it does not replace that
drain procedure.

Kyverno mutation occurs before schema validation, so client-supplied actor
fields are replaced before the CRD validates and persists the object. The
[Kyverno mutation documentation](https://kyverno.io/docs/policy-types/cluster-policy/mutate/)
describes that admission order.

These manifests are a reference implementation, not an operator runtime
dependency. Complete the deployment-specific subject mapping and metadata
budget choices described above. An alternative admission controller or broker
is acceptable if it satisfies the same enforcement contract. Test create,
approve, deny, delete, lifecycle-status, finalizer, and forged-identity paths
before enabling user access.

## Identity and durable audit

`spec.requestedBy` and `status.decidedBy` make the current request and lifecycle
logs self-describing. They are authoritative only to the extent that admission
or the broker prevents callers from choosing them.

In-cluster policy, request, plan, status, and Event objects are operational
state. They are **not the system of record**: finalizers, retention, garbage
collection, administrators, and etcd lifecycle can remove or rewrite them.
Retain Kubernetes API audit events or broker audit events in an off-cluster
backend with an independent retention policy.

This Kubernetes audit-policy fragment records request and response bodies for
security-relevant pgroles mutations. It is API-server configuration, not a
Kubernetes object to apply with `kubectl`; configure it through the control
plane or the audit controls exposed by your managed Kubernetes provider.

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
backend accordingly. At minimum, retain request creation, status decisions, and
deletion with the authenticated caller and admission result. In the trusted
broker model, Kubernetes sees the broker identity; the broker must separately
retain the authenticated end-user identity.

Every request lifecycle transition also emits a structured
`pgroles.ephemeral_access.lifecycle` log with request UID, access-policy UID,
target-policy UID, bundle hash, subject, requester, decision maker, old and new
phase, reason, and lifecycle timestamps. Configure OTLP export or another
container-log pipeline to append-only or otherwise tamper-resistant off-cluster
storage. Kubernetes Events and metrics are operational signals, not durable
audit records.

## Bound resource consumption

The CRD bounds every user-controlled ephemeral spec and status string and
collection. One access policy may contain at most 32 memberships, one actor at
most 64 groups, and justification and description text at most 2 KiB.
Kubernetes `metadata` has separate platform limits and is not governed by the
CRD's nested schema; the reference admission policy rejects client-supplied
request finalizers, but deployments which permit annotations or labels should
also bound them in admission. Per-object bounds do not limit how many objects a
caller can create.

Apply a Kubernetes `ResourceQuota` in every namespace where ephemeral access is
enabled. The supplied example permits 50 access policies and 500 retained
requests:

```shell
kubectl apply -f k8s/security/ephemeral-access-resource-quota.yaml
```

Edit its namespace and limits for expected request volume and retention. The
quota rejects excess objects before they enter the controller cache or
reconciliation queue. It limits persisted requests, not simultaneous active
grants; policy-level concurrency limits are tracked separately in
[issue #163](https://github.com/hardbyte/pgroles/issues/163).

Delete terminal request objects according to an explicit retention policy after
their durable audit records have been exported.

## Residual risks

- Revocation prevents a new `SET ROLE` but does not de-elevate a session which
  already assumed the granted role. Bound or evict pooled sessions when access
  must end at a wall-clock deadline.
- A cluster administrator can bypass admission, alter objects, or remove
  finalizers. Cluster-admin activity must be covered by the external audit
  boundary.
- Force-removing a request or policy finalizer can strand membership. Durable
  authoritative reconciliation may heal it; additive mode may not.
- A namespace `ResourceQuota` limits object count, not active database access.
  Choose a conservative quota until policy-level concurrency ceilings exist.
- `use` authorization happens at request creation. Removing that permission
  later does not cancel a pending request or revoke an active one; delete the
  request or its access policy to trigger revocation.
- OTLP logs, Kubernetes Events, and in-cluster status improve operations but do
  not replace authenticated, independently retained audit evidence.
