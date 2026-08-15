---
name: pgroles-operator
description: Configure, review, operate, and troubleshoot the pgroles Kubernetes operator and PostgresPolicy resources. Use when editing a PostgresPolicy or Helm release, reviewing or approving plans, diagnosing conflicts or status conditions, forcing reconciliation, or coordinating maintenance with the operator.
license: MIT
compatibility: Live operations require Kubernetes access; CLI workflows require a pgroles version compatible with the deployed operator and CRDs.
---

# Pgroles Operator

Use the deployed chart and CRD as the schema authority. Do not copy fields from
newer upstream documentation into an older cluster.

Load the `pgroles-policy` skill as well when changing roles, profiles, grants,
memberships, ownership, default privileges, or retirements.

Install or upgrade with the Helm instructions for the target release. Always
inspect chart values and rendered resources before applying an upgrade:

```bash
helm show values oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --version <version>
helm template pgroles-operator \
  oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --version <version> --namespace pgroles-system --include-crds \
  --values values.yaml > pgroles-operator-rendered.yaml
```

Helm does not upgrade objects shipped in a chart's `crds/` directory. Apply the
version-matched CRDs explicitly before upgrading the controller:

```bash
set -euo pipefail
helm show crds oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --version <version> > pgroles-operator-crds.yaml
test -s pgroles-operator-crds.yaml
kubectl apply --server-side -f pgroles-operator-crds.yaml
helm upgrade --install pgroles-operator \
  oci://ghcr.io/hardbyte/charts/pgroles-operator \
  --version <version> --namespace pgroles-system --create-namespace \
  --values values.yaml
```

Review the rendered CRD and workload diff before applying it. The API is
`v1alpha1` and has no conversion webhook; check release notes for compatibility
and rollback implications.

## Execution And Reconciliation

Two independent controls determine behavior:

- `spec.mode: plan` computes and publishes a filtered plan without executing
  PostgreSQL SQL.
- `spec.mode: apply` may execute the filtered plan, subject to `spec.approval`.
- `spec.reconciliation_mode` selects `additive`, `adopt`, or `authoritative`
  filtering. See the policy skill before changing it.

Treat `plan` to `apply`, approval changes, and stronger reconciliation modes as
operational database migrations. Review generated SQL and replacement access
before enabling execution.

## Policy Scope And Conflicts

Prefer one policy per database. Multiple policies may share a database only when
their ownership claims are disjoint.

Claims conservatively include declared and profile-expanded roles, grant and
default-privilege grantees, both sides of memberships, and declared or referenced
schemas. Sharing a referenced schema conflicts even if policies intend to manage
different objects inside it.

Conflict detection compares policies with the same operator database identity.
That identity comes from namespace-qualified connection references or structured
connection inputs, not from resolving every connection to a PostgreSQL endpoint.
Use the same canonical connection reference for policies intended to share a
database. Different Secrets can point to the same database without being
recognized as the same identity.

Plan-only policies retain claims. A suspended policy returns before checking
peers, but an active peer can still detect overlap with its claims.

## Rollout Workflow

1. Verify the target chart version, CRDs, connection Secret, executor privileges,
   and provider/IaC prerequisites.
2. Render the actual Kubernetes overlay or Helm release.
3. Start in `mode: plan` for brownfield or high-impact changes.
4. Inspect the `PostgresPolicyPlan`, SQL, change summary, revocations, role
   retirements, and transitive memberships.
5. Move to `mode: apply` with the smallest safe reconciliation mode and approval
   policy.
6. Wait for apply-mode convergence, then test positive and negative operations
   as the actual service identities.
7. Remove temporary grants or old credentials only after the replacement access
   and workload rollout are verified.

Argo CD `Synced`, resource creation, or a `Ready=True` condition alone does not
prove database convergence.

## Status Interpretation

`Ready=True` records a completed successful controller outcome. It may remain
while another reconcile starts or contends for a lock, and it can mean
`Planned` rather than applied.

`Drifted=True` means the latest successfully computed, reconciliation-mode-
filtered plan has pending changes. The condition may be absent during
reconciliation, suspension, conflict, or failure; absence is not in-sync proof.

For convergence within the selected reconciliation mode, require all of:

- `spec.mode: apply`
- `status.observed_generation == metadata.generation`
- `Ready=True` with reason `Reconciled`
- `Drifted=False`
- no current plan in `Pending`, `Approved`, or `Applying`

An `Applied` plan may remain referenced. Only authoritative mode represents full
convergence within pgroles' managed inspection scope; additive mode can leave
existing attributes and undeclared access untouched.

## Force Reconciliation

Prefer the version-matched CLI and specify the namespace:

```bash
pgroles reconcile postgrespolicy/<name> -n <namespace> --wait --timeout 2m
kubectl -n <namespace> get postgrespolicy <name> -o yaml
```

`--wait` acknowledges that the request reached a successful planning or
reconciliation outcome through `status.lastHandledReconcileAt`. It does not
guarantee SQL was applied. Requests blocked by suspension, conflict, contention,
or failure may remain unacknowledged.

## Plans And Approval

Before approving a plan:

- confirm it targets the current policy generation and database state
- inspect SQL and the change summary, not only the total count
- verify external identities and referenced schemas exist
- inspect revocations, membership removals, ownership changes, and retirements
- reject or allow supersession rather than approving a stale plan
- check `status.targetPhysicalIdentity` and `status.targetLogicalFingerprint`
  name the database you intend. Both are bound into the approval, so a plan
  whose target moved — a repointed connection Secret, a restore, a major
  version upgrade, a blue-green cutover — is superseded instead of executing,
  and needs a fresh approval. Set
  `spec.connection.requirePhysicalIdentity: true` to refuse to proceed at all
  when `pg_control_system().system_identifier` cannot be read.

Approve or reject the current plan explicitly:

A decision is a write to the plan's status subresource: one terminal `Approved`
or `Denied` condition plus the deciding identity, in the same write. There are
no approval annotations — setting `pgroles.io/approved` does nothing.

```bash
kubectl -n <namespace> patch pgplan <plan-name> \
  --subresource=status --type=merge -p '{
    "status": {
      "conditions": [{
        "type": "Approved", "status": "True",
        "reason": "ApprovedByReviewer",
        "message": "reviewed change summary",
        "lastTransitionTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }],
      "decidedBy": {"username": "'"$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')"'"}
    }
  }'
```

Reject by writing `Denied` with reason `DeniedByReviewer` in place of
`Approved`. A merge patch replaces the whole `conditions` array — never append a
second `Approved` entry alongside the `Approved=False` a plan is created with,
or the CRD's terminality rule wedges the plan. A decision is terminal and
write-once; iterating means a new plan, not an edited decision.

After approval, wait for `Applied` and then verify the parent policy's convergence
conditions. A plan object supports review and recent history, but is not
independent proof of current database state and may be removed by terminal-plan
retention.

## Ephemeral Access

Use `EphemeralAccessPolicy` for a GitOps-managed, bounded bundle of concrete
memberships and `EphemeralAccessRequest` for one runtime lease. Do not patch
`PostgresPolicy` memberships for just-in-time access.

For `approval.mode: Required`, first choose an admission-enforced or trusted
broker model. Kubernetes RBAC cannot isolate approval writes on a CRD's
`/status` subresource. The version-matched Kyverno and RBAC manifests under
`k8s/security/` are the CI-tested reference implementation, not an operator
runtime dependency. Any alternative must authenticate requester and decision
identities, define who may select each PostgreSQL subject, authorize the logical
`use`, `approve`, and `manage` actions, bind the exact resolved bundle hash and
duration, restrict cross-request deletion, reject client-owned finalizers, and
protect controller-owned lifecycle state. The reference `use` check delegates
selection of any concrete subject; add an identity mapping where that is too
broad. Verify `status.observedGeneration`, request phase, expiry, request-owned
scoped plan, and database membership rather than treating creation or approval
alone as success.

Every request supplies `spec.requestedBy`. The supplied Kyverno reference policy
replaces it from authenticated admission `userInfo` and records the identity
which approves or denies in write-once `status.decidedBy`. Without that
admission boundary both fields are broker assertions, not independent proof.
Apply a namespace `ResourceQuota` for
`count/ephemeralaccessrequests.pgroles.io` and
`count/ephemeralaccesspolicies.pgroles.io`; the repository ships
`k8s/security/ephemeral-access-resource-quota.yaml` as a tunable example.
For a single-namespace installation, set the Helm value
`operator.watchNamespace`; this scopes all watches and changes the chart RBAC
from cluster-wide roles to a namespaced `Role` and `RoleBinding`.

Deleting a request revokes its final-owner memberships through a finalizer.
Deleting an access policy is revoke-all, while suspension blocks new activation
and leaves active requests on their existing deadlines. Never force-remove
finalizers: authoritative reconciliation may repair the edge later, but
additive reconciliation can strand access. Membership expiry does not terminate
an existing session which already executed `SET ROLE`; apply a separate session
or pool lifetime when that guarantee is required.

## Suspension And Maintenance

`spec.suspend: true` prevents new work after a reconcile observes the suspended
spec. It does not cancel SQL already executing. The in-flight apply transaction
continues to commit or roll back.

`Paused=True` shows that a reconcile observed suspension. It is not a general
cross-replica drain barrier because suspension is handled before pgroles acquires
the per-database advisory lock. For destructive database maintenance, coordinate
an explicit operator writer drain appropriate to the deployment, such as safely
scaling the operator to zero and waiting for pod termination. Account for the
cluster-wide impact before doing so.

Resume reconciliation before removing recovery or maintenance-blocking state,
then force reconciliation and verify recovery.

## Troubleshooting Order

1. Confirm Kubernetes context, namespace, chart version, CRD, and policy
   generation.
2. Read all conditions, `last_error`, current plan, and recent Events.
3. Inspect operator logs without exposing Secrets or database URLs.
4. Confirm the connection identity and referenced Secrets exist.
5. Check policy ownership conflicts and overlapping role/schema claims.
6. Verify the executor's PostgreSQL ownership, grant options, role administration,
   and managed-provider limitations.
7. Recompute the plan only after resolving prerequisites; do not repeatedly
   approve unchanged failing SQL.

Policy deletion means stop managing. The operator intentionally leaves roles and
grants in the database.
