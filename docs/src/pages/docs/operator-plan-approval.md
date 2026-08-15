---
title: Plan and approval
description: Preview changes with observe mode and gate execution behind a reviewed, approved plan.
---

Seeing what the operator would do before it does it. {% .lead %}

---

{% callout type="warning" title="Design preview" %}
This page documents the target design from
[#173](https://github.com/hardbyte/pgroles/issues/173) ahead of implementation:
`mode: observe` (renamed from `plan`), the semantic change digest, write-once
plan decisions, and tiered target identity. Released behaviour still uses
`mode: plan`, approval annotations, and SQL-hash matching.
{% /callout %}

## Observe mode

Set `mode: observe` to let the operator inspect the database, compute the
diff, and publish the planned SQL without executing it. (`observe` is the mode
previously named `plan` — renamed so that "plan" means exactly one thing: the
`PostgresPolicyPlan` resource.)

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  mode: observe
  approval: manual
  roles:
    - name: preview-user
      login: true
```

In `observe` mode:

- the operator connects to the database and computes the full diff normally
- no mutating PostgreSQL SQL is executed and no Kubernetes Secrets are created
- `status.change_summary` records the pending changes
- `status.current_plan_ref.name` points at the generated `PostgresPolicyPlan`,
  which holds the rendered SQL in `status.sqlInline` or, for larger plans, a
  gzipped ConfigMap referenced by `status.sqlRef`
- `Ready=True` with reason `Planned`; `Drifted=True` while changes are pending

Be clear about what `observe` is not: it is a mutable spec field, not a
security boundary. Anyone who can edit the policy can switch it to `apply`,
and the operator still holds whatever database credential it was given. For
deployments where the operator must never write, the guarantee is a
**read-only PostgreSQL credential** — `observe` is what makes running under
one coherent (drift visibility without a stream of permission-denied errors).
For a reviewed apply, use `mode: apply` with `approval: manual`. Use `suspend`
to stop reconciling entirely.

The rendered SQL lives on the plan; follow `current_plan_ref` to it:

```bash
POLICY=observed-policy
PLAN="$(kubectl get pgr "$POLICY" -o jsonpath='{.status.current_plan_ref.name}')"
kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlInline}'
```

Plans above the inline size limit set `status.sqlRef`, naming a ConfigMap
whose `plan.sql.gz` entry holds the gzipped SQL. The preview is a review
artifact in every case: **pgroles never executes stored SQL**.

## What executes: mode and approval together

`suspend`, `mode`, and `approval` are three separate gates, checked in that
order. Only the last one is about human review:

| `suspend` | `mode` | `approval` | Plan created? | Mutating SQL executed? |
|---|---|---|---|---|
| `true` | — | — | no | no — nothing reconciles at all |
| `false` | `observe` | *ignored* | yes | **never** |
| `false` | `apply` | `auto` | yes | immediately, plan auto-approved |
| `false` | `apply` | `manual` | yes | only once approved *and* still current |

`approval` has no effect in `observe` mode; a decision recorded on an
observe-mode plan is accepted and does nothing, and the policy reports an
`ApprovalIgnored` condition so this is distinguishable from a stalled
operator.

## Approval identity: the change digest

What a decision approves is the plan's **change digest**: a versioned hash
(`pgroles.io/approval-effect/v1`) of the canonical, deterministically ordered
typed effects — role lifecycle, grants, memberships, ownership and default
privileges, retirements — bound together with the reconciliation mode, the
managed scope, the applied-base digest, and the target identity.

The digest deliberately excludes anything that legitimately differs between
planning and execution: cleartext passwords, SCRAM salts and verifiers, and
renderer-specific SQL text. A password change is identified semantically as
*(role, password source, source version)* — rotating the source Secret
produces exactly one new plan, and re-planning an unchanged source produces
the same digest every time. `status.sqlHash` still exists, but only as a
diagnostic for the preview text; it is never the approval gate.

Because identity is semantic, plans survive irrelevant change. A policy
generation bump, an unrelated base edit, or unrelated ephemeral-access
activity re-plans to an identical digest and the pending plan — including a
decision already recorded on it — is retained, with the revalidated
generation noted on its status.

## Deciding a plan

A decision is a status write on the plan — one terminal condition and
`status.decidedBy`, recorded together, exactly as `EphemeralAccessRequest`
decisions work:

```bash
pgroles plan approve orders-plan-9f21c4      # or: pgroles plan reject ...
```

The CLI patches the plan's status subresource; raw `kubectl patch
--subresource=status` works identically. The approval annotations from
earlier releases are removed.

The trust model has two layers, and both matter:

- **CEL validation rules** (shipped in the CRD) make decisions terminal and
  write-once: `Approved=True` and `Denied=True` are mutually exclusive, a
  recorded decision can never change, and `decidedBy` must be written in the
  same operation as the decision.
- **Actor identity requires the admission layer.** CEL cannot see the
  requesting user, so `decidedBy` is truthful only when the shipped Kyverno
  reference policy (or an equivalent mutating webhook) overwrites it from
  admission `userInfo`. Without that layer, `decidedBy` is whatever the
  client asserted. Deploy the reference policy anywhere approvals are a
  control you rely on.

Approval RBAC is per-kind: granting a team create on policies or candidates
grants nothing on plan status. Execution settings (`approval`, managed scope)
are platform-controlled — protect them with an admission policy so a policy
author cannot weaken them in the same edit that introduces a change.

## Plans stay current while awaiting review

A pending plan is revalidated on every reconcile — there is no frozen-plan
window. When the policy, database, target, or overlays change while a plan
awaits a decision:

- **effects unchanged** (identical change digest): the plan is retained, the
  revalidated generation recorded; the policy's change summary and
  `current_plan_ref` always describe the same plan.
- **effects changed**: the plan is superseded with an explicit condition and
  Event, and a fresh plan is created for review.

Approving a plan therefore approves what the plan currently shows. If a
supersede races your approval, the decision lands on a plan that is no longer
current and nothing executes — the fresh plan awaits its own decision.

Rejecting a plan marks it `Rejected` and clears `status.current_plan_ref`;
the replacement is created on the next reconcile, which keeps a rejected plan
from spinning in a reject-recreate loop.

## Target identity

Every plan binds the identity of the database it was computed against, at the
strongest tier available:

1. **Physical**: `pg_control_system().system_identifier`, when the server
   exposes it.
2. **Logical**: the resolved connection fingerprint — host, port, database
   name — plus the connection Secret's version.

Execution fails closed on a *mismatch* at either tier, and on a *tier
downgrade* (the identifier was readable at approval but not at execution).
Repointing the connection Secret at a different server therefore invalidates
every approval made against the old one, even though the Kubernetes reference
is unchanged. Environments where the physical identifier is consistently
unavailable run on the logical tier; set `requirePhysicalIdentity: true` to
refuse execution without tier 1.

A target change is not an error to work around — it flows through the
ordinary supersede-and-review path. The fresh approval is the sanctioned
acknowledgement that the target moved.

## Passwords and planning

Planning is side-effect free in every mode. For `password.generate` roles the
operator synthesizes in-memory material while planning and creates the real
Kubernetes Secret only during post-approval execution — under `apply +
manual` there is no generated Secret in the cluster until a reviewer has
approved the plan that introduces it.

## Execution

Approval never executes a stored artifact. Under the same database and
advisory lock, with no unlock window, the operator re-inspects, recomputes
the effects, and verifies the recomputed change digest against the approved
one. The statements executed are exactly the approved canonical effects
recomputed against the state observed under that lock; any divergence aborts
before the first statement and supersedes the plan.

To review proposed changes *without* editing the active policy at all, see
[Candidates and promotion](/docs/operator-candidates).

{% callout type="warning" title="Set `spec.approval` explicitly" %}
`spec.approval` decides whether a human gates SQL execution. When omitted the
operator still infers it from `spec.mode` — `apply` implies `auto`, `observe`
implies `manual` — which leaves the gate invisible on the object. That
inference is deprecated: a policy relying on it reports an `ApprovalUnset`
condition, emits a warning Event, and counts toward
`pgroles.deprecated.approval_unset`. Write the value down explicitly.
{% /callout %}
