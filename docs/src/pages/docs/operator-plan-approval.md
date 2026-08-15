---
title: Plan and approval
description: Preview changes with observe mode and gate execution behind a reviewed, approved plan.
---

Seeing what the operator would do before it does it. {% .lead %}

---

{% callout type="warning" title="Partly a design preview" %}
Shipped and described accurately below: the semantic change digest as approval
identity, revalidation of pending plans, write-once plan decisions with
`decidedBy` — including the annotation removal — deferring generated
password Secrets until after approval
([#181](https://github.com/hardbyte/pgroles/issues/181)), and dual target
identity with `requirePhysicalIdentity`
([#180](https://github.com/hardbyte/pgroles/issues/180)).

**Not yet built**, though this page describes them: `mode: observe` (today it is
still `mode: plan`), the `PostgresPolicyCandidate` CRD, and every `pgroles plan ...` /
`pgroles candidate ...` command shown here — the CLI has no such subcommands
yet. Use `kubectl` for anything you need to do today; see the
[quick start](/docs/operator-quick-start) for the exact commands.
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

The rendered SQL lives on the plan; follow `current_plan_ref` to it. Small
plans carry it inline:

```bash
POLICY=observed-policy
PLAN="$(kubectl get pgr "$POLICY" -o jsonpath='{.status.current_plan_ref.name}')"
kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlInline}'
```

Plans above the inline size limit leave `sqlInline` empty and set
`status.sqlRef` instead, naming a ConfigMap whose `plan.sql.gz` entry holds
the gzipped SQL — so the command above prints nothing for a large plan.
Fetching that takes a decode step:

```bash
CM="$(kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlRef.name}')"
kubectl get configmap "$CM" -o jsonpath="{.binaryData['plan\.sql\.gz']}" |
  base64 -d | gunzip
```

`pgroles plan show <plan>` follows whichever branch applies. A plan whose
compressed preview would still exceed the ConfigMap limit sets no `sqlRef`,
and `sqlInline` carries a truncated preview ending in a `-- truncated: ... --`
marker. The preview is a review artifact in every case: **pgroles never
executes stored SQL**.

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
(`pgroles.io/approval-effect/v2`) of the canonical, deterministically ordered
typed effects — role lifecycle, grants, memberships, ownership and default
privileges, retirements — bound together with the reconciliation mode and the
[target identity](#target-identity), physical and logical. (Managed scope joins the binding once it becomes a
first-class field; today a scope change shows up as a change in effects.)

The applied base is deliberately *not* a digest input. The plan records which
base it was computed against as provenance, and that record advances whenever
revalidation confirms the effects are unchanged. Hashing the base in would
make every unrelated policy edit invalidate every pending approval, which is
exactly the churn semantic identity exists to prevent. What the base record
does buy is the promotion check: execution requires the promoted content to
match the approved candidate *and* the base to be the one the plan last
revalidated against.

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

There is one rejection model across the product. A rejected plan records
`Denied=True` with reason `DeniedByReviewer` and moves to phase `Rejected`;
`Approved=True` and `Denied=True` are mutually exclusive and neither can be
changed once written. ("Rejected" is the phase; `Denied` is the condition —
they always travel together.) A candidate whose plan is denied is terminal
too, reporting `Superseded=True, reason=PlanDenied`.

Decisions are written to the plan's status subresource with `kubectl patch
--subresource=status` (the CLI wrapper is not built yet). The
`pgroles.io/approved` and `pgroles.io/rejected` annotations that earlier
releases used have been removed outright: setting them now does nothing at all,
which is deliberate — a retired approval mechanism that still worked would be a
silent bypass of everything below.

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

Rejecting a plan — `Denied=True`, phase `Rejected`, as above — clears
`status.current_plan_ref` on the policy. The replacement is created on the
next reconcile rather than immediately, which keeps a rejected plan from
spinning in a reject-recreate loop. For a candidate's plan there is no
replacement: fix the proposal by filing a successor candidate.

## Target identity

`DatabaseIdentity` — the Secret name and key a policy points at — says which
*reference* was followed, not which database answered. Repointing that Secret
leaves plan, conflict and lock identity untouched, so the approval identity
binds the database itself, in both of the forms that mean something:

1. **Physical**: `pg_control_system().system_identifier`. It answers *same
   storage lineage?* — it survives failover to a streaming replica, and it
   catches a restore taken from a different cluster behind an unchanged
   endpoint.
2. **Logical**: the resolved connection fingerprint — host, port, database
   name. It answers *same endpoint?* — which is what catches a clone, a
   branch, or a replica, since those all inherit the parent's
   `system_identifier`.

Neither is sufficient alone, so both are bound and a change in either fails
closed. The logical half is fooled by connection poolers and DNS; the physical
half is a *lineage* identifier, not an instance one. Credentials are
deliberately excluded from both, so rotating a password or a token does not
invalidate an open approval.

These are not tiers with a fallback. On the research: no mainstream managed
PostgreSQL blocks `pg_control_system()` — it has been executable by `PUBLIC`
since PostgreSQL 9.6, and monitoring tooling such as Datadog's Postgres
integration and `pgmetrics` calls it unconditionally on RDS, Aurora and Cloud
SQL. What lacks it are engines that merely speak the PostgreSQL protocol —
CockroachDB, Spanner's PostgreSQL interface, Redshift, Aurora DSQL — plus
YugabyteDB, where the value carries no meaning. Those targets run on the
logical identity, which is an ordinary configuration rather than a degraded
one. Set `connection.requirePhysicalIdentity: true` where a real PostgreSQL is
expected: the policy then reports `TargetIdentityBlocked` and makes no
progress at all rather than proceeding on the logical answer alone.

Between approval and execution the operator re-reads both identities under the
same lock and compares them to what the plan bound. Anything other than a
match stops the plan before any SQL runs, with an explicit reason on the
condition and a Warning Event:

| Observed | Reason | Result |
| --- | --- | --- |
| Either identity reads differently | `TargetChanged` | plan superseded, fresh plan for review |
| An identity readable at approval is unreadable now | `TargetIdentityUnavailable` | plan superseded — a downgrade is never treated as a match |
| An identity unavailable at approval is readable now | `TargetIdentityAppeared` | plan superseded once; the approval was never bound to it |
| `requirePhysicalIdentity` set, physical identity missing | `PhysicalIdentityRequired` | `TargetIdentityBlocked`; no plan progresses |

A target change is not an error to work around — it flows through the ordinary
supersede-and-review path, and the fresh approval *is* the sanctioned
acknowledgement that the target moved.

Two routine operations move the physical identity legitimately, and both will
invalidate approvals open across them: a **major version upgrade**, because
`pg_upgrade` runs a fresh `initdb` and mints a new `system_identifier`, and a
**blue-green cutover**, where the new colour is a different cluster. This is
the design working: the plan was reviewed against the old database. Re-approve
the plan the operator opens afterwards.

## Passwords and planning

Planning is side-effect free in every mode. For `password.generate` roles the
operator synthesizes in-memory material while planning and creates the real
Kubernetes Secret only during post-approval execution — under `apply +
manual` there is no generated Secret in the cluster until a reviewer has
approved the plan that introduces it, and a plan that is rejected or
abandoned leaves none behind.

The Secret is written immediately *before* the SQL transaction, not after: a
crash between the two then leaves an unused Secret that the next reconcile
adopts, rather than a password committed to the database that exists nowhere
else. If an equivalent Secret already exists — another replica won the race,
or a previous attempt got that far — that Secret's password is the one the
database is set from.

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
