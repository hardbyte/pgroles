---
title: Plan and approval
description: Preview changes with plan mode and gate execution behind a reviewed, approved plan.
---

Seeing what the operator would do before it does it. {% .lead %}

---

## Plan mode

Set `mode: plan` to let the operator inspect the database, compute the diff, and publish the planned SQL without executing it.

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  mode: plan
  approval: manual
  roles:
    - name: preview-user
      login: true
```

Plan mode is useful when you want the operator to stay in-cluster but you are not ready to trust it with PostgreSQL mutations yet.

In `plan` mode:

- the operator connects to the database and computes the full diff normally
- no mutating PostgreSQL SQL is executed
- `status.change_summary` records the pending changes
- `status.current_plan_ref.name` points at the generated `PostgresPolicyPlan`, which holds the rendered SQL in `status.sqlInline` or, for larger plans, a gzipped ConfigMap referenced by `status.sqlRef`
- `Ready=True` with reason `Planned`
- `Drifted=True` when changes are pending, `Drifted=False` when the database is already in sync
- for `password.generate`, the controller does not create or recreate the generated Kubernetes Secret while running in `plan` mode
- for password-managed roles, `Drifted=False` is only possible after a prior successful `apply` recorded the password source version; a plan-only policy cannot prove an existing database password already matches the configured source

Example `kubectl get` output:

```text
NAME          READY   MODE   DRIFT   CHANGES   LAST RECONCILE   AGE
plan-policy   True    plan   True    2         2s               2s
```

Example status fields:

```yaml
status:
  change_summary:
    grants_added: 1
    roles_created: 1
    total: 2
  conditions:
    - type: Ready
      status: "True"
      reason: Planned
      message: Plan computed; 2 change(s) pending
    - type: Drifted
      status: "True"
      reason: DriftDetected
      message: 2 planned change(s) pending review
  current_plan_ref:
    name: plan-policy-plan-20260512-090308-118e50e437c9
  last_reconcile_mode: plan
```

The rendered SQL lives on the plan, so start from the policy name you already
have and follow `current_plan_ref` to it:

```bash
POLICY=plan-policy
PLAN="$(kubectl get pgr "$POLICY" -o jsonpath='{.status.current_plan_ref.name}')"
kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlInline}'
```

```text
CREATE ROLE "plan-preview-user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE "plan-preview-user" IS 'Preview-only role';
GRANT CONNECT ON DATABASE "postgres" TO "plan-preview-user";
```

To see every plan a policy has produced rather than just the current one, list
plans and read the `POLICY` column, which carries the full policy name:

```bash
kubectl get pgplan
```

```text
NAME                                                     POLICY        MODE            APPROVED   CHANGES   PHASE     AGE
plan-policy-plan-20260512-090308-118e50e437c9            plan-policy   authoritative   False      2         Pending   3s
```

Avoid selecting plans with `-l pgroles.io/policy=<name>`. That label is a
server-side prefilter truncated to 63 bytes, so it is not an identity and two
policies sharing a long prefix select each other's plans.

Plans above the inline size limit set `status.sqlRef` instead of `sqlInline`,
naming a ConfigMap whose `plan.sql.gz` entry holds the gzipped SQL under
`binaryData`. Fetching that takes a decode step:

```bash
CM="$(kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlRef.name}')"
kubectl get configmap "$CM" -o jsonpath="{.binaryData['plan\.sql\.gz']}" |
  base64 -d | gunzip
```

A plan whose compressed preview would still exceed the ConfigMap limit sets no
`sqlRef` at all, and `status.sqlInline` carries a truncated preview ending in a
`-- truncated: ... --` marker.

The preview is a review artifact in every case. pgroles never executes stored
SQL: an approved plan is re-rendered from the current diff at execution time and
superseded if the hash no longer matches.

Use `suspend` when you want the controller to stop reconciling entirely. Use `plan` when you want it to keep inspecting and showing you what it would do.

## What executes: mode and approval together

`suspend`, `mode`, and `approval` are three separate gates, checked in that
order. Only the last one is about human review:

| `suspend` | `mode` | `approval` | Plan created? | SQL executed? |
|---|---|---|---|---|
| `true` | — | — | no | no — nothing reconciles at all |
| `false` | `plan` | *ignored* | yes | **never** |
| `false` | `apply` | `auto` | yes | immediately, plan auto-approved |
| `false` | `apply` | `manual` | yes | only once approved *and* still current |

**`approval` has no effect in `plan` mode.** A plan-mode policy computes the
diff, publishes a `PostgresPolicyPlan`, and returns before it ever consults
`approval`. Annotating that plan with `pgroles.io/approved=true` is accepted by
the API server and then does nothing: the plan stays `Pending` and no SQL runs.
Because that is indistinguishable from a stalled operator, the policy reports an
`ApprovalIgnored` condition naming the plan and emits a warning Event. If you
want a reviewed apply, the combination you want is `mode: apply` with
`approval: manual` — plan mode is for looking, not for gated applying.

Execution never trusts stored SQL. An approved plan is re-rendered from the
current diff and its hash compared against the approved one, so the plan object
is a review artifact rather than an execution payload.

### When the policy changes mid-review

With `mode: apply` and `approval: manual`, a pending plan is **frozen** — the
operator returns early while a plan awaits a decision, so it neither refreshes
nor supersedes it. Two consequences worth knowing before you rely on the review
step:

- The policy's status reports the *freshly computed* change count each reconcile,
  while the pending plan still holds the SQL from when it was created. Status and
  plan can therefore disagree after a manifest change, and the plan is the stale
  one.
- Approving a stale plan does not apply it. On the next reconcile the hash
  comparison fails, the plan is marked `Superseded`, and a **new** plan is
  created awaiting approval. Nothing unsafe executes, but the approval is
  consumed without effect and a second review round is required.

Check that the plan you are approving matches the current generation:

```bash
kubectl get pgr <policy> -o jsonpath='{.metadata.generation}{"\n"}'
kubectl get pgplan <plan> -o jsonpath='{.spec.policyGeneration}{"\n"}'
```

Everywhere else, a superseding write happens automatically: creating a plan marks
any other `Pending` plan for the same policy `Superseded`, so plan mode and the
first plan after an approval both converge on a single current plan.

Rejecting with `pgroles.io/rejected=true` marks the plan `Rejected` and clears
`status.current_plan_ref`. The replacement is created on the *next* reconcile
rather than immediately, which keeps a rejected plan from spinning in a
reject-recreate loop.

## Plan approval resources

{% callout type="warning" title="Set `spec.approval` explicitly" %}
`spec.approval` decides whether a human gates SQL execution. When it is omitted
the operator still infers it from `spec.mode` — `apply` implies `auto`, `plan`
implies `manual` — which leaves that gate invisible on the object: nothing in
`kubectl get pgr -o yaml` tells you whether the policy applies DDL on its own.

That inference is deprecated. A policy relying on it reports an `ApprovalUnset`
status condition naming the inferred value, emits a warning Event, and counts
toward the `pgroles.deprecated.approval_unset` metric. A future release will
reject a policy that omits the field.

Write down the value you are already getting — `approval: auto` for a policy in
`mode: apply`, `approval: manual` for `mode: plan` — and the condition clears on
the next reconcile with no change in behaviour.
{% /callout %}

When `spec.approval: manual` is used with `mode: apply`, the operator creates a `PostgresPolicyPlan` and waits for approval instead of immediately executing the SQL.

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  mode: apply
  approval: manual
```

A generated plan looks like this:

```text
NAME                                                     POLICY                 MODE            APPROVED   CHANGES   PHASE     AGE
plan-approval-policy-plan-20260512-090318-454373251739   plan-approval-policy   authoritative   False      2         Pending   3s
```

Approve it by annotating the plan:

```shell
kubectl annotate pgplan plan-approval-policy-plan-20260512-090318-454373251739 \
  pgroles.io/approved=true --overwrite
```

After approval, the plan moves to `Applied`:

```text
NAME                                                     POLICY                 MODE            APPROVED   CHANGES   PHASE     AGE
plan-approval-policy-plan-20260512-090318-454373251739   plan-approval-policy   authoritative   True       2         Applied   5s
```

The plan status included:

```yaml
status:
  appliedAt: "2026-05-12T09:03:21Z"
  changeSummary:
    grants_added: 1
    roles_created: 1
    total: 2
  conditions:
    - type: Computed
      status: "True"
      reason: PlanComputed
      message: Plan computed with 2 change(s)
    - type: Approved
      status: "True"
      reason: Approved
      message: Plan approved and executed
  phase: Applied
  sqlHash: 454373251739fdfbe188ae07358b01d9e0465eb47011fe2d4f386fa34ef7de1b
  sqlInline: |-
    CREATE ROLE "approval_test_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
    GRANT CONNECT ON DATABASE "postgres" TO "approval_test_user";
  sqlStatements: 2
  sqlTruncated: false
```

With `spec.approval: auto`, the operator creates a `PostgresPolicyPlan` and applies it immediately:

```text
NAME                                                     POLICY                 MODE            APPROVED   CHANGES   PHASE     AGE
auto-approval-policy-plan-20260512-090329-11a6ca1d7c09   auto-approval-policy   authoritative   True       2         Applied   2s
```

The corresponding database role is present after reconcile:

```text
auto_approved_user
```
