---
title: Candidates and promotion
description: Propose policy changes, review their exact PostgreSQL effects, and promote them — while the active policy keeps enforcing during review.
---

Review what a change would do to production before it becomes the desired state. {% .lead %}

---

{% callout type="warning" title="Design preview" %}
This page documents the target design from
[#173](https://github.com/hardbyte/pgroles/issues/173) ahead of implementation.
It is written as end-state documentation so the design can be reviewed in the
form users will meet it. Nothing on this page is released yet.
{% /callout %}

## What a candidate is

A `PostgresPolicyCandidate` is a one-shot, immutable proposal: policy content
that an author wants reviewed against a live database without touching the
`PostgresPolicy` that is enforcing it. The operator plans the candidate in the
active policy's own execution context — same credentials, same advisory lock,
same managed scope — and publishes a `PostgresPolicyPlan` describing exactly
what would change. The active policy keeps enforcing throughout review. (After
promotion the picture changes if the promotion does not match its approval —
see [Promotion](#promotion).)

A candidate is not a second policy. It carries no interval or mode, and no
connection unless it is explicitly previewing a different target; it can never
execute SQL in any state; and it is terminal once promoted, superseded, stale,
or its plan is rejected. Think of it the way you think of a
`CertificateSigningRequest`: a request for the controller to produce a
reviewable result, not a piece of desired state.

The kinds divide authority. Anyone granted create on candidates can propose;
only whoever can write `PostgresPolicy` (typically your GitOps controller) can
promote; only plan approvers can approve. None of those grants implies the
others.

## Who does what

The intended workflow, end to end:

1. An author (or CI, from a PR branch) files a candidate against the cluster.
2. The operator plans it and publishes the redacted effects.
3. A reviewer approves or rejects the **plan** — this is the single
   operator-checked approval.
4. The pull request merges, promoting the same content into
   `PostgresPolicy.spec`. The merge is *promotion*, not a second approval:
   `pgroles candidate verify` runs in CI to confirm the PR content digest
   matches the approved candidate before merge.
5. The operator executes only when the promoted content digest matches the
   approved candidate and the recomputed effects match the approved change
   digest, verified under the database lock.

Candidates are imperative, CI- or CLI-created objects. They are deliberately
not GitOps-managed: `generateName` does not work with Argo CD or Flux tracking,
and a proposal has no business being continuously re-applied.

## Creating a candidate

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata:
  generateName: orders-change-
spec:
  policyRef:
    name: orders
  content:
    reconciliation_mode: authoritative
    roles:
      - name: reporting-reader
        login: true
    grants: []
    default_privileges: []
    memberships: []
    retirements: []
```

`spec.content` is the exact policy-content schema from `PostgresPolicySpec` —
everything except connection, interval, mode, and approval. Interval, mode and
approval always come from the parent policy; the connection does too, unless
`spec.target` overrides it (see [Previewing a connection
migration](#previewing-a-connection-migration)). The whole spec is immutable
(`self == oldSelf`); to revise a proposal, create a successor:

```bash
pgroles candidate create --policy orders -f revised.yaml --replaces orders-change-x7k2p
```

`spec.replaces` marks the named earlier draft superseded. Supersession is
always explicit — the operator never infers it from creator identity, because
CI typically files every team's candidates under one service account.

There is no base pin in the spec. The plan records which applied base it was
computed against; staleness is decided semantically from there (see
[Staleness](#staleness-and-revalidation)).

## What the operator does with it

A new candidate enqueues its parent policy. Inside one lock hold, the
operator:

1. reconciles the active policy first, so the candidate is planned against
   post-enforcement reality rather than drift
2. plans the candidate content against that state
3. publishes an operator-owned `PostgresPolicyPlan` bound to the candidate
   (name and UID), its content digest, the target identity, the managed
   scope, and the canonical change digest — and records the applied base it
   observed as provenance (see [Staleness](#staleness-and-revalidation))

Planning writes nothing: no PostgreSQL statements, no generated password
Secrets, no changes to the active policy. Filing a candidate may advance the
parent's scheduled convergence — the reconcile it triggers is the same one the
interval would have run — but no effect of the candidate itself executes.

If the active policy is failing or awaiting its own approval, the candidate
reports `Ready=False` with reason `BlockedByActivePolicy` and is re-planned
when the parent recovers.

```text
NAME                  POLICY   PHASE     CHANGES   PLAN                              AGE
orders-change-x7k2p   orders   Planned   3         orders-change-x7k2p-plan-9f21c4   14s
```

## Reviewing and deciding

The candidate's plan is reviewed and decided exactly like any other
`PostgresPolicyPlan` — same redacted SQL preview, same change summary, same
write-once decision recorded on the plan status with an admission-stamped
`decidedBy`. See [Plan and approval](/docs/operator-plan-approval) for the
decision mechanics and their trust model.

```bash
pgroles candidate show orders-change-x7k2p     # plan summary, effects, digests
pgroles plan approve orders-change-x7k2p-plan-9f21c4
```

Rejection lands on the plan, not the candidate: the plan records
`Denied=True` (phase `Rejected`) and is terminal. The candidate is terminal
too — it has no other plan coming — and reports `Superseded=True` with reason
`PlanDenied`. To propose a revised version, file a successor candidate.

## Promotion

Approval does not change the `PostgresPolicy`. Promotion is the ordinary
GitOps write: the PR carrying the same content merges, the GitOps controller
updates `PostgresPolicy.spec`, and the operator recognises the update as the
approved candidate by digest.

Run `pgroles candidate verify` in CI before merge:

```bash
pgroles candidate verify orders-change-x7k2p --against path/to/policy.yaml
```

It fails when the PR's rendered content digest differs from the candidate's —
catching edited-after-approval content *before* the merge, when it is cheap,
instead of at promotion, when the spec has already changed.

The edge cases are defined, not implied:

| What happens | Result |
| --- | --- |
| Promoted content matches the approved candidate, base unchanged | Executes under the lock after fresh verification |
| Promoted content was edited after approval (digest mismatch) | Nothing executes; the policy falls back to the normal manual-plan flow with an explicit condition |
| Promotion with no approved plan at all | Normal manual-plan flow |
| Plan X approved, candidate Y merged | Y plans fresh; X goes stale |

One honest cost to know: after a mismatched promotion, nothing has executed
and the database is unchanged — but the merged spec is now the desired state
and is not being converged, so drift against *either* state goes unreconciled
until a fresh plan is approved. That is the same suspension `apply + manual`
has always had, surfaced by condition and Event and bounded by the plan
retention TTL. Continued enforcement of the *previous* state through a failed
promotion is what a future Revision model would add.

## Staleness and revalidation

Staleness is semantic, and the applied base is *provenance, not identity*. The
plan records which base it was computed against so you can see what it was
compared to, but that value is not hashed into the change digest — if it were,
every unrelated base edit would invalidate every open candidate. When anything
the plan depends on changes — the applied base, the live database, active
ephemeral overlays — the operator replans the candidate and compares canonical
change digests:

- **identical digest**: the plan and any decision on it are retained; the
  recorded base advances to the one just observed and the revalidation is
  noted. Unrelated base changes and unrelated ephemeral activity do not cost
  you a review round.
- **changed digest**: the plan is superseded with an explicit condition and
  Event, and the fresh plan awaits a fresh decision.

An ephemeral overlay that overlaps the candidate's effects supersedes the plan
with reason `OverlayOverlap`. One that does not leaves the digest identical
and the plan stands — candidates remain usable on policies with active
ephemeral traffic.

After a successful promotion, other candidates against the same policy are
replanned against the new base by the same rule.

## Previewing a connection migration

A candidate may target a different connection than its parent policy, to
inspect what convergence would do on a migration destination before the
active policy follows it:

```yaml
spec:
  policyRef:
    name: orders
  target:
    connectionRef:
      secretName: orders-new-postgres
      key: url
  content: ...
```

A target override changes the execution context, and the contract is
explicit about it:

- **Credentials and connection settings come from the override**, not the
  parent. The referenced Secret must carry credentials for the destination.
- **Locking follows the target.** Advisory and in-process locks are keyed by
  database identity, so planning against the override acquires that
  database's locks — it cannot share the parent's lock state, and it does not
  block the parent's reconcile. The enforce-then-plan ordering still applies
  to the parent (it is reconciled first on its own target); the override is
  then inspected separately within the same reconcile.
- **The plan binds the override's target identity**, so it can never be
  promoted onto the current target by accident: the identity check fails
  before execution.

Because of that last point, a target-override plan is a *preview*, not a
migration step. Promoting a migration is a deliberate two-part sequence:
merge the connection change into `PostgresPolicy.spec` so the active policy
points at the destination, then approve a plan computed against the new
target. The override lets you see the destination's diff before committing to
step one; it never performs the cutover itself.

## Retention

Candidates carry an `ownerReference` to their parent policy, and each derived
plan is owned by its candidate, so pruning cascades. Terminal candidates —
`Promoted=True`, or `Superseded=True` for any reason including `PlanDenied` —
are pruned by the same bounded retention loop as plans; label a candidate
`pgroles.io/keep=true` to exempt it. Plans also expire after a TTL — an
approval is not an indefinite authorisation.

## Conditions

`status.phase` is a printable summary; conditions are the source of truth.

| Condition | Meaning |
| --- | --- |
| `Ready=True, reason=Planned` | A current plan exists for this candidate |
| `Ready=False, reason=BlockedByActivePolicy` | Parent is failing or awaiting its own approval; will re-plan |
| `Ready=False, reason=OverlayOverlap` | An ephemeral grant overlaps this candidate's effects; fresh review required |
| `Superseded=True, reason=Replaced` | A successor candidate named this one in `spec.replaces` |
| `Superseded=True, reason=EffectsChanged` | Replanning produced a different change digest; the fresh plan awaits its own decision |
| `Superseded=True, reason=PlanDenied` | The candidate's plan was rejected (terminal) |
| `Promoted=True` | This candidate's content was promoted and executed |

Rejection is recorded on the plan (`Denied=True`, phase `Rejected`); the
candidate reflects it as `Superseded=True, reason=PlanDenied`. Both are
terminal.

## Limits

`spec.content` collections carry explicit size bounds (required by the
whole-spec immutability rule's CEL cost budget). Policies too large to embed
can pass content by reference; the digest binding is identical either way.
