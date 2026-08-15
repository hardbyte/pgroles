---
title: Candidates and promotion
description: Propose policy changes, review their exact PostgreSQL effects, and promote them — while the active policy keeps enforcing during review.
---

Review what a change would do to production before it becomes the desired state. {% .lead %}

---

{% callout type="note" title="What is not built" %}
The kind, the content digest, the planning lifecycle and **promotion** — the
subject of this page — are implemented. Two things named below are not: the
`pgroles candidate` and `pgroles plan` CLI subcommands (use `kubectl`; the
recipes here do), and `spec.contentRef` for content too large to embed.
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
   `PostgresPolicy.spec`. The merge is *promotion*, not a second approval —
   CI confirms before merge that the PR's content is the content that was
   reviewed (see [Verifying before the
   merge](#verifying-before-the-merge)).
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

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata:
  generateName: orders-change-
spec:
  policyRef:
    name: orders
  replaces: orders-change-x7k2p
  content:
    roles:
      - name: reporting-reader
        login: true
        connection_limit: 4
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
kubectl get pgcand orders-change-x7k2p -o wide          # phase, plan, digest
kubectl get pgplan orders-change-x7k2p-plan-9f21c4 -o yaml
```

There are no `pgroles candidate` or `pgroles plan` subcommands: everything here
is `kubectl`. Deciding a plan is a write to its status subresource — see
[Deciding a plan](/docs/operator-plan-approval#deciding-a-plan) for the exact
patch, which is identical for a candidate's plan and a policy's.

Rejection lands on the plan, not the candidate: the plan records
`Denied=True` (phase `Rejected`) and is terminal. The candidate is terminal
too — it has no other plan coming — and reports `Superseded=True` with reason
`PlanDenied`. To propose a revised version, file a successor candidate.

## Promotion

Approval does not change the `PostgresPolicy`. Promotion is the ordinary
GitOps write: the PR carrying the same content merges, the GitOps controller
updates `PostgresPolicy.spec`, and the operator recognises the update as the
approved candidate by digest.

Recognition is exact. The digest is computed over the same canonical form for
both kinds — `PostgresPolicy.spec`'s content fields project into the candidate
content type and are digested through the identical function — so promoting a
candidate's content verbatim yields a byte-identical digest, and anything else
yields a different one. The policy publishes what it recognised in
`status.content_digest`, beside the candidate's `status.contentDigest`.

### The gate

When the promoted content is a candidate whose plan is **approved**, that plan
becomes the policy's plan for this transition. Nothing about execution is
special-cased: the operator takes the reviewed plan — the one carrying the
human decision, the `decidedBy`, the approved change digest and the bound
target identity — and runs it through the ordinary approved-plan path, which
under the database lock re-inspects, recomputes the canonical effects, and
executes only if the recomputed digest equals the approved one.

The property this buys, stated plainly:

> The statements executed are exactly the approved canonical effects,
> recomputed under the lock.

The operator never mints an approval of its own to make a promotion execute.
Adopting the candidate's plan is what makes that possible: transferring an
approval onto a freshly created policy plan would mean writing a decision no
human made, with a `decidedBy` the operator invented.

On success the candidate becomes `Promoted=True` (terminal), its plan reaches
phase `Applied`, and any *other* candidate that was sitting on an approved plan
has that plan retired — phase `Superseded`, condition `Superseded=True` with
reason `SupersededByPromotion` — because its approval was made against a base
this promotion replaced. The decision record on that plan is left exactly as
the reviewer wrote it; retiring a plan never rewrites who decided what.

### Verifying before the merge

There is no `pgroles candidate verify`. The dependable pre-merge check is
equality of the content itself, which is what the digest measures:

```bash
# In CI, on the PR branch: the candidate you filed and the policy you are about
# to merge must carry identical content.
diff <(yq -P '.spec.content' candidate.yaml) \
     <(yq -P 'del(.spec.connection, .spec.interval, .spec.mode, .spec.suspend, .spec.approval) | .spec' policy.yaml)
```

Filing the candidate from the very same file the PR promotes makes this
structural rather than checked. After the merge, the cluster answers directly:

```bash
kubectl get pgcand orders-change-x7k2p -o jsonpath='{.status.contentDigest}'
kubectl get pgr    orders             -o jsonpath='{.status.content_digest}'
```

A CLI subcommand is deliberately absent rather than pending: a faithful digest
has to be computed over the operator's typed content model, and a second
implementation in the CLI would be a second definition of the thing the digest
exists to make unambiguous.

### Edge cases

Defined, not implied — each row is a unit test, and the first three are covered
end to end in the kind E2E:

| What happens | Result |
| --- | --- |
| Promoted content matches the approved candidate | Its plan is adopted and executes under the lock after fresh verification; candidate → `Promoted=True` |
| Promoted content matches a candidate whose plan is *not* approved | Nothing executes on it. The policy falls back to its ordinary manual-plan flow, and the candidate reports `Promoted=False, reason=PromotedWithoutApproval`. It becomes `Promoted=True` once that fresh plan is approved and applied — the content did reach the database, just on a different approval |
| Promoted content was edited after approval (digest mismatch) | Nothing executes. The policy falls back to the manual-plan flow, and the approved candidate reports `Promoted=False, reason=PromotionDigestMismatch` naming the enforcement gap below |
| Promoted content matches no candidate at all | The ordinary policy flow. Nothing is reported, because nothing unusual happened |
| Plan X approved, candidate Y merged | Y promotes and executes; X's plan is retired with `SupersededByPromotion` and X is replanned against the new base |

Two execution modes make the gate moot rather than absent:

- **`approval: auto`** — the policy approves and executes its own plan on every
  reconcile, so there is no approval to gate and the candidate's plan is not
  adopted. Promotion executes immediately, and the bookkeeping still happens:
  the candidate reaches `Promoted=True` once the content is applied.
- **`mode: plan`** — the policy never executes anything, so a promoted
  candidate cannot reach `Promoted`. It reports `Promoted=False,
  reason=PromotionNotExecuted` and stays open; it becomes `Promoted=True` if
  and when the policy is switched to `mode: apply` and the content applies.

Promotion is recognised by digest and not by a one-shot transition, so it
survives an interrupted reconcile: if the SQL executed and the operator
restarted before writing `Promoted=True`, the next reconcile recognises the
same promotion and records it, with nothing to replay because the effects are
already gone.

One honest cost to know: after a mismatched promotion under `apply` +
`manual`, nothing has executed and the database is unchanged — but the merged
spec is now the desired state and is not being converged, so drift against
*either* state goes unreconciled until a fresh plan is approved. That is the
same suspension `apply + manual` has always had; the condition and Event on the
candidate say so in those words. Continued enforcement of the *previous* state
through a failed promotion is what a future Revision model would add.

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
| `Ready=True, reason=NoEffects` | The content is already the database's state, so there is nothing to review. Not terminal — the content may diverge again |
| `Ready=False, reason=BlockedByActivePolicy` | Parent is failing or awaiting its own approval; will re-plan |
| `Ready=False, reason=OverlayOverlap` | An ephemeral grant overlaps this candidate's effects; fresh review required |
| `Ready=False, reason=PlanningFailed` | The candidate could not be planned at all; the message carries the error |
| `Superseded=True, reason=Replaced` | A successor candidate named this one in `spec.replaces` |
| `Superseded=True, reason=EffectsChanged` | Replanning produced a different change digest; the fresh plan awaits its own decision |
| `Superseded=True, reason=PlanDenied` | The candidate's plan was rejected (terminal) |
| `Promoted=True, reason=Promoted` | This candidate's content was promoted and executed (terminal) |
| `Promoted=False, reason=PromotedWithoutApproval` | The content was promoted while this candidate's plan held no approval |
| `Promoted=False, reason=PromotionDigestMismatch` | The policy's content changed into something that is not this approved candidate |
| `Promoted=False, reason=PromotionNotExecuted` | The content was promoted into a policy in `mode: plan`, which never executes |
| `Promoted=False, reason=SupersededByPromotion` | Another candidate was promoted; this one's approved plan was retired |

Rejection is recorded on the plan (`Denied=True`, phase `Rejected`); the
candidate reflects it as `Superseded=True, reason=PlanDenied`. Both are
terminal.

`Promoted` is a separate condition from `Ready` deliberately. `Ready` belongs to
the planning lifecycle and is rewritten on every cycle — including with
`BlockedByActivePolicy` the moment a fallen-back promotion opens a plan of its
own, which is exactly when a reviewer needs to read why the promotion did not
execute.

## Limits

`spec.content` collections carry explicit size bounds — 1024 roles, 4096
grants, 63-character identifiers and the rest of the table in the [manifest
reference](/docs/manifest-reference#size-limits). They are required by the
whole-spec immutability rule's CEL cost budget, and they apply to
`PostgresPolicy` too. Policies too large to embed can pass content by
reference; the digest binding is identical either way.

`spec.content` also emits no OpenAPI defaults, unlike `PostgresPolicy.spec`.
An API-server default is written into the stored object, so if a default value
ever changed, a stored candidate would keep the old value while the identical
source YAML would now mean the new one — and the stored object's content
digest would no longer match the digest CI computed from that YAML. Omitted
content fields are resolved by the operator instead, identically for policies
and candidates.
