# pgroles Correctness Models

TLA+ models for verifying concurrency invariants in the pgroles operator.

These models check state machine properties that are difficult to verify
with integration tests — particularly race conditions between concurrent
operator reconciles, user annotations, database drift, and operator crashes.

## Models

### `races/PlanLifecycle.tla`

Verifies the PostgresPolicyPlan lifecycle state machine:

- A plan can only reach Applied if its approval was verified
- A rejected plan is never executed
- Applied plans match the current database drift (no stale execution)
- Failed plans always have last_error set
- Stuck Applying plans are recovered after operator crash

Races modeled:
1. User approves while operator computes new plan (hash validation)
2. User approves + rejects simultaneously (reject wins)
3. Operator crashes during Applying phase
4. Database drift changes between plan creation and approval
5. Hash dedup skips identical plans

### `races/PlanRevalidation.tla`

Verifies what must hold while a plan awaits a manual decision, across the
reconciles that keep happening underneath it:

- what the policy *reports* and what the pending plan *holds* describe the same
  effects — a reviewer never reads a fresh summary beside a stale plan
- an approval survives a policy edit that turns out to be effect-neutral
- a plan holding no effects never sits waiting for a decision

```sh
./run-tlc.sh races/PlanRevalidation.tla races/PlanRevalidation.cfg                # passes
./run-tlc.sh races/PlanRevalidation.tla races/PlanRevalidation_frozen.cfg         # SummaryMatchesPlan violated
./run-tlc.sh races/PlanRevalidation.tla races/PlanRevalidation_generational.cfg   # ApprovalSurvivesEffectNeutralEdits violated
./run-tlc.sh races/PlanRevalidation.tla races/PlanRevalidation_replace.cfg        # NoEmptyPendingPlan violated
```

| Config | `RevalidationMode` | Result |
| --- | --- | --- |
| `PlanRevalidation.cfg` | `semantic` | passes |
| `PlanRevalidation_frozen.cfg` | `frozen` | `SummaryMatchesPlan` violated |
| `PlanRevalidation_generational.cfg` | `generational` | `ApprovalSurvivesEffectNeutralEdits` violated |
| `PlanRevalidation_replace.cfg` | `replace` | `NoEmptyPendingPlan` violated |
| `PlanRevalidation_drift.cfg` | `generational`, drift allowed | `SummaryMatchesPlan` violated |

The four failing configurations bracket the design. `frozen` is the behaviour
before this work: the Pending arm returned early without revalidating, so the
status summary advanced while the plan stood still. `generational` is the
plausible wrong fix — superseding whenever the policy generation moves — which
restores the pairing but discards a decision on every effect-neutral edit. That
is why `policyGeneration` is a revalidation *trigger* and the change digest is
the *identity*.

`replace` is the narrower mistake: revalidate semantically, but always leave a
replacement plan behind. When an edit does not move the effects but removes
them, the replacement holds nothing and still blocks on an approval, while the
policy reports `Drifted=False` beside it. Superseding a pending plan and
opening a new one are separate decisions, and only the first applies when there
is nothing left to execute.

`drift` is the same `generational` strategy with the database allowed to move
underneath the plan with no policy edit behind it — someone runs the DDL by
hand, or another actor converges part of it. Under policy edits alone
`generational` keeps the summary and the plan paired, which is what makes it
look adequate; drift carries no generation bump, so it has nothing to trigger
on. It refreshes the reported summary from the new database state and retains a
plan holding the old effects — a reviewer reads one and approves the other. The
shipped `semantic` strategy compares the effects themselves and passes the same
configuration, which is the whole argument for keying revalidation on the change
digest rather than the generation. The configuration checks `SummaryMatchesPlan`
alone: `generational` also leaves an empty plan behind when the effects vanish,
and checking both would leave which violation TLC reports first an accident of
exploration order.

### `races/PlanApproval.tla`

Verifies what an approval actually binds, by separating two things
`PlanLifecycle.tla` conflates: the *semantic effects* of a plan, and the
*rendered SQL* those effects produce.

- Nothing executes without a recorded approval of the plan being executed
- What executed is what was reviewed, never a different set of effects
- An approval never carries across a change in effects
- **Liveness**: once drift stops, a plan is eventually applied

The constant `SqlHashApproval` selects the approval gate:

```sh
./run-tlc.sh races/PlanApproval.tla races/PlanApproval.cfg           # passes
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_buggy.cfg     # liveness violated (#174)
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_unlocked.cfg  # NoStaleExecution violated
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_no_password.cfg # passes
```

Each configuration demonstrates a distinct requirement:

| Config | `SqlHashApproval` | `LockDuringApply` | `HasPasswordChange` | Result |
| --- | --- | --- | --- | --- |
| `PlanApproval.cfg` | FALSE | TRUE | TRUE | passes |
| `PlanApproval_buggy.cfg` | TRUE | TRUE | TRUE | `EventuallyApplies` violated |
| `PlanApproval_unlocked.cfg` | FALSE | FALSE | TRUE | `NoStaleExecution` violated |
| `PlanApproval_no_password.cfg` | FALSE | TRUE | FALSE | passes |

`PlanApproval_no_password.cfg` passes, like the shipped configuration — it earns
its place by what it catches when the model is *wrong*. Under
`HasPasswordChange = TRUE`, `OperatorExecutes` also requires `planRenderStale`,
which only `OperatorRevalidates` sets and which itself requires `approved`. The
approval gate therefore stands transitively, and deleting the `approved`
conjunct from `OperatorExecutes` leaves all three password-bearing
configurations passing their safety invariants: the mutation is invisible. A
change set with no password has no second path, so the same deletion is reported
immediately as `NoUnreviewedExecution` violated. Every model needs at least one
configuration in which its central invariant is load-bearing.

`PlanApproval_unlocked.cfg` shows why verification and execution must share one
lock hold: with drift permitted while a plan is `Applying`, what executes no
longer matches the state it was verified against. `NoStaleExecution` records a
witness at apply time rather than comparing `appliedEffects` to `dbEffects` as a
state invariant — the database may legitimately drift again after a successful
apply, and a plain comparison would fire on that instead of on a stale one.

The buggy configuration reproduces issue #174. A `SetPassword` change embeds a
SCRAM verifier built with a fresh random salt on every computation, so a
rendered-SQL gate can never be satisfied: at approve time the operator
re-renders, the hash differs, the reviewed plan is superseded, and the
replacement has the same problem. TLC reports a violation of
`EventuallyApplies` with a `Back to state ... OperatorSupersedes` lasso — the
endless approve/supersede cycle.

Note that every *safety* invariant still holds in the buggy configuration.
Nothing unsafe executes; the workflow simply never converges. That is why the
bug survived a safety-focused test suite, and why this model checks a temporal
property rather than only invariants.

### `races/PlanStorage.tla`

Verifies the Kubernetes persistence ordering around plan SQL previews:

- A visible plan is never created before its SQL review artifact is ready
- SQL persistence failure does not materialise a status-less plan
- Stale status-less plans are eventually collected
- Orphan SQL ConfigMaps are eventually collected
- At most one actionable plan exists in the modeled lifecycle

### `races/Convergence.tla`

Verifies that wildcard grants converge under external mutations to managed
objects (added in v0.7.1 after the partly-dev15 reconcile-flap incident):

- Eventually-permanently `currentGrants = Inventory` under fairness on the
  reconcile action and a finite number of external `DROP+CREATE`s
- The set of "objects with the per-role ACL" never moves further from the
  desired wildcard across a single reconcile

The model abstracts a single `(role, schema, object_type)` scope. Two diff
semantics are switchable via the `UseFixedDiff` constant:

- `UseFixedDiff = TRUE` — the v0.7.1 fix (per-name `REVOKE`s shadow-suppressed
  by a desired wildcard for the same scope). `EventuallyConverged` holds.
- `UseFixedDiff = FALSE` — the v0.7.0 behaviour. TLC produces a 4-state lasso
  counterexample: a single external `DROP+CREATE` causes the reconcile to
  invert the set of granted objects each cycle, exactly the
  partly-dev15 oscillation between two stable plan hashes.

```bash
# Verify the fix converges
./correctness/run-tlc.sh races/Convergence.tla races/Convergence.cfg

# Reproduce the v0.7.0 flap as a TLC counterexample
./correctness/run-tlc.sh races/Convergence.tla races/Convergence_buggy.cfg
```

## Running

```bash
# Build the TLC Docker image and run a model
./correctness/run-tlc.sh races/PlanLifecycle.tla

# Run with a specific config
./correctness/run-tlc.sh races/PlanLifecycle.tla races/PlanLifecycle.cfg
```

Requires Docker. Uses the same Docker-based TLC runner as
[awa](https://github.com/hardbyte/awa/tree/main/correctness).
