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
- No generated password Secret is created by a reconcile that is not executing
  an approved plan
- Every password the database holds is readable from a Secret
- A settled policy costs at most one human decision
- **Liveness**: once drift stops, a plan is eventually applied

The constant `SqlHashApproval` selects the approval gate:

```sh
./run-tlc.sh races/PlanApproval.tla races/PlanApproval.cfg           # passes
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_buggy.cfg     # liveness violated (#174)
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_unlocked.cfg  # NoStaleExecution violated
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_no_password.cfg # passes
```

The same model also covers where a *generated password Secret* is created, and
which source version the policy records once it has been — issue #181. A
generated password's source version is derived from the Secret holding it, with
a `<secret>:<key>:missing` sentinel standing in while no Secret exists.

```sh
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_secret_deferral.cfg    # passes
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_secret_eager.cfg       # NoSecretBeforeApproval violated (#181)
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_secret_sentinel.cfg    # ApprovalsBounded violated
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_secret_first_crash.cfg # passes
./run-tlc.sh races/PlanApproval.tla races/PlanApproval_sql_first_crash.cfg    # PasswordRecoverable violated
```

Each configuration demonstrates a distinct requirement:

| Config | `SqlHashApproval` | `LockDuringApply` | `HasPasswordChange` | Result |
| --- | --- | --- | --- | --- |
| `PlanApproval.cfg` | FALSE | TRUE | TRUE | passes |
| `PlanApproval_buggy.cfg` | TRUE | TRUE | TRUE | `EventuallyApplies` violated |
| `PlanApproval_unlocked.cfg` | FALSE | FALSE | TRUE | `NoStaleExecution` violated |
| `PlanApproval_no_password.cfg` | FALSE | TRUE | FALSE | passes |

All five run with `DeferSecretMaterialization = TRUE`,
`RecordMaterializedVersion = TRUE` and `SecretBeforeSql = TRUE` — the shipped
design — and no crashes. The Secret configurations vary those instead:

| Config | `Defer…` | `Record…` | `SecretBeforeSql` | `MaxCrashes` | Result |
| --- | --- | --- | --- | --- | --- |
| `PlanApproval_secret_deferral.cfg` | TRUE | TRUE | TRUE | 0 | passes |
| `PlanApproval_secret_eager.cfg` | FALSE | TRUE | TRUE | 0 | `NoSecretBeforeApproval` violated |
| `PlanApproval_secret_sentinel.cfg` | TRUE | FALSE | TRUE | 0 | `ApprovalsBounded` violated |
| `PlanApproval_secret_first_crash.cfg` | TRUE | TRUE | TRUE | 1 | passes |
| `PlanApproval_sql_first_crash.cfg` | TRUE | TRUE | FALSE | 1 | `PasswordRecoverable` violated |

`secret_eager` is pgroles before #181: resolving a `password.generate` role
created the Secret during reconciliation, so the credential existed while the
plan was still pending and outlived a plan that was rejected or never approved.

`secret_sentinel` is the deferral done naively — materialize at execution, but
record the planning-time sentinel as the applied source version. It is not a
loop and nothing unsafe executes; it costs exactly one extra human approval,
because the next reconcile compares a recorded `missing` against a now-real
version and plans a password change for work already done. Only
`ApprovalsBounded`, checked with `MaxDrifts = 0` so that a second decision can
have no legitimate cause, can see the difference. Threading the
post-materialization version back out of execution is the fix.

The two crash configurations settle the *order* of execution's two writes. With
the Secret written first, a crash leaves an inert Secret that the next reconcile
adopts. With the SQL written first, the transaction commits a password that was
never stored anywhere readable — `PasswordRecoverable` violated, and
unrecoverable in production. `ApprovalsBounded` is deliberately not checked in
either: a crash costs a re-approval by design.

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

### `races/LockStarvation.tla`

Verifies that a policy which can never succeed does not deny the database's
advisory lock to every other policy pointed at it.

The lock key is computed server-side from `current_database()`, so all policies
on one server share one lock — deliberately, since two policies converging the
same database concurrently is the thing it prevents. The hazard is a policy
whose apply fails permanently: it still holds an approved plan, so every
reconcile re-executes it, and executing writes the plan twice (`Applying`, then
`Failed`). The controller wakes on its own plans, so each attempt schedules the
next. The failing policy reconciles as fast as it can execute — ~9 times a
second in CI — and takes the shared lock every time.

- **Liveness**: another policy on the same database eventually gets the lock

```sh
./run-tlc.sh races/LockStarvation.tla races/LockStarvation.cfg                   # passes
./run-tlc.sh races/LockStarvation.tla races/LockStarvation_spin.cfg              # EventuallyRecovers violated
./run-tlc.sh races/LockStarvation.tla races/LockStarvation_plan_writes_only.cfg  # EventuallyRecovers violated
```

| Config | `SelfWakeOnPolicyStatus` | `SelfWakeOnPlanStatus` | Result |
| --- | --- | --- | --- |
| `LockStarvation.cfg` | FALSE | FALSE | passes |
| `LockStarvation_spin.cfg` | TRUE | TRUE | `EventuallyRecovers` violated |
| `LockStarvation_plan_writes_only.cfg` | FALSE | TRUE | `EventuallyRecovers` violated |

All three run with `MaxTicks = 2` and `MaxAttempts = 4`. `MaxAttempts` must
exceed `MaxTicks`, or the starving policy could lose to the other one's
*legitimate* interval reconciles and the violation would be an artefact of the
bounds rather than the bug.

The counterexample is the production trace in miniature:

```
BBackoffExpires -> AAcquire -> BAttempt (loses) -> AFailAndRelease -> ...
Back to state 17: <AAcquire>
```

The waiting policy's back-off expires, the failing one takes the lock first, the
waiter loses an attempt, the lock is released, and round again — until the
waiter's caller gives up and the cycle continues without it forever.

`spin` is the behaviour before the fix. `plan_writes_only` is why the model
exists: it is the *first attempt* at the fix, which suppressed the policy-status
write and left the plan-status write alone. That self-wake loop was real, so the
change looked principled, but either write regenerates the wake on its own and
the storm continued — the observed reconcile rate went *up*, because each cycle
had one less API write to make. A fix addressing one of two sufficient causes is
not a fix, and no test in the tree said otherwise. The shipped behaviour makes
both writes disappear by declining to re-execute a plan that failed inside the
retry window, so a failing policy takes the lock once per interval.

As in `PlanApproval.tla`, every safety property holds in both failing
configurations. `LockHeldOnlyWhileRunning` and `BNeverProgressesWhileLocked` are
checked in all three and never violated: mutual exclusion is respected
throughout, nothing executes unreviewed, no state is corrupted. The system
simply stops making progress. That is why a safety-focused suite — unit tests,
integration tests, and a full green E2E run — reported nothing wrong twice.

## Running

```bash
# Build the TLC Docker image and run a model
./correctness/run-tlc.sh races/PlanLifecycle.tla

# Run with a specific config
./correctness/run-tlc.sh races/PlanLifecycle.tla races/PlanLifecycle.cfg
```

Requires Docker. Uses the same Docker-based TLC runner as
[awa](https://github.com/hardbyte/awa/tree/main/correctness).
