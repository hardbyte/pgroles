---- MODULE LockStarvation ----
EXTENDS Naturals

(*
  Advisory-lock starvation by a self-waking reconcile.

  The operator serialises reconciles per *database* with a PostgreSQL
  advisory lock whose key is computed server-side from
  `current_database()`. Every policy pointed at one server therefore
  contends for one lock, regardless of which Secret or user it connects
  as. That is deliberate: two policies managing the same database must
  not converge concurrently.

  The hazard is what happens when one of those policies can never
  succeed. A policy whose apply fails permanently — `permission denied
  to create role`, say — still holds an approved plan, so every
  reconcile re-executes it. A failing attempt writes that plan several
  times: re-approval on the way in, `Applying`, then `Failed` with a
  freshly stamped timestamp. The policy controller wakes on its own
  plans (`reconcile_on(plan_triggers)`), so each attempt schedules the
  next one. The failing policy then reconciles as fast as it can
  execute — several times a second — and takes the shared lock every
  time.

  Nothing unsafe happens. The lock is respected, no plan executes
  without approval, no state is corrupted. Other policies simply never
  get the lock: they try, lose, back off with jitter, and their callers
  time out. This is the same shape as issue #174 in PlanApproval.tla —
  every safety invariant holds and the system still fails — which is
  why it survived a safety-focused test suite, and why it is checked
  here as a temporal property.

  Modelled scenario:

    Policy A is the failing one. It holds an approved plan that always
    fails to execute. Each attempt takes the lock, fails, releases.

    Policy B is any other policy on the same database that needs one
    successful reconcile to make progress — in the E2E it is
    `rotated-secret-policy`, whose credentials have just been restored
    and which must reach Ready=True and emit `Recovered`.

  The wake sources are separated because the design question is which
  of them a fix has to suppress:

    SelfWakeOnPolicyStatus — the failing reconcile rewrites the
      *policy* status (Reconciling on entry, stripped again on the
      failure path), and the controller watches policies.

    SelfWakeOnPlanStatus — the failing attempt rewrites the *plan*
      status (re-approval, Applying, then Failed with a freshly
      stamped timestamp), and the controller wakes on its own plans.

  Either source alone regenerates A's wake, so either alone sustains
  the storm: the answer is both. LockStarvation_plan_writes_only.cfg
  suppresses only the policy-status source and is still violated,
  which is what makes a half fix distinguishable from a fix here.

  A's other wake source is its ordinary interval requeue, bounded by
  MaxTicks. That bound is what makes the fixed configuration finite:
  once A can only wake on its interval, it takes the lock a bounded
  number of times and B gets it.

  B's attempts are bounded by MaxAttempts, modelling the finite window
  its caller waits — a `wait_for_*` helper with 30 tries, or a human.
  Starvation is not "B never runs"; it is "B runs, loses every time,
  and gives up".

  MaxAttempts must exceed MaxTicks or B can lose to A's legitimate
  interval reconciles alone, which would be a bound-chosen-badly
  artefact rather than the bug.

  Caveats / what is NOT modelled:
    - Real time. The production dynamic is a duty cycle: A holds the
      lock ~9 times a second while B samples every 24-30s. Untimed
      TLA+ represents that as "arbitrarily many A holds between two B
      attempts", which is the same property without the arithmetic.
    - Jittered back-off. B's retry delay changes nothing about whether
      it collides; it only sets how many attempts fit in the window,
      which is MaxAttempts.
    - More than two policies. Starvation is a property of one starving
      pair; further policies add contenders, not behaviour.
    - The plan state machine. PlanLifecycle.tla and PlanApproval.tla
      cover it; here a failing execution is one atomic failure.
*)

CONSTANTS
    SelfWakeOnPolicyStatus,  \* Failing reconcile rewrites policy status
    SelfWakeOnPlanStatus,    \* Failing execution rewrites plan status
    MaxTicks,                \* Interval requeues available to A
    MaxAttempts              \* Attempts B's caller waits through

ASSUME
    /\ SelfWakeOnPolicyStatus \in BOOLEAN
    /\ SelfWakeOnPlanStatus \in BOOLEAN
    /\ MaxTicks \in Nat
    /\ MaxAttempts \in Nat
    \* Otherwise A's ordinary interval reconciles alone could exhaust B.
    /\ MaxAttempts > MaxTicks

VARIABLES
    \* Is the per-database advisory lock currently held by A? B never
    \* holds it in this model: the step where B would is the step where
    \* it has already made progress.
    lockHeld,

    \* A has taken the lock and not yet failed and released it.
    aRunning,

    \* Pending wakes queued for A. Consumed by starting a reconcile,
    \* produced by interval ticks and — the bug — by A's own writes.
    aWakes,

    \* Interval requeues A has left. Bounding this is what lets the
    \* fixed configuration terminate A's activity.
    aTicks,

    \* Attempts B's caller has left before it gives up.
    bAttempts,

    \* B is due to try. A losing attempt puts B into back-off, and the
    \* back-off only expires once A is not mid-hold: B waits 24-30s
    \* between tries and A's hold is milliseconds, so by the time B
    \* comes back the previous hold is certainly over. Whether B
    \* collides again depends on A having taken the lock *afresh* —
    \* which is precisely what the self-wake regenerates.
    bDue,

    \* B got the lock and made its progress.
    bRecovered

vars == <<lockHeld, aRunning, aWakes, aTicks, bAttempts, bDue, bRecovered>>

\* aWakes is bounded for model checking. Under the buggy configurations
\* A regenerates a wake for every one it consumes, so the count never
\* needs to exceed what ticks and one in-flight self-wake can produce.
MaxWakes == MaxTicks + 2

TypeOK ==
    /\ lockHeld \in BOOLEAN
    /\ aRunning \in BOOLEAN
    /\ aWakes \in 0..MaxWakes
    /\ aTicks \in 0..MaxTicks
    /\ bAttempts \in 0..MaxAttempts
    /\ bDue \in BOOLEAN
    /\ bRecovered \in BOOLEAN

Init ==
    /\ lockHeld = FALSE
    /\ aRunning = FALSE
    /\ aWakes = 1          \* A has been woken once and will fail
    /\ aTicks = MaxTicks
    /\ bAttempts = MaxAttempts
    /\ bDue = TRUE
    /\ bRecovered = FALSE

\* How many wakes A's own writes regenerate when a reconcile fails.
SelfWakes ==
    (IF SelfWakeOnPolicyStatus THEN 1 ELSE 0)
        + (IF SelfWakeOnPlanStatus THEN 1 ELSE 0)

\* A's interval requeue fires. Bounded, and the only wake source that
\* survives the fix.
ATick ==
    /\ aTicks > 0
    /\ aWakes < MaxWakes
    /\ aTicks' = aTicks - 1
    /\ aWakes' = aWakes + 1
    /\ UNCHANGED <<lockHeld, aRunning, bAttempts, bDue, bRecovered>>

\* A consumes a wake and takes the shared advisory lock.
AAcquire ==
    /\ aWakes > 0
    /\ ~lockHeld
    /\ ~aRunning
    /\ lockHeld' = TRUE
    /\ aRunning' = TRUE
    /\ aWakes' = aWakes - 1
    /\ UNCHANGED <<aTicks, bAttempts, bDue, bRecovered>>

\* A's execution fails and it releases the lock, regenerating a wake for
\* each status object it wrote on the way. With both wake sources
\* suppressed this is where the storm stops.
AFailAndRelease ==
    /\ aRunning
    /\ lockHeld' = FALSE
    /\ aRunning' = FALSE
    /\ aWakes' = IF aWakes + SelfWakes > MaxWakes
                    THEN MaxWakes
                    ELSE aWakes + SelfWakes
    /\ UNCHANGED <<aTicks, bAttempts, bDue, bRecovered>>

\* B tries to reconcile. If A holds the lock it loses one attempt and
\* backs off; otherwise it makes its progress. `try_lock` is
\* non-blocking, which is why losing costs an attempt rather than
\* queueing.
BAttempt ==
    /\ bDue
    /\ ~bRecovered
    /\ bAttempts > 0
    /\ IF lockHeld
         THEN /\ bAttempts' = bAttempts - 1
              /\ bDue' = FALSE
              /\ UNCHANGED bRecovered
         ELSE /\ bRecovered' = TRUE
              /\ bDue' = FALSE
              /\ UNCHANGED bAttempts
    /\ UNCHANGED <<lockHeld, aRunning, aWakes, aTicks>>

\* B's back-off expires and it becomes due again. Gated on A not being
\* mid-hold: B's delay is orders of magnitude longer than A's, so the
\* hold it just lost to is over. A may of course take the lock again
\* before B actually tries — that race is the bug.
BBackoffExpires ==
    /\ ~bDue
    /\ ~bRecovered
    /\ bAttempts > 0
    /\ ~aRunning
    /\ bDue' = TRUE
    /\ UNCHANGED <<lockHeld, aRunning, aWakes, aTicks, bAttempts, bRecovered>>

Next ==
    \/ ATick
    \/ AAcquire
    \/ AFailAndRelease
    \/ BAttempt
    \/ BBackoffExpires

\* Weak fairness on A releasing: without it TLC could hold the lock
\* forever and starve B for an uninteresting reason. The question here
\* is re-acquisition *rate*, not a stuck reconcile — PlanLifecycle.tla
\* covers plans wedged in Applying.
\*
\* Weak fairness on B attempting: its caller does keep polling. Without
\* this, "B never tried" would satisfy the violation and say nothing.
\*
\* No fairness on AAcquire or ATick: A is permitted to storm, not
\* required to. The fixed configuration must hold even when it does.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AFailAndRelease)
    /\ WF_vars(BAttempt)
    /\ WF_vars(BBackoffExpires)

\* --- Properties ---

\* The point of the model. B is another policy on the same database
\* with something to do; it must eventually get to do it.
EventuallyRecovers == <>bRecovered

\* B gave up with attempts exhausted and no progress. The negation of
\* recovery, stated positively so a violation reads as the symptom seen
\* in CI: the wait ran out.
NeverStarved == [](~(bAttempts = 0 /\ ~bRecovered))

\* --- Safety, which holds in every configuration ---
\*
\* These are here to make the argument that the bug is invisible to
\* safety checking, not because they are in doubt. Both hold under the
\* storm; only the temporal properties above separate the designs.

\* The lock is held exactly while A is inside its reconcile. Lock
\* discipline is never what breaks here.
LockHeldOnlyWhileRunning == [](lockHeld <=> aRunning)

\* B never slips past a held lock. Its progress is always taken from a
\* free lock, under the storm as much as without it — the storm denies
\* B the lock, it does not corrupt the mutual exclusion.
BNeverProgressesWhileLocked ==
    [][(BAttempt /\ lockHeld) => bRecovered' = bRecovered]_vars

====
