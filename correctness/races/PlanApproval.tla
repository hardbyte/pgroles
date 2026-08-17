---- MODULE PlanApproval ----
EXTENDS FiniteSets, Naturals

(*
  Approval identity model for pgroles PostgresPolicyPlan.

  `PlanLifecycle.tla` models the plan state machine assuming one hash stands
  for both "what the reviewer approved" and "what would execute now". This
  model separates the two, because they are not the same thing:

    - the *semantic effects* of a plan (typed changes: roles, grants,
      memberships, ...), which are stable while policy, database and password
      sources are unchanged
    - the *rendered SQL* those effects produce, which for a password change
      embeds a SCRAM-SHA-256 verifier built with a fresh random salt on every
      computation, and therefore differs on every recomputation

  Gating approval on rendered SQL makes a password-bearing plan impossible to
  approve: at approve time the operator re-renders, the hash differs, the
  reviewed plan is superseded, and the replacement has the same problem. That
  is issue #174, and it is a *liveness* failure — nothing unsafe executes, but
  the workflow never converges. Safety invariants alone cannot see it.

  The constant `SqlHashApproval` selects the gate:

    - FALSE (PlanApproval.cfg)       — approval binds the semantic effect
                                       digest. Safety and liveness hold.
    - TRUE  (PlanApproval_buggy.cfg) — approval binds the rendered SQL hash,
                                       reproducing #174. TLC reports a
                                       liveness violation: an endless
                                       approve/supersede cycle.

  The constants `DeferSecretMaterialization` and `RecordMaterializedVersion`
  model issue #181, which lives one layer below the approval gate: where a
  *generated password Secret* is created, and which source version the policy
  records once it has been.

  A generated password has a "source version" derived from the Secret holding
  it. When no Secret exists the operator uses a `<secret>:<key>:missing`
  sentinel, modeled here as `Missing`; a real Secret yields `Real`. A password
  change is planned whenever the recorded version differs from the current one.

    - DeferSecretMaterialization = FALSE — the Secret is written while the plan
      is merely *pending*, so a plan that is never approved still leaves a live
      credential behind. This is the behavior #181 removes.
    - DeferSecretMaterialization = TRUE  — the Secret is written at execution,
      after the decision. The plan is then created against `Missing` and the
      Secret becomes `Real` as it applies.
    - RecordMaterializedVersion = FALSE  — the naive deferral: the policy
      records the planning-time sentinel it started from. The next reconcile
      sees `Real /= Missing`, plans another password change, and asks for a
      second human approval. `ApprovalsBounded` catches exactly this.
    - RecordMaterializedVersion = TRUE   — the shipped fix: the version the
      Secret actually reported is threaded back out of execution and recorded,
      so the next reconcile is quiet.

  `SecretBeforeSql` justifies the ordering of the two writes execution makes.
  With a crash between them, writing the Secret first leaves an inert Secret
  that the next reconcile adopts; writing the SQL first commits a password to
  the database that exists nowhere else, which `PasswordRecoverable` reports.

  What is NOT modeled:
    - the encoding of the digest itself (see pgroles_core::approval)
    - operator crashes and lock contention (covered by PlanLifecycle.tla)
    - SQL execution against a real database
*)

CONSTANTS
    SqlHashApproval,     \* TRUE reproduces the #174 rendered-SQL gate
    LockDuringApply,     \* TRUE models verification and execution happening
                         \* under one lock hold with no unlock window
    HasPasswordChange,   \* TRUE when the change set contains a SetPassword
    MaxDrifts,           \* Bound on external database drift, so the system
                         \* eventually quiesces and liveness is meaningful
    DeferSecretMaterialization, \* TRUE writes the generated Secret at
                                \* execution rather than at planning (#181)
    RecordMaterializedVersion,  \* TRUE records the post-materialization
                                \* source version rather than the sentinel
    SecretBeforeSql,     \* TRUE writes the Secret before the SQL transaction
    MaxCrashes,          \* Bound on crashes between the two writes
    MaxApprovals         \* Saturation cap on the approval counter, purely to
                         \* keep the state space finite

\* Plan phases relevant to approval. Rejection and crash recovery are
\* PlanLifecycle.tla's business.
NoPlan == "none"
Pending == "Pending"
Applying == "Applying"
Applied == "Applied"

\* Distinct semantic effect sets, standing in for change digests.
Effects == {"e1", "e2"}
NoEffects == "none"

VARIABLES
    planPhase,        \* Phase of the active plan
    planEffects,      \* Semantic effects the plan was computed from
    planRenderStale,  \* The stored rendered SQL no longer matches a fresh
                      \* render of the same effects (true once re-rendered
                      \* for a password-bearing change set)
    approved,         \* A reviewer has recorded approval of this exact plan
    dbEffects,        \* Effects the policy would produce against the live database
    driftsLeft,       \* Remaining external database changes
    appliedEffects,   \* Effects that actually executed (for safety checking)
    planVersion,      \* Password source version snapshotted when the plan was
                      \* computed — what the reviewer's decision was bound to
    secretExists,     \* Whether the generated password Secret exists
    recordedVersion,  \* status.appliedPasswordSourceVersions for this role
    dbPasswordSet,    \* Whether the database holds the generated password
    secretMadeUnapproved, \* A Secret was created by a reconcile that had no
                          \* approved plan to execute — the #181 defect
    crashesLeft,      \* Remaining crashes between the Secret and SQL writes
    approvalsUsed,    \* How many human decisions the workflow has consumed
    appliedInSync     \* Whether, *at the moment of execution*, the executed
                      \* effects still matched the live database. Recorded as a
                      \* witness because the database may legitimately drift
                      \* again afterwards — a plain state invariant comparing
                      \* appliedEffects to dbEffects would fire on that normal
                      \* post-apply drift instead of on a stale execution.

vars == <<planPhase, planEffects, planRenderStale, approved, dbEffects,
          driftsLeft, appliedEffects, appliedInSync, planVersion, secretExists,
          recordedVersion, dbPasswordSet, secretMadeUnapproved, crashesLeft,
          approvalsUsed>>

\* Password source versions. `Missing` is the `<secret>:<key>:missing`
\* sentinel the operator uses while no Secret exists; `Real` stands for any
\* version derived from a live Secret. `NoVersion` is "nothing recorded yet".
NoVersion == "none"
Missing == "missing"
Real == "real"
Versions == {NoVersion, Missing, Real}

\* The source version the operator would resolve right now.
CurrentVersion == IF secretExists THEN Real ELSE Missing

\* A password change is planned exactly when the recorded version differs from
\* the one resolution produces — `select_password_changes` in the operator.
SetPasswordNeeded == HasPasswordChange /\ recordedVersion /= CurrentVersion

TypeOK ==
    /\ planPhase \in {NoPlan, Pending, Applying, Applied}
    /\ planEffects \in Effects \cup {NoEffects}
    /\ planRenderStale \in BOOLEAN
    /\ approved \in BOOLEAN
    /\ dbEffects \in Effects
    /\ driftsLeft \in 0..MaxDrifts
    /\ appliedEffects \in Effects \cup {NoEffects}
    /\ appliedInSync \in BOOLEAN
    /\ planVersion \in Versions
    /\ secretExists \in BOOLEAN
    /\ recordedVersion \in Versions
    /\ dbPasswordSet \in BOOLEAN
    /\ secretMadeUnapproved \in BOOLEAN
    /\ crashesLeft \in 0..MaxCrashes
    /\ approvalsUsed \in 0..MaxApprovals

\* --- The approval gate ---

\* Whether execution is permitted for the currently approved plan.
\*
\* Both gates require the reviewed effects to still be the effects the policy
\* would produce. The rendered-SQL gate *additionally* requires the freshly
\* rendered text to match what was stored — which a password change can never
\* satisfy.
GatePasses ==
    /\ planEffects = dbEffects
    /\ (SqlHashApproval => ~planRenderStale)
    \* The password source must still be the one the plan was computed
    \* against. A Secret that appeared or vanished since is a different plan.
    /\ planVersion = CurrentVersion

\* --- Safety invariants ---

\* Nothing executes without a recorded approval of the plan being executed.
NoUnreviewedExecution ==
    (planPhase \in {Applying, Applied}) => approved

\* What executed is what was reviewed — never a different set of effects.
ExecutedWhatWasApproved ==
    (planPhase = Applied) => appliedEffects = planEffects

\* What executed matches the database state it was verified against — no drift
\* slipped in between the gate check and execution.
\*
\* Note this compares against `dbEffects`, not `planEffects`: comparing to
\* `planEffects` would merely restate ExecutedWhatWasApproved and could never
\* observe drift. This is the property that requires verification and execution
\* to share one lock hold; with LockDuringApply = FALSE, TLC finds the stale
\* apply (see PlanApproval_unlocked.cfg).
NoStaleExecution ==
    (planPhase = Applied /\ appliedEffects /= NoEffects) => appliedInSync

\* No generated Secret is ever created by a reconcile that is not executing an
\* approved plan. A plan that is rejected, or never approved, leaves no
\* credential behind. This is the #181 property, and it is stated over the
\* *creation* rather than over `secretExists`: once a plan has legitimately
\* applied, the Secret rightly outlives it and coexists with later plans.
\* DeferSecretMaterialization = FALSE violates it.
NoSecretBeforeApproval == ~secretMadeUnapproved

\* Every password the database holds is readable from a Secret. Violated when
\* the SQL transaction commits before the Secret is written and the operator
\* crashes in between — the password then exists nowhere a client can read it.
PasswordRecoverable == dbPasswordSet => secretExists

\* The workflow spends at most one human decision on a settled policy. The
\* naive deferral — materialize at execution but record the planning-time
\* sentinel — needs two: the first applies the password, and the second
\* approves a plan that exists only because the recorded version went stale.
ApprovalsBounded == approvalsUsed <= 1

\* --- Liveness ---

\* The workflow converges: once drift stops, a plan is eventually applied.
\* This is the property #174 violates.
EventuallyApplies == <>(planPhase = Applied)

Init ==
    /\ planPhase = NoPlan
    /\ planEffects = NoEffects
    /\ planRenderStale = FALSE
    /\ approved = FALSE
    /\ dbEffects = "e1"
    /\ driftsLeft = MaxDrifts
    /\ appliedEffects = NoEffects
    /\ appliedInSync = TRUE
    /\ planVersion = NoVersion
    /\ secretExists = FALSE
    /\ recordedVersion = NoVersion
    /\ dbPasswordSet = FALSE
    /\ secretMadeUnapproved = FALSE
    /\ crashesLeft = MaxCrashes
    /\ approvalsUsed = 0

\* --- Actions ---

\* External modification to the database changes what the policy would do.
\* Bounded by MaxDrifts so the system eventually quiesces.
\*
\* While the operator is executing it holds the database and advisory locks, so
\* nothing can change underneath it — the design's "no unlock window" between
\* pre-execution verification and execution.
DatabaseDrifts ==
    /\ LockDuringApply => planPhase /= Applying
    /\ driftsLeft > 0
    /\ \E e \in Effects:
        /\ e /= dbEffects
        /\ dbEffects' = e
    /\ driftsLeft' = driftsLeft - 1
    /\ UNCHANGED <<planPhase, planEffects, planRenderStale, approved,
                    appliedEffects, appliedInSync, planVersion, secretExists,
                    recordedVersion, dbPasswordSet,
                    secretMadeUnapproved, crashesLeft, approvalsUsed>>

\* The operator computes a plan for the current effects.
\*
\* A plan is computed only when there is something to do: the effects moved, or
\* the password source version the policy recorded no longer matches what
\* resolution produces.
OperatorCreatesPlan ==
    /\ planPhase = NoPlan
    /\ (planEffects /= dbEffects \/ SetPasswordNeeded \/ appliedEffects = NoEffects)
    /\ planPhase' = Pending
    /\ planEffects' = dbEffects
    /\ planRenderStale' = FALSE   \* Freshly rendered and stored together
    /\ approved' = FALSE
    \* Pre-#181, resolving a generated password created the Secret right here,
    \* while the plan was still only pending.
    /\ secretExists' = (secretExists \/ (HasPasswordChange /\ ~DeferSecretMaterialization))
    /\ secretMadeUnapproved' = (secretMadeUnapproved
                                 \/ (secretExists' /= secretExists))
    \* The decision is bound to the source version resolution just produced.
    /\ planVersion' = (IF secretExists' THEN Real ELSE Missing)
    /\ UNCHANGED <<dbEffects, driftsLeft, appliedEffects, appliedInSync,
                    recordedVersion, dbPasswordSet, crashesLeft, approvalsUsed>>

\* A reviewer approves the pending plan.
UserApproves ==
    /\ planPhase = Pending
    /\ ~approved
    /\ approved' = TRUE
    \* Saturating, so the counter bounds the state space without ever
    \* disabling the action and making liveness vacuous.
    /\ approvalsUsed' = (IF approvalsUsed < MaxApprovals
                         THEN approvalsUsed + 1
                         ELSE approvalsUsed)
    /\ UNCHANGED <<planPhase, planEffects, planRenderStale, dbEffects,
                    driftsLeft, appliedEffects, appliedInSync, planVersion,
                    secretExists, recordedVersion, dbPasswordSet,
                    secretMadeUnapproved, crashesLeft>>

\* Before executing, the operator recomputes the diff and re-renders the SQL.
\*
\* For a password-bearing change set this yields a fresh SCRAM verifier, so
\* the stored rendered SQL is now stale even though the effects are identical.
\* This is the step that makes the rendered-SQL gate unsatisfiable.
OperatorRevalidates ==
    /\ planPhase = Pending
    /\ approved
    /\ ~planRenderStale
    /\ HasPasswordChange
    /\ planRenderStale' = TRUE
    /\ UNCHANGED <<planPhase, planEffects, approved, dbEffects, driftsLeft,
                    appliedEffects, appliedInSync, planVersion, secretExists,
                    recordedVersion, dbPasswordSet,
                    secretMadeUnapproved, crashesLeft, approvalsUsed>>

\* The gate passes: execute the reviewed effects.
OperatorExecutes ==
    /\ planPhase = Pending
    /\ approved
    /\ (HasPasswordChange => planRenderStale)  \* Revalidation has happened
    /\ GatePasses
    /\ planPhase' = Applying
    /\ UNCHANGED <<planEffects, planRenderStale, approved, dbEffects,
                    driftsLeft, appliedEffects, appliedInSync, planVersion,
                    secretExists, recordedVersion, dbPasswordSet,
                    secretMadeUnapproved, crashesLeft, approvalsUsed>>

\* The gate fails: supersede the reviewed plan and start a fresh one.
\*
\* With the digest gate this happens only when the effects genuinely changed.
\* With the rendered-SQL gate it also happens for an unchanged password
\* source — the #174 loop.
OperatorSupersedes ==
    /\ planPhase = Pending
    /\ approved
    /\ (HasPasswordChange => planRenderStale)
    /\ ~GatePasses
    /\ planPhase' = Pending
    /\ planEffects' = dbEffects
    /\ planRenderStale' = FALSE
    /\ approved' = FALSE          \* The replacement needs its own decision
    /\ secretExists' = (secretExists \/ (HasPasswordChange /\ ~DeferSecretMaterialization))
    /\ secretMadeUnapproved' = (secretMadeUnapproved
                                 \/ (secretExists' /= secretExists))
    /\ planVersion' = (IF secretExists' THEN Real ELSE Missing)
    /\ UNCHANGED <<dbEffects, driftsLeft, appliedEffects, appliedInSync,
                    recordedVersion, dbPasswordSet, crashesLeft, approvalsUsed>>

\* Execution: materialize any deferred Secret, then run the SQL, then record
\* the source version the database was actually set from.
ApplySucceeds ==
    /\ planPhase = Applying
    /\ planPhase' = Applied
    /\ appliedEffects' = planEffects
    \* The witness: did the database still hold the verified state when the
    \* statements ran? Under a single lock hold it must have.
    /\ appliedInSync' = (planEffects = dbEffects)
    \* The deferred Secret is written here, after the decision.
    /\ secretExists' = (secretExists \/ HasPasswordChange)
    /\ dbPasswordSet' = (dbPasswordSet \/ HasPasswordChange)
    \* Which version the policy records is the whole of the #181 fix: the
    \* sentinel the plan started from, or the one the Secret reported.
    /\ recordedVersion' =
        IF ~HasPasswordChange THEN recordedVersion
        ELSE IF RecordMaterializedVersion THEN Real
        ELSE planVersion
    /\ UNCHANGED <<planEffects, planRenderStale, approved, dbEffects,
                    driftsLeft, planVersion, secretMadeUnapproved, crashesLeft,
                    approvalsUsed>>

\* The operator crashes between execution's two writes. Which write survives is
\* the ordering question `SecretBeforeSql` settles.
ApplyCrashes ==
    /\ planPhase = Applying
    /\ crashesLeft > 0
    /\ crashesLeft' = crashesLeft - 1
    /\ HasPasswordChange
    /\ IF SecretBeforeSql
       THEN \* The Secret landed; the transaction did not. An inert Secret.
            /\ secretExists' = TRUE
            /\ UNCHANGED dbPasswordSet
       ELSE \* The transaction committed; the Secret was never written. The
            \* database now holds a password nothing can read.
            /\ dbPasswordSet' = TRUE
            /\ UNCHANGED secretExists
    \* Recovery re-plans from scratch; the interrupted decision is spent.
    /\ planPhase' = NoPlan
    /\ approved' = FALSE
    /\ UNCHANGED <<planEffects, planRenderStale, dbEffects, driftsLeft,
                    appliedEffects, appliedInSync, planVersion,
                    recordedVersion, secretMadeUnapproved, approvalsUsed>>

\* The operator reconciles again after an apply. Without this the model stops
\* at the first Applied state and can never show a *second* plan being demanded
\* for work the first one already did.
OperatorRequeues ==
    /\ planPhase = Applied
    /\ (planEffects /= dbEffects \/ SetPasswordNeeded)
    /\ planPhase' = NoPlan
    /\ approved' = FALSE
    /\ UNCHANGED <<planEffects, planRenderStale, dbEffects, driftsLeft,
                    appliedEffects, appliedInSync, planVersion, secretExists,
                    recordedVersion, dbPasswordSet,
                    secretMadeUnapproved, crashesLeft, approvalsUsed>>

Next ==
    \/ DatabaseDrifts
    \/ OperatorCreatesPlan
    \/ UserApproves
    \/ OperatorRevalidates
    \/ OperatorExecutes
    \/ OperatorSupersedes
    \/ ApplySucceeds
    \/ ApplyCrashes
    \/ OperatorRequeues

\* Weak fairness on every progress action: the operator keeps reconciling and
\* the reviewer keeps reviewing. Drift is deliberately *not* fair — it is
\* bounded and may stop at any time, which is what makes convergence
\* meaningful to ask about.
Fairness ==
    /\ WF_vars(OperatorCreatesPlan)
    /\ WF_vars(UserApproves)
    /\ WF_vars(OperatorRevalidates)
    /\ WF_vars(OperatorExecutes)
    /\ WF_vars(OperatorSupersedes)
    /\ WF_vars(ApplySucceeds)
    /\ WF_vars(OperatorRequeues)

Spec == Init /\ [][Next]_vars /\ Fairness

====
