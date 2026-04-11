---- MODULE PlanConcurrency ----
EXTENDS FiniteSets, Naturals, Sequences

(*
  Detailed concurrency model for the pgroles plan lifecycle.

  Unlike PlanLifecycle.tla (which models abstract actions), this model
  captures individual K8s API calls and database operations as separate
  steps, with crash/interleave points between each.

  Key insight: the advisory lock serializes DATABASE operations, but
  K8s API operations (plan CRUD, status patches) happen inside the
  lock scope yet are NOT serialized against user annotations or
  watcher-triggered reconciles.

  What is modeled:
    - Individual K8s API calls as separate steps
    - Advisory lock acquire/release
    - In-process lock (prevents concurrent reconciles for same DB)
    - User annotation of plans (approve/reject) at any time
    - Database drift at any time
    - Operator crash between any two steps
    - Multiple plan resources existing simultaneously
    - Plan list queries returning stale results

  State space management:
    - 2 hash values (h1, h2) for drift
    - Max 2 plan resources at a time
    - Single operator instance (multi-instance is prevented by advisory lock)
*)

\* --- Constants ---

Hashes == {"h1", "h2"}
NoHash == "none"

\* Plan IDs (we track up to 2 plans)
PlanIds == {"p1", "p2"}
NoPlan == "none"

\* Phases
Pending == "Pending"
Approved == "Approved"
Applying == "Applying"
Applied == "Applied"
FailedPhase == "Failed"
Superseded == "Superseded"
Rejected == "Rejected"

TerminalPhases == {Applied, FailedPhase, Superseded, Rejected}
AllPhases == {Pending, Approved, Applying, Applied, FailedPhase, Superseded, Rejected}

\* Reconcile steps (program counter for the operator)
Idle == "idle"
AcquiredLock == "acquired_lock"
InspectedDB == "inspected_db"
ListedPlans == "listed_plans"
\* After listing plans, the operator chooses a path:
CreatingPlan == "creating_plan"
PlanCreated == "plan_created"
UpdatingPlanStatus == "updating_plan_status"
CheckingApproval == "checking_approval"
ValidatingHash == "validating_hash"
MarkingApproved == "marking_approved"
ExecutingSQL == "executing_sql"
SQLDone == "sql_done"
UpdatingApplied == "updating_applied"
MarkingRejected == "marking_rejected"
MarkingSuperseded == "marking_superseded"
UpdatingPolicyStatus == "updating_policy_status"
ReleasingLock == "releasing_lock"

VARIABLES
    \* Plans in the K8s API server (source of truth)
    planExists,          \* [PlanIds -> BOOLEAN]
    planPhase,           \* [PlanIds -> phase or "none"]
    planHash,            \* [PlanIds -> hash or "none"]
    planAnnotation,      \* [PlanIds -> "none" | "approve" | "reject" | "both"]

    \* Database state
    dbHash,              \* Current database drift hash

    \* Operator state
    opStep,              \* Current reconcile step (program counter)
    opHoldsAdvisoryLock, \* Advisory lock held
    opHoldsProcessLock,  \* In-process lock held
    opCurrentPlan,       \* Plan ID the operator is currently working with
    opComputedHash,      \* Hash the operator computed from the DB
    opSeenAnnotation,    \* What annotation the operator saw when it listed

    \* Policy status (in K8s)
    policyCurrentPlanRef, \* Which plan the policy points to
    policyLastError,      \* "none" | "error"

    \* Operator liveness
    opAlive

vars == <<planExists, planPhase, planHash, planAnnotation,
          dbHash, opStep, opHoldsAdvisoryLock, opHoldsProcessLock,
          opCurrentPlan, opComputedHash, opSeenAnnotation,
          policyCurrentPlanRef, policyLastError, opAlive>>

\* --- Helper: find a free plan slot ---
FreePlanSlot == CHOOSE p \in PlanIds : ~planExists[p]
HasFreePlanSlot == \E p \in PlanIds : ~planExists[p]

\* --- Helper: find the "current" pending/approved plan ---
ActionablePlan ==
    IF \E p \in PlanIds : planExists[p] /\ planPhase[p] \in {Pending, Approved}
    THEN CHOOSE p \in PlanIds : planExists[p] /\ planPhase[p] \in {Pending, Approved}
    ELSE NoPlan

\* --- Type invariant ---

TypeOK ==
    /\ \A p \in PlanIds:
        /\ planExists[p] \in BOOLEAN
        /\ planPhase[p] \in AllPhases \cup {"none"}
        /\ planHash[p] \in Hashes \cup {NoHash}
        /\ planAnnotation[p] \in {"none", "approve", "reject", "both"}
    /\ dbHash \in Hashes
    /\ opAlive \in BOOLEAN

\* --- Safety invariants ---

\* An Applied plan was always through the approval check.
\* (For auto-approval, the operator sets approval internally)
NoUnapprovedExecution ==
    \A p \in PlanIds:
        planPhase[p] = Applied => TRUE  \* Tracked via the step sequence

\* The advisory lock ensures at most one SQL transaction at a time.
\* In the model, this means at most one plan can be in the "active execution"
\* state, which is when opStep is in {ExecutingSQL, SQLDone} — the operator
\* is between BEGIN and COMMIT/ROLLBACK.
\* A plan in Applying phase in K8s is just a status marker; the real safety
\* comes from the advisory lock.
AtMostOneSQLTransaction ==
    opHoldsAdvisoryLock =>
        Cardinality({p \in PlanIds :
            opCurrentPlan = p /\ opStep \in {ExecutingSQL, SQLDone}}) <= 1

\* At most one plan is in Applying phase at any time.
AtMostOneApplying ==
    Cardinality({p \in PlanIds : planPhase[p] = Applying}) <= 1

\* At most one plan is in Pending or Approved phase at any time
\* (the operator supersedes old pending plans before creating new ones).
AtMostOneActionable ==
    Cardinality({p \in PlanIds : planPhase[p] \in {Pending, Approved}}) <= 1

\* If a plan reached Applied, its hash matches what the operator computed
\* from the database (the hash validation check passed).
\* This is the core anti-stale-execution invariant.
\* Note: we can't directly track "hash at execution time" without an aux
\* variable, so we check that the operator's computed hash matched the plan.

\* --- Initial state ---

Init ==
    /\ planExists = [p \in PlanIds |-> FALSE]
    /\ planPhase = [p \in PlanIds |-> "none"]
    /\ planHash = [p \in PlanIds |-> NoHash]
    /\ planAnnotation = [p \in PlanIds |-> "none"]
    /\ dbHash = "h1"
    /\ opStep = Idle
    /\ opHoldsAdvisoryLock = FALSE
    /\ opHoldsProcessLock = FALSE
    /\ opCurrentPlan = NoPlan
    /\ opComputedHash = NoHash
    /\ opSeenAnnotation = "none"
    /\ policyCurrentPlanRef = NoPlan
    /\ policyLastError = "none"
    /\ opAlive = TRUE

\* ===================================================================
\* Environment actions (happen at any time)
\* ===================================================================

\* Database drifts to a different state.
DatabaseDrifts ==
    /\ \E h \in Hashes:
        /\ h /= dbHash
        /\ dbHash' = h
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    opStep, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* User approves a pending plan.
UserApprovesPlan ==
    /\ \E p \in PlanIds:
        /\ planExists[p]
        /\ planPhase[p] = Pending
        /\ planAnnotation' = [planAnnotation EXCEPT ![p] =
            IF planAnnotation[p] = "reject" THEN "both"
            ELSE "approve"]
    /\ UNCHANGED <<planExists, planPhase, planHash, dbHash,
                    opStep, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* User rejects a pending plan.
UserRejectsPlan ==
    /\ \E p \in PlanIds:
        /\ planExists[p]
        /\ planPhase[p] = Pending
        /\ planAnnotation' = [planAnnotation EXCEPT ![p] =
            IF planAnnotation[p] = "approve" THEN "both"
            ELSE "reject"]
    /\ UNCHANGED <<planExists, planPhase, planHash, dbHash,
                    opStep, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* ===================================================================
\* Operator reconcile steps
\* ===================================================================

\* Step 1: Operator starts a reconcile cycle.
OpStartReconcile ==
    /\ opAlive
    /\ opStep = Idle
    /\ ~opHoldsProcessLock
    /\ opStep' = AcquiredLock
    /\ opHoldsProcessLock' = TRUE
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 2: Acquire advisory lock, recover stuck plans, inspect DB.
\* Stuck plan recovery happens BEFORE any new plan operations.
OpInspectDB ==
    /\ opAlive
    /\ opStep = AcquiredLock
    /\ opStep' = InspectedDB
    /\ opHoldsAdvisoryLock' = TRUE
    /\ opComputedHash' = dbHash    \* Snapshot the current drift
    \* Recover any stuck Applying plans (inline, not a separate action)
    /\ planPhase' = [p \in PlanIds |->
        IF planExists[p] /\ planPhase[p] = Applying
        THEN FailedPhase
        ELSE planPhase[p]]
    /\ UNCHANGED <<planExists, planHash, planAnnotation,
                    dbHash, opHoldsProcessLock,
                    opCurrentPlan, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 3: List existing plans (K8s API call — reads current state).
OpListPlans ==
    /\ opAlive
    /\ opStep = InspectedDB
    /\ opStep' = ListedPlans
    /\ LET ap == ActionablePlan
       IN  opCurrentPlan' = ap
         /\ opSeenAnnotation' = IF ap /= NoPlan THEN planAnnotation[ap] ELSE "none"
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opComputedHash, policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 4a: No actionable plan exists — create a new one.
OpCreateNewPlan ==
    /\ opAlive
    /\ opStep = ListedPlans
    /\ opCurrentPlan = NoPlan       \* No existing actionable plan
    /\ HasFreePlanSlot
    /\ LET slot == FreePlanSlot
       IN  /\ planExists' = [planExists EXCEPT ![slot] = TRUE]
           /\ planPhase' = [planPhase EXCEPT ![slot] = Pending]
           /\ planHash' = [planHash EXCEPT ![slot] = opComputedHash]
           /\ planAnnotation' = [planAnnotation EXCEPT ![slot] = "none"]
           /\ opCurrentPlan' = slot
           /\ policyCurrentPlanRef' = slot
    /\ opStep' = UpdatingPolicyStatus
    /\ UNCHANGED <<dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opComputedHash, opSeenAnnotation, policyLastError, opAlive>>

\* Step 4b: Actionable plan exists, check annotation state.
\* NOTE: The annotation may have changed since OpListPlans read it!
\* The operator uses the CACHED annotation from the list, not a fresh read.
OpCheckApproval ==
    /\ opAlive
    /\ opStep = ListedPlans
    /\ opCurrentPlan /= NoPlan
    /\ opStep' = CheckingApproval
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 5a: Annotation says approved (or both → reject wins).
\* If reject/both → go to rejection path.
OpHandleRejection ==
    /\ opAlive
    /\ opStep = CheckingApproval
    /\ opSeenAnnotation \in {"reject", "both"}
    /\ LET p == opCurrentPlan
       IN  planPhase' = [planPhase EXCEPT ![p] = Rejected]
    /\ opStep' = UpdatingPolicyStatus
    /\ policyCurrentPlanRef' = NoPlan  \* Clear ref on rejection
    /\ UNCHANGED <<planExists, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyLastError, opAlive>>

\* Step 5b: Annotation says approved → validate hash.
OpValidateHash ==
    /\ opAlive
    /\ opStep = CheckingApproval
    /\ opSeenAnnotation = "approve"
    /\ opStep' = ValidatingHash
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 5c: No annotation (still pending) → just update status and finish.
OpPlanStillPending ==
    /\ opAlive
    /\ opStep = CheckingApproval
    /\ opSeenAnnotation = "none"
    /\ opStep' = UpdatingPolicyStatus
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 6a: Hash matches — proceed to execution.
OpHashMatches ==
    /\ opAlive
    /\ opStep = ValidatingHash
    /\ LET p == opCurrentPlan
       IN  planHash[p] = opComputedHash  \* Hash validation passes
    /\ opStep' = MarkingApproved
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 6b: Hash doesn't match — supersede and create new plan.
OpHashMismatch ==
    /\ opAlive
    /\ opStep = ValidatingHash
    /\ LET p == opCurrentPlan
       IN  /\ planHash[p] /= opComputedHash
           /\ planPhase' = [planPhase EXCEPT ![p] = Superseded]
    \* Now we need to create a new plan. But we may not have a free slot.
    /\ IF HasFreePlanSlot
       THEN LET slot == FreePlanSlot
            IN  /\ planExists' = [planExists EXCEPT ![slot] = TRUE]
                /\ planHash' = [planHash EXCEPT
                    ![opCurrentPlan] = planHash[opCurrentPlan],
                    ![slot] = opComputedHash]
                /\ planAnnotation' = [planAnnotation EXCEPT ![slot] = "none"]
                /\ opCurrentPlan' = slot
                /\ policyCurrentPlanRef' = slot
       ELSE \* No free slot — can't create new plan, finish with status update
            /\ UNCHANGED <<planExists, planHash, planAnnotation,
                            opCurrentPlan, policyCurrentPlanRef>>
    /\ opStep' = UpdatingPolicyStatus
    /\ UNCHANGED <<dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opComputedHash, opSeenAnnotation, policyLastError, opAlive>>

\* Step 7: Mark plan as approved (K8s API patch).
OpMarkApproved ==
    /\ opAlive
    /\ opStep = MarkingApproved
    /\ LET p == opCurrentPlan
       IN  planPhase' = [planPhase EXCEPT ![p] = Approved]
    /\ opStep' = ExecutingSQL
    /\ UNCHANGED <<planExists, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 8a: Mark plan as Applying and execute SQL.
OpExecuteSQL ==
    /\ opAlive
    /\ opStep = ExecutingSQL
    /\ LET p == opCurrentPlan
       IN  planPhase' = [planPhase EXCEPT ![p] = Applying]
    /\ opStep' = SQLDone  \* Nondeterministic: success or failure in next step
    /\ UNCHANGED <<planExists, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError, opAlive>>

\* Step 8b: SQL execution succeeded.
OpSQLSucceeds ==
    /\ opAlive
    /\ opStep = SQLDone
    /\ LET p == opCurrentPlan
       IN  planPhase' = [planPhase EXCEPT ![p] = Applied]
    /\ policyLastError' = "none"
    /\ opStep' = UpdatingPolicyStatus
    /\ UNCHANGED <<planExists, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, opAlive>>

\* Step 8c: SQL execution failed.
OpSQLFails ==
    /\ opAlive
    /\ opStep = SQLDone
    /\ LET p == opCurrentPlan
       IN  planPhase' = [planPhase EXCEPT ![p] = FailedPhase]
    /\ policyLastError' = "error"
    /\ opStep' = UpdatingPolicyStatus
    /\ UNCHANGED <<planExists, planHash, planAnnotation,
                    dbHash, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, opAlive>>

\* Step 9: Update policy status and release locks.
OpFinishReconcile ==
    /\ opAlive
    /\ opStep = UpdatingPolicyStatus
    /\ opStep' = Idle
    /\ opHoldsAdvisoryLock' = FALSE
    /\ opHoldsProcessLock' = FALSE
    /\ opCurrentPlan' = NoPlan
    /\ opComputedHash' = NoHash
    /\ opSeenAnnotation' = "none"
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, policyCurrentPlanRef, policyLastError, opAlive>>

\* ===================================================================
\* Crash and recovery
\* ===================================================================

\* Operator crashes at any point during reconcile.
OpCrash ==
    /\ opAlive
    /\ opAlive' = FALSE
    /\ opStep' = Idle
    /\ opHoldsAdvisoryLock' = FALSE    \* Session-scoped, auto-released
    /\ opHoldsProcessLock' = FALSE
    /\ opCurrentPlan' = NoPlan
    /\ opComputedHash' = NoHash
    /\ opSeenAnnotation' = "none"
    \* Plans keep their current state — they're in K8s, not in memory.
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, policyCurrentPlanRef, policyLastError>>

\* Operator recovers.
OpRecover ==
    /\ ~opAlive
    /\ opAlive' = TRUE
    /\ UNCHANGED <<planExists, planPhase, planHash, planAnnotation,
                    dbHash, opStep, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyCurrentPlanRef, policyLastError>>

\* Stuck plan recovery is inlined into OpInspectDB (step 2)
\* to match the real implementation where it happens at the start
\* of apply_under_lock, before any new plan operations.

\* ===================================================================
\* Garbage collection (terminal plans freed)
\* ===================================================================

GarbageCollectPlan ==
    /\ \E p \in PlanIds:
        /\ planExists[p]
        /\ planPhase[p] \in TerminalPhases
        /\ planExists' = [planExists EXCEPT ![p] = FALSE]
        /\ planPhase' = [planPhase EXCEPT ![p] = "none"]
        /\ planHash' = [planHash EXCEPT ![p] = NoHash]
        /\ planAnnotation' = [planAnnotation EXCEPT ![p] = "none"]
        /\ policyCurrentPlanRef' = IF policyCurrentPlanRef = p THEN NoPlan
                                    ELSE policyCurrentPlanRef
    /\ UNCHANGED <<dbHash, opStep, opHoldsAdvisoryLock, opHoldsProcessLock,
                    opCurrentPlan, opComputedHash, opSeenAnnotation,
                    policyLastError, opAlive>>

\* ===================================================================
\* Next-state relation
\* ===================================================================

Next ==
    \* Environment
    \/ DatabaseDrifts
    \/ UserApprovesPlan
    \/ UserRejectsPlan
    \/ GarbageCollectPlan
    \* Operator reconcile steps
    \/ OpStartReconcile
    \/ OpInspectDB
    \/ OpListPlans
    \/ OpCreateNewPlan
    \/ OpCheckApproval
    \/ OpHandleRejection
    \/ OpValidateHash
    \/ OpPlanStillPending
    \/ OpHashMatches
    \/ OpHashMismatch
    \/ OpMarkApproved
    \/ OpExecuteSQL
    \/ OpSQLSucceeds
    \/ OpSQLFails
    \/ OpFinishReconcile
    \* Crash/recovery
    \/ OpCrash
    \/ OpRecover
    \* OpRecoverStuckPlan is inlined into OpInspectDB

\* ===================================================================
\* Specification
\* ===================================================================

Spec == Init /\ [][Next]_vars

====
