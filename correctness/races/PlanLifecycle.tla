---- MODULE PlanLifecycle ----
EXTENDS FiniteSets, Naturals, Sequences

(*
  Plan lifecycle model for pgroles PostgresPolicyPlan.

  Verifies the state machine for plan creation, approval, execution,
  supersede, and rejection under concurrent operator reconciles and
  user annotations.

  Key races modeled:
    1. User approves plan while operator is computing a new plan
       (the approved plan may get superseded before execution)
    2. Two reconcile cycles running concurrently for the same policy
       (advisory lock should serialize, but plan CRUD happens outside lock)
    3. Operator crashes during Applying phase (stuck plan recovery)
    4. User approves + rejects simultaneously (reject wins)
    5. Hash dedup: identical drift produces no new plan
    6. Status updates racing with error handler (last_error overwrite)

  What is NOT modeled:
    - Actual SQL execution / database state
    - Kubernetes API server internals
    - Network partitions
    - Multiple policies (single-policy focus)
*)

\* --- Constants ---

\* Plan phases
NoPlan == "none"
Pending == "Pending"
Approved == "Approved"
Applying == "Applying"
Applied == "Applied"
Failed == "Failed"
Superseded == "Superseded"
Rejected == "Rejected"

TerminalPhases == {Applied, Failed, Superseded, Rejected}

\* The set of possible SQL hashes (representing different drift states).
\* Using small set for model checking tractability.
Hashes == {"h1", "h2", "h3"}
NoHash == "none"

\* Approval annotations
NoAnnotation == "none"
ApproveAnnotation == "approve"
RejectAnnotation == "reject"
BothAnnotations == "both"

VARIABLES
    \* Plan state
    planPhase,          \* Current phase of the active plan
    planHash,           \* SQL hash of the active plan
    planAnnotation,     \* User annotation on the active plan: none/approve/reject/both

    \* Database state
    dbHash,             \* Hash of what the current database drift would produce

    \* Operator state
    operatorHoldsLock,  \* Whether the operator holds the advisory lock
    operatorComputing,  \* Whether the operator is mid-reconcile
    lastError,          \* The policy's last_error field (or "none")
    policyReady,        \* Policy ready condition status

    \* Crash state
    operatorAlive,      \* Whether the operator is running

    \* History tracking for invariant checking
    appliedHash,        \* Hash of the plan that was actually applied (for safety check)
    approvalWasChecked  \* Whether the approval annotation was verified before execution

vars == <<planPhase, planHash, planAnnotation, dbHash, operatorHoldsLock,
          operatorComputing, lastError, policyReady, operatorAlive,
          appliedHash, approvalWasChecked>>

\* --- Type invariant ---

TypeOK ==
    /\ planPhase \in {NoPlan, Pending, Approved, Applying, Applied, Failed, Superseded, Rejected}
    /\ planHash \in Hashes \cup {NoHash}
    /\ planAnnotation \in {NoAnnotation, ApproveAnnotation, RejectAnnotation, BothAnnotations}
    /\ dbHash \in Hashes
    /\ operatorHoldsLock \in BOOLEAN
    /\ operatorComputing \in BOOLEAN
    /\ lastError \in {"none", "error"}
    /\ policyReady \in BOOLEAN
    /\ operatorAlive \in BOOLEAN
    /\ appliedHash \in Hashes \cup {NoHash}
    /\ approvalWasChecked \in BOOLEAN

\* --- Safety invariants ---

\* A plan can only be in Applied phase if it was approved first.
AppliedImpliesApproved ==
    planPhase = Applied => approvalWasChecked

\* A rejected plan's hash was never the hash that was applied in this cycle.
\* (appliedHash tracks the most recent application; it resets on new plan creation)
RejectedNeverExecuted ==
    planPhase = Rejected => appliedHash /= planHash

\* Only one plan is active at a time (the current plan).
\* Terminal plans are garbage collected; we model only the active plan.

\* The applied hash must match the plan hash (we executed what we planned).
\* Note: the database may drift AFTER execution starts — that's fine.
\* What matters is that we didn't execute a stale plan whose hash didn't
\* match the drift at the time we decided to execute.
AppliedMatchesPlanHash ==
    (planPhase = Applied /\ appliedHash /= NoHash) =>
        appliedHash = planHash

\* last_error is set when in a failed state.
FailedImpliesError ==
    (planPhase = Failed /\ operatorAlive) => lastError = "error"

\* --- Initial state ---

Init ==
    /\ planPhase = NoPlan
    /\ planHash = NoHash
    /\ planAnnotation = NoAnnotation
    /\ dbHash = "h1"              \* Initial database state has drift
    /\ operatorHoldsLock = FALSE
    /\ operatorComputing = FALSE
    /\ lastError = "none"
    /\ policyReady = FALSE
    /\ operatorAlive = TRUE
    /\ appliedHash = NoHash
    /\ approvalWasChecked = FALSE

\* --- Actions ---

\* Database drift changes (external modifications to the database).
DatabaseDrifts ==
    /\ \E h \in Hashes:
        /\ h /= dbHash
        /\ dbHash' = h
    /\ UNCHANGED <<planPhase, planHash, planAnnotation, operatorHoldsLock,
                    operatorComputing, lastError, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* User adds approval annotation.
UserApproves ==
    /\ planPhase = Pending
    /\ planAnnotation' = IF planAnnotation = RejectAnnotation
                          THEN BothAnnotations
                          ELSE ApproveAnnotation
    /\ UNCHANGED <<planPhase, planHash, dbHash, operatorHoldsLock,
                    operatorComputing, lastError, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* User adds rejection annotation.
UserRejects ==
    /\ planPhase = Pending
    /\ planAnnotation' = IF planAnnotation = ApproveAnnotation
                          THEN BothAnnotations
                          ELSE RejectAnnotation
    /\ UNCHANGED <<planPhase, planHash, dbHash, operatorHoldsLock,
                    operatorComputing, lastError, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* Operator starts reconcile: acquires advisory lock.
OperatorAcquiresLock ==
    /\ operatorAlive
    /\ ~operatorHoldsLock
    /\ ~operatorComputing
    /\ operatorHoldsLock' = TRUE
    /\ operatorComputing' = TRUE
    /\ UNCHANGED <<planPhase, planHash, planAnnotation, dbHash,
                    lastError, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* Operator computes plan (no existing pending plan).
\* Creates a new plan with hash matching current database drift.
OperatorCreatesPlan ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase \in {NoPlan} \cup TerminalPhases
    /\ planPhase' = Pending
    /\ planHash' = dbHash           \* Plan reflects current drift
    /\ planAnnotation' = NoAnnotation
    /\ policyReady' = TRUE
    /\ lastError' = "none"
    /\ approvalWasChecked' = FALSE
    /\ appliedHash' = NoHash        \* Reset for new plan lifecycle
    /\ UNCHANGED <<dbHash, operatorHoldsLock, operatorComputing,
                    operatorAlive>>

\* Operator finds existing pending plan with same hash (dedup).
OperatorDedup ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase = Pending
    /\ planHash = dbHash            \* Hash matches — no new plan needed
    /\ UNCHANGED vars               \* No state change (dedup skip)

\* Operator finds existing pending plan with different hash (supersede).
OperatorSupersedesPlan ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase = Pending
    /\ planHash /= dbHash           \* Drift changed since plan was created
    /\ planPhase' = Pending         \* New plan replaces old one
    /\ planHash' = dbHash           \* New plan reflects current drift
    /\ planAnnotation' = NoAnnotation
    /\ approvalWasChecked' = FALSE
    /\ appliedHash' = NoHash        \* Reset for new plan lifecycle
    /\ UNCHANGED <<dbHash, operatorHoldsLock, operatorComputing,
                    lastError, policyReady, operatorAlive>>

\* Operator detects approved annotation and validates hash.
\* Only proceeds if hash matches current drift.
OperatorExecutesApprovedPlan ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase = Pending
    /\ planAnnotation \in {ApproveAnnotation}
    /\ planHash = dbHash            \* Hash validation passes
    /\ planPhase' = Applying
    /\ approvalWasChecked' = TRUE
    /\ UNCHANGED <<planHash, planAnnotation, dbHash, operatorHoldsLock,
                    operatorComputing, lastError, policyReady, operatorAlive,
                    appliedHash>>

\* Operator detects approved annotation but hash doesn't match.
\* Supersedes the plan and creates a new one.
OperatorSupersedeStalePlan ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase = Pending
    /\ planAnnotation \in {ApproveAnnotation}
    /\ planHash /= dbHash           \* Hash mismatch — DB changed since approval
    /\ planPhase' = Pending         \* New plan created
    /\ planHash' = dbHash
    /\ planAnnotation' = NoAnnotation
    /\ approvalWasChecked' = FALSE
    /\ appliedHash' = NoHash        \* Reset for new plan lifecycle
    /\ UNCHANGED <<dbHash, operatorHoldsLock, operatorComputing,
                    lastError, policyReady, operatorAlive>>

\* Operator detects rejection annotation (reject wins over approve).
OperatorRejectsPlan ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase = Pending
    /\ planAnnotation \in {RejectAnnotation, BothAnnotations}
    /\ planPhase' = Rejected
    /\ UNCHANGED <<planHash, planAnnotation, dbHash, operatorHoldsLock,
                    operatorComputing, lastError, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* Applying plan succeeds.
ApplySucceeds ==
    /\ operatorAlive
    /\ planPhase = Applying
    /\ planPhase' = Applied
    /\ appliedHash' = planHash
    /\ lastError' = "none"
    /\ UNCHANGED <<planHash, planAnnotation, dbHash, operatorHoldsLock,
                    operatorComputing, policyReady, operatorAlive,
                    approvalWasChecked>>

\* Applying plan fails.
ApplyFails ==
    /\ operatorAlive
    /\ planPhase = Applying
    /\ planPhase' = Failed
    /\ lastError' = "error"
    /\ UNCHANGED <<planHash, planAnnotation, dbHash, operatorHoldsLock,
                    operatorComputing, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* Operator releases lock (end of reconcile cycle).
OperatorReleasesLock ==
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ operatorHoldsLock' = FALSE
    /\ operatorComputing' = FALSE
    /\ UNCHANGED <<planPhase, planHash, planAnnotation, dbHash,
                    lastError, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* Operator crashes.
OperatorCrashes ==
    /\ operatorAlive
    /\ operatorAlive' = FALSE
    /\ operatorHoldsLock' = FALSE   \* Session-scoped lock released
    /\ operatorComputing' = FALSE
    /\ UNCHANGED <<planPhase, planHash, planAnnotation, dbHash,
                    lastError, policyReady, appliedHash, approvalWasChecked>>

\* Operator recovers after crash.
OperatorRecovers ==
    /\ ~operatorAlive
    /\ operatorAlive' = TRUE
    /\ UNCHANGED <<planPhase, planHash, planAnnotation, dbHash,
                    operatorHoldsLock, operatorComputing, lastError,
                    policyReady, appliedHash, approvalWasChecked>>

\* Operator detects stuck Applying plan after recovery and marks Failed.
OperatorRecoverStuckPlan ==
    /\ operatorAlive
    /\ planPhase = Applying
    /\ ~operatorComputing           \* Not mid-reconcile (recovery check happens at start)
    /\ planPhase' = Failed
    /\ lastError' = "error"
    /\ UNCHANGED <<planHash, planAnnotation, dbHash, operatorHoldsLock,
                    operatorComputing, policyReady, operatorAlive,
                    appliedHash, approvalWasChecked>>

\* --- Auto-approval shortcut (for mode: apply, approval: auto) ---

\* Operator creates and immediately executes in one cycle.
OperatorAutoApproveAndExecute ==
    /\ operatorAlive
    /\ operatorHoldsLock
    /\ operatorComputing
    /\ planPhase \in {NoPlan} \cup TerminalPhases
    /\ planPhase' = Applying
    /\ planHash' = dbHash
    /\ planAnnotation' = NoAnnotation
    /\ approvalWasChecked' = TRUE   \* Auto-approved counts as checked
    /\ UNCHANGED <<dbHash, operatorHoldsLock, operatorComputing,
                    lastError, policyReady, operatorAlive, appliedHash>>

\* --- Next-state relation ---

Next ==
    \/ DatabaseDrifts
    \/ UserApproves
    \/ UserRejects
    \/ OperatorAcquiresLock
    \/ OperatorCreatesPlan
    \/ OperatorDedup
    \/ OperatorSupersedesPlan
    \/ OperatorExecutesApprovedPlan
    \/ OperatorSupersedeStalePlan
    \/ OperatorRejectsPlan
    \/ ApplySucceeds
    \/ ApplyFails
    \/ OperatorReleasesLock
    \/ OperatorCrashes
    \/ OperatorRecovers
    \/ OperatorRecoverStuckPlan
    \/ OperatorAutoApproveAndExecute

\* --- Specification ---

Spec == Init /\ [][Next]_vars

====
