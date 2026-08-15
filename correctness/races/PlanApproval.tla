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
    MaxDrifts            \* Bound on external database drift, so the system
                         \* eventually quiesces and liveness is meaningful

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
    appliedInSync     \* Whether, *at the moment of execution*, the executed
                      \* effects still matched the live database. Recorded as a
                      \* witness because the database may legitimately drift
                      \* again afterwards — a plain state invariant comparing
                      \* appliedEffects to dbEffects would fire on that normal
                      \* post-apply drift instead of on a stale execution.

vars == <<planPhase, planEffects, planRenderStale, approved, dbEffects,
          driftsLeft, appliedEffects, appliedInSync>>

TypeOK ==
    /\ planPhase \in {NoPlan, Pending, Applying, Applied}
    /\ planEffects \in Effects \cup {NoEffects}
    /\ planRenderStale \in BOOLEAN
    /\ approved \in BOOLEAN
    /\ dbEffects \in Effects
    /\ driftsLeft \in 0..MaxDrifts
    /\ appliedEffects \in Effects \cup {NoEffects}
    /\ appliedInSync \in BOOLEAN

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
                    appliedEffects, appliedInSync>>

\* The operator computes a plan for the current effects.
OperatorCreatesPlan ==
    /\ planPhase = NoPlan
    /\ planPhase' = Pending
    /\ planEffects' = dbEffects
    /\ planRenderStale' = FALSE   \* Freshly rendered and stored together
    /\ approved' = FALSE
    /\ UNCHANGED <<dbEffects, driftsLeft, appliedEffects, appliedInSync>>

\* A reviewer approves the pending plan.
UserApproves ==
    /\ planPhase = Pending
    /\ ~approved
    /\ approved' = TRUE
    /\ UNCHANGED <<planPhase, planEffects, planRenderStale, dbEffects,
                    driftsLeft, appliedEffects, appliedInSync>>

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
                    appliedEffects, appliedInSync>>

\* The gate passes: execute the reviewed effects.
OperatorExecutes ==
    /\ planPhase = Pending
    /\ approved
    /\ (HasPasswordChange => planRenderStale)  \* Revalidation has happened
    /\ GatePasses
    /\ planPhase' = Applying
    /\ UNCHANGED <<planEffects, planRenderStale, approved, dbEffects,
                    driftsLeft, appliedEffects, appliedInSync>>

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
    /\ UNCHANGED <<dbEffects, driftsLeft, appliedEffects, appliedInSync>>

ApplySucceeds ==
    /\ planPhase = Applying
    /\ planPhase' = Applied
    /\ appliedEffects' = planEffects
    \* The witness: did the database still hold the verified state when the
    \* statements ran? Under a single lock hold it must have.
    /\ appliedInSync' = (planEffects = dbEffects)
    /\ UNCHANGED <<planEffects, planRenderStale, approved, dbEffects,
                    driftsLeft>>

Next ==
    \/ DatabaseDrifts
    \/ OperatorCreatesPlan
    \/ UserApproves
    \/ OperatorRevalidates
    \/ OperatorExecutes
    \/ OperatorSupersedes
    \/ ApplySucceeds

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

Spec == Init /\ [][Next]_vars /\ Fairness

====
