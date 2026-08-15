---- MODULE PlanRevalidation ----
EXTENDS FiniteSets, Naturals

(*
  Pending-plan revalidation for pgroles PostgresPolicyPlan.

  While a plan awaits a manual decision, the policy keeps reconciling. Two
  things must stay true across those reconciles, and they pull in opposite
  directions:

    1. What the policy *reports* and what the pending plan *holds* must
       describe the same effects. Otherwise a reviewer reads a fresh change
       summary, approves the plan beside it, and approves something else.

    2. An approval must survive a policy edit that turns out to be
       effect-neutral. Review is expensive; a comment change, a reordering, or
       any edit the diff engine collapses to nothing must not cost a round.

  `RevalidationMode` selects the strategy:

    - "semantic"     (PlanRevalidation.cfg) — revalidate by comparing effects.
                     Both properties hold.
    - "frozen"       (PlanRevalidation_frozen.cfg) — today's behaviour: the
                     Pending arm returns early without revalidating, refreshing
                     the summary while the plan stands. Violates property 1.
    - "generational" (PlanRevalidation_generational.cfg) — the plausible wrong
                     fix: supersede whenever the policy generation moves.
                     Property 1 holds, but property 2 fails — every
                     effect-neutral edit throws away a decision. This is why
                     `policyGeneration` is a revalidation *trigger* and the
                     change digest is the *identity*.

  What is NOT modeled: approval mechanics and execution (PlanApproval.tla),
  crashes and locking (PlanLifecycle.tla).
*)

CONSTANTS
    RevalidationMode,  \* "semantic" | "frozen" | "generational"
    MaxEdits           \* Bound on policy edits, so the state space is finite

NoPlan == "none"
Pending == "Pending"

\* Distinct semantic effect sets, standing in for change digests.
Effects == {"e1", "e2"}
NoEffects == "none"

VARIABLES
    planPhase,       \* Whether a plan is currently pending review
    planEffects,     \* Effects the pending plan holds
    planGen,         \* Policy generation the plan was last confirmed against
    summaryEffects,  \* Effects the policy's status reports to the reader
    approved,        \* A reviewer has decided on the current plan
    dbEffects,       \* Effects the policy would produce right now
    policyGen,       \* Current policy generation
    editsLeft,       \* Remaining policy edits
    lostApproval     \* Witness: an approval was discarded even though the
                     \* effects under review had not changed

vars == <<planPhase, planEffects, planGen, summaryEffects, approved,
          dbEffects, policyGen, editsLeft, lostApproval>>

TypeOK ==
    /\ planPhase \in {NoPlan, Pending}
    /\ planEffects \in Effects \cup {NoEffects}
    /\ planGen \in 0..MaxEdits
    /\ summaryEffects \in Effects \cup {NoEffects}
    /\ approved \in BOOLEAN
    /\ dbEffects \in Effects
    /\ policyGen \in 0..MaxEdits
    /\ editsLeft \in 0..MaxEdits
    /\ lostApproval \in BOOLEAN

\* --- Properties ---

\* Property 1. A reviewer reading the policy's summary and opening the plan it
\* points at must see the same change. The frozen strategy breaks this.
SummaryMatchesPlan ==
    (planPhase = Pending /\ summaryEffects /= NoEffects) =>
        summaryEffects = planEffects

\* Property 2. An effect-neutral policy edit must not discard a decision.
\* The generational strategy breaks this.
ApprovalSurvivesEffectNeutralEdits == ~lostApproval

Init ==
    /\ planPhase = NoPlan
    /\ planEffects = NoEffects
    /\ planGen = 0
    /\ summaryEffects = NoEffects
    /\ approved = FALSE
    /\ dbEffects = "e1"
    /\ policyGen = 0
    /\ editsLeft = MaxEdits
    /\ lostApproval = FALSE

\* --- Actions ---

OperatorCreatesPlan ==
    /\ planPhase = NoPlan
    /\ planPhase' = Pending
    /\ planEffects' = dbEffects
    /\ summaryEffects' = dbEffects
    /\ planGen' = policyGen
    /\ approved' = FALSE
    /\ UNCHANGED <<dbEffects, policyGen, editsLeft, lostApproval>>

\* A policy edit the diff engine collapses to nothing: the generation moves,
\* the effects do not. Comment changes, reordering, redundant declarations.
PolicyEditEffectNeutral ==
    /\ editsLeft > 0
    /\ policyGen' = policyGen + 1
    /\ editsLeft' = editsLeft - 1
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, approved,
                    dbEffects, lostApproval>>

\* A policy edit that genuinely changes what would be executed.
PolicyEditEffective ==
    /\ editsLeft > 0
    /\ \E e \in Effects:
        /\ e /= dbEffects
        /\ dbEffects' = e
    /\ policyGen' = policyGen + 1
    /\ editsLeft' = editsLeft - 1
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, approved,
                    lostApproval>>

UserApproves ==
    /\ planPhase = Pending
    /\ ~approved
    /\ approved' = TRUE
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, dbEffects,
                    policyGen, editsLeft, lostApproval>>

\* Replace the pending plan with one describing the current effects.
SupersedeAndReplace ==
    /\ planEffects' = dbEffects
    /\ summaryEffects' = dbEffects
    /\ planGen' = policyGen
    /\ approved' = FALSE
    \* Record the cost if a decision was discarded while the effects under
    \* review were in fact unchanged.
    /\ lostApproval' = (lostApproval \/ (approved /\ planEffects = dbEffects))
    /\ UNCHANGED <<planPhase, dbEffects, policyGen, editsLeft>>

\* Keep the plan and its decision; only the provenance advances.
RetainPlan ==
    /\ summaryEffects' = dbEffects
    /\ planGen' = policyGen
    /\ UNCHANGED <<planPhase, planEffects, approved, dbEffects, policyGen,
                    editsLeft, lostApproval>>

\* One reconcile while a plan is pending.
ReconcilePending ==
    /\ planPhase = Pending
    /\ \/ /\ RevalidationMode = "semantic"
          \* Compare effects. Identical effects retain the plan and its
          \* decision; changed effects supersede it.
          /\ \/ /\ planEffects = dbEffects
                /\ RetainPlan
             \/ /\ planEffects /= dbEffects
                /\ SupersedeAndReplace
       \/ /\ RevalidationMode = "frozen"
          \* Today: refresh the reported summary and return, leaving the plan
          \* untouched however far the effects have moved.
          /\ summaryEffects' = dbEffects
          /\ UNCHANGED <<planPhase, planEffects, planGen, approved, dbEffects,
                          policyGen, editsLeft, lostApproval>>
       \/ /\ RevalidationMode = "generational"
          \* Supersede whenever the generation moved, without asking whether
          \* the effects did.
          /\ \/ /\ planGen = policyGen
                /\ RetainPlan
             \/ /\ planGen /= policyGen
                /\ SupersedeAndReplace

Next ==
    \/ OperatorCreatesPlan
    \/ PolicyEditEffectNeutral
    \/ PolicyEditEffective
    \/ UserApproves
    \/ ReconcilePending

Spec == Init /\ [][Next]_vars

====
