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
    - "replace"      (PlanRevalidation_replace.cfg) — compares effects, but
                     always leaves a replacement plan behind. When the effects
                     did not move but *vanished*, the replacement holds nothing
                     and still blocks on a decision. Violates property 3.

  Database drift — the effects moving with no policy edit behind them — is a
  first-class action here. It is what separates the two strategies that both
  keep the summary and the plan paired under policy edits alone: "semantic"
  compares effects and still holds, while "generational" has nothing to trigger
  on and reports a summary the plan does not match. See
  PlanRevalidation_drift.cfg.

  What is NOT modeled: approval mechanics and execution (PlanApproval.tla),
  crashes and locking (PlanLifecycle.tla).
*)

CONSTANTS
    RevalidationMode,  \* "semantic" | "frozen" | "generational" | "replace"
    MaxEdits,          \* Bound on policy edits, so the state space is finite
    MaxDrifts          \* Bound on database drift, likewise

NoPlan == "none"
Pending == "Pending"

\* Distinct semantic effect sets, standing in for change digests. `NoEffects`
\* is a first-class value here: a policy edit can remove the drift entirely,
\* and what happens to a pending plan at that moment is property 3 below.
Effects == {"e1", "e2"}
NoEffects == "none"
MaybeEffects == Effects \cup {NoEffects}

VARIABLES
    planPhase,       \* Whether a plan is currently pending review
    planEffects,     \* Effects the pending plan holds
    planGen,         \* Policy generation the plan was last confirmed against
    summaryEffects,  \* Effects the policy's status reports to the reader
    approved,        \* A reviewer has decided on the current plan
    dbEffects,       \* Effects the policy would produce right now
    policyGen,       \* Current policy generation
    editsLeft,       \* Remaining policy edits
    driftsLeft,      \* Remaining database drifts
    lostApproval     \* Witness: an approval was discarded even though the
                     \* effects under review had not changed

vars == <<planPhase, planEffects, planGen, summaryEffects, approved,
          dbEffects, policyGen, editsLeft, driftsLeft, lostApproval>>

TypeOK ==
    /\ planPhase \in {NoPlan, Pending}
    /\ planEffects \in MaybeEffects
    /\ planGen \in 0..MaxEdits
    /\ summaryEffects \in MaybeEffects
    /\ approved \in BOOLEAN
    /\ dbEffects \in MaybeEffects
    /\ policyGen \in 0..MaxEdits
    /\ editsLeft \in 0..MaxEdits
    /\ driftsLeft \in 0..MaxDrifts
    /\ lostApproval \in BOOLEAN

\* --- Properties ---

\* Property 1. A reviewer reading the policy's summary and opening the plan it
\* points at must see the same change. The frozen strategy breaks this.
\*
\* Stated with no guard on summaryEffects. An earlier form exempted
\* summaryEffects = NoEffects, which excused exactly the worst reading: the
\* policy reporting no drift while a plan holding real changes waits beside it.
\* A strategy that clears the summary but keeps the plan pending passed the
\* whole suite under the guarded form.
SummaryMatchesPlan ==
    (planPhase = Pending) => summaryEffects = planEffects

\* Property 2. An effect-neutral policy edit must not discard a decision.
\* The generational strategy breaks this.
ApprovalSurvivesEffectNeutralEdits == ~lostApproval

\* Property 3. Nothing to execute means nothing to approve. A pending plan
\* holding no effects parks the policy on a decision that buys nothing, while
\* the policy reports no drift beside it. The "replace" strategy breaks this.
NoEmptyPendingPlan ==
    (planPhase = Pending) => planEffects /= NoEffects

Init ==
    /\ planPhase = NoPlan
    /\ planEffects = NoEffects
    /\ planGen = 0
    /\ summaryEffects = NoEffects
    /\ approved = FALSE
    /\ dbEffects = "e1"
    /\ policyGen = 0
    /\ editsLeft = MaxEdits
    /\ driftsLeft = MaxDrifts
    /\ lostApproval = FALSE

\* --- Actions ---

\* The operator opens a plan only when there is something to execute; with no
\* changes it reports InSync and creates nothing.
OperatorCreatesPlan ==
    /\ planPhase = NoPlan
    /\ dbEffects /= NoEffects
    /\ planPhase' = Pending
    /\ planEffects' = dbEffects
    /\ summaryEffects' = dbEffects
    /\ planGen' = policyGen
    /\ approved' = FALSE
    /\ UNCHANGED <<dbEffects, policyGen, editsLeft, driftsLeft, lostApproval>>

\* A policy edit the diff engine collapses to nothing: the generation moves,
\* the effects do not. Comment changes, reordering, redundant declarations.
PolicyEditEffectNeutral ==
    /\ editsLeft > 0
    /\ policyGen' = policyGen + 1
    /\ editsLeft' = editsLeft - 1
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, approved,
                    dbEffects, driftsLeft, lostApproval>>

\* A policy edit that genuinely changes what would be executed — including one
\* that removes the drift altogether, leaving nothing to do.
PolicyEditEffective ==
    /\ editsLeft > 0
    /\ \E e \in MaybeEffects:
        /\ e /= dbEffects
        /\ dbEffects' = e
    /\ policyGen' = policyGen + 1
    /\ editsLeft' = editsLeft - 1
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, approved,
                    driftsLeft, lostApproval>>

\* The database moves underneath a pending plan with no policy edit behind it:
\* someone runs the DDL by hand, another tool converges part of it, or a role is
\* dropped out of band. `policyGen` does not move, which is the whole point — a
\* strategy keyed on the generation cannot see this happen, and will keep
\* reporting a summary computed from the new database beside a plan holding the
\* old effects.
DatabaseDrift ==
    /\ driftsLeft > 0
    /\ \E e \in MaybeEffects:
        /\ e /= dbEffects
        /\ dbEffects' = e
    /\ driftsLeft' = driftsLeft - 1
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, approved,
                    policyGen, editsLeft, lostApproval>>

UserApproves ==
    /\ planPhase = Pending
    /\ ~approved
    /\ approved' = TRUE
    /\ UNCHANGED <<planPhase, planEffects, planGen, summaryEffects, dbEffects,
                    policyGen, editsLeft, driftsLeft, lostApproval>>

\* Replace the pending plan with one describing the current effects.
SupersedeAndReplace ==
    /\ planEffects' = dbEffects
    /\ summaryEffects' = dbEffects
    /\ planGen' = policyGen
    /\ approved' = FALSE
    \* Record the cost if a decision was discarded while the effects under
    \* review were in fact unchanged.
    /\ lostApproval' = (lostApproval \/ (approved /\ planEffects = dbEffects))
    /\ UNCHANGED <<planPhase, dbEffects, policyGen, editsLeft, driftsLeft>>

\* Drop the pending plan without opening another: there is nothing left to
\* execute, so there is nothing to review.
ClearPlan ==
    /\ planPhase' = NoPlan
    /\ planEffects' = NoEffects
    /\ summaryEffects' = NoEffects
    /\ planGen' = policyGen
    /\ approved' = FALSE
    /\ UNCHANGED <<dbEffects, policyGen, editsLeft, driftsLeft, lostApproval>>

\* Keep the plan and its decision; only the provenance advances.
RetainPlan ==
    /\ summaryEffects' = dbEffects
    /\ planGen' = policyGen
    /\ UNCHANGED <<planPhase, planEffects, approved, dbEffects, policyGen,
                    editsLeft, driftsLeft, lostApproval>>

\* One reconcile while a plan is pending.
ReconcilePending ==
    /\ planPhase = Pending
    /\ \/ /\ RevalidationMode = "semantic"
          \* Compare effects. Identical effects retain the plan and its
          \* decision; changed effects supersede it; vanished effects clear it.
          /\ \/ /\ dbEffects = NoEffects
                /\ ClearPlan
             \/ /\ dbEffects /= NoEffects
                /\ \/ /\ planEffects = dbEffects
                      /\ RetainPlan
                   \/ /\ planEffects /= dbEffects
                      /\ SupersedeAndReplace
       \/ /\ RevalidationMode = "replace"
          \* Compare effects, but always leave a replacement behind, however
          \* little it holds. The defect property 3 exists to catch.
          /\ \/ /\ planEffects = dbEffects
                /\ RetainPlan
             \/ /\ planEffects /= dbEffects
                /\ SupersedeAndReplace
       \/ /\ RevalidationMode = "frozen"
          \* Today: refresh the reported summary and return, leaving the plan
          \* untouched however far the effects have moved.
          /\ summaryEffects' = dbEffects
          /\ UNCHANGED <<planPhase, planEffects, planGen, approved, dbEffects,
                          policyGen, editsLeft, driftsLeft, lostApproval>>
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
    \/ DatabaseDrift
    \/ UserApproves
    \/ ReconcilePending

Spec == Init /\ [][Next]_vars

====
