---- MODULE PlanRevalidation_TTrace_1786830535 ----
EXTENDS PlanRevalidation, Sequences, TLCExt, Toolbox, Naturals, TLC

_expression ==
    LET PlanRevalidation_TEExpression == INSTANCE PlanRevalidation_TEExpression
    IN PlanRevalidation_TEExpression!expression
----

_trace ==
    LET PlanRevalidation_TETrace == INSTANCE PlanRevalidation_TETrace
    IN PlanRevalidation_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        policyGen = (1)
        /\
        approved = (FALSE)
        /\
        dbEffects = ("none")
        /\
        summaryEffects = ("none")
        /\
        planGen = (1)
        /\
        driftsLeft = (0)
        /\
        planEffects = ("none")
        /\
        planPhase = ("Pending")
        /\
        lostApproval = (FALSE)
        /\
        editsLeft = (1)
    )
----

_init ==
    /\ summaryEffects = _TETrace[1].summaryEffects
    /\ policyGen = _TETrace[1].policyGen
    /\ planEffects = _TETrace[1].planEffects
    /\ approved = _TETrace[1].approved
    /\ editsLeft = _TETrace[1].editsLeft
    /\ planGen = _TETrace[1].planGen
    /\ driftsLeft = _TETrace[1].driftsLeft
    /\ planPhase = _TETrace[1].planPhase
    /\ dbEffects = _TETrace[1].dbEffects
    /\ lostApproval = _TETrace[1].lostApproval
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ summaryEffects  = _TETrace[i].summaryEffects
        /\ summaryEffects' = _TETrace[j].summaryEffects
        /\ policyGen  = _TETrace[i].policyGen
        /\ policyGen' = _TETrace[j].policyGen
        /\ planEffects  = _TETrace[i].planEffects
        /\ planEffects' = _TETrace[j].planEffects
        /\ approved  = _TETrace[i].approved
        /\ approved' = _TETrace[j].approved
        /\ editsLeft  = _TETrace[i].editsLeft
        /\ editsLeft' = _TETrace[j].editsLeft
        /\ planGen  = _TETrace[i].planGen
        /\ planGen' = _TETrace[j].planGen
        /\ driftsLeft  = _TETrace[i].driftsLeft
        /\ driftsLeft' = _TETrace[j].driftsLeft
        /\ planPhase  = _TETrace[i].planPhase
        /\ planPhase' = _TETrace[j].planPhase
        /\ dbEffects  = _TETrace[i].dbEffects
        /\ dbEffects' = _TETrace[j].dbEffects
        /\ lostApproval  = _TETrace[i].lostApproval
        /\ lostApproval' = _TETrace[j].lostApproval

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("PlanRevalidation_TTrace_1786830535.json", _TETrace)

=============================================================================

 Note that you can extract this module `PlanRevalidation_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `PlanRevalidation_TEExpression.tla` file takes precedence 
  over the module `PlanRevalidation_TEExpression` below).

---- MODULE PlanRevalidation_TEExpression ----
EXTENDS PlanRevalidation, Sequences, TLCExt, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `PlanRevalidation` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        summaryEffects |-> summaryEffects
        ,policyGen |-> policyGen
        ,planEffects |-> planEffects
        ,approved |-> approved
        ,editsLeft |-> editsLeft
        ,planGen |-> planGen
        ,driftsLeft |-> driftsLeft
        ,planPhase |-> planPhase
        ,dbEffects |-> dbEffects
        ,lostApproval |-> lostApproval
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_summaryEffectsUnchanged |-> summaryEffects = summaryEffects'
        
        \* Format the `summaryEffects` variable as Json value.
        \* ,_summaryEffectsJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(summaryEffects)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_summaryEffectsModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].summaryEffects # _TETrace[s-1].summaryEffects
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE PlanRevalidation_TETrace ----
\*EXTENDS PlanRevalidation, IOUtils, TLC
\*
\*trace == IODeserialize("PlanRevalidation_TTrace_1786830535.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE PlanRevalidation_TETrace ----
EXTENDS PlanRevalidation, TLC

trace == 
    <<
    ([policyGen |-> 0,approved |-> FALSE,dbEffects |-> "e1",summaryEffects |-> "none",planGen |-> 0,driftsLeft |-> 0,planEffects |-> "none",planPhase |-> "none",lostApproval |-> FALSE,editsLeft |-> 2]),
    ([policyGen |-> 0,approved |-> FALSE,dbEffects |-> "e1",summaryEffects |-> "e1",planGen |-> 0,driftsLeft |-> 0,planEffects |-> "e1",planPhase |-> "Pending",lostApproval |-> FALSE,editsLeft |-> 2]),
    ([policyGen |-> 1,approved |-> FALSE,dbEffects |-> "none",summaryEffects |-> "e1",planGen |-> 0,driftsLeft |-> 0,planEffects |-> "e1",planPhase |-> "Pending",lostApproval |-> FALSE,editsLeft |-> 1]),
    ([policyGen |-> 1,approved |-> FALSE,dbEffects |-> "none",summaryEffects |-> "none",planGen |-> 1,driftsLeft |-> 0,planEffects |-> "none",planPhase |-> "Pending",lostApproval |-> FALSE,editsLeft |-> 1])
    >>
----


=============================================================================

---- CONFIG PlanRevalidation_TTrace_1786830535 ----
CONSTANTS
    RevalidationMode = "replace"
    MaxDrifts = 0
    MaxEdits = 2

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Sat Aug 15 21:48:55 UTC 2026