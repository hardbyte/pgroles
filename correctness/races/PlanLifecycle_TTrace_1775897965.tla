---- MODULE PlanLifecycle_TTrace_1775897965 ----
EXTENDS Sequences, TLCExt, PlanLifecycle, Toolbox, Naturals, TLC

_expression ==
    LET PlanLifecycle_TEExpression == INSTANCE PlanLifecycle_TEExpression
    IN PlanLifecycle_TEExpression!expression
----

_trace ==
    LET PlanLifecycle_TETrace == INSTANCE PlanLifecycle_TETrace
    IN PlanLifecycle_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        lastError = ("none")
        /\
        operatorHoldsLock = (TRUE)
        /\
        dbHash = ("h2")
        /\
        operatorComputing = (TRUE)
        /\
        policyReady = (FALSE)
        /\
        appliedHash = ("h1")
        /\
        operatorAlive = (TRUE)
        /\
        planPhase = ("Applied")
        /\
        approvalWasChecked = (TRUE)
        /\
        planHash = ("h1")
        /\
        planAnnotation = ("none")
    )
----

_init ==
    /\ planHash = _TETrace[1].planHash
    /\ planAnnotation = _TETrace[1].planAnnotation
    /\ operatorHoldsLock = _TETrace[1].operatorHoldsLock
    /\ dbHash = _TETrace[1].dbHash
    /\ appliedHash = _TETrace[1].appliedHash
    /\ lastError = _TETrace[1].lastError
    /\ operatorAlive = _TETrace[1].operatorAlive
    /\ operatorComputing = _TETrace[1].operatorComputing
    /\ policyReady = _TETrace[1].policyReady
    /\ planPhase = _TETrace[1].planPhase
    /\ approvalWasChecked = _TETrace[1].approvalWasChecked
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ planHash  = _TETrace[i].planHash
        /\ planHash' = _TETrace[j].planHash
        /\ planAnnotation  = _TETrace[i].planAnnotation
        /\ planAnnotation' = _TETrace[j].planAnnotation
        /\ operatorHoldsLock  = _TETrace[i].operatorHoldsLock
        /\ operatorHoldsLock' = _TETrace[j].operatorHoldsLock
        /\ dbHash  = _TETrace[i].dbHash
        /\ dbHash' = _TETrace[j].dbHash
        /\ appliedHash  = _TETrace[i].appliedHash
        /\ appliedHash' = _TETrace[j].appliedHash
        /\ lastError  = _TETrace[i].lastError
        /\ lastError' = _TETrace[j].lastError
        /\ operatorAlive  = _TETrace[i].operatorAlive
        /\ operatorAlive' = _TETrace[j].operatorAlive
        /\ operatorComputing  = _TETrace[i].operatorComputing
        /\ operatorComputing' = _TETrace[j].operatorComputing
        /\ policyReady  = _TETrace[i].policyReady
        /\ policyReady' = _TETrace[j].policyReady
        /\ planPhase  = _TETrace[i].planPhase
        /\ planPhase' = _TETrace[j].planPhase
        /\ approvalWasChecked  = _TETrace[i].approvalWasChecked
        /\ approvalWasChecked' = _TETrace[j].approvalWasChecked

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("PlanLifecycle_TTrace_1775897965.json", _TETrace)

=============================================================================

 Note that you can extract this module `PlanLifecycle_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `PlanLifecycle_TEExpression.tla` file takes precedence 
  over the module `PlanLifecycle_TEExpression` below).

---- MODULE PlanLifecycle_TEExpression ----
EXTENDS Sequences, TLCExt, PlanLifecycle, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `PlanLifecycle` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        planHash |-> planHash
        ,planAnnotation |-> planAnnotation
        ,operatorHoldsLock |-> operatorHoldsLock
        ,dbHash |-> dbHash
        ,appliedHash |-> appliedHash
        ,lastError |-> lastError
        ,operatorAlive |-> operatorAlive
        ,operatorComputing |-> operatorComputing
        ,policyReady |-> policyReady
        ,planPhase |-> planPhase
        ,approvalWasChecked |-> approvalWasChecked
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_planHashUnchanged |-> planHash = planHash'
        
        \* Format the `planHash` variable as Json value.
        \* ,_planHashJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(planHash)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_planHashModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].planHash # _TETrace[s-1].planHash
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE PlanLifecycle_TETrace ----
\*EXTENDS IOUtils, PlanLifecycle, TLC
\*
\*trace == IODeserialize("PlanLifecycle_TTrace_1775897965.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE PlanLifecycle_TETrace ----
EXTENDS PlanLifecycle, TLC

trace == 
    <<
    ([lastError |-> "none",operatorHoldsLock |-> FALSE,dbHash |-> "h1",operatorComputing |-> FALSE,policyReady |-> FALSE,appliedHash |-> "none",operatorAlive |-> TRUE,planPhase |-> "none",approvalWasChecked |-> FALSE,planHash |-> "none",planAnnotation |-> "none"]),
    ([lastError |-> "none",operatorHoldsLock |-> TRUE,dbHash |-> "h1",operatorComputing |-> TRUE,policyReady |-> FALSE,appliedHash |-> "none",operatorAlive |-> TRUE,planPhase |-> "none",approvalWasChecked |-> FALSE,planHash |-> "none",planAnnotation |-> "none"]),
    ([lastError |-> "none",operatorHoldsLock |-> TRUE,dbHash |-> "h1",operatorComputing |-> TRUE,policyReady |-> FALSE,appliedHash |-> "none",operatorAlive |-> TRUE,planPhase |-> "Applying",approvalWasChecked |-> TRUE,planHash |-> "h1",planAnnotation |-> "none"]),
    ([lastError |-> "none",operatorHoldsLock |-> TRUE,dbHash |-> "h2",operatorComputing |-> TRUE,policyReady |-> FALSE,appliedHash |-> "none",operatorAlive |-> TRUE,planPhase |-> "Applying",approvalWasChecked |-> TRUE,planHash |-> "h1",planAnnotation |-> "none"]),
    ([lastError |-> "none",operatorHoldsLock |-> TRUE,dbHash |-> "h2",operatorComputing |-> TRUE,policyReady |-> FALSE,appliedHash |-> "h1",operatorAlive |-> TRUE,planPhase |-> "Applied",approvalWasChecked |-> TRUE,planHash |-> "h1",planAnnotation |-> "none"])
    >>
----


=============================================================================

---- CONFIG PlanLifecycle_TTrace_1775897965 ----

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
\* Generated on Sat Apr 11 08:59:25 UTC 2026