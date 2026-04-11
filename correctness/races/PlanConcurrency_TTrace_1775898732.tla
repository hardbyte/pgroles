---- MODULE PlanConcurrency_TTrace_1775898732 ----
EXTENDS Sequences, TLCExt, Toolbox, PlanConcurrency, Naturals, TLC

_expression ==
    LET PlanConcurrency_TEExpression == INSTANCE PlanConcurrency_TEExpression
    IN PlanConcurrency_TEExpression!expression
----

_trace ==
    LET PlanConcurrency_TETrace == INSTANCE PlanConcurrency_TETrace
    IN PlanConcurrency_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        opHoldsAdvisoryLock = (TRUE)
        /\
        dbHash = ("h1")
        /\
        opHoldsProcessLock = (TRUE)
        /\
        opCurrentPlan = ("p2")
        /\
        planPhase = ([p1 |-> "Applying", p2 |-> "Applying"])
        /\
        planHash = ([p1 |-> "h1", p2 |-> "h1"])
        /\
        planExists = ([p1 |-> TRUE, p2 |-> TRUE])
        /\
        opComputedHash = ("h1")
        /\
        policyCurrentPlanRef = ("p2")
        /\
        opAlive = (TRUE)
        /\
        opStep = ("sql_done")
        /\
        policyLastError = ("none")
        /\
        planAnnotation = ([p1 |-> "approve", p2 |-> "approve"])
        /\
        opSeenAnnotation = ("approve")
    )
----

_init ==
    /\ opSeenAnnotation = _TETrace[1].opSeenAnnotation
    /\ planHash = _TETrace[1].planHash
    /\ planAnnotation = _TETrace[1].planAnnotation
    /\ policyLastError = _TETrace[1].policyLastError
    /\ dbHash = _TETrace[1].dbHash
    /\ opHoldsAdvisoryLock = _TETrace[1].opHoldsAdvisoryLock
    /\ policyCurrentPlanRef = _TETrace[1].policyCurrentPlanRef
    /\ opStep = _TETrace[1].opStep
    /\ planExists = _TETrace[1].planExists
    /\ opComputedHash = _TETrace[1].opComputedHash
    /\ opHoldsProcessLock = _TETrace[1].opHoldsProcessLock
    /\ planPhase = _TETrace[1].planPhase
    /\ opAlive = _TETrace[1].opAlive
    /\ opCurrentPlan = _TETrace[1].opCurrentPlan
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ opSeenAnnotation  = _TETrace[i].opSeenAnnotation
        /\ opSeenAnnotation' = _TETrace[j].opSeenAnnotation
        /\ planHash  = _TETrace[i].planHash
        /\ planHash' = _TETrace[j].planHash
        /\ planAnnotation  = _TETrace[i].planAnnotation
        /\ planAnnotation' = _TETrace[j].planAnnotation
        /\ policyLastError  = _TETrace[i].policyLastError
        /\ policyLastError' = _TETrace[j].policyLastError
        /\ dbHash  = _TETrace[i].dbHash
        /\ dbHash' = _TETrace[j].dbHash
        /\ opHoldsAdvisoryLock  = _TETrace[i].opHoldsAdvisoryLock
        /\ opHoldsAdvisoryLock' = _TETrace[j].opHoldsAdvisoryLock
        /\ policyCurrentPlanRef  = _TETrace[i].policyCurrentPlanRef
        /\ policyCurrentPlanRef' = _TETrace[j].policyCurrentPlanRef
        /\ opStep  = _TETrace[i].opStep
        /\ opStep' = _TETrace[j].opStep
        /\ planExists  = _TETrace[i].planExists
        /\ planExists' = _TETrace[j].planExists
        /\ opComputedHash  = _TETrace[i].opComputedHash
        /\ opComputedHash' = _TETrace[j].opComputedHash
        /\ opHoldsProcessLock  = _TETrace[i].opHoldsProcessLock
        /\ opHoldsProcessLock' = _TETrace[j].opHoldsProcessLock
        /\ planPhase  = _TETrace[i].planPhase
        /\ planPhase' = _TETrace[j].planPhase
        /\ opAlive  = _TETrace[i].opAlive
        /\ opAlive' = _TETrace[j].opAlive
        /\ opCurrentPlan  = _TETrace[i].opCurrentPlan
        /\ opCurrentPlan' = _TETrace[j].opCurrentPlan

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("PlanConcurrency_TTrace_1775898732.json", _TETrace)

=============================================================================

 Note that you can extract this module `PlanConcurrency_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `PlanConcurrency_TEExpression.tla` file takes precedence 
  over the module `PlanConcurrency_TEExpression` below).

---- MODULE PlanConcurrency_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, PlanConcurrency, Naturals, TLC

expression == 
    [
        \* To hide variables of the `PlanConcurrency` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        opSeenAnnotation |-> opSeenAnnotation
        ,planHash |-> planHash
        ,planAnnotation |-> planAnnotation
        ,policyLastError |-> policyLastError
        ,dbHash |-> dbHash
        ,opHoldsAdvisoryLock |-> opHoldsAdvisoryLock
        ,policyCurrentPlanRef |-> policyCurrentPlanRef
        ,opStep |-> opStep
        ,planExists |-> planExists
        ,opComputedHash |-> opComputedHash
        ,opHoldsProcessLock |-> opHoldsProcessLock
        ,planPhase |-> planPhase
        ,opAlive |-> opAlive
        ,opCurrentPlan |-> opCurrentPlan
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_opSeenAnnotationUnchanged |-> opSeenAnnotation = opSeenAnnotation'
        
        \* Format the `opSeenAnnotation` variable as Json value.
        \* ,_opSeenAnnotationJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(opSeenAnnotation)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_opSeenAnnotationModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].opSeenAnnotation # _TETrace[s-1].opSeenAnnotation
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE PlanConcurrency_TETrace ----
\*EXTENDS IOUtils, PlanConcurrency, TLC
\*
\*trace == IODeserialize("PlanConcurrency_TTrace_1775898732.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE PlanConcurrency_TETrace ----
EXTENDS PlanConcurrency, TLC

trace == 
    <<
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> FALSE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "none", p2 |-> "none"],planHash |-> [p1 |-> "none", p2 |-> "none"],planExists |-> [p1 |-> FALSE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "none",opAlive |-> TRUE,opStep |-> "idle",policyLastError |-> "none",planAnnotation |-> [p1 |-> "none", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "none", p2 |-> "none"],planHash |-> [p1 |-> "none", p2 |-> "none"],planExists |-> [p1 |-> FALSE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "none",opAlive |-> TRUE,opStep |-> "acquired_lock",policyLastError |-> "none",planAnnotation |-> [p1 |-> "none", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "none", p2 |-> "none"],planHash |-> [p1 |-> "none", p2 |-> "none"],planExists |-> [p1 |-> FALSE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "none",opAlive |-> TRUE,opStep |-> "inspected_db",policyLastError |-> "none",planAnnotation |-> [p1 |-> "none", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "none", p2 |-> "none"],planHash |-> [p1 |-> "none", p2 |-> "none"],planExists |-> [p1 |-> FALSE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "none",opAlive |-> TRUE,opStep |-> "listed_plans",policyLastError |-> "none",planAnnotation |-> [p1 |-> "none", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "updating_policy_status",policyLastError |-> "none",planAnnotation |-> [p1 |-> "none", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "updating_policy_status",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> FALSE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "idle",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "acquired_lock",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "inspected_db",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "listed_plans",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "checking_approval",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "validating_hash",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Pending", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "marking_approved",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Approved", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "executing_sql",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p1",planPhase |-> [p1 |-> "Applying", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "sql_done",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> FALSE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p1",opAlive |-> FALSE,opStep |-> "idle",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> FALSE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "idle",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "acquired_lock",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "inspected_db",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "none"],planHash |-> [p1 |-> "h1", p2 |-> "none"],planExists |-> [p1 |-> TRUE, p2 |-> FALSE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p1",opAlive |-> TRUE,opStep |-> "listed_plans",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "updating_policy_status",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "none"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "updating_policy_status",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> FALSE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "idle",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> FALSE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "none",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "acquired_lock",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "none",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "inspected_db",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "none"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "listed_plans",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "checking_approval",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "validating_hash",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Pending"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "marking_approved",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Approved"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "executing_sql",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "approve"]),
    ([opHoldsAdvisoryLock |-> TRUE,dbHash |-> "h1",opHoldsProcessLock |-> TRUE,opCurrentPlan |-> "p2",planPhase |-> [p1 |-> "Applying", p2 |-> "Applying"],planHash |-> [p1 |-> "h1", p2 |-> "h1"],planExists |-> [p1 |-> TRUE, p2 |-> TRUE],opComputedHash |-> "h1",policyCurrentPlanRef |-> "p2",opAlive |-> TRUE,opStep |-> "sql_done",policyLastError |-> "none",planAnnotation |-> [p1 |-> "approve", p2 |-> "approve"],opSeenAnnotation |-> "approve"])
    >>
----


=============================================================================

---- CONFIG PlanConcurrency_TTrace_1775898732 ----

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
\* Generated on Sat Apr 11 09:12:13 UTC 2026