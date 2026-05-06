---- MODULE PlanStorage ----
EXTENDS Naturals

(*
  Model for the Kubernetes persistence ordering around PostgresPolicyPlan SQL
  previews. The operator must persist the SQL review artifact before making a
  plan visible, and cleanup must eventually collect stale status-less plans and
  orphan SQL artifacts.
*)

NoPlan == "none"
Statusless == "statusless"
Pending == "pending"
Terminal == "terminal"

NoStorage == "none"
StorageReady == "ready"
StorageFailed == "failed"

VARIABLES
    planState,
    storageState,
    artifactExists,
    statuslessAge,
    orphanArtifactAge,
    actionableCount

vars == <<planState, storageState, artifactExists, statuslessAge,
          orphanArtifactAge, actionableCount>>

TypeOK ==
    /\ planState \in {NoPlan, Statusless, Pending, Terminal}
    /\ storageState \in {NoStorage, StorageReady, StorageFailed}
    /\ artifactExists \in BOOLEAN
    /\ statuslessAge \in 0..2
    /\ orphanArtifactAge \in 0..2
    /\ actionableCount \in 0..1

NoVisiblePlanBeforeStorage ==
    planState /= NoPlan => storageState = StorageReady

AtMostOneActionable ==
    actionableCount <= 1

Init ==
    /\ planState = NoPlan
    /\ storageState = NoStorage
    /\ artifactExists = FALSE
    /\ statuslessAge = 0
    /\ orphanArtifactAge = 0
    /\ actionableCount = 0

PersistInlineSql ==
    /\ planState = NoPlan
    /\ storageState = NoStorage
    /\ storageState' = StorageReady
    /\ artifactExists' = FALSE
    /\ orphanArtifactAge' = 0
    /\ UNCHANGED <<planState, statuslessAge, actionableCount>>

PersistConfigMapSql ==
    /\ planState = NoPlan
    /\ storageState = NoStorage
    /\ storageState' = StorageReady
    /\ artifactExists' = TRUE
    /\ orphanArtifactAge' = 0
    /\ UNCHANGED <<planState, statuslessAge, actionableCount>>

PersistSqlFails ==
    /\ planState = NoPlan
    /\ storageState = NoStorage
    /\ storageState' = StorageFailed
    /\ artifactExists' = FALSE
    /\ orphanArtifactAge' = 0
    /\ UNCHANGED <<planState, statuslessAge, actionableCount>>

CreatePlanAfterStorage ==
    /\ planState = NoPlan
    /\ storageState = StorageReady
    /\ planState' = Statusless
    /\ statuslessAge' = 0
    /\ UNCHANGED <<storageState, artifactExists, orphanArtifactAge, actionableCount>>

StatusWriteSucceeds ==
    /\ planState = Statusless
    /\ planState' = Pending
    /\ actionableCount' = 1
    /\ statuslessAge' = 0
    /\ UNCHANGED <<storageState, artifactExists, orphanArtifactAge>>

StatusWriteFails ==
    /\ planState = Statusless
    /\ statuslessAge' = IF statuslessAge < 2 THEN statuslessAge + 1 ELSE 2
    /\ UNCHANGED <<planState, storageState, artifactExists, orphanArtifactAge,
                  actionableCount>>

TerminalizePlan ==
    /\ planState = Pending
    /\ planState' = Terminal
    /\ actionableCount' = 0
    /\ UNCHANGED <<storageState, artifactExists, statuslessAge, orphanArtifactAge>>

DeleteTerminalPlan ==
    /\ planState = Terminal
    /\ planState' = NoPlan
    /\ storageState' = NoStorage
    /\ artifactExists' = FALSE
    /\ statuslessAge' = 0
    /\ orphanArtifactAge' = 0
    /\ UNCHANGED actionableCount

AgeStatuslessPlan ==
    /\ planState = Statusless
    /\ statuslessAge' = IF statuslessAge < 2 THEN statuslessAge + 1 ELSE 2
    /\ UNCHANGED <<planState, storageState, artifactExists, orphanArtifactAge,
                  actionableCount>>

CleanupStaleStatuslessPlan ==
    /\ planState = Statusless
    /\ statuslessAge = 2
    /\ planState' = NoPlan
    /\ storageState' = NoStorage
    /\ artifactExists' = FALSE
    /\ statuslessAge' = 0
    /\ orphanArtifactAge' = 0
    /\ actionableCount' = 0

AgeOrphanArtifact ==
    /\ planState = NoPlan
    /\ artifactExists
    /\ orphanArtifactAge' = IF orphanArtifactAge < 2 THEN orphanArtifactAge + 1 ELSE 2
    /\ UNCHANGED <<planState, storageState, artifactExists, statuslessAge,
                  actionableCount>>

CleanupOrphanArtifact ==
    /\ planState = NoPlan
    /\ artifactExists
    /\ orphanArtifactAge = 2
    /\ artifactExists' = FALSE
    /\ storageState' = NoStorage
    /\ orphanArtifactAge' = 0
    /\ UNCHANGED <<planState, statuslessAge, actionableCount>>

ResetFailedStorage ==
    /\ storageState = StorageFailed
    /\ storageState' = NoStorage
    /\ UNCHANGED <<planState, artifactExists, statuslessAge, orphanArtifactAge,
                  actionableCount>>

Next ==
    \/ PersistInlineSql
    \/ PersistConfigMapSql
    \/ PersistSqlFails
    \/ CreatePlanAfterStorage
    \/ StatusWriteSucceeds
    \/ StatusWriteFails
    \/ TerminalizePlan
    \/ DeleteTerminalPlan
    \/ AgeStatuslessPlan
    \/ CleanupStaleStatuslessPlan
    \/ AgeOrphanArtifact
    \/ CleanupOrphanArtifact
    \/ ResetFailedStorage

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(CleanupStaleStatuslessPlan)
    /\ WF_vars(CleanupOrphanArtifact)

StaleStatuslessEventuallyGone ==
    [](planState = Statusless /\ statuslessAge = 2 => <>(planState /= Statusless))

OrphanArtifactEventuallyGone ==
    [](planState = NoPlan /\ artifactExists /\ orphanArtifactAge = 2 =>
        <>(~artifactExists \/ planState /= NoPlan))

====
