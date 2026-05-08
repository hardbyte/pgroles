---- MODULE Convergence ----
EXTENDS FiniteSets, Naturals

(*
  Reconcile-convergence model for pgroles wildcard grants.

  Captures the property that — under finitely many external mutations to
  managed objects — the operator's reconcile loop eventually drives the
  database to match the manifest and stays there. The existing
  PlanLifecycle and PlanStorage models assume this convergence (their
  Apply* actions leave dbHash untouched, implicitly modelling apply as
  idempotent). v0.7.0's wildcard-grant bug showed that assumption can
  fail: a single externally-recreated function (proacl reset to NULL)
  could send the controller into a permanent oscillation between two
  stable, non-convergent states.

  Modelled scenario:
    1. Manifest has a single wildcard grant: every object in `Inventory`
       must have the privilege for the role. (One role, one schema,
       one object type, one privilege — the smallest faithful slice.)
       Each object also has per-object grantability from the executor's
       point of view, modelling ownership / WITH GRANT OPTION.
    2. The operator inspects, computes a diff against the wildcard,
       and applies. Apply runs every GRANT before any REVOKE — matches
       diff() in pgroles-core/src/diff.rs.
    3. An external actor (e.g. cdc-relay's startup migrations) DROPs and
       CREATEs an object, resetting its proacl to NULL. The inspector's
       per-name aclexplode then misses that object, and the
       wildcard-collapse in normalize_wildcard_grants fails for the
       (role, schema, type) scope. The recreated object may be owned by
       the executor (grantable) or by another role (not grantable).
    4. The operator reconciles again.

  Two diff semantics are modelled:

    - UseFixedDiff = FALSE — the v0.7.0 behaviour. When collapse fails,
      diff_grants emits both a wildcard GRANT (for the desired
      `name = "*"` key not present in current) AND per-name REVOKEs
      (for current per-name entries not present in desired). Apply
      order: GRANTs then REVOKEs. Net effect: the wildcard GRANT
      materialises ACLs on every inventory object, then per-name
      REVOKEs strip them from exactly the previously-known set. The
      set of "objects with an ACL" INVERTS each reconcile.

    - UseFixedDiff = TRUE — the v0.7.1 behaviour (PR #104). diff_grants
      shadow-suppresses per-name REVOKEs whose privileges are covered
      by a desired wildcard for the same (role, schema, type). Apply
      emits the wildcard GRANT only; the next reconcile's collapse
      succeeds and the diff is empty.

    - UseDiagnostics = TRUE — the v0.7.2 behaviour (PR #106). Before
      planning/applying, inspection detects any object that is both
      missing the wildcard privilege and not grantable by the executor.
      Reconcile reports an UnsatisfiableWildcardGrant diagnostic and
      does not mutate grants or create another plan.

  Property to verify:

    EventuallySettled ==
        <>[](currentGrants = Inventory \/ diagnosed)

  With all objects grantable, "settled" means converged. With a
  non-grantable object missing the wildcard privilege, "settled" means
  diagnosed and stable instead of repeatedly planning impossible SQL.
  Under UseFixedDiff = FALSE, TLC still finds the v0.7.0 flap.

  Caveats / what is NOT modelled:
    - Multiple roles / schemas / object types — the bug is a per-scope
      property, so a single scope is sufficient.
    - Privilege subsets — the bug surfaces with exactly one privilege
      (EXECUTE for functions). A multi-privilege model would add no
      new behaviour.
    - PostgreSQL's detailed grantor chains — per-object grantability is
      reduced to "executor can grant this object" vs "cannot grant this
      object", which is the distinction used by diagnostics.
    - The plan lifecycle around the apply (Pending/Approved/Applying
      etc.) — covered by PlanLifecycle.tla. We collapse a reconcile
      into a single atomic state transition.
*)

CONSTANTS
    Inventory,        \* Set of object names in the managed schema, e.g. {f1,f2,f3}
    UseFixedDiff,     \* TRUE for v0.7.1 semantics, FALSE for v0.7.0 (buggy)
    UseDiagnostics,   \* TRUE for v0.7.2 unsatisfiable-wildcard diagnostics
    MaxDrops          \* Bound the number of external drop+creates for model checking

ASSUME
    /\ Inventory /= {}
    /\ UseFixedDiff \in BOOLEAN
    /\ UseDiagnostics \in BOOLEAN
    /\ MaxDrops \in Nat

VARIABLES
    \* Set of inventory objects that currently have an explicit per-role
    \* ACL row visible to the inspector (i.e. survive the
    \* aclexplode → managed_roles filter). When = Inventory the wildcard
    \* collapse succeeds and the system is converged.
    currentGrants,

    \* Set of objects for which the executor can currently grant the
    \* wildcard privilege. This abstracts ownership / WITH GRANT OPTION.
    grantable,

    \* How many external drop+creates remain. Each one removes one object
    \* from currentGrants. Bounded so TLC explores a finite state space.
    dropsRemaining,

    \* Whether reconcile has surfaced UnsatisfiableWildcardGrant. A new
    \* external mutation clears it because the environment changed.
    diagnosed

vars == <<currentGrants, grantable, dropsRemaining, diagnosed>>

TypeOK ==
    /\ currentGrants \subseteq Inventory
    /\ grantable \subseteq Inventory
    /\ dropsRemaining \in 0..MaxDrops
    /\ diagnosed \in BOOLEAN

Init ==
    \* Start in the steady state: every object has the per-role ACL,
    \* the inspector's collapse holds, and the diff is empty. Ownership
    \* starts grantable, but external drop+create can change it per object.
    /\ currentGrants = Inventory
    /\ grantable = Inventory
    /\ dropsRemaining = MaxDrops
    /\ diagnosed = FALSE

MissingNonGrantable ==
    (Inventory \ currentGrants) \ grantable

\* An external service (e.g. cdc-relay) DROPs and CREATEs an object.
\* Its proacl resets to NULL, so the inspector no longer produces a row
\* for it under managed_roles, and the wildcard collapse fails. The
\* recreated object may be grantable by the executor or owned by another
\* role; all other object ownership is unchanged.
ExternalDropCreate ==
    /\ dropsRemaining > 0
    /\ \E n \in currentGrants:
        /\ currentGrants' = currentGrants \ {n}
        /\ grantable' \in { grantable \ {n}, grantable \cup {n} }
    /\ dropsRemaining' = dropsRemaining - 1
    /\ diagnosed' = FALSE

\* No-op reconcile: already converged.
ReconcileNoop ==
    /\ currentGrants = Inventory
    /\ diagnosed' = FALSE
    /\ UNCHANGED <<currentGrants, grantable, dropsRemaining>>

\* v0.7.2 diagnostic reconcile. If a wildcard target is missing the
\* privilege and is not grantable by the executor, strict desired-state
\* semantics stop before planning/applying repeated SQL.
ReconcileDiagnostic ==
    /\ UseDiagnostics
    /\ currentGrants /= Inventory
    /\ MissingNonGrantable /= {}
    /\ diagnosed' = TRUE
    /\ UNCHANGED <<currentGrants, grantable, dropsRemaining>>

\* v0.7.0 (buggy) reconcile. When collapse fails, diff emits:
\*   - GRANT wildcard                   (covers all of Inventory)
\*   - REVOKE per-name FOR EACH n in currentGrants
\* Apply order is GRANTs then REVOKEs, so:
\*   after wildcard GRANT:    grantable objects have ACLs
\*   after per-name REVOKEs:  previous currentGrants are stripped
\* The set of "objects with an ACL" INVERTS each reconcile.
ReconcileBuggy ==
    /\ ~UseFixedDiff
    /\ currentGrants /= Inventory
    /\ ~(UseDiagnostics /\ MissingNonGrantable /= {})
    /\ currentGrants' = (currentGrants \cup grantable) \ currentGrants
    /\ diagnosed' = FALSE
    /\ UNCHANGED dropsRemaining
    /\ UNCHANGED grantable

\* v0.7.1 reconcile. Per-name REVOKEs are filtered when their privileges
\* are shadowed by a desired wildcard for the same scope, so the diff
\* emits only the wildcard GRANT. It converges in one step when every
\* missing object is grantable; otherwise v0.7.2 diagnostics preempt it.
ReconcileFixed ==
    /\ UseFixedDiff
    /\ currentGrants /= Inventory
    /\ ~(UseDiagnostics /\ MissingNonGrantable /= {})
    /\ currentGrants' = currentGrants \cup grantable
    /\ diagnosed' = FALSE
    /\ UNCHANGED dropsRemaining
    /\ UNCHANGED grantable

Reconcile ==
    \/ ReconcileNoop
    \/ ReconcileDiagnostic
    \/ ReconcileBuggy
    \/ ReconcileFixed

Next ==
    \/ ExternalDropCreate
    \/ Reconcile

\* Weak fairness on Reconcile: if a reconcile is continuously enabled, it
\* eventually fires. This matches the controller's requeue behaviour.
\* No fairness on ExternalDropCreate — drops are bounded by MaxDrops, so
\* eventually no drops are enabled and Reconcile alone drives convergence.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Reconcile)

\* --- Properties ---

\* Eventually-permanently settled. Under fairness on Reconcile and a
\* finite number of external drops, the database either matches the
\* manifest or has surfaced a stable UnsatisfiableWildcardGrant
\* diagnostic. With all missing objects grantable, this reduces to
\* convergence; with a missing non-grantable object, strict semantics
\* settle by diagnosing instead of churning.
EventuallySettled ==
    <>[]((currentGrants = Inventory) \/ diagnosed)

\* Eventually-permanently converged. This remains useful in configs where
\* all objects stay grantable, but is intentionally stronger than the
\* v0.7.2 ownership-aware contract.
EventuallyConverged ==
    <>[](currentGrants = Inventory)

\* Bounded-step convergence: under the fixed semantics, the gap between
\* desired and current never grows across fixed/diagnostic reconciles.
\* Useful as a sanity check on the action shape.
NoStrictlyWorseReconcile ==
    [][(currentGrants /= Inventory /\ (ReconcileFixed \/ ReconcileDiagnostic)) =>
        Cardinality(Inventory \ currentGrants') <= Cardinality(Inventory \ currentGrants)]_vars

DiagnosticDoesNotMutateGrants ==
    [][ReconcileDiagnostic => currentGrants' = currentGrants]_vars

====
