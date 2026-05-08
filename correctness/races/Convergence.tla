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
    2. The operator inspects, computes a diff against the wildcard,
       and applies. Apply runs every GRANT before any REVOKE — matches
       diff() in pgroles-core/src/diff.rs.
    3. An external actor (e.g. cdc-relay's startup migrations) DROPs and
       CREATEs an object, resetting its proacl to NULL. The inspector's
       per-name aclexplode then misses that object, and the
       wildcard-collapse in normalize_wildcard_grants fails for the
       (role, schema, type) scope.
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

  Property to verify:

    EventuallyConverged ==
        <>[](currentGrants = Inventory)

  Holds under UseFixedDiff = TRUE; fails under UseFixedDiff = FALSE
  with a TLC trace that exhibits the flap.

  Caveats / what is NOT modelled:
    - Multiple roles / schemas / object types — the bug is a per-scope
      property, so a single scope is sufficient.
    - Privilege subsets — the bug surfaces with exactly one privilege
      (EXECUTE for functions). A multi-privilege model would add no
      new behaviour.
    - The plan lifecycle around the apply (Pending/Approved/Applying
      etc.) — covered by PlanLifecycle.tla. We collapse a reconcile
      into a single atomic state transition.
*)

CONSTANTS
    Inventory,        \* Set of object names in the managed schema, e.g. {f1,f2,f3}
    UseFixedDiff,     \* TRUE for v0.7.1 semantics, FALSE for v0.7.0 (buggy)
    MaxDrops          \* Bound the number of external drop+creates for model checking

ASSUME
    /\ Inventory /= {}
    /\ UseFixedDiff \in BOOLEAN
    /\ MaxDrops \in Nat

VARIABLES
    \* Set of inventory objects that currently have an explicit per-role
    \* ACL row visible to the inspector (i.e. survive the
    \* aclexplode → managed_roles filter). When = Inventory the wildcard
    \* collapse succeeds and the system is converged.
    currentGrants,

    \* How many external drop+creates remain. Each one removes one object
    \* from currentGrants. Bounded so TLC explores a finite state space.
    dropsRemaining

vars == <<currentGrants, dropsRemaining>>

TypeOK ==
    /\ currentGrants \subseteq Inventory
    /\ dropsRemaining \in 0..MaxDrops

Init ==
    \* Start in the steady state: every object has the per-role ACL,
    \* the inspector's collapse holds, the diff is empty.
    /\ currentGrants = Inventory
    /\ dropsRemaining = MaxDrops

\* An external service (e.g. cdc-relay) DROPs and CREATEs an object.
\* Its proacl resets to NULL, so the inspector no longer produces a row
\* for it under managed_roles, and the wildcard collapse fails.
ExternalDropCreate ==
    /\ dropsRemaining > 0
    /\ \E n \in currentGrants:
        currentGrants' = currentGrants \ {n}
    /\ dropsRemaining' = dropsRemaining - 1

\* No-op reconcile: already converged.
ReconcileNoop ==
    /\ currentGrants = Inventory
    /\ UNCHANGED vars

\* v0.7.0 (buggy) reconcile. When collapse fails, diff emits:
\*   - GRANT wildcard                   (covers all of Inventory)
\*   - REVOKE per-name FOR EACH n in currentGrants
\* Apply order is GRANTs then REVOKEs, so:
\*   after wildcard GRANT:    set = Inventory
\*   after per-name REVOKEs:  set = Inventory \ currentGrants_before
\* The set of "objects with an ACL" INVERTS each reconcile.
ReconcileBuggy ==
    /\ ~UseFixedDiff
    /\ currentGrants /= Inventory
    /\ currentGrants' = Inventory \ currentGrants
    /\ UNCHANGED dropsRemaining

\* v0.7.1 reconcile. Per-name REVOKEs are filtered when their privileges
\* are shadowed by a desired wildcard for the same scope, so the diff
\* emits only the wildcard GRANT and apply converges in one step.
ReconcileFixed ==
    /\ UseFixedDiff
    /\ currentGrants /= Inventory
    /\ currentGrants' = Inventory
    /\ UNCHANGED dropsRemaining

Reconcile ==
    \/ ReconcileNoop
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

\* Eventually-permanently converged. Under fairness on Reconcile and a
\* finite number of external drops, the database eventually matches the
\* manifest and stays there. Holds under UseFixedDiff = TRUE; fails
\* under UseFixedDiff = FALSE with a counterexample showing the flap.
EventuallyConverged ==
    <>[](currentGrants = Inventory)

\* Bounded-step convergence: under the fixed semantics, the gap between
\* desired and current shrinks monotonically across reconciles (a single
\* reconcile closes it). Useful as a sanity check on the action shape.
NoStrictlyWorseReconcile ==
    [][(currentGrants /= Inventory /\ Reconcile) =>
        Cardinality(Inventory \ currentGrants') <= Cardinality(Inventory \ currentGrants)]_vars

====
