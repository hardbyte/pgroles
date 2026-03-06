# pgroles Roadmap

## Goals

- Make the current CLI/operator behavior safe and actually convergent.
- Tighten the declarative contract so the manifest expresses intent, not just SQL-shaped inputs.
- Harden the operator only after the core reconciliation model is reliable.

## Phase 1: Safety and Semantic Validation

- Extend the current live destructive-operation preflight:
  - ownership and active-session checks are implemented now
  - next add broader unmanaged dependency detection before destructive changes
  - next surface likely blockers more precisely in dry-run output
- Harden the new role-retirement path:
  - explicit `retirements` with `REASSIGN OWNED` / `DROP OWNED` are implemented now
  - next decide whether session termination should ever be an explicit opt-in workflow
  - next document the current single-database boundary for retirement cleanup more clearly
- Expand manifest semantic validation:
  - top-level default privileges must declare `grant.role`
  - object target combinations should be checked for required/forbidden fields
  - unsupported default privilege object types should be rejected
  - privilege/object combinations should be validated early
- Keep transactional apply as the default execution model.
- Keep membership flag changes covered by regression tests; the current remove-then-add behavior is acceptable because apply is transactional.
- Broaden function grant coverage, especially for overloaded signatures and inspect/render parity.

## Phase 2: Test Coverage

- Add live PostgreSQL tests for:
  - wildcard table/sequence/function grants
  - function grants with arguments
  - membership option changes
  - default privilege validation and reconciliation
  - destructive preflight checks for owned objects and unsafe drops
- Add operator tests for:
  - Secret rotation
  - degraded status on failure
  - reconcile recovery after failure
  - safe failure reporting for blocked destructive changes

## Phase 3: Declarative Boundary

- Introduce an explicit managed scope:
  - managed roles
  - managed schemas
  - managed ownership transitions
  - whether revokes/drops are authoritative inside that scope
- Add reconcile modes:
  - `authoritative`
  - `additive`
  - `adopt`
- Treat selectors like "all tables in schema X" as first-class intent, not a string convention.
- Make owner context for default privileges explicit instead of relying on fallbacks.

## Phase 4: Scope and UX

- Keep the current contract explicit: one manifest reconciles one database connection.
- Decide whether multi-database manifests are a non-goal or a later orchestration feature.
- If multi-database support is added, model it above the current single-database diff engine rather than overloading one manifest with ambiguous scope.

- Add `--format json` to `validate`, `diff`, and `inspect`.
- Add a drift exit code for CI.
- Make `inspect` emit a detailed normalized graph, not just counts.
- Add a manifest/schema export command for editor and pipeline integration.

## Phase 5: Operator Hardening

- Cache pools by Secret resource version and watch for Secret updates.
- Surface `Ready`, `Reconciling`, and `Degraded` conditions consistently.
- Add rate-limited retries and clearer failure summaries.
- Add policy around deletion behavior instead of relying on implicit defaults.

## Declarative Direction

Today, pgroles is declarative at the manifest surface but still partly operational internally. The next step is to make the core model intent-based:

- desired selectors and edges in
- normalized current state over the same managed boundary
- diff between those two graphs
- SQL only as an execution backend

That makes the tool more predictable for both the CLI and the operator.
