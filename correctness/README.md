# pgroles Correctness Models

TLA+ models for verifying concurrency invariants in the pgroles operator.

These models check state machine properties that are difficult to verify
with integration tests — particularly race conditions between concurrent
operator reconciles, user annotations, database drift, and operator crashes.

## Models

### `races/PlanLifecycle.tla`

Verifies the PostgresPolicyPlan lifecycle state machine:

- A plan can only reach Applied if its approval was verified
- A rejected plan is never executed
- Applied plans match the current database drift (no stale execution)
- Failed plans always have last_error set
- Stuck Applying plans are recovered after operator crash

Races modeled:
1. User approves while operator computes new plan (hash validation)
2. User approves + rejects simultaneously (reject wins)
3. Operator crashes during Applying phase
4. Database drift changes between plan creation and approval
5. Hash dedup skips identical plans

## Running

```bash
# Build the TLC Docker image and run a model
./correctness/run-tlc.sh races/PlanLifecycle.tla

# Run with a specific config
./correctness/run-tlc.sh races/PlanLifecycle.tla races/PlanLifecycle.cfg
```

Requires Docker. Uses the same Docker-based TLC runner as
[awa](https://github.com/hardbyte/awa/tree/main/correctness).
