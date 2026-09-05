# ACL inspection measurements (#214)

Use a disposable PostgreSQL database. The fixture creates 1,000 functions,
40 grantees, and 40,040 managed ACL rows (including schema USAGE).

```sh
scripts/generate-acl-burst-sql.sh bench 1 1000 bench 40 | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
```

Create a manifest declaring the 40 `bench_01` through `bench_40` roles and an
EXECUTE wildcard on `bench_1` functions for each role. The profile example is
read-only and reports any extra schema-USAGE revocations without applying them.

```sh
cargo build --release -p pgroles-inspect --example inspection_profile
TOKIO_WORKER_THREADS=1 PROFILE_INLINE=1 target/release/examples/inspection_profile policy.yaml
TOKIO_WORKER_THREADS=1 target/release/examples/inspection_profile policy.yaml
# Repeat with TOKIO_WORKER_THREADS=2.
```

The workload runs on a Tokio worker, not the root thread of `tokio::main`.
A separate 10 ms timer reports its maximum scheduling delay. This is a runtime
responsiveness experiment, not an HTTP health-probe latency measurement.
`PROFILE_INLINE=1` uses the synchronous derivation API; the default exercises
the bounded path used by production inspection and shared candidate planning.

## Query experiment

PostgreSQL 18 in a local Docker container, macOS host, nine runs per variant.
The SQL files alongside this document preserve both queries. Prefix each with
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` to reproduce. For sparse results,
replace the 40-role array with `ARRAY['bench_01']`.

| Qualifying ACLs | Existing query, median | Filtered materialized signature query, median |
| --- | ---: | ---: |
| Dense: 40 roles | 18.708 ms | 25.047 ms |
| Sparse: 1 role | 6.194 ms | 11.039 ms |

The materialized variant first identifies qualifying functions, computes each
identity signature once, then expands their ACLs. In this fixture its extra
qualification pass/materialization costs more than it saves. It is deliberately
**not** used in production. The result does not rule out a different query or a
different result with more expensive signatures; benchmark before changing it.

## Representation and memory

Wildcard grants remain compact, but removal needs concrete object/grantor
identity. `grant_entry_grantors` is now consumed by wildcard range scans, not
orphaned by normalization. Removing it would lose the information needed to
revoke delegated grants safely. Owner entries carry inherent tags instead.

The derivation no longer allocates an intermediate `Vec<&AclRow>`. The bounded
path shares raw state with `Arc`, moves the derived state between phases, and
holds a single process-wide CPU permit only during computation. Async
query waits do not hold it; cancellation does not release it while blocking
work is still running. The existing controller concurrency limits still bound
how many raw snapshots can be queued; they remain serial by default.

## Production-shaped validation

The nightly ACL burst job runs both one- and two-worker Tokio runtimes with
the chart's 200m CPU limit. It raises memory to 512Mi to compare bounded and
unbounded reconciliation without an OOM truncating the comparison. A passing
run therefore does not certify this fixture under the default 128Mi limit.
The existing restart gate remains mandatory. Correlate its working-set samples
with `pgroles.inspect.duration`, ACL/grantor counts, and
`pgroles.runtime.scheduling_lag`. No digest/cache fast path is introduced.

## Local runtime sample (2026-09-05)

On the macOS host with PostgreSQL 18 in Docker, the final one-worker sample
measured 197.863 ms maximum timer delay inline and 14.568 ms bounded. Process
maximum resident set size (`/usr/bin/time -l`) was 103,792,640 bytes inline and
103,235,584 bytes bounded. This is process RSS, not an allocation/heap profile;
it supports no extra full snapshot copy, not a general memory reduction claim.
Timing varies with host load. Use the low-CPU cluster gate for deployment claims.

## Cluster validation

Run [33926081262](https://github.com/thepartly/pgroles/actions/runs/33926081262) tested the chart's 200m CPU setting with one and two Tokio workers, ten policies, and 40,000 ACL rows per policy. Serial reconciliation converged with zero restarts and peak working sets of 76,382,208 and 76,492,800 bytes respectively. The test used a 512 MiB memory limit. Unbounded reconciliation failed to complete, so these runs do not provide a bounded/unbounded ratio or a 128 MiB production guarantee.

The burst gate additionally samples real `/livez` and `/readyz` requests to the new pod through the Kubernetes API proxy. It reports p95 and maximum latency, includes proxy overhead, requires at least three samples per endpoint, and rejects failures or requests at or above the shipped two-second timeout after each endpoint first responds. Startup before the endpoint listens is excluded; pod restart checks remain independent. Tokio scheduling lag is a separate metric and is not presented as HTTP latency.
