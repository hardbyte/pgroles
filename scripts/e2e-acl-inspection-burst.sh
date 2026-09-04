#!/usr/bin/env bash
set -euo pipefail

# Does peak reconcile memory track the concurrency bound, or the policy count?
#
# Reconciling a PostgresPolicy materialises the whole managed ACL surface of
# its database, and the function read is one `aclexplode` row per function per
# grantee. With unbounded concurrency every policy whose watch fires allocates
# its own copy of that at the same moment, so peak scales with how many
# policies happen to be due — which on operator startup is all of them. Nothing
# else in this repository could see that failure mode: every other scenario asserts
# convergence, which an operator that was killed and came back still reaches.
#
# The measurement here is a configuration rollout, because startup is the
# burst: every watch fires together. It runs twice against the same fixture, unbounded
# first so each phase starts from a fresh pod with a clean baseline, and
# asserts the relationship rather than an absolute — a threshold nobody has
# measured is a coin flip, while "bounded must cost materially less than
# unbounded" is exactly the property the bound claims, and it fails the moment
# the bound stops being applied.
#
# Sizing is env-overridable so the shape can be turned up as runners allow.
# Rows per policy are schemas x functions x roles: the defaults give 40,000,
# which is large enough to exercise the inspection path meaningfully.
policy_count="${BURST_POLICIES:-10}"
schema_count="${BURST_SCHEMAS:-10}"
function_count="${BURST_FUNCTIONS:-100}"
role_count="${BURST_ROLES:-40}"
# The bounded run must stay under this share of the unbounded run's peak.
# Generous on purpose: the defaults give unbounded 10x the concurrency of
# bounded, so a real bound clears this comfortably and only its removal, which
# makes the two runs identical, cannot.
max_bounded_share_percent="${BURST_MAX_BOUNDED_SHARE_PERCENT:-80}"

namespace=pgroles-system
deployment="deployment/pgroles-operator"
sample_file="$(mktemp)"
probe_file="$(mktemp)"
probe_pid=""
stop_file="$(mktemp)"
rm -f "$stop_file"
sampler_pid=""

cleanup() {
  touch "$stop_file"
  if [ -n "$sampler_pid" ]; then
    wait "$sampler_pid" 2>/dev/null || true
  fi
  if [ -n "$probe_pid" ]; then wait "$probe_pid" 2>/dev/null || true; fi
  rm -f "$sample_file" "$stop_file" "$probe_file"
}
trap cleanup EXIT

source "$(dirname "$0")/e2e-helpers.sh"

policy_name() { printf 'burst-%02d' "$1"; }
database_name() { printf 'burst%02d' "$1"; }
secret_name() { printf 'burst-%02d-credentials' "$1"; }
# Roles are cluster-wide even though databases are not, so every policy needs
# its own role names. Sharing them would put ten policies in charge of one set
# of roles, which the operator correctly reports as a conflict.
role_prefix_for() { printf 'burst%02d_reader' "$1"; }

# Every burst policy has reconciled at least once since `since`, an RFC3339
# UTC timestamp. These sort lexicographically, which is the whole reason the
# comparison can be done in the shell.
wait_for_reconciles_since() {
  local since="$1" attempts="${2:-120}"
  local attempt done_count i name stamp
  for attempt in $(seq 1 "$attempts"); do
    done_count=0
    for i in $(seq 1 "$policy_count"); do
      name="$(policy_name "$i")"
      stamp="$(kubectl get pgr "$name" \
        -o jsonpath='{.status.last_successful_reconcile_time}' 2>/dev/null || true)"
      if [ -n "$stamp" ] && [ "$stamp" \> "$since" ]; then
        done_count=$(( done_count + 1 ))
      fi
    done
    if [ "$done_count" -eq "$policy_count" ]; then
      echo "all $policy_count policies reconciled since $since"
      return 0
    fi
    echo "Waiting for reconciles since $since ($done_count/$policy_count, attempt $attempt/$attempts)"
    sleep 5
  done
  echo "::error::only $done_count/$policy_count policies reconciled since $since"
  kubectl get pgr -o wide || true
  kubectl -n "$namespace" logs "$deployment" --tail=200 || true
  return 1
}

# Roll the operator into one configuration, sample across that rollout, and set
# `measured_peak` to the highest working-set sample from the fresh pod.
#
# The result is a global rather than stdout because everything in here — the
# rollout, the reconcile wait — is output a caller would want to see, and
# capturing the function's stdout would swallow it.
measured_peak=0
stop_sampler() {
  if [ -n "$sampler_pid" ]; then
    touch "$stop_file"
    wait "$sampler_pid" 2>/dev/null || true
    sampler_pid=""
  fi
  if [ -n "$probe_pid" ]; then
    wait "$probe_pid"
    probe_pid=""
  fi
}

run_phase() {
  local label="$1"
  shift
  local baseline old_pod_uid peak

  # A phase that failed part way may have left its sampler running; it would
  # otherwise keep appending to the file this phase is about to read.
  stop_sampler

  rm -f "$sample_file" "$stop_file"
  touch "$sample_file"
  old_pod_uid="$(active_operator_pod_json "$namespace" | jq -r '.metadata.uid')" || return 1
  (
    while [ ! -e "$stop_file" ]; do
      operator_memory_bytes "$namespace" "$old_pod_uid" >>"$sample_file" 2>/dev/null || true
      sleep 1
    done
  ) &
  sampler_pid="$!"
  python3 "$(dirname "$0")/sample-operator-probes.py" --namespace "$namespace" \
    --exclude-uid "$old_pod_uid" --output "$probe_file" --stop "$stop_file" &
  probe_pid="$!"

  # `set env` changes the pod template in both phases (absent -> 0 -> absent),
  # so it is itself the one rollout under measurement. Starting the sampler and
  # timestamp before that mutation avoids missing the startup burst. A separate
  # `rollout restart` would create a second pod and allow late status writes
  # from the configuration rollout to satisfy the wait for the wrong burst.
  local since
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if ! kubectl -n "$namespace" set env "$deployment" "$@"; then
    stop_sampler
    return 1
  fi
  if ! kubectl -n "$namespace" rollout status "$deployment" --timeout=180s; then
    stop_sampler
    return 1
  fi

  if ! wait_for_reconciles_since "$since"; then
    stop_sampler
    return 1
  fi

  stop_sampler
  operator_memory_bytes "$namespace" "$old_pod_uid" >>"$sample_file" 2>/dev/null || true

  baseline="$(head -n 1 "$sample_file")"
  peak="$(sort -nr "$sample_file" | head -n 1)"
  if [ -z "$peak" ]; then
    echo "::error::no memory samples were collected for the $label phase" >&2
    return 1
  fi
  measured_peak="$peak"
  printf '%s: first-sample=%s peak=%s bytes\n' \
    "$label" "$baseline" "$measured_peak"
}

# -- Fixture ------------------------------------------------------------------

echo "Seeding $policy_count databases with ${schema_count}x${function_count} functions granted to $role_count roles"

for i in $(seq 1 "$policy_count"); do
  database="$(database_name "$i")"
  if ! kubectl exec -i postgres-0 -- psql -tA -U postgres -d postgres \
    -c "SELECT 1 FROM pg_database WHERE datname = '${database}'" | grep -qx 1; then
    kubectl exec -i postgres-0 -- psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
      -c "CREATE DATABASE \"${database}\""
  fi
  kubectl create secret generic "$(secret_name "$i")" \
    --from-literal=DATABASE_URL="postgres://postgres:devpassword@postgres.default.svc.cluster.local:5432/${database}" \
    --dry-run=client -o yaml | kubectl apply -f -
done

for i in $(seq 1 "$policy_count"); do
  database="$(database_name "$i")"
  bash "$(dirname "$0")/generate-acl-burst-sql.sh" \
    "burst" "$schema_count" "$function_count" "$(role_prefix_for "$i")" "$role_count" \
    | kubectl exec -i postgres-0 -- psql -q -v ON_ERROR_STOP=1 -U postgres -d "$database"
  echo "seeded $database"
done

for i in $(seq 1 "$policy_count"); do
  bash "$(dirname "$0")/generate-acl-burst-policy.sh" \
    "$(policy_name "$i")" "$(secret_name "$i")" \
    "burst" "$schema_count" "$(role_prefix_for "$i")" "$role_count" \
    "/tmp/$(policy_name "$i").yaml"
  kubectl apply -f "/tmp/$(policy_name "$i").yaml"
done

# The fixture is pre-granted, so this first pass should find every database
# already converged. Waiting it out separates the apply from the measurement:
# what follows measures inspection, not the cost of a first apply.
for i in $(seq 1 "$policy_count"); do
  wait_for_ready_true "$(policy_name "$i")" 90 5
done

# -- Measurement --------------------------------------------------------------

# The unbounded phase is allowed to fail. Being OOM-killed, or never getting
# every policy through a reconcile because it keeps being killed, is a result
# rather than an error — it says the bound matters more loudly than any ratio
# would. What it costs is the comparison, so the ratio assertion below is
# skipped when this phase does not complete, and the bounded phase carries the
# run on its own.
unbounded_completed=1
run_phase 'unbounded (RECONCILE_CONCURRENCY=0)' RECONCILE_CONCURRENCY=0 || unbounded_completed=0
unbounded_peak="$measured_peak"
# The shipped liveness/readiness timeout is two seconds. This measures actual
# HTTP requests via the API proxy, rather than treating zero restarts as a
# latency measurement. Proxy overhead makes this a conservative bound.
python3 "$(dirname "$0")/sample-operator-probes.py" --check --output "$probe_file" \
  | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
kubectl -n "$namespace" get pods -o wide || true
if [ "$unbounded_completed" -eq 0 ]; then
  echo "the unbounded phase did not complete; the bounded phase is the whole assertion"
fi

run_phase 'bounded (default)' RECONCILE_CONCURRENCY-
bounded_peak="$measured_peak"

printf 'ACL inspection burst: %s policies x %s schemas x %s functions x %s roles (%s ACL rows each). Peak working set after restart: unbounded %s MiB, bounded %s MiB.\n' \
  "$policy_count" "$schema_count" "$function_count" "$role_count" \
  "$(( schema_count * function_count * role_count ))" \
  "$(( unbounded_peak / 1048576 ))" "$(( bounded_peak / 1048576 ))" \
  | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

# -- Assertions ---------------------------------------------------------------

# The bounded run is the one that has to survive. An operator killed while
# reconciling its own policies fails the property this scenario protects.
assert_operator_healthy "$namespace"

if [ "$unbounded_completed" -eq 0 ]; then
  printf 'Unbounded phase did not complete, so only the bounded phase was asserted. Bounded peak %s bytes.\n' \
    "$bounded_peak"
  exit 0
fi

if [ "$unbounded_peak" -le 0 ]; then
  echo "::error::the unbounded run produced no working-set samples, so the comparison measured nothing"
  exit 1
fi

allowed=$(( unbounded_peak * max_bounded_share_percent / 100 ))
if [ "$bounded_peak" -gt "$allowed" ]; then
  echo "::error::bounded reconciles reached a ${bounded_peak}-byte working set against ${unbounded_peak} unbounded (allowed ${allowed}, ${max_bounded_share_percent}%). Peak memory is tracking policy count rather than the concurrency bound."
  exit 1
fi

printf 'Bounded peak %s bytes is within %s%% of unbounded %s bytes\n' \
  "$bounded_peak" "$max_bounded_share_percent" "$unbounded_peak"
