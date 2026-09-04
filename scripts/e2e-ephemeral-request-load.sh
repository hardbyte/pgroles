#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/e2e-helpers.sh"

# A deliberately modest request-cache regression for a standard GitHub-hosted
# runner. This does not claim a production capacity limit; ResourceQuota should
# provide that hard stop. It catches accidental per-request memory explosions
# and severe reconcile-throughput regressions in the current all-request cache.
request_count="${EPHEMERAL_LOAD_REQUESTS:-250}"
max_peak_bytes="${EPHEMERAL_LOAD_MAX_PEAK_BYTES:-115343360}" # 110 MiB
max_delta_bytes="${EPHEMERAL_LOAD_MAX_DELTA_BYTES:-41943040}" # 40 MiB
max_elapsed_seconds="${EPHEMERAL_LOAD_MAX_ELAPSED_SECONDS:-120}"
request_prefix="ephemeral-load-request-"
policy_name="ephemeral-load-policy"
sample_file="$(mktemp)"
stop_file="$(mktemp)"
rm -f "$stop_file"
sampler_pid=""

cleanup() {
  touch "$stop_file"
  if [ -n "$sampler_pid" ]; then
    wait "$sampler_pid" 2>/dev/null || true
  fi
  kubectl get pgear -o name 2>/dev/null \
    | grep "/${request_prefix}" \
    | xargs -r kubectl delete --wait=false >/dev/null 2>&1 || true
  kubectl delete pgeap "$policy_name" --wait=false >/dev/null 2>&1 || true
  rm -f "$sample_file" "$stop_file"
}
trap cleanup EXIT

wait_for_access_policy() {
  for attempt in $(seq 1 45); do
    if [ "$(kubectl get pgeap "$policy_name" \
      -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' \
      2>/dev/null || true)" = "True" ]; then
      return 0
    fi
    echo "Waiting for $policy_name Accepted=True (attempt $attempt/45)"
    sleep 2
  done
  kubectl get pgeap "$policy_name" -o yaml || true
  return 1
}

wait_for_pending_requests() {
  for attempt in $(seq 1 90); do
    pending="$(kubectl get pgear -o json | jq --arg prefix "$request_prefix" '
      [.items[]
        | select(.metadata.name | startswith($prefix))
        | select(.status.phase == "PendingApproval")]
      | length
    ')"
    if [ "$pending" -eq "$request_count" ]; then
      return 0
    fi
    echo "Waiting for $request_count PendingApproval requests ($pending ready, attempt $attempt/90)"
    sleep 2
  done
  return 1
}

kubectl apply -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessPolicy
metadata:
  name: ephemeral-load-policy
spec:
  postgresPolicyRef:
    name: load-policy
  memberships:
    - role: loada_01-viewer
      inherit: false
  maximumDuration: 1h
  defaultDuration: 30m
  pendingRequestTTL: 30m
  justification:
    required: true
  approval:
    mode: Required
EOF
wait_for_access_policy

# Let startup and the access-policy reconcile settle before taking a baseline.
sleep 3
baseline_bytes="$(operator_memory_bytes)"
printf 'Operator baseline working set: %s bytes\n' "$baseline_bytes"

(
  while [ ! -e "$stop_file" ]; do
    operator_memory_bytes >>"$sample_file" 2>/dev/null || true
    sleep 1
  done
) &
sampler_pid="$!"

started_at="$(date +%s)"
{
  for i in $(seq 1 "$request_count"); do
    printf -- '---\n'
    cat <<EOF
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ${request_prefix}$(printf '%04d' "$i")
spec:
  accessPolicyRef:
    name: ${policy_name}
  subject:
    role: loada_01-editor
  requestedBy:
    username: github-actions-load-test
    groups: [pgroles-load-tests]
  requestedDuration: 30m
  justification: Bounded request-cache regression
EOF
  done
} | kubectl create -f - >/dev/null

wait_for_pending_requests
elapsed_seconds="$(( $(date +%s) - started_at ))"
post_bytes="$(operator_memory_bytes)"
touch "$stop_file"
wait "$sampler_pid" || true
sampler_pid=""
printf '%s\n' "$post_bytes" >>"$sample_file"
peak_bytes="$(sort -nr "$sample_file" | head -n 1)"
delta_bytes="$(( peak_bytes - baseline_bytes ))"
if [ "$delta_bytes" -lt 0 ]; then
  delta_bytes=0
fi

printf 'Resolved %s pending requests in %ss; operator working set baseline=%s, post=%s, peak=%s, delta=%s bytes\n' \
  "$request_count" "$elapsed_seconds" "$baseline_bytes" "$post_bytes" "$peak_bytes" "$delta_bytes"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf 'Ephemeral request cache: %s requests in %ss; working set baseline %.1f MiB, peak %.1f MiB, delta %.1f MiB.\n' \
    "$request_count" "$elapsed_seconds" \
    "$(( baseline_bytes / 1048576 ))" "$(( peak_bytes / 1048576 ))" "$(( delta_bytes / 1048576 ))" \
    >>"$GITHUB_STEP_SUMMARY"
fi

test "$elapsed_seconds" -le "$max_elapsed_seconds" || {
  echo "::error::ephemeral request reconciliation took ${elapsed_seconds}s (limit ${max_elapsed_seconds}s)"
  exit 1
}
test "$peak_bytes" -le "$max_peak_bytes" || {
  echo "::error::operator peak working set ${peak_bytes} bytes exceeded ${max_peak_bytes}"
  exit 1
}
test "$delta_bytes" -le "$max_delta_bytes" || {
  echo "::error::operator working-set delta ${delta_bytes} bytes exceeded ${max_delta_bytes}"
  exit 1
}
