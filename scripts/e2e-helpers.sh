#!/usr/bin/env bash
# Shared helper functions for E2E test suites.
# Source this file at the start of each E2E test step:
#   source scripts/e2e-helpers.sh
set -euo pipefail

# -- Policy status helpers ----------------------------------------------------

wait_for_ready_true() {
  local policy="$1"
  local attempts="${2:-30}"
  local sleep_secs="${3:-3}"
  for i in $(seq 1 "$attempts"); do
    status="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
    if [ "$status" = "True" ]; then
      echo "$policy reached Ready=True"
      return 0
    fi
    echo "Waiting for $policy Ready=True... (attempt $i/$attempts)"
    sleep "$sleep_secs"
  done
  echo "::error::$policy did not reach Ready=True"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_ready_status_reason() {
  local policy="$1"
  local expected_status="$2"
  local expected_reason="$3"
  for i in $(seq 1 30); do
    status="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
    reason="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ] && [ "$reason" = "$expected_reason" ]; then
      echo "$policy reached Ready=$expected_status with reason=$expected_reason"
      return 0
    fi
    echo "Waiting for $policy Ready=$expected_status/$expected_reason... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy did not reach Ready=$expected_status with reason=$expected_reason"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_ready_reason() {
  local policy="$1"
  local expected_reason="$2"
  wait_for_ready_status_reason "$policy" "False" "$expected_reason"
}

wait_for_drift_status() {
  local policy="$1"
  local expected_status="$2"
  for i in $(seq 1 30); do
    status="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Drifted")].status}' 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "$policy reached Drifted=$expected_status"
      return 0
    fi
    echo "Waiting for $policy Drifted=$expected_status... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy did not reach Drifted=$expected_status"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_last_error_contains() {
  local policy="$1"
  local expected_substring="$2"
  for i in $(seq 1 30); do
    last_error="$(kubectl get pgr "$policy" -o jsonpath='{.status.last_error}' 2>/dev/null || true)"
    normalized_last_error="$(printf '%s' "$last_error" | tr '\n' ' ' | tr -s ' ')"
    if printf '%s' "$normalized_last_error" | grep -Fq "$expected_substring"; then
      echo "$policy reported expected error substring: $expected_substring"
      return 0
    fi
    echo "Waiting for $policy lastError to contain '$expected_substring'... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy lastError did not contain $expected_substring"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_event_reason() {
  local policy="$1"
  local expected_reason="$2"
  local namespace="${3:-default}"
  for i in $(seq 1 30); do
    events="$(
      kubectl get events.events.k8s.io -n "$namespace" \
        -o jsonpath='{range .items[*]}{.regarding.name}{"\t"}{.reason}{"\n"}{end}' \
        2>/dev/null || true
    )"
    if printf '%s\n' "$events" | grep -Fxq "$policy	$expected_reason"; then
      echo "$policy emitted Event reason=$expected_reason"
      return 0
    fi
    echo "Waiting for $policy Event/$expected_reason... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy did not emit Event reason=$expected_reason"
  kubectl get events.events.k8s.io -n "$namespace" || true
  kubectl describe pgr "$policy" || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

# -- PostgreSQL helpers -------------------------------------------------------

pg_query() {
  local db="${2:-postgres}"
  kubectl exec postgres-0 -- psql -U postgres -d "$db" -tAc "$1"
}

assert_role_exists() {
  pg_query "SELECT rolname FROM pg_roles WHERE rolname = '$1'" | grep -qx "$1"
}

assert_role_absent() {
  ! pg_query "SELECT 1 FROM pg_roles WHERE rolname = '$1'" | grep -qx "1"
}

get_password_hash() {
  pg_query "SELECT rolpassword FROM pg_authid WHERE rolname = '$1'"
}

assert_password_set() {
  local hash
  hash="$(get_password_hash "$1")"
  if [ -z "$hash" ] || [ "$hash" = "" ]; then
    echo "::error::Password hash is null/empty for role $1"
    return 1
  fi
  echo "Password hash present for $1: ${hash:0:20}..."
}

wait_for_password_hash_change() {
  local role="$1" previous_hash="$2"
  for i in $(seq 1 40); do
    local current
    current="$(get_password_hash "$role")"
    if [ -n "$current" ] && [ "$current" != "$previous_hash" ]; then
      echo "Password hash changed for $role"
      return 0
    fi
    echo "Waiting for $role password hash to change... (attempt $i/40)"
    sleep 5
  done
  echo "::error::Password hash for $role did not change"
  echo "Previous: $previous_hash"
  echo "Current:  $(get_password_hash "$role")"
  return 1
}

wait_for_password_hash_stable() {
  local role="$1" expected_hash="$2"
  for i in $(seq 1 6); do
    sleep 5
    local current
    current="$(get_password_hash "$role")"
    if [ -z "$current" ] || [ "$current" != "$expected_hash" ]; then
      echo "::error::Password hash for $role changed unexpectedly"
      echo "Expected: $expected_hash"
      echo "Current:  $current"
      return 1
    fi
    echo "Password hash still stable for $role (attempt $i/6)"
  done
}

# -- Secret helpers -----------------------------------------------------------

assert_secret_has_keys() {
  local name="$1"; shift
  for key in "$@"; do
    local value
    value="$(kubectl get secret "$name" -o "jsonpath={.data.$key}" 2>/dev/null || true)"
    if [ -z "$value" ]; then
      echo "::error::Secret $name is missing key $key"
      return 1
    fi
  done
  echo "Secret $name contains expected keys: $*"
}

upsert_secret() {
  local name="$1"; shift
  local args=()
  for kv in "$@"; do
    args+=(--from-literal="$kv")
  done
  kubectl create secret generic "$name" "${args[@]}" \
    --dry-run=client -o yaml | kubectl apply -f -
}

# -- Operator helpers ---------------------------------------------------------

assert_operator_logs_clean() {
  local forbidden="$1"
  local logs
  logs="$(kubectl -n pgroles-system logs deployment/pgroles-operator --tail=500 2>/dev/null || true)"
  if printf '%s' "$logs" | grep -qF "$forbidden"; then
    echo "::error::Operator logs contain forbidden string: $forbidden"
    return 1
  fi
  echo "Operator logs clean (no '$forbidden')"
}

# -- Plan helpers -------------------------------------------------------------

wait_for_plan_phase() {
  local plan="$1" expected_phase="$2"
  for i in $(seq 1 30); do
    phase="$(kubectl get pgplan "$plan" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" = "$expected_phase" ]; then
      echo "$plan reached phase=$expected_phase"
      return 0
    fi
    echo "Waiting for $plan phase=$expected_phase (current=$phase)... ($i/30)"
    sleep 3
  done
  echo "::error::$plan did not reach phase=$expected_phase within timeout"
  kubectl get pgplan "$plan" -o yaml || true
  return 1
}

approve_plan() {
  local plan="$1"
  kubectl annotate pgplan "$plan" pgroles.io/approved=true --overwrite
}

reject_plan() {
  local plan="$1"
  kubectl annotate pgplan "$plan" pgroles.io/rejected=true --overwrite
}

get_plan_sql() {
  local plan="$1"
  local inline
  inline="$(kubectl get pgplan "$plan" -o jsonpath='{.status.sqlInline}' 2>/dev/null || true)"
  if [ -n "$inline" ]; then
    echo "$inline"
    return 0
  fi
  local cm_name cm_key
  cm_name="$(kubectl get pgplan "$plan" -o jsonpath='{.status.sqlRef.name}' 2>/dev/null || true)"
  cm_key="$(kubectl get pgplan "$plan" -o jsonpath='{.status.sqlRef.key}' 2>/dev/null || true)"
  if [ -n "$cm_name" ] && [ -n "$cm_key" ]; then
    kubectl get configmap "$cm_name" -o jsonpath="{.data.${cm_key}}" 2>/dev/null || true
    return 0
  fi
  echo ""
}

wait_for_current_plan_ref() {
  local policy="$1"
  for i in $(seq 1 30); do
    local plan_name
    plan_name="$(kubectl get pgr "$policy" -o jsonpath='{.status.current_plan_ref.name}' 2>/dev/null || true)"
    if [ -n "$plan_name" ]; then
      echo "$plan_name"
      return 0
    fi
    echo "Waiting for $policy currentPlanRef... ($i/30)"
    sleep 3
  done
  echo "::error::$policy did not get currentPlanRef within timeout"
  return 1
}

get_plan_count() {
  local policy="$1"
  kubectl get pgplan -l "pgroles.io/policy=$policy" --no-headers 2>/dev/null | wc -l | tr -d ' '
}
