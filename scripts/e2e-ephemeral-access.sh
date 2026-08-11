#!/usr/bin/env bash
set -euo pipefail

secure_mode="${1:-false}"
source scripts/e2e-helpers.sh

wait_request_phase() {
  local request="$1" expected="$2" attempts="${3:-60}"
  for i in $(seq 1 "$attempts"); do
    phase="$(kubectl get pgear "$request" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" = "$expected" ]; then
      echo "$request reached phase $expected"
      return 0
    fi
    echo "Waiting for $request phase $expected (currently $phase, attempt $i/$attempts)"
    sleep 2
  done
  kubectl get pgear "$request" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=300 || true
  return 1
}

wait_access_policy_accepted() {
  local policy="$1"
  for i in $(seq 1 45); do
    accepted="$(kubectl get pgeap "$policy" -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)"
    if [ "$accepted" = "True" ]; then
      return 0
    fi
    echo "Waiting for $policy Accepted=True (attempt $i/45)"
    sleep 2
  done
  kubectl get pgeap "$policy" -o yaml || true
  return 1
}

wait_policy_generation() {
  local policy="$1"
  for i in $(seq 1 45); do
    generation="$(kubectl get pgr "$policy" -o jsonpath='{.metadata.generation}')"
    observed="$(kubectl get pgr "$policy" -o jsonpath='{.status.observed_generation}' 2>/dev/null || true)"
    if [ "$generation" = "$observed" ]; then
      return 0
    fi
    echo "Waiting for $policy generation $generation (observed $observed, attempt $i/45)"
    sleep 2
  done
  kubectl get pgr "$policy" -o yaml || true
  return 1
}

membership_count() {
  local role="$1" member="$2"
  pg_query "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='$role' AND u.rolname='$member'"
}

assert_membership() {
  local role="$1" member="$2" expected="$3"
  for i in $(seq 1 30); do
    actual="$(membership_count "$role" "$member")"
    if [ "$actual" = "$expected" ]; then
      return 0
    fi
    echo "Waiting for membership $member -> $role to equal $expected (currently $actual)"
    sleep 2
  done
  return 1
}

create_request() {
  local name="$1" policy="$2" duration="$3"
  kubectl create -f - <<EOF
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ${name}
spec:
  accessPolicyRef:
    name: ${policy}
  subject:
    role: ephemeral_e2e_subject
  requestedDuration: ${duration}
  justification: E2E validation
EOF
}

kubectl apply -f k8s/samples/ephemeral-access-e2e.yaml
wait_for_ready_true ephemeral-e2e
wait_access_policy_accepted ephemeral-e2e-automatic
wait_access_policy_accepted ephemeral-e2e-required

if [ "$secure_mode" = "true" ]; then
  if kubectl --as=system:serviceaccount:default:ephemeral-untrusted-requester \
    create -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ephemeral-use-denied
spec:
  accessPolicyRef:
    name: ephemeral-e2e-automatic
  subject:
    role: ephemeral_e2e_subject
  requestedDuration: 10s
  justification: This caller lacks the logical use verb
EOF
  then
    echo "::error::request creation without the logical use verb unexpectedly succeeded"
    exit 1
  fi
  kubectl --as=system:serviceaccount:default:ephemeral-requester create -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ephemeral-use-allowed
spec:
  accessPolicyRef:
    name: ephemeral-e2e-automatic
  subject:
    role: ephemeral_e2e_subject
  requestedDuration: 10s
  justification: Logical use verb validation
EOF
  wait_request_phase ephemeral-use-allowed Active
  kubectl --as=system:serviceaccount:default:ephemeral-requester \
    delete pgear ephemeral-use-allowed --wait=true
fi

echo "Automatic activation, immutable status, scoped plan, and natural expiry"
create_request ephemeral-auto-expiry ephemeral-e2e-automatic 15s
wait_request_phase ephemeral-auto-expiry Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
assert_membership ephemeral_e2e_auditor ephemeral_e2e_subject 1

request_uid="$(kubectl get pgear ephemeral-auto-expiry -o jsonpath='{.metadata.uid}')"
plan_owner_uid="$(kubectl get pgplan -o json | jq -r --arg uid "$request_uid" '.items[] | select(.spec.origin.uid == $uid and .spec.scope.operation == "Activate") | .metadata.ownerReferences[] | select(.controller == true) | .uid' | head -1)"
test "$plan_owner_uid" = "$request_uid"

if kubectl patch pgear ephemeral-auto-expiry --subresource=status --type=merge \
  -p '{"status":{"resolvedAccess":{"bundleHash":"sha256:forged"}}}'; then
  echo "::error::resolvedAccess mutation unexpectedly succeeded"
  exit 1
fi

wait_request_phase ephemeral-auto-expiry Ended
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
assert_membership ephemeral_e2e_auditor ephemeral_e2e_subject 0

echo "Overlapping requests retain the edge until the final owner ends"
create_request ephemeral-overlap-a ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-overlap-a Active
create_request ephemeral-overlap-b ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-overlap-b Active
kubectl delete pgear ephemeral-overlap-a --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-overlap-b --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "A membership made durable during access is retained"
create_request ephemeral-durable-race ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-durable-race Active
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"memberships":[{"role":"ephemeral_e2e_editor","members":[{"name":"ephemeral_e2e_subject","inherit":false}]}]}}'
wait_policy_generation ephemeral-e2e
kubectl delete pgear ephemeral-durable-race --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"memberships":[]}}'
wait_policy_generation ephemeral-e2e
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "An active request blocks durable removal of a role it still needs"
create_request ephemeral-role-drop-block ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-role-drop-block Active
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_auditor","login":false}]}}'
wait_for_ready_reason ephemeral-e2e InvalidSpec
wait_for_last_error_contains ephemeral-e2e "active ephemeral request"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_editor","login":false},{"name":"ephemeral_e2e_auditor","login":false}]}}'
wait_for_ready_true ephemeral-e2e
kubectl delete pgear ephemeral-role-drop-block --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Suspend blocks pending activation but leaves active access unchanged"
create_request ephemeral-active-while-suspended ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-active-while-suspended Active
kubectl patch pgeap ephemeral-e2e-automatic --type=merge -p '{"spec":{"suspend":true}}'
sleep 5
test "$(kubectl get pgear ephemeral-active-while-suspended -o jsonpath='{.status.phase}')" = "Active"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-active-while-suspended --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgeap ephemeral-e2e-automatic --type=merge -p '{"spec":{"suspend":false}}'

create_request ephemeral-pending-suspended ephemeral-e2e-required 45s
wait_request_phase ephemeral-pending-suspended PendingApproval
kubectl patch pgeap ephemeral-e2e-required --type=merge -p '{"spec":{"suspend":true}}'
sleep 6
test "$(kubectl get pgear ephemeral-pending-suspended -o jsonpath='{.status.phase}')" = "PendingApproval"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgeap ephemeral-e2e-required --type=merge -p '{"spec":{"suspend":false}}'
kubectl delete pgear ephemeral-pending-suspended --wait=true

echo "Required approval trust boundary"
create_request ephemeral-required ephemeral-e2e-required 45s
wait_request_phase ephemeral-required PendingApproval
bundle_hash="$(kubectl get pgear ephemeral-required -o jsonpath='{.status.resolvedAccess.bundleHash}')"
granted_duration="$(kubectl get pgear ephemeral-required -o jsonpath='{.status.resolvedAccess.grantedDuration}')"
approval_patch="{\"status\":{\"conditions\":[{\"type\":\"Approved\",\"status\":\"True\",\"reason\":\"E2EApproval\",\"bundleHash\":\"${bundle_hash}\",\"grantedDuration\":\"${granted_duration}\"}]}}"

if [ "$secure_mode" = "true" ]; then
  test "$(kubectl auth can-i approve ephemeralaccesspolicies.pgroles.io --as=system:serviceaccount:pgroles-system:pgroles-operator -n default)" = "no"
  if kubectl --as=system:serviceaccount:default:ephemeral-status-writer \
    patch pgear ephemeral-required --subresource=status --type=merge -p "$approval_patch"; then
    echo "::error::unauthorized approval unexpectedly passed Kyverno"
    exit 1
  fi
  kubectl --as=system:serviceaccount:default:ephemeral-approver \
    patch pgear ephemeral-required --subresource=status --type=merge -p "$approval_patch"
else
  kubectl --as=system:serviceaccount:default:ephemeral-status-writer \
    patch pgear ephemeral-required --subresource=status --type=merge -p "$approval_patch"
fi

wait_request_phase ephemeral-required Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-required --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Access-policy deletion is a revoke-all kill switch"
create_request ephemeral-policy-delete ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-policy-delete Active
kubectl delete pgeap ephemeral-e2e-automatic --wait=true
kubectl wait --for=delete pgear/ephemeral-policy-delete --timeout=90s
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Target-policy deletion waits for scoped revocation"
kubectl apply -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessPolicy
metadata:
  name: ephemeral-e2e-target-delete
spec:
  postgresPolicyRef:
    name: ephemeral-e2e
  memberships:
    - role: ephemeral_e2e_editor
      inherit: false
  maximumDuration: 2m
  defaultDuration: 1m
  pendingRequestTTL: 1m
  justification:
    required: true
  approval:
    mode: Automatic
EOF
wait_access_policy_accepted ephemeral-e2e-target-delete
create_request ephemeral-target-delete ephemeral-e2e-target-delete 1m
wait_request_phase ephemeral-target-delete Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgr ephemeral-e2e --wait=true --timeout=120s
kubectl wait --for=delete pgeap/ephemeral-e2e-target-delete --timeout=90s
kubectl wait --for=delete pgear/ephemeral-target-delete --timeout=90s
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Structured lifecycle audit event reached the OTLP collector"
for i in $(seq 1 30); do
  # Read the complete stream without buffering it in the shell. Metrics and
  # ordinary reconciliation logs are deliberately noisy in this shared debug
  # collector, so a fixed tail can discard the lifecycle transition.
  if kubectl -n pgroles-system logs deployment/otel-collector 2>/dev/null |
    awk '
      /pgroles\.ephemeral_access\.lifecycle/ { lifecycle = 1 }
      /bundle_hash/ { bundle = 1 }
      END { exit !(lifecycle && bundle) }
    '
  then
    exit 0
  fi
  echo "Waiting for structured access audit event (attempt $i/30)"
  sleep 2
done

kubectl -n pgroles-system logs deployment/pgroles-operator --tail=300 || true
kubectl -n pgroles-system logs deployment/otel-collector --tail=500 || true
exit 1
