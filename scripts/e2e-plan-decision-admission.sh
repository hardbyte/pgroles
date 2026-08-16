#!/usr/bin/env bash
# Plan-decision admission boundary E2E, run only in the Kyverno-secured leg.
#
# The plan CRD's CEL rules make a decision terminal and paired with a
# decidedBy, but CEL cannot see request.userInfo — the Kyverno policy in
# k8s/security/plan-decision-kyverno.yaml is what makes the identity real and
# the approve verb load-bearing. This script tests that boundary in both
# directions on a live API server:
#
#   deny  — patch access to plans/status without the logical approve verb
#           cannot record a decision;
#   allow — a bound approver can, and the decidedBy it *claims* is replaced
#           with the identity the API server authenticated;
#   exempt — the operator's own status writes pass the policy untouched,
#           proven end to end by the approved plan actually executing.
set -euo pipefail
source scripts/e2e-helpers.sh

echo "Install the plan-decision admission policy and test identities"
kubectl apply -f k8s/security/plan-decision-kyverno.yaml
kubectl apply -f k8s/security/plan-decision-e2e-rbac.yaml
kubectl wait --for=condition=Ready \
  clusterpolicy/pgroles-plan-decision-authorization --timeout=120s

echo "RBAC shape: the approve verb sits exactly where it should"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as=system:serviceaccount:default:plan-approver -n default)" = "yes"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as=system:serviceaccount:default:plan-status-writer -n default)" = "no"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as=system:serviceaccount:pgroles-system:pgroles-operator -n default)" = "no"

echo "A manual-approval policy opens a plan under the enforcing admission policy"
# The operator writes this plan's entire status while the ClusterPolicy is
# enforcing: creation (Approved=False), revalidation, and later execution.
# The plan existing at all is the first half of the operator-exemption proof.
kubectl apply -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: admission-gate-policy
  namespace: default
spec:
  connection:
    secretRef:
      name: postgres-credentials
  mode: apply
  approval: manual
  reconciliation_mode: additive
  interval: 30s
  roles:
    - name: admission_gate_user
      login: false
      comment: created only through an admission-authorised approval
EOF
plan_name="$(wait_for_current_plan_ref admission-gate-policy)"
assert_role_absent admission_gate_user

echo "Deny: status patch access without the approve verb records nothing"
if DECIDE_AS=system:serviceaccount:default:plan-status-writer \
  approve_plan "$plan_name"; then
  echo "::error::a caller without the approve verb recorded an approval"
  exit 1
fi
if DECIDE_AS=system:serviceaccount:default:plan-status-writer \
  reject_plan "$plan_name"; then
  echo "::error::a caller without the approve verb recorded a denial"
  exit 1
fi
assert_role_absent admission_gate_user

echo "Allow: a bound approver approves, and the forged decider is replaced"
DECIDE_AS=system:serviceaccount:default:plan-approver \
  DECIDE_BY=forged-approver \
  approve_plan "$plan_name"
decided="$(kubectl get pgplan "$plan_name" -o jsonpath='{.status.decidedBy.username}')"
test "$decided" = "system:serviceaccount:default:plan-approver" || {
  echo "::error::decidedBy holds '$decided', not the authenticated approver"
  exit 1
}

echo "Exempt: the operator's execution writes pass the policy and the plan applies"
wait_for_plan_phase "$plan_name" Applied
assert_role_exists admission_gate_user

echo "Cleanup"
kubectl delete pgr admission-gate-policy --wait=true
pg_query "DROP ROLE IF EXISTS admission_gate_user;"

echo "Plan-decision admission boundary E2E passed"
