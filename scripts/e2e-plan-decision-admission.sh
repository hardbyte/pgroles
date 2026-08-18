#!/usr/bin/env bash
# Plan-decision admission boundary E2E, run only in the Kyverno-secured leg.
#
# The plan CRD's CEL rules make a decision terminal and paired with a
# decidedBy, but CEL cannot see request.userInfo — the Kyverno policy in
# k8s/security/plan-decision-kyverno.yaml is what makes the identity real and
# the approve verb load-bearing. This script tests that boundary on a live API
# server:
#
#   deny   — patch access to plans/status without the logical approve verb
#            cannot record a decision;
#   allow  — a bound approver can, and the decidedBy it *claims* is replaced
#            with the identity the API server authenticated;
#   exempt — a controller holding the logical `manage` verb writes decisions
#            untouched, and two differently named controllers in different
#            namespaces are exempt at the same time;
#   named  — an account named like the default operator, without the `manage`
#            grant, is not exempt.
#
# The last two are what distinguish an exemption keyed on authorization from
# one keyed on a ServiceAccount identity.
set -euo pipefail
source scripts/e2e-helpers.sh

policy_name=pgroles-plan-decision-authorization
operator_subject=system:serviceaccount:pgroles-system:pgroles-operator
manager_subject=system:serviceaccount:pgroles-alt:pgroles-operator-alt
namesake_subject=system:serviceaccount:pgroles-alt:pgroles-operator

echo "Install the plan-decision admission policy and test identities"
kubectl apply -f k8s/security/plan-decision-e2e-rbac.yaml
kubectl apply -f k8s/security/plan-decision-kyverno.yaml
kubectl wait --for=condition=Ready "clusterpolicy/${policy_name}" --timeout=120s

# Guard against a vacuous pass: if the policy that ended up served is not the
# one under test, every "was this admitted?" check below measures the wrong
# thing. Both decision rules must exempt on the manage review, and neither may
# key on an identity.
echo "Guard: the served policy exempts by authorization, not by identity"
live="$(kubectl get "clusterpolicy/${policy_name}" -o json)"
manage_reviews="$(grep -c '"verb": "manage"' <<<"$live" || true)"
if [ "$manage_reviews" -ne 2 ]; then
  echo "::error::${policy_name} performs ${manage_reviews} manage reviews, expected 2"
  exit 1
fi
if grep -q 'system:serviceaccount:' <<<"$live"; then
  echo "::error::${policy_name} names a ServiceAccount subject"
  grep -n 'system:serviceaccount:' <<<"$live" || true
  exit 1
fi

echo "RBAC shape: approve and manage sit exactly where they should"
can_i() {
  kubectl auth can-i "$1" postgrespolicies.pgroles.io --as="$2" -n default
}
test "$(can_i approve system:serviceaccount:default:plan-approver)" = "yes"
test "$(can_i manage system:serviceaccount:default:plan-approver)" = "no"
test "$(can_i approve system:serviceaccount:default:plan-status-writer)" = "no"
test "$(can_i manage system:serviceaccount:default:plan-status-writer)" = "no"
# The controllers: authority to write plan status, no authority to approve.
test "$(can_i approve "$operator_subject")" = "no"
test "$(can_i manage "$operator_subject")" = "yes"
test "$(can_i approve "$manager_subject")" = "no"
test "$(can_i manage "$manager_subject")" = "yes"
# Same name as the default operator, no controller grant.
test "$(can_i approve "$namesake_subject")" = "no"
test "$(can_i manage "$namesake_subject")" = "no"

# A plan under a manual-approval policy, opened while the ClusterPolicy is
# enforcing. Prints the plan name.
open_plan() {
  local policy="$1" role="$2"
  kubectl apply -f - >&2 <<EOF
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: ${policy}
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
    - name: ${role}
      login: false
      comment: created only through an admission-authorised approval
EOF
  wait_for_current_plan_ref "$policy"
}

echo "A manual-approval policy opens a plan under the enforcing admission policy"
# The operator writes this plan's entire status while the ClusterPolicy is
# enforcing: creation (Approved=False), revalidation, and later execution.
# The plan existing at all is the first half of the operator-exemption proof.
plan_name="$(open_plan admission-gate-policy admission_gate_user)"
assert_role_absent admission_gate_user

echo "Deny: status patch access without approve or manage records nothing"
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

# ---------------------------------------------------------------------------
# The exemption is the `manage` grant, not a ServiceAccount name.
#
# Everything above runs under the identity the shipped defaults name, so it
# passes just as well against a policy with that identity hardcoded. What
# follows does not: a second controller under a different name and namespace
# decides successfully, the default-named operator keeps working through the
# same window, and an account that merely carries the default operator's name
# is refused.
# ---------------------------------------------------------------------------
echo "A second controller identity decides without the approve verb"
manager_plan="$(open_plan admission-manager-policy admission_manager_user)"
DECIDE_AS="$manager_subject" DECIDE_BY=controller-claimed-identity \
  approve_plan "$manager_plan"

# An exempt writer skips the mutate rule too, so the claimed decider stands.
# A reviewer's would have been replaced with its authenticated username.
manager_decided="$(kubectl get pgplan "$manager_plan" -o jsonpath='{.status.decidedBy.username}')"
test "$manager_decided" = "controller-claimed-identity" || {
  echo "::error::decidedBy holds '$manager_decided'; the second controller was treated as a reviewer"
  exit 1
}

# The plan reaching Applied is the in-cluster operator — a *differently* named
# controller in a different namespace — writing execution status through the
# same enforcing policy that just admitted the decision above. Both controller
# identities are therefore exempt simultaneously, which no single hardcoded
# subject can express.
wait_for_plan_phase "$manager_plan" Applied
assert_role_exists admission_manager_user

echo "An account named like the operator, without the manage grant, is refused"
namesake_plan="$(open_plan admission-namesake-policy admission_namesake_user)"
if DECIDE_AS="$namesake_subject" approve_plan "$namesake_plan"; then
  echo "::error::'${namesake_subject}' recorded a decision holding neither approve nor manage; the exemption is keyed on a name, not on authorization"
  exit 1
fi
assert_role_absent admission_namesake_user

echo "Cleanup"
kubectl delete pgr admission-gate-policy admission-manager-policy \
  admission-namesake-policy --wait=true
pg_query "DROP ROLE IF EXISTS admission_gate_user;"
pg_query "DROP ROLE IF EXISTS admission_manager_user;"

echo "Plan-decision admission boundary E2E passed"
