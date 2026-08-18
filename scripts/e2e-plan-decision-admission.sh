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
#
# It then re-renders the same policy for a *different* operator identity and
# repeats the exemption test both ways, which is what distinguishes a policy
# bound to the configured install from one bound to a literal default.
set -euo pipefail
source scripts/e2e-helpers.sh

policy_name=pgroles-plan-decision-authorization
operator_subject=system:serviceaccount:pgroles-system:pgroles-operator
alt_subject=system:serviceaccount:pgroles-alt:pgroles-operator-alt

# Install the policy rendered for one operator identity and block until the
# live ClusterPolicy carries exactly that subject.
#
# Asserting on the served object is the guard against a vacuous pass: if the
# render or the apply silently did nothing, every "was this admitted?" check
# below would be measuring the previous policy, or no policy at all.
install_policy_for() {
  local namespace="$1" service_account="$2"
  local subject="system:serviceaccount:${namespace}:${service_account}"
  local live found

  scripts/render-kyverno-policies.sh \
    --namespace "$namespace" --service-account "$service_account" \
    k8s/security/plan-decision-kyverno.yaml | kubectl apply -f -
  kubectl wait --for=condition=Ready "clusterpolicy/${policy_name}" --timeout=120s

  # JSON, not YAML: the served object quotes every string, so the match cannot
  # depend on how the API server chose to render a scalar.
  live="$(kubectl get "clusterpolicy/${policy_name}" -o json)"
  found="$(grep -cF "\"${subject}\"" <<<"$live" || true)"
  if [ "$found" -ne 2 ]; then
    echo "::error::${policy_name} exempts '${subject}' in ${found} rules, expected 2"
    grep -nE 'system:serviceaccount:' <<<"$live" || true
    exit 1
  fi
}

echo "Install the plan-decision admission policy and test identities"
kubectl apply -f k8s/security/plan-decision-e2e-rbac.yaml
install_policy_for pgroles-system pgroles-operator

echo "RBAC shape: the approve verb sits exactly where it should"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as=system:serviceaccount:default:plan-approver -n default)" = "yes"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as=system:serviceaccount:default:plan-status-writer -n default)" = "no"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as="$operator_subject" -n default)" = "no"
test "$(kubectl auth can-i approve postgrespolicies.pgroles.io \
  --as="$alt_subject" -n default)" = "no"

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

# ---------------------------------------------------------------------------
# The exemption is bound to the configured install, not to a default name.
#
# Everything above runs under the identity the shipped defaults happen to name,
# so it passes just as well against a policy with that identity hardcoded. The
# rest of this script re-renders the policy for a different namespace and
# ServiceAccount and asserts the exemption moved with it: the alt identity is
# now exempt despite holding no approve verb, and the default identity is not.
# ---------------------------------------------------------------------------
echo "Rebind: render the policy for a non-default operator identity"
install_policy_for pgroles-alt pgroles-operator-alt

echo "The configured operator identity decides without the approve verb"
alt_plan="$(open_plan admission-rebind-policy admission_rebind_user)"

# Kyverno reloads a replaced ClusterPolicy asynchronously, so the first
# attempts can still be judged by the previous rules, under which this identity
# is a reviewer and is denied. A denied patch records nothing, so retrying is
# safe, and success is the point at which the new rules are provably live.
admitted=false
for attempt in $(seq 1 30); do
  if DECIDE_AS="$alt_subject" DECIDE_BY=operator-claimed-identity \
    approve_plan "$alt_plan"; then
    admitted=true
    break
  fi
  echo "Waiting for the rebound policy to take effect (attempt $attempt/30)"
  sleep 2
done
if [ "$admitted" != true ]; then
  echo "::error::the configured operator identity '${alt_subject}' was refused; the exemption did not follow the rendered subject"
  exit 1
fi

# An exempt writer skips the mutate rule too, so the claimed decider stands.
# A reviewer's would have been replaced with its authenticated username.
alt_decided="$(kubectl get pgplan "$alt_plan" -o jsonpath='{.status.decidedBy.username}')"
test "$alt_decided" = "operator-claimed-identity" || {
  echo "::error::decidedBy holds '$alt_decided'; the exempt operator identity was treated as a reviewer"
  exit 1
}

wait_for_plan_phase "$alt_plan" Applied
assert_role_exists admission_rebind_user

echo "The default operator identity is no longer exempt"
stale_plan="$(open_plan admission-stale-subject-policy admission_stale_user)"
if DECIDE_AS="$operator_subject" approve_plan "$stale_plan"; then
  echo "::error::'${operator_subject}' decided a plan while the policy was rendered for '${alt_subject}'; the exemption is pinned to a literal, not to the configured identity"
  exit 1
fi
assert_role_absent admission_stale_user

echo "Cleanup"
# Restore the policy for the identity the operator in this cluster actually
# runs as, so anything after this point sees a consistent admission chain.
install_policy_for pgroles-system pgroles-operator
kubectl delete pgr admission-gate-policy admission-rebind-policy \
  admission-stale-subject-policy --wait=true
pg_query "DROP ROLE IF EXISTS admission_gate_user;"
pg_query "DROP ROLE IF EXISTS admission_rebind_user;"

echo "Plan-decision admission boundary E2E passed"
