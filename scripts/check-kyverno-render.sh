#!/usr/bin/env bash
# Assert that the operator exemption in the plan-decision Kyverno policy
# follows the install identity, through both supported rendering paths.
#
# The exemption decides whether a status write is the operator's own or a
# reviewer decision subject to the approve verb. A subject that does not track
# `operator.serviceAccount.name` and the install namespace is wrong in one of
# two ways: it stalls plans when it names nobody, or it exempts an account this
# install does not own. Neither is visible in a chart that renders cleanly, so
# the subject is asserted here rather than eyeballed.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

chart=charts/pgroles-operator
placeholder="__PGROLES_OPERATOR_SUBJECT__"

failed=0

# Count the exemption values in a rendered manifest that equal $2. Both rules
# of the policy carry one, so the expected count is 2 — asserting the count,
# not just presence, catches a substitution that reached only one rule.
count_subject() {
  grep -cF "value: \"$2\"" <<<"$1" || true
}

assert_subject() {
  local label="$1" expected="$2" rendered="$3"
  local found

  if grep -qF "$placeholder" <<<"$rendered"; then
    echo "::error::${label}: rendered policy still contains ${placeholder}"
    failed=1
    return
  fi

  found="$(count_subject "$rendered" "$expected")"
  if [ "$found" -ne 2 ]; then
    echo "::error::${label}: expected 2 exemptions for '${expected}', found ${found}"
    grep -nE 'value: "system:serviceaccount:' <<<"$rendered" || true
    failed=1
  fi
}

render_chart() {
  helm template pgroles-operator "$chart" \
    --set admissionPolicies.enabled=true \
    --set admissionPolicies.ephemeralAccess.enabled=false \
    "$@"
}

# Default install: the fullname helper resolves the ServiceAccount name.
assert_subject "chart defaults" \
  "system:serviceaccount:pgroles-system:pgroles-operator" \
  "$(render_chart --namespace pgroles-system)"

# The regression this guards: a non-default name and namespace must both reach
# the exemption. A policy hardcoded to the defaults passes the case above and
# fails this one.
assert_subject "chart with custom ServiceAccount and namespace" \
  "system:serviceaccount:pgroles-alt:pgroles-operator-alt" \
  "$(render_chart --namespace pgroles-alt \
    --set operator.serviceAccount.name=pgroles-operator-alt)"

# An externally managed ServiceAccount goes through the other branch of the
# name helper.
assert_subject "chart with serviceAccount.create=false" \
  "system:serviceaccount:pgroles-alt:preprovisioned-sa" \
  "$(render_chart --namespace pgroles-alt \
    --set operator.serviceAccount.create=false \
    --set operator.serviceAccount.name=preprovisioned-sa)"

# The Deployment and the exemption must name the same account, or the policy
# binds to an identity the operator never presents.
deployment_sa="$(render_chart --namespace pgroles-alt \
  --set operator.serviceAccount.name=pgroles-operator-alt |
  grep -E '^ +serviceAccountName:' | awk '{print $2}')"
if [ "$deployment_sa" != "pgroles-operator-alt" ]; then
  echo "::error::Deployment serviceAccountName is '${deployment_sa}', not the configured name"
  failed=1
fi

# The chart-less path substitutes the same placeholder.
assert_subject "render-kyverno-policies.sh" \
  "system:serviceaccount:pgroles-alt:pgroles-operator-alt" \
  "$(scripts/render-kyverno-policies.sh \
    --namespace pgroles-alt --service-account pgroles-operator-alt \
    k8s/security/plan-decision-kyverno.yaml)"

# Refusing to emit an unusable subject is part of the contract.
if scripts/render-kyverno-policies.sh --namespace pgroles-alt \
  --service-account "" >/dev/null 2>&1; then
  echo "::error::render-kyverno-policies.sh accepted an empty --service-account"
  failed=1
fi
if scripts/render-kyverno-policies.sh --namespace "" \
  --service-account pgroles-operator >/dev/null 2>&1; then
  echo "::error::render-kyverno-policies.sh accepted an empty --namespace"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "Kyverno operator exemption tracks the install identity."
