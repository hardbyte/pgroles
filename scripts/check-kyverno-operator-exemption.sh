#!/usr/bin/env bash
# Assert the plan-decision Kyverno policy tells the operator's own plan-status
# writes from a reviewer's decision by authorization, not by identity.
#
# The exemption decides whether a status write is subject to the approve-verb
# check. Keying it on a ServiceAccount username makes it install-specific, and
# wrong in two silent ways: it stalls plans when it names an account the
# operator does not run as, and it hands the approve-verb bypass to whoever can
# create that account when it names one this install does not own. The policy
# therefore asks a SubjectAccessReview for the logical `manage` verb, which the
# operator's controller role grants.
#
# What that shape has to keep true is checked here rather than eyeballed: the
# policy renders identically for every install, it names no ServiceAccount, it
# actually performs the `manage` review, and `manage` is granted to controllers
# and withheld from reviewers.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

chart=charts/pgroles-operator
policy_file="$chart/files/kyverno-plan-decision.yaml"
mirror=k8s/security/plan-decision-kyverno.yaml

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

failed=0

# Reads a manifest stream on stdin and exits 0 when the named Role or
# ClusterRole grants `manage` on postgrespolicies.
grants_manage="$tmpdir/grants_manage.py"
cat >"$grants_manage" <<'PY'
import sys
import yaml

role = sys.argv[1]
for doc in yaml.safe_load_all(sys.stdin):
    if not doc or doc.get("kind") not in ("Role", "ClusterRole"):
        continue
    if doc["metadata"]["name"] != role:
        continue
    for rule in doc.get("rules") or []:
        if ("pgroles.io" in (rule.get("apiGroups") or [])
                and "postgrespolicies" in (rule.get("resources") or [])
                and "manage" in (rule.get("verbs") or [])):
            sys.exit(0)
sys.exit(1)
PY

# Render only the admission policies, so install-specific objects such as the
# Deployment and the ServiceAccount stay out of the comparison, and nothing
# belonging to the ephemeral-access policy can satisfy an assertion here.
render_policy() {
  helm template pgroles-operator "$chart" \
    --show-only templates/admission-policies.yaml \
    --set admissionPolicies.enabled=true \
    --set admissionPolicies.ephemeralAccess.enabled=false \
    "$@"
}

render_rbac() {
  helm template pgroles-operator "$chart" \
    --show-only templates/clusterrole.yaml "$@"
}

# Guard against a vacuous pass: every assertion below is a search over rendered
# output, and an empty render satisfies most of them.
default_render="$(render_policy --namespace pgroles-system)"
if ! grep -q 'name: pgroles-plan-decision-authorization' <<<"$default_render"; then
  echo "::error::the chart did not render the plan-decision ClusterPolicy; the assertions below would be meaningless"
  exit 1
fi

# The regression this exists for: nothing about the install may reach the
# policy. Byte-identical renders across names and namespaces is the strongest
# statement of that, and it fails for any substitution that creeps back in.
alt_render="$(render_policy --namespace pgroles-alt \
  --set operator.serviceAccount.name=pgroles-operator-alt)"
preprovisioned_render="$(render_policy --namespace pgroles-elsewhere \
  --set operator.serviceAccount.create=false \
  --set operator.serviceAccount.name=preprovisioned-sa)"

if [ "$default_render" != "$alt_render" ]; then
  echo "::error::the rendered plan-decision policy changes with operator.serviceAccount.name and the release namespace"
  diff <(printf '%s\n' "$default_render") <(printf '%s\n' "$alt_render") || true
  failed=1
fi
if [ "$default_render" != "$preprovisioned_render" ]; then
  echo "::error::the rendered plan-decision policy changes with an externally managed ServiceAccount"
  diff <(printf '%s\n' "$default_render") <(printf '%s\n' "$preprovisioned_render") || true
  failed=1
fi

# Identical-but-wrong is still possible: a literal default is identical
# everywhere too. Neither copy may name a ServiceAccount subject at all.
for file in "$policy_file" "$mirror"; do
  if grep -nE '^[^#]*system:serviceaccount:' "$file"; then
    echo "::error::${file} names a ServiceAccount subject. The operator exemption is authorization-based; it must not depend on an identity."
    failed=1
  fi
done
if grep -q 'system:serviceaccount:' <<<"$default_render"; then
  echo "::error::the rendered plan-decision policy names a ServiceAccount subject"
  failed=1
fi

# ...and the replacement must actually be present. Both decision rules carry
# the review, so the expected count is 2.
manage_reviews="$(grep -c 'verb: manage' <<<"$default_render" || true)"
if [ "$manage_reviews" -ne 2 ]; then
  echo "::error::the rendered plan-decision policy performs ${manage_reviews} manage reviews, expected 2"
  failed=1
fi

# The exemption is only as narrow as the grant. `manage` on postgrespolicies
# must come from the operator's controller role, and must not ride along with
# the reviewer role — a reviewer holding it would be exempt from the very check
# the reviewer role exists to enforce.
assert_grants_manage() {
  local label="$1" role="$2"
  if ! python3 "$grants_manage" "$role" >/dev/null; then
    echo "::error::${label}: ${role} does not grant manage on postgrespolicies"
    failed=1
  fi
}

assert_withholds_manage() {
  local label="$1" role="$2"
  if python3 "$grants_manage" "$role" >/dev/null; then
    echo "::error::${label}: ${role} grants manage on postgrespolicies; that exempts it from the approve-verb check"
    failed=1
  fi
}

assert_grants_manage "chart" pgroles-operator \
  <<<"$(render_rbac --namespace pgroles-system)"
assert_grants_manage "chart with watchNamespace" pgroles-operator \
  <<<"$(render_rbac --namespace pgroles-system --set operator.watchNamespace=apps)"
assert_grants_manage "k8s/deploy/rbac.yaml" pgroles-operator \
  <"k8s/deploy/rbac.yaml"

# The reviewer role ships inside the policy manifest itself.
assert_withholds_manage "chart" pgroles-plan-approver <<<"$default_render"
assert_withholds_manage "$mirror" pgroles-plan-approver <"$mirror"

if [ "$failed" -ne 0 ]; then
  exit 1
fi

echo "The plan-decision operator exemption is authorization-based and install-independent."
