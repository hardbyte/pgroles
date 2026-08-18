#!/usr/bin/env bash
# Verify the chart-less Kyverno mirrors in k8s/security/ stay in sync with the
# canonical chart copies in charts/pgroles-operator/files/.
#
# The two copies legitimately differ only in their leading header comments —
# one is applied by helm, the other by scripts/render-kyverno-policies.sh.
# Everything else, the __PGROLES_OPERATOR_SUBJECT__ placeholder included, must
# be byte-identical, so drift is checked with comments and blank lines
# stripped.
#
# This also guards the placeholder itself: a literal ServiceAccount subject in
# either copy is the bug that made the exemption install-specific, and it is
# invisible in a diff between two copies that were hardcoded together.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

placeholder="__PGROLES_OPERATOR_SUBJECT__"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

normalize() {
  grep -vE '^\s*#' "$1" | grep -vE '^\s*$'
}

failed=0

# Every rule that exempts the operator must key on the placeholder, so both
# rules of the plan-decision policy are expected to carry one.
expected_placeholders=2

check_subject_is_templated() {
  local file="$1"
  local found

  found="$(grep -cF "$placeholder" "$file" || true)"
  if [ "$found" -ne "$expected_placeholders" ]; then
    echo "::error::${file} has ${found} ${placeholder} occurrences, expected ${expected_placeholders}."
    failed=1
  fi

  if grep -nE '^[^#]*value:[[:space:]]*"?system:serviceaccount:' "$file"; then
    echo "::error::${file} pins a literal ServiceAccount subject. The operator exemption must stay templated; run scripts/render-kyverno-policies.sh to produce an install-specific manifest."
    failed=1
  fi
}

check_pair() {
  local chart_copy="$1"
  local mirror="$2"

  normalize "$chart_copy" >"$tmpdir/chart.yaml"
  normalize "$mirror" >"$tmpdir/mirror.yaml"

  if ! diff -u "$tmpdir/mirror.yaml" "$tmpdir/chart.yaml" >/dev/null 2>&1; then
    echo "::error::${mirror} has drifted from ${chart_copy} (the canonical copy). Update the mirror to match."
    diff -u "$tmpdir/mirror.yaml" "$tmpdir/chart.yaml" || true
    failed=1
  fi
}

check_pair charts/pgroles-operator/files/kyverno-plan-decision.yaml \
  k8s/security/plan-decision-kyverno.yaml
check_pair charts/pgroles-operator/files/kyverno-ephemeral-access.yaml \
  k8s/security/ephemeral-access-kyverno.yaml

check_subject_is_templated charts/pgroles-operator/files/kyverno-plan-decision.yaml
check_subject_is_templated k8s/security/plan-decision-kyverno.yaml

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Kyverno policy mirrors are in sync."
