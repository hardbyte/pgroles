#!/usr/bin/env bash
# Verify the chart-less Kyverno mirrors in k8s/security/ stay in sync with the
# canonical chart copies in charts/pgroles-operator/files/.
#
# The two copies legitimately differ in exactly two ways: their leading header
# comments, and the operator exemption subject (the chart copy carries the
# __PGROLES_OPERATOR_SUBJECT__ placeholder that helm substitutes; the mirror
# pins the default namespace and ServiceAccount name). Everything else must be
# byte-identical, so drift is checked on a normalized form: comments stripped,
# placeholder substituted with the default subject.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

default_subject="system:serviceaccount:pgroles-system:pgroles-operator"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

normalize() {
  # Drop full-line comments and blank lines; substitute the chart placeholder.
  sed -e 's/__PGROLES_OPERATOR_SUBJECT__/'"$default_subject"'/g' "$1" |
    grep -vE '^\s*#' | grep -vE '^\s*$'
}

failed=0

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

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Kyverno policy mirrors are in sync."
