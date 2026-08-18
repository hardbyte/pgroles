#!/usr/bin/env bash
# Verify the chart-less Kyverno mirrors in k8s/security/ stay in sync with the
# canonical chart copies in charts/pgroles-operator/files/.
#
# The two copies legitimately differ only in their leading header comments —
# one is applied by helm, the other with kubectl. Neither carries anything
# install-specific, so everything else must be byte-identical, and drift is
# checked with comments and blank lines stripped.
#
# The exemption shape itself is checked by
# scripts/check-kyverno-operator-exemption.sh; a subject hardcoded into both
# copies at once is invisible to a copy-to-copy diff.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

normalize() {
  grep -vE '^\s*#' "$1" | grep -vE '^\s*$'
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
