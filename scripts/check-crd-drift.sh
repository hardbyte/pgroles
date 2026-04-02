#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

generated_crd="$(mktemp)"
trap 'rm -f "$generated_crd"' EXIT

cargo run --bin crdgen > "$generated_crd"

check_drift() {
  local committed_path="$1"

  if ! diff -u "$committed_path" "$generated_crd"; then
    echo "::error::${committed_path} is out of date. Regenerate with 'cargo run --bin crdgen > k8s/crd.yaml' and copy it to charts/pgroles-operator/crds/postgrespolicies.pgroles.io.yaml."
    exit 1
  fi
}

check_drift "k8s/crd.yaml"
check_drift "charts/pgroles-operator/crds/postgrespolicies.pgroles.io.yaml"
