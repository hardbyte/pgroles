#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# crdgen outputs multiple CRDs separated by "---"
cargo run --bin crdgen > "$tmpdir/all.json"

# Split on the --- separator
python3 -c "
import sys
content = open('$tmpdir/all.json').read()
parts = content.split('\n---\n')
for i, part in enumerate(parts):
    open(f'$tmpdir/crd-{i}.json', 'w').write(part.strip() + '\n')
"

failed=0

check_drift() {
  local committed_path="$1"
  local generated_path="$2"

  if ! diff -u "$committed_path" "$generated_path" >/dev/null 2>&1; then
    echo "::error::${committed_path} is out of date. Regenerate with 'cargo run --bin crdgen' and split the output."
    diff -u "$committed_path" "$generated_path" || true
    failed=1
  fi
}

# PostgresPolicy CRD (first document)
check_drift "k8s/crd.yaml" "$tmpdir/crd-0.json"
check_drift "charts/pgroles-operator/crds/postgrespolicies.pgroles.io.yaml" "$tmpdir/crd-0.json"

# PostgresPolicyPlan CRD (second document)
check_drift "k8s/postgrespolicyplan-crd.yaml" "$tmpdir/crd-1.json"
check_drift "charts/pgroles-operator/crds/postgrespolicyplans.pgroles.io.yaml" "$tmpdir/crd-1.json"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
