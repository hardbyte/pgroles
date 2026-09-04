#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
cargo run --bin crdgen -- --docs-dir "$tmpdir/pages" --schemas-dir "$tmpdir/schemas"
if ! diff -ru docs/src/pages/docs/reference "$tmpdir/pages" || ! diff -ru docs/public/crd-reference "$tmpdir/schemas"; then
  echo '::error::CRD reference drift. Run: cargo run --bin crdgen -- --docs-dir docs/src/pages/docs/reference --schemas-dir docs/public/crd-reference'
  exit 1
fi
