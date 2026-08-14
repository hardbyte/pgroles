#!/usr/bin/env bash
# Fail if charts/pgroles-operator/README.md is out of date with respect to
# values.yaml, Chart.yaml, and README.md.gotmpl.
#
# Regenerating leaves the corrected file in the working tree, so running this
# locally is also how you fix the drift it reports.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

HELM_DOCS_VERSION="${HELM_DOCS_VERSION:-1.14.2}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if command -v helm-docs >/dev/null 2>&1; then
  helm_docs=helm-docs
else
  case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
      echo "::error::unsupported architecture $(uname -m) for helm-docs" >&2
      exit 1
      ;;
  esac
  url="https://github.com/norwoodj/helm-docs/releases/download/v${HELM_DOCS_VERSION}/helm-docs_${HELM_DOCS_VERSION}_$(uname -s)_${arch}.tar.gz"
  curl -fsSL "$url" | tar -xz -C "$tmpdir" helm-docs
  helm_docs="$tmpdir/helm-docs"
fi

"$helm_docs" --chart-search-root charts

if ! git diff --exit-code -- charts/pgroles-operator/README.md; then
  echo "::error::charts/pgroles-operator/README.md is out of date. Regenerate with: helm-docs --chart-search-root charts"
  exit 1
fi
