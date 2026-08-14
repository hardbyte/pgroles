#!/usr/bin/env bash
# Fail if charts/pgroles-operator/README.md is out of date with respect to
# values.yaml, Chart.yaml, and README.md.gotmpl.
#
# Regenerating leaves the corrected file in the working tree, so running this
# locally is also how you fix the drift it reports.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

HELM_DOCS_VERSION=1.14.2

# SHA-256 of each release archive, from the publisher's checksums.txt at the
# time this version was pinned. Verifying against values committed here rather
# than against a checksums file fetched alongside the archive is the point: an
# attacker who can substitute one asset can substitute both. Bumping
# HELM_DOCS_VERSION means replacing these too.
helm_docs_sha256() {
  case "$1" in
    Linux_x86_64) echo a8cf72ada34fad93285ba2a452b38bdc5bd52cc9a571236244ec31022928d6cc ;;
    Linux_arm64) echo c3787212332386dcd122debef7848feb165aa701467ae3e3442df7638f3ac4e4 ;;
    Darwin_x86_64) echo b2f1ffd0feef8dc0901a38a2053481d1d67b63ca30da4ac774166c6b52fa2245 ;;
    Darwin_arm64) echo 2d8399db5b33d240d5f8985241bcf5483563150b968e3229823822979f3e4b8b ;;
    *) return 1 ;;
  esac
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# A helm-docs already on PATH is only trusted at the pinned version: output
# differs between releases, so an unpinned local tool turns into a local pass
# and a CI failure.
helm_docs=""
if command -v helm-docs >/dev/null 2>&1; then
  if helm-docs --version 2>/dev/null | grep -qF "$HELM_DOCS_VERSION"; then
    helm_docs=helm-docs
  else
    echo "note: ignoring helm-docs $(helm-docs --version 2>/dev/null | tr -d '\n')" \
      "on PATH; this check pins ${HELM_DOCS_VERSION}" >&2
  fi
fi

if [ -z "$helm_docs" ]; then
  case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
      echo "::error::unsupported architecture $(uname -m) for helm-docs" >&2
      exit 1
      ;;
  esac
  platform="$(uname -s)_${arch}"

  if ! expected="$(helm_docs_sha256 "$platform")"; then
    echo "::error::no pinned helm-docs checksum for ${platform}" >&2
    exit 1
  fi

  archive="$tmpdir/helm-docs.tar.gz"
  url="https://github.com/norwoodj/helm-docs/releases/download/v${HELM_DOCS_VERSION}/helm-docs_${HELM_DOCS_VERSION}_${platform}.tar.gz"
  curl -fsSL -o "$archive" "$url"

  actual="$(sha256sum "$archive" | cut -d' ' -f1)"
  if [ "$actual" != "$expected" ]; then
    echo "::error::helm-docs checksum mismatch for ${platform}" >&2
    echo "  expected $expected" >&2
    echo "  actual   $actual" >&2
    echo "  from     $url" >&2
    exit 1
  fi

  tar -xzf "$archive" -C "$tmpdir" helm-docs
  helm_docs="$tmpdir/helm-docs"
fi

"$helm_docs" --chart-search-root charts

if ! git diff --exit-code -- charts/pgroles-operator/README.md; then
  echo "::error::charts/pgroles-operator/README.md is out of date. Regenerate with: helm-docs --chart-search-root charts"
  exit 1
fi
