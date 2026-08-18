#!/usr/bin/env bash
# Render the chart-less Kyverno manifests in k8s/security/ for one install.
#
# The plan-decision policy exempts the operator's own status writes by
# authenticated ServiceAccount username. That username is install-specific, so
# the manifest carries a placeholder instead of a default: a default names the
# operator of some *other* install, and exempting a ServiceAccount this cluster
# does not run the operator as hands the approve-verb bypass to anyone who can
# create that account.
#
# Rendering is therefore mandatory, and this script fails rather than emit a
# manifest whose exemption is still a placeholder or names an empty subject.
# Chart installs do the same substitution from `operator.serviceAccount.name`
# and the release namespace.
#
# Usage:
#   scripts/render-kyverno-policies.sh \
#     --namespace pgroles-system --service-account pgroles-operator \
#     [manifest ...] > policies.yaml
set -euo pipefail

placeholder="__PGROLES_OPERATOR_SUBJECT__"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

namespace=""
service_account=""
manifests=()

usage() {
  # The header comment block, minus the shebang, is the help text.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' \
    "${BASH_SOURCE[0]}" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --namespace)
      namespace="${2-}"
      shift 2 || true
      ;;
    --service-account)
      service_account="${2-}"
      shift 2 || true
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "::error::unknown option $1" >&2
      usage
      exit 2
      ;;
    *)
      manifests+=("$1")
      shift
      ;;
  esac
done

if [ "${#manifests[@]}" -eq 0 ]; then
  manifests=(
    "$repo_root/k8s/security/plan-decision-kyverno.yaml"
    "$repo_root/k8s/security/ephemeral-access-kyverno.yaml"
  )
fi

# A ServiceAccount subject is only meaningful if both halves are real names.
# An empty half renders `system:serviceaccount::name`, which matches no
# authenticated user and would silently un-exempt the operator.
dns1123='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
if [[ ! "$namespace" =~ $dns1123 ]]; then
  echo "::error::--namespace must be a DNS-1123 label; got '${namespace}'" >&2
  usage
  exit 2
fi
if [[ ! "$service_account" =~ $dns1123 ]]; then
  echo "::error::--service-account must be a DNS-1123 label; got '${service_account}'" >&2
  usage
  exit 2
fi

subject="system:serviceaccount:${namespace}:${service_account}"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

first=true
for manifest in "${manifests[@]}"; do
  if [ ! -f "$manifest" ]; then
    echo "::error::no such manifest: ${manifest}" >&2
    exit 1
  fi
  if [ "$first" = true ]; then
    first=false
  else
    echo "---" >>"$rendered"
  fi
  sed "s|${placeholder}|${subject}|g" "$manifest" >>"$rendered"
done

# The output is an authorization control: emitting it half-substituted would
# ship an exemption keyed on a literal that no request can ever match.
if grep -qF "$placeholder" "$rendered"; then
  echo "::error::rendered output still contains ${placeholder}" >&2
  exit 1
fi

cat "$rendered"
