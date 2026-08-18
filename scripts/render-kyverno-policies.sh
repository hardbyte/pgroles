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
# manifest whose exemption is still a placeholder, or names a subject the API
# server could never issue a token for.
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

# The option's value must be present before shifting past it. `shift 2` on a
# single remaining argument fails without advancing $1, which spins the loop.
require_value() {
  if [ "$2" -lt 2 ]; then
    echo "::error::$1 requires a value" >&2
    usage
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --namespace)
      require_value "$1" "$#"
      namespace="$2"
      shift 2
      ;;
    --service-account)
      require_value "$1" "$#"
      service_account="$2"
      shift 2
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

# A subject is only meaningful if both halves name something the API server
# can actually issue a token for. A half that no request can present renders
# an exemption that matches nobody, which silently un-exempts the operator.
#
# The two halves are validated by different rules, as Kubernetes validates
# them: a Namespace is a DNS-1123 label, a ServiceAccount is a DNS-1123
# subdomain, so dots are legal in the account name and not in the namespace.
# Both are length-bounded, because an over-long name is accepted by the
# character class and rejected by the API server.
dns_label='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
dns_subdomain="^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\$"
if [[ ! "$namespace" =~ $dns_label ]] || [ "${#namespace}" -gt 63 ]; then
  echo "::error::--namespace must be a DNS-1123 label of at most 63 characters; got '${namespace}'" >&2
  usage
  exit 2
fi
if [[ ! "$service_account" =~ $dns_subdomain ]] || [ "${#service_account}" -gt 253 ]; then
  echo "::error::--service-account must be a DNS-1123 subdomain of at most 253 characters; got '${service_account}'" >&2
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
