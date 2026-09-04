#!/usr/bin/env bash
# A PostgresPolicy declaring exactly what generate-acl-burst-sql.sh seeded, so
# the first reconcile finds the database already converged and its cost is the
# inspection rather than the apply.
#
# The roles are shared across every schema on purpose. Profiles scope a role to
# one schema, which keeps the ACL row count linear in schemas; a role granted
# in every schema makes it the product and exercises the high-cardinality ACL
# inspection path this fixture is intended to measure.
set -euo pipefail

policy_name="${1:?policy name}"
secret_name="${2:?secret name}"
schema_prefix="${3:?schema prefix}"
schema_count="${4:?schema count}"
role_prefix="${5:?role prefix}"
role_count="${6:?role count}"
output_path="${7:-/dev/stdout}"

{
  cat <<YAML
---
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: ${policy_name}
  namespace: default
spec:
  connection:
    secretRef:
      name: ${secret_name}
  interval: "5m"
  mode: apply
  approval: auto
  default_owner: postgres

  schemas:
YAML

  for s in $(seq -w 1 "${schema_count}"); do
    echo "    - name: ${schema_prefix}_${s}"
  done

  echo "  roles:"
  for r in $(seq -w 1 "${role_count}"); do
    cat <<YAML
    - name: ${role_prefix}_${r}
      login: false
YAML
  done

  echo "  grants:"
  for r in $(seq -w 1 "${role_count}"); do
    for s in $(seq -w 1 "${schema_count}"); do
      cat <<YAML
    - role: ${role_prefix}_${r}
      privileges: [USAGE]
      object: { type: schema, name: ${schema_prefix}_${s} }
    - role: ${role_prefix}_${r}
      privileges: [EXECUTE]
      object: { type: function, schema: ${schema_prefix}_${s}, name: "*" }
YAML
    done
  done
} > "${output_path}"
