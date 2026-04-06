#!/usr/bin/env bash
set -euo pipefail

schema_count="${1:-20}"
output_path="${2:-/dev/stdout}"
policy_name="${3:-load-policy}"
secret_name="${4:-postgres-credentials}"
schema_prefix="${5:-load}"

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
  default_owner: postgres

  profiles:
    editor:
      grants:
        - object: { type: schema }
          privileges: [USAGE]
        - object: { type: table, name: "*" }
          privileges: [SELECT, INSERT, UPDATE, DELETE]
        - object: { type: sequence, name: "*" }
          privileges: [USAGE]
      default_privileges:
        - on_type: table
          privileges: [SELECT, INSERT, UPDATE, DELETE]
        - on_type: sequence
          privileges: [USAGE]
    viewer:
      grants:
        - object: { type: schema }
          privileges: [USAGE]
        - object: { type: table, name: "*" }
          privileges: [SELECT]
      default_privileges:
        - on_type: table
          privileges: [SELECT]

  schemas:
YAML

  for i in $(seq -w 1 "${schema_count}"); do
    cat <<YAML
    - name: ${schema_prefix}_${i}
      profiles: [editor, viewer]
YAML
  done
} > "${output_path}"
