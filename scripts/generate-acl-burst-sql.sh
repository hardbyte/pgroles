#!/usr/bin/env bash
# Seed one database with the object shape that makes a reconcile expensive to
# *read*: many functions, in many schemas, each granted to many roles.
#
# Inspection cost is one `aclexplode` row per function per grantee, so rows
# are schemas x functions x roles. The grants are pre-seeded here rather than
# left for the operator to apply, because this fixture exists to size the
# inspection, not the apply — a policy that converges on its first pass still
# reads the whole inventory, which is the allocation being measured.
#
# Roles are created here too, so the policy adopts existing roles instead of
# spending its first reconcile creating them.
set -euo pipefail

schema_prefix="${1:?schema prefix}"
schema_count="${2:?schema count}"
function_count="${3:?functions per schema}"
role_prefix="${4:?role prefix}"
role_count="${5:?role count}"

echo "BEGIN;"

for r in $(seq -w 1 "${role_count}"); do
  role="${role_prefix}_${r}"
  # DO block rather than CREATE ROLE IF NOT EXISTS, which PostgreSQL has no
  # spelling for.
  cat <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN
    CREATE ROLE "${role}" NOLOGIN;
  END IF;
END \$\$;
SQL
done

for s in $(seq -w 1 "${schema_count}"); do
  schema="${schema_prefix}_${s}"
  echo "CREATE SCHEMA IF NOT EXISTS \"${schema}\";"
  for f in $(seq -w 1 "${function_count}"); do
    # Trivial bodies: the ACL entry is the payload, not the function.
    echo "CREATE OR REPLACE FUNCTION \"${schema}\".fn_${f}(input integer) RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT input';"
  done
  for r in $(seq -w 1 "${role_count}"); do
    role="${role_prefix}_${r}"
    echo "GRANT USAGE ON SCHEMA \"${schema}\" TO \"${role}\";"
    echo "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA \"${schema}\" TO \"${role}\";"
  done
done

echo "COMMIT;"
