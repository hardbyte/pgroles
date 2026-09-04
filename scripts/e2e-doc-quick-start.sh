#!/usr/bin/env bash
# Run the complete policy example from the operator quick start against the
# disposable setup-e2e cluster. Do not maintain a second copy of the manifest.
set -euo pipefail
policy_file="$(mktemp)"
cleanup() {
  kubectl delete pgr quick-start -n pgroles-quick-start --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete namespace pgroles-quick-start --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl exec postgres-0 -- psql -U postgres -d docs_quickstart -c 'DROP OWNED BY pgroles_quickstart_reader' >/dev/null 2>&1 || true
  kubectl exec postgres-0 -- psql -U postgres -d postgres -c 'DROP DATABASE IF EXISTS docs_quickstart' >/dev/null 2>&1 || true
  kubectl exec postgres-0 -- psql -U postgres -d postgres -c 'DROP ROLE IF EXISTS pgroles_quickstart_reader' >/dev/null 2>&1 || true
  rm -f "$policy_file"
}
trap cleanup EXIT
python3 - "$policy_file" <<'PY'
import re, sys
from pathlib import Path
page = Path('docs/src/pages/docs/operator-quick-start.md').read_text()
blocks = [b for b in re.findall(r'```yaml\n(.*?)\n```', page, re.S) if 'kind: PostgresPolicy\n' in b]
assert len(blocks) == 1, 'expected one complete quick-start policy'
assert 'object: { type: database, name: app }' in blocks[0]
Path(sys.argv[1]).write_text(blocks[0].replace('name: app }', 'name: docs_quickstart }'))
PY
kubectl exec postgres-0 -- psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c 'CREATE DATABASE docs_quickstart'
kubectl create namespace pgroles-quick-start
kubectl create secret generic quick-start-database -n pgroles-quick-start \
  --from-literal=DATABASE_URL=postgres://postgres:devpassword@postgres.default.svc.cluster.local:5432/docs_quickstart
kubectl apply -f "$policy_file"
kubectl wait -n pgroles-quick-start --for=condition=Ready pgr/quick-start --timeout=120s
plan="$(kubectl get pgr quick-start -n pgroles-quick-start -o jsonpath='{.status.current_plan_ref.name}')"
test -n "$plan"
phase="$(kubectl get pgplan "$plan" -n pgroles-quick-start -o jsonpath='{.status.phase}')"
test "$phase" = Pending
sql="$(kubectl get pgplan "$plan" -n pgroles-quick-start -o jsonpath='{.status.sqlInline}')"
[[ "$sql" == *'CREATE ROLE'* && "$sql" == *'GRANT CONNECT'* ]]
[[ "$sql" != *REVOKE* && "$sql" != *'DROP '* ]]
kubectl patch pgplan "$plan" -n pgroles-quick-start --subresource=status --type=merge -p \
  "{\"status\":{\"conditions\":[{\"type\":\"Approved\",\"status\":\"True\",\"reason\":\"DocsSmokeTest\",\"lastTransitionTime\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}],\"decidedBy\":{\"username\":\"$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')\"}}}"
kubectl wait -n pgroles-quick-start --for=jsonpath='{.status.phase}'=Applied "pgplan/$plan" --timeout=120s
kubectl wait -n pgroles-quick-start --for=condition=Drifted=false pgr/quick-start --timeout=120s
result="$(kubectl exec postgres-0 -- psql -U postgres -d docs_quickstart -At -c "SELECT has_database_privilege('pgroles_quickstart_reader','docs_quickstart','CONNECT')")"
test "$result" = t
