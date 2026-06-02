#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP_BUNDLE="$ROOT_DIR/examples/microservices/pgroles.bootstrap.yaml"
BUNDLE="$ROOT_DIR/examples/microservices/pgroles.bundle.yaml"

: "${DATABASE_URL:?DATABASE_URL must point at a disposable PostgreSQL database}"

export ALICE_PAYMENTS_PASSWORD="${ALICE_PAYMENTS_PASSWORD:-alice-payments-pass}"
export BOB_FULFILLMENT_PASSWORD="${BOB_FULFILLMENT_PASSWORD:-bob-fulfillment-pass}"
export BILLING_MIGRATOR_PASSWORD="${BILLING_MIGRATOR_PASSWORD:-billing-migrator-pass}"
export BILLING_API_PASSWORD="${BILLING_API_PASSWORD:-billing-api-pass}"
export BILLING_WORKER_PASSWORD="${BILLING_WORKER_PASSWORD:-billing-worker-pass}"
export SHIPPING_MIGRATOR_PASSWORD="${SHIPPING_MIGRATOR_PASSWORD:-shipping-migrator-pass}"
export SHIPPING_API_PASSWORD="${SHIPPING_API_PASSWORD:-shipping-api-pass}"
export SHIPPING_REPORTS_PASSWORD="${SHIPPING_REPORTS_PASSWORD:-shipping-reports-pass}"

PGROLES_BIN="${PGROLES_BIN:-cargo run -q -p pgroles-cli --}"

service_url() {
  local user="$1"
  local password="$2"
  python3 - "$DATABASE_URL" "$user" "$password" <<'PY'
import sys
from urllib.parse import urlsplit, urlunsplit, quote

url, user, password = sys.argv[1:4]
parts = urlsplit(url)
host = parts.hostname or ""
if ":" in host and not host.startswith("["):
    host = f"[{host}]"
netloc = f"{quote(user)}:{quote(password)}@{host}"
if parts.port:
    netloc += f":{parts.port}"
print(urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)))
PY
}

psql_as() {
  local user="$1"
  local password="$2"
  shift 2
  psql "$(service_url "$user" "$password")" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}

expect_sqlstate() {
  local expected_sqlstate="$1"
  local description="$2"
  shift 2

  local stdout stderr status
  stdout="$(mktemp "${TMPDIR:-/tmp}/pgroles-stdout.XXXXXX")"
  stderr="$(mktemp "${TMPDIR:-/tmp}/pgroles-stderr.XXXXXX")"

  set +e
  "$@" >"$stdout" 2>"$stderr"
  status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    echo "::error::Expected SQLSTATE $expected_sqlstate: $description"
    cat "$stdout"
    cat "$stderr"
    rm -f "$stdout" "$stderr"
    exit 1
  fi

  if ! grep -Eq "(^ERROR: +$expected_sqlstate:|SQLSTATE $expected_sqlstate|(^|[^0-9])$expected_sqlstate([^0-9]|$))" "$stderr"; then
    echo "::error::Expected SQLSTATE $expected_sqlstate: $description"
    echo "Command exited with status $status instead"
    cat "$stdout"
    cat "$stderr"
    rm -f "$stdout" "$stderr"
    exit 1
  fi

  rm -f "$stdout" "$stderr"
  echo "SQLSTATE $expected_sqlstate as expected: $description"
}

expect_denied() {
  local description="$1"
  shift
  expect_sqlstate 42501 "$description" "$@"
}

echo "Validating bundles"
$PGROLES_BIN validate --bundle "$BOOTSTRAP_BUNDLE"
$PGROLES_BIN validate --bundle "$BUNDLE"

echo "Bootstrapping migration roles and schemas"
$PGROLES_BIN apply --bundle "$BOOTSTRAP_BUNDLE" --database-url "$DATABASE_URL"

echo "Running billing migration with the billing migrator role"
psql_as billing_migrator "$BILLING_MIGRATOR_PASSWORD" -f "$ROOT_DIR/examples/microservices/migrations/billing.sql"

echo "Applying full policy after billing objects exist"
$PGROLES_BIN apply --bundle "$BUNDLE" --database-url "$DATABASE_URL"

echo "Running shipping migration with the shipping migrator role"
psql_as shipping_migrator "$SHIPPING_MIGRATOR_PASSWORD" -f "$ROOT_DIR/examples/microservices/migrations/shipping.sql"

echo "Reapplying full policy after shipping objects exist"
$PGROLES_BIN apply --bundle "$BUNDLE" --database-url "$DATABASE_URL"

echo "Verifying billing API can write billing data"
psql_as billing_api "$BILLING_API_PASSWORD" -c "INSERT INTO billing.customers (email) VALUES ('buyer@example.com');"
psql_as billing_api "$BILLING_API_PASSWORD" -c "INSERT INTO billing.invoices (customer_id, amount_cents) VALUES (1, 4200);"
psql_as billing_api "$BILLING_API_PASSWORD" -c "UPDATE billing.invoices SET status = 'sent' WHERE id = 1;"
psql_as billing_api "$BILLING_API_PASSWORD" -c "SELECT count(*) FROM billing.invoices;"

echo "Verifying billing worker can update but not insert"
psql_as billing_worker "$BILLING_WORKER_PASSWORD" -c "UPDATE billing.invoices SET status = 'paid' WHERE id = 1;"
expect_denied "billing_worker cannot update customers" \
  psql_as billing_worker "$BILLING_WORKER_PASSWORD" -c "UPDATE billing.customers SET email = 'worker@example.com' WHERE id = 1;"
expect_denied "billing_worker cannot insert invoices" \
  psql_as billing_worker "$BILLING_WORKER_PASSWORD" -c "INSERT INTO billing.invoices (customer_id, amount_cents) VALUES (1, 1000);"

echo "Verifying shipping API can write shipping data"
psql_as shipping_api "$SHIPPING_API_PASSWORD" -c "INSERT INTO shipping.shipments (billing_invoice_id, destination) VALUES (1, 'Auckland');"
expect_sqlstate 23503 "shipping_api cannot create shipment for a missing invoice" \
  psql_as shipping_api "$SHIPPING_API_PASSWORD" -c "INSERT INTO shipping.shipments (billing_invoice_id, destination) VALUES (999999, 'No linked invoice');"
psql_as shipping_api "$SHIPPING_API_PASSWORD" -c "UPDATE shipping.shipments SET status = 'packed' WHERE id = 1;"
psql_as shipping_api "$SHIPPING_API_PASSWORD" -c "SELECT count(*) FROM shipping.shipments;"

echo "Verifying shipping reports are read-only"
psql_as shipping_reports "$SHIPPING_REPORTS_PASSWORD" -c "SELECT count(*) FROM shipping.shipments;"
expect_denied "shipping_reports cannot insert shipments" \
  psql_as shipping_reports "$SHIPPING_REPORTS_PASSWORD" -c "INSERT INTO shipping.shipments (billing_invoice_id, destination) VALUES (1, 'Wellington');"

echo "Verifying team memberships and cross-team isolation"
psql_as alice_payments "$ALICE_PAYMENTS_PASSWORD" -c "SELECT count(*) FROM billing.invoices;"
expect_denied "alice_payments cannot read shipping" \
  psql_as alice_payments "$ALICE_PAYMENTS_PASSWORD" -c "SELECT count(*) FROM shipping.shipments;"
expect_denied "alice_payments cannot write billing" \
  psql_as alice_payments "$ALICE_PAYMENTS_PASSWORD" -c "UPDATE billing.invoices SET status = 'void' WHERE id = 1;"

psql_as bob_fulfillment "$BOB_FULFILLMENT_PASSWORD" -c "SELECT count(*) FROM shipping.shipments;"
expect_denied "bob_fulfillment cannot read billing" \
  psql_as bob_fulfillment "$BOB_FULFILLMENT_PASSWORD" -c "SELECT count(*) FROM billing.invoices;"
expect_denied "bob_fulfillment cannot write shipping" \
  psql_as bob_fulfillment "$BOB_FULFILLMENT_PASSWORD" -c "UPDATE shipping.shipments SET status = 'delivered' WHERE id = 1;"

echo "Verifying cross-service isolation"
expect_denied "billing_api cannot read shipping" \
  psql_as billing_api "$BILLING_API_PASSWORD" -c "SELECT count(*) FROM shipping.shipments;"
expect_denied "shipping_api cannot read billing" \
  psql_as shipping_api "$SHIPPING_API_PASSWORD" -c "SELECT count(*) FROM billing.invoices;"

echo "Microservices example passed"
