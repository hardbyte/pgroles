---
title: Troubleshooting the operator
description: "Diagnosing a PostgresPolicy that is not converging: insufficient privileges, missing objects, and stuck plans."
---

Symptom, cause, fix. {% .lead %}

---

## Insufficient privileges

If the operator can connect to PostgreSQL but the management role cannot inspect or apply the requested changes, the policy settles to a non-ready state instead of hot-looping as if the failure were transient.

Current behavior:

- `Ready=False`
- `Degraded=True`
- reason `InsufficientPrivileges`
- `last_error` contains the PostgreSQL error message, for example `permission denied to create role`
- the policy retries on its normal reconcile interval rather than exponential transient backoff

This is the expected state when the database credential is valid but under-privileged for the requested manifest.

## Missing database object

Before issuing any DDL, the operator validates that every externally referenced
schema exists in the target database. A schema declared in `spec.schemas` is
excluded from this check because the operator creates it; schemas referenced
only by top-level grants or default privileges must already exist. If one of
those is missing, the apply is aborted up front and the policy settles into a
non-ready state with a clear message.

- `Ready=False`
- `Degraded=True`
- reason `MissingDatabaseObject`
- `last_error` lists the missing objects, e.g. `policy references objects that do not exist in target database: schema "etl". Either create the missing objects, remove them from the policy, or verify the policy is pointing at the intended database.`
- the policy retries on its normal reconcile interval rather than exponential transient backoff

This catches common misconfigurations like a grant which names an undeclared,
missing schema, or a policy pointed at the wrong database. Declare a schema in
`spec.schemas` when the operator should create and own it. As a fallback, the
same reason is also produced when a SQL-level error with PostgreSQL codes
`3F000` (invalid_schema_name), `42P01` (undefined_table), `42883`
(undefined_function), or `42704` (undefined_object) slips past the pre-flight
validator.
