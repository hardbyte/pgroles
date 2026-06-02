# Multi-service teams example

This example models a shared PostgreSQL database used by multiple teams and services:

- `billing` is owned by the payments team.
- `shipping` is owned by the fulfillment team.
- each service has a migration role that owns its schema objects.
- each service has tightly scoped runtime roles for API and worker/reporting access.
- human users receive read access through team roles instead of one-off grants.

The example is intentionally small, but it exercises the same split used in production deployments:

1. `pgroles.bootstrap.yaml` creates only the migration roles and service schemas needed to run the first migrations.
2. `pgroles.bundle.yaml` composes platform, billing, and shipping policy fragments into the full desired policy.
3. pgroles rejects overlapping ownership before it connects to PostgreSQL.
4. pgroles creates login roles, team roles, schemas, grants, default privileges, and memberships.
5. service migrations run with the service-specific migrator role.
6. application connections use service-specific runtime roles.
7. team users inherit team-level read access without receiving migration or write privileges.

Run it against a disposable local database:

```shell
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
./scripts/test-microservices-example.sh
```

The script applies the bootstrap bundle, runs the billing migration, applies the full bundle once billing tables exist, runs the shipping migration with its cross-service foreign key, reapplies the full bundle so wildcard/default privileges converge over shipping objects, and then verifies positive and negative access checks for every app and team role.
