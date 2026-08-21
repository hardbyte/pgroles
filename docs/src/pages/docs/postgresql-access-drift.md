---
title: 3. Access drift
description: Add Bob, remove Alice, and discover why revoking one membership does not prove effective access is gone.
---

Bob joins reporting and Alice moves to another team. The role hierarchy makes the intended change obvious: add Bob to `orders_reader`, remove Alice. The database has a longer memory. {% .lead %}

{% postgres-access-drift-lab /%}

## Desired state turns the surprise into a plan

The policy already says Alice is no longer a member and contains no direct Alice grants:

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: alice
    login: true
  - name: bob
    login: true
  - name: reporting_app
    login: true
  - name: orders_reader

grants:
  - role: orders_reader
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: orders_reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: orders }

memberships:
  - role: orders_reader
    members:
      - name: bob
      - name: reporting_app
```

An authoritative `pgroles plan` compares that graph with PostgreSQL. Alice’s old `USAGE` and `SELECT` appear as revocations instead of remaining invisible history. Review the exact SQL, then apply it as one transaction.

**Revoking one edge proves only that the edge is gone. Test the operation to prove effective access is gone.**

{% callout type="note" title="Negative tests belong in offboarding" %}
PGlite can prove the authorization result, but it does not model passwords, `pg_hba.conf`, concurrent sessions, or session termination. In production, revoke durable authorization, terminate sessions when required, and verify both.
{% /callout %}

{% quick-links %}
{% quick-link title="Continue: ownership" description="Let Acme's migration login collide with a founder-owned table." icon="installation" href="/docs/postgresql-ownership" /%}
{% quick-link title="Staged adoption" description="Choose additive or authoritative reconciliation deliberately." icon="presets" href="/docs/adoption" /%}
{% /quick-links %}
