---
title: 7. Membership mechanics
description: Explore nested role membership, automatic inheritance, SET ROLE, and delegated membership administration.
---

The core Acme story needed only one membership edge and one migration recipe. Now inspect the machinery underneath: nested roles, automatic privilege flow, deliberate role switching, and delegation. {% .lead %}

## Follow one directed graph

```text
alice (LOGIN)
      │ member of
      ▼
analyst (NOLOGIN)
      │ member of
      ▼
orders_reader (NOLOGIN) ──> schema USAGE + table SELECT
```

Read `GRANT orders_reader TO analyst` as **analyst becomes a member of orders_reader**. Reversing the names reverses the privilege flow.

{% postgres-role-hierarchy-lab /%}

## Declare the edges

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: alice
    login: true
  - name: analyst
  - name: orders_reader

memberships:
  - role: orders_reader
    members:
      - name: analyst
  - role: analyst
    members:
      - name: alice
        inherit: false
      - name: team_lead
        inherit: false
        admin: true
```

`INHERIT` answers whether ordinary privileges flow automatically. `SET` answers whether the member may become the granted role. `ADMIN` answers whether the member may grant or revoke that membership for others. These are three separate facts.

{% callout type="warning" title="SET is outside the pgroles model" %}
PostgreSQL 16 and later stores `INHERIT`, `SET`, and `ADMIN` per membership. pgroles manages `inherit` and `admin`, but does not inspect or converge `SET`. A managed edge receives PostgreSQL’s default `SET TRUE`; do not rely on `SET FALSE` remaining a security boundary on that edge.
{% /callout %}

Delegated administration and desired-state reconciliation also answer different questions. A team lead may grant a membership in PostgreSQL; if that edge is absent from policy, the next authoritative pgroles plan treats it as drift.

{% quick-links %}
{% quick-link title="Continue: security review" description="Audit PUBLIC, SECURITY DEFINER, and delegated grant options." icon="lightbulb" href="/docs/postgresql-security-review" /%}
{% quick-link title="Memberships reference" description="See the complete policy and version behavior." icon="presets" href="/docs/memberships" /%}
{% /quick-links %}
