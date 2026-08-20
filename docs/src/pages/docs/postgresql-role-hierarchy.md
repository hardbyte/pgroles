---
title: Build and manage a role hierarchy
description: Follow PostgreSQL privileges through nested roles, then control inheritance, SET ROLE, and membership administration.
---

A role hierarchy separates **who connects**, **which job they perform**, and **where object privileges live**. Build one edge at a time, observe what PostgreSQL makes effective, and then translate the graph into pgroles policy. {% .lead %}

## Follow one hierarchy

This lesson keeps object privileges at the leaf and composes them into a job role:

```text
alice (LOGIN)
      |
      | member of
      v
analyst (NOLOGIN)
      |
      | member of
      v
orders_read (NOLOGIN) ──> schema USAGE + table SELECT
```

Read each edge from the granted role to its member: `GRANT orders_read TO analyst` means **analyst is a member of orders_read**. When inheritance is enabled, privileges flow back toward Alice along that path.

{% postgres-role-hierarchy-lab /%}

## Declare the graph in pgroles

The first checkpoint corresponds to two membership edges:

```yaml
roles:
  - name: alice
    login: true
  - name: analyst
  - name: orders_read

memberships:
  - role: orders_read
    members:
      - name: analyst
  - role: analyst
    members:
      - name: alice
```

The defaults are `inherit: true` and `admin: false`. Make a different edge explicit when the hierarchy needs it:

```yaml
memberships:
  - role: analyst
    members:
      - name: alice
        inherit: false
      - name: team_lead
        inherit: false
        admin: true
```

`role` is the capability being granted; each entry under `members` receives that capability. Reversing those names reverses the privilege flow.

## Delegation and reconciliation answer different questions

PostgreSQL `ADMIN TRUE` lets a member grant or revoke membership in the granted role. It does not grant table access, `CREATEROLE`, or ownership.

pgroles then applies a second rule: the declared graph is authoritative. If `team_lead` grants `analyst` to Bob but Bob is absent from the manifest, the next pgroles plan treats that edge as drift and revokes it. Durable delegation therefore needs a workflow that writes the approved membership back to policy.

{% callout type="warning" title="SET is a PostgreSQL boundary outside the pgroles model" %}
PostgreSQL 16 and later stores `INHERIT`, `SET`, and `ADMIN` independently on each membership. pgroles manages `inherit` and `admin`, but does not currently inspect or converge `SET`. Edges created by pgroles receive PostgreSQL's default `SET TRUE`; changing a managed edge can recreate it and restore that default. Do not rely on `SET FALSE` as a security boundary for a pgroles-managed membership.
{% /callout %}

For the full policy syntax and reconciliation behavior, continue to [Memberships](/docs/memberships). To revisit schema and table gates, return to [How PostgreSQL access works](/docs/postgresql-access-model).
