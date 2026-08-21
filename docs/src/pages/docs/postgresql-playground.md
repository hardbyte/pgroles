---
title: The Acme playground
description: Explore the complete Acme database with arbitrary SQL and challenge prompts.
---

The whole Acme database is yours: durable ownership, capability roles, defaults, application logins, and the security-review function. There is no scripted finish. Choose a role, change the query, and follow the evidence. {% .lead %}

{% postgres-acme-playground /%}

## A practical audit loop

1. Name the exact operation and starting role.
2. Run the operation instead of inferring it from one catalog row.
3. Trace every surviving path: membership, schema and object ACLs, ownership, `PUBLIC`, functions, and delegation.
4. Compare PostgreSQL with the desired pgroles graph.
5. Review the plan, apply it, and repeat the operation as a positive or negative test.

The [grants](/docs/grants), [memberships](/docs/memberships), [default privileges](/docs/default-privileges), and [limitations](/docs/limitations) pages are the exhaustive reference. This course stays focused on the operational story that makes those mechanisms worth remembering.
