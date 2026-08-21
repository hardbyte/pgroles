---
title: 2. Capability roles
description: Replace copied grants with an orders_reader capability role and expose Alice's duplicate access path.
---

Acme launches an automated reporting service. It needs exactly the access Alice already has, but copying Alice’s grants onto another login will make every team change harder to audit. {% .lead %}

{% postgres-capability-roles-lab /%}

## Put privileges on jobs, not people

`orders_reader` cannot log in. It names one capability: reach `app`, then read `app.orders`. Alice and `reporting_app` receive that capability through membership.

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: alice
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
      - name: alice
      - name: reporting_app
```

The lesson deliberately left Alice’s original direct grants in the database. The desired policy no longer declares them. That difference becomes the bug in the next chapter—and the reason a declarative plan is more useful than a pile of successful `GRANT` statements.

**A membership adds a path; it does not erase any path that already exists.**

{% quick-links %}
{% quick-link title="Continue: drift" description="Change the team and watch an old direct grant defeat the intended offboarding." icon="lightbulb" href="/docs/postgresql-access-drift" /%}
{% quick-link title="Memberships reference" description="See pgroles membership syntax and reconciliation behavior." icon="presets" href="/docs/memberships" /%}
{% /quick-links %}
