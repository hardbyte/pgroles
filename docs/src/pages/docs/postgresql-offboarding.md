---
title: 6. Offboarding an owner
description: Let DROP ROLE expose Priya's remaining objects, then transfer them to app_owner and retire her safely.
---

Priya is leaving Acme. Her application permissions were easy to remove, but one legacy table still belongs to her. PostgreSQL refuses the simple `DROP ROLE`—and that is the clue you need. {% .lead %}

{% postgres-offboarding-lab /%}

## Encode the retirement, not just the absence

Omitting an owned role from desired state says where you want to end. A retirement declares how pgroles can reach that state safely:

```yaml {% schema="pgroles-manifest" %}
retirements:
  - role: priya
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
```

pgroles inspects dependencies before applying a drop. The generated sequence can terminate other sessions, reassign owned objects, remove remaining privileges, and finally drop the role. Review this plan carefully: role retirement is deliberately destructive.

{% callout type="warning" title="The browser cannot prove session termination" %}
PGlite demonstrates ownership dependencies, `REASSIGN OWNED`, `DROP OWNED`, and `DROP ROLE`. It has no pool of authenticated concurrent sessions. In production, verify that old sessions have ended and that the identity provider can no longer authenticate the person.
{% /callout %}

**Offboarding is complete when authentication is disabled, every authorization path is gone, owned objects have a successor, and active sessions are handled.**

{% quick-links %}
{% quick-link title="Advanced: membership mechanics" description="Control automatic inheritance, SET ROLE, and delegated administration." icon="presets" href="/docs/postgresql-role-hierarchy" /%}
{% quick-link title="Role retirement reference" description="Review retirement fields and executor requirements." icon="plugins" href="/docs/manifest-reference#retirements" /%}
{% /quick-links %}
