---
title: 8. The security review
description: "Audit three effective-access surprises: PUBLIC function execution, SECURITY DEFINER, and grant-option delegation."
---

An auditor asks a harder question than “what grants are in our YAML?”: **can this role actually perform the operation?** Acme’s role graph is tidy, but PostgreSQL has access paths outside ordinary named ACLs. {% .lead %}

{% postgres-security-review-lab /%}

## Close the PUBLIC path explicitly

PostgreSQL gives `PUBLIC`—every role—`EXECUTE` on new functions by default. State both desired absences so existing and future functions converge:

```yaml {% schema="pgroles-manifest" %}
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: billing_api, name: "*" }

default_privileges:
  - owner: app_owner
    scope: { type: global }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
```

The global default matters because PostgreSQL’s built-in function default is global. A schema-scoped revoke cannot subtract a global grant.

## Keep the other two boundaries visible

A `SECURITY DEFINER` function is an intentional privilege boundary. Review its owner, body, fixed `search_path`, callable surface, and `PUBLIC` exposure. pgroles manages who may execute the function; it does not prove the function body is safe.

`WITH GRANT OPTION` lets an application grantee delegate an object privilege. pgroles checks whether its executor can grant wildcard privileges safely, but it does not model or converge grant options held by application roles. Audit and manage that boundary separately.

**Desired ACLs are necessary; effective-access tests tell you whether every other path agrees with them.**

{% quick-links %}
{% quick-link title="Open the Acme playground" description="Investigate the finished database with any role and any SQL." icon="lightbulb" href="/docs/postgresql-playground" /%}
{% quick-link title="Limits and boundaries" description="Review unmanaged column grants, grant options, and effective access." icon="plugins" href="/docs/limitations" /%}
{% /quick-links %}
