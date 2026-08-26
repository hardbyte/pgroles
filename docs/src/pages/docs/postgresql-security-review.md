---
title: 8. The security review
description: "Audit four effective-access surprises: PUBLIC function execution, SECURITY DEFINER, grant-option delegation, and the predefined master-key roles."
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

## The predefined master keys

`pg_read_all_data`, `pg_write_all_data`, `pg_monitor`, and the other [predefined roles](https://www.postgresql.org/docs/current/predefined-roles.html) pass PostgreSQL’s permission checks for every matching object—current and future—without an ACL entry anywhere, so no table-level review will surface them. Auditing effective access therefore always includes one more query: who is a member of a `pg_*` role?

pgroles can make the answer policy. A membership stanza may name a predefined role directly; declared members converge, and `exclusive: true` asserts that the member list is complete, revoking anyone else:

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: auditor
    login: true

memberships:
  - role: pg_read_all_data
    exclusive: true
    members:
      - name: auditor
```

Without `exclusive`, undeclared members are left untouched—cloud platforms grant `pg_*` memberships to their own management roles, and adopting pgroles must not strip them. Even with `exclusive`, members that are themselves predefined roles are never revoked, so PostgreSQL’s built-in `pg_*` hierarchy stays intact. `pgroles inspect` reports every `pg_*` membership informationally either way, so the master keys are visible before anyone opts into managing them.

## Keep the other two boundaries visible

A `SECURITY DEFINER` function is an intentional privilege boundary. Review its owner, body, fixed `search_path`, callable surface, and `PUBLIC` exposure. pgroles manages who may execute the function; it does not prove the function body is safe.

`WITH GRANT OPTION` lets an application grantee delegate an object privilege. pgroles checks whether its executor can grant wildcard privileges safely, but it does not model or converge grant options held by application roles. Audit and manage that boundary separately. Delegation also constrains cleanup: PostgreSQL's [`REVOKE`](https://www.postgresql.org/docs/current/sql-revoke.html) removes only grants attributable to the executor, so a delegated grant survives a revoke run by anyone who cannot act as the delegate — silently for object privileges, with only a `WARNING` for role memberships. Removing it means revoking the delegate's grant option with `CASCADE`, or revoking `GRANTED BY` the delegate with that role's privileges.

One more finding costs nothing to write down: Acme’s application still connects with the founder-era admin credentials, and a superuser bypasses every check in this chapter. No grant, policy, or RLS rule constrains that connection—pgroles cannot manage it away. Moving the application onto a scoped login, the way `reporting_app` was built in chapter 2, is the remediation an auditor will ask for first.

**Desired ACLs are necessary; effective-access tests tell you whether every other path agrees with them.**

{% quick-links %}
{% quick-link title="Open the Acme playground" description="Investigate the finished database with any role and any SQL." icon="lightbulb" href="/docs/postgresql-playground" /%}
{% quick-link title="Limits and boundaries" description="Review unmanaged column grants, grant options, and effective access." icon="plugins" href="/docs/limitations" /%}
{% /quick-links %}
