---
title: Getting started
pageTitle: pgroles - Declarative PostgreSQL role management
description: One YAML file. Every role, grant, and privilege in your database — defined, diffed, and applied.
---

One YAML file. Every role, grant, and privilege in your database — defined, diffed, and applied. {% .lead %}

---

## Why pgroles?

Managing PostgreSQL roles and privileges across environments is error-prone. Teams typically resort to ad-hoc SQL scripts, manual `GRANT` statements, or fragile migration files. When a new schema is added or a role needs adjusting, it's easy to miss a grant or leave stale privileges in place.

pgroles takes a **convergent, declarative approach**: you define the desired state in a YAML manifest, and pgroles computes the exact SQL needed to bring your database in line. Anything in the database but not in the manifest gets revoked or dropped — so your access control never drifts.

Built for platform teams, DBAs, and anyone managing more than a handful of PostgreSQL roles across environments.

## Key features

- **Write privilege rules once**, expand them across every schema automatically via profiles
- **See exactly what will change** before touching the database with `pgroles diff`
- **Convergent diff engine** — the manifest is the entire truth; stale grants get revoked
- **Dry-run mode** to preview generated SQL without executing
- **Default privilege management** so future tables get the right grants automatically
- **Role membership management** with inherit and admin flags
- **Safe drops** — preflight checks block dropping roles with owned objects or active sessions

{% quick-links %}

{% quick-link title="Learn PostgreSQL access" icon="lightbulb" href="/docs/postgresql-access-model" description="Follow Acme from its first grant through roles, drift, ownership, defaults, offboarding, and a security review." /%}

{% quick-link title="CLI quick start" icon="installation" href="/docs/quick-start" description="Install pgroles and run your first diff against a live database." /%}

{% quick-link title="Manifest guide" icon="presets" href="/docs/manifest-format" description="Learn how manifest sections fit together when designing a policy." /%}

{% quick-link title="Profiles & schemas" icon="plugins" href="/docs/profiles" description="Use profiles to define reusable privilege templates across schemas." /%}

{% /quick-links %}
