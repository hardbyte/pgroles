---
title: Getting started
pageTitle: pgroles - Declarative PostgreSQL role management
description: Define roles, memberships, object privileges, and default privileges in YAML. pgroles diffs against live databases and applies changes.
---

Manage PostgreSQL roles, grants, and privileges declaratively. {% .lead %}

---

## Why pgroles?

Managing PostgreSQL roles and privileges across environments is error-prone. Teams typically resort to ad-hoc SQL scripts, manual `GRANT` statements, or fragile migration files. When a new schema is added or a role needs adjusting, it's easy to miss a grant or leave stale privileges in place.

pgroles takes a **convergent, declarative approach**: you define the desired state in a YAML manifest, and pgroles computes the exact SQL needed to bring your database in line. Anything in the database not declared in the manifest gets revoked or dropped.

This is the same "infrastructure as code" pattern used by Terraform and Kubernetes, applied to PostgreSQL access control.

## Key features

- **Declarative YAML manifests** with reusable privilege profiles
- **Profile expansion** across schemas to reduce boilerplate
- **Convergent diff engine** that computes minimal changes
- **Safe planning** via `pgroles diff` before applying
- **Dry-run mode** to preview SQL without executing
- **Default privilege management** via `ALTER DEFAULT PRIVILEGES`
- **Role membership management** with inherit/admin flags

{% quick-links %}

{% quick-link title="Quick start" icon="installation" href="/docs/quick-start" description="Install pgroles and run your first diff against a live database." /%}

{% quick-link title="Manifest format" icon="presets" href="/docs/manifest-format" description="Learn the full YAML manifest schema for defining roles and privileges." /%}

{% quick-link title="Profiles & schemas" icon="plugins" href="/docs/profiles" description="Use profiles to define reusable privilege templates across schemas." /%}

{% quick-link title="CLI reference" icon="theming" href="/docs/cli" description="All available commands: validate, diff, apply, and inspect." /%}

{% /quick-links %}
