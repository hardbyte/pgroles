---
title: Quick start
description: Install pgroles and run your first manifest against a PostgreSQL database.
---

Get up and running with pgroles in a few minutes. {% .lead %}

---

## Prerequisites

- **PostgreSQL 16+** (pgroles uses `GRANT ... WITH INHERIT` syntax from PG 16)
- **Rust toolchain** (for building from source)

## Installation

Build from source using Cargo:

```shell
cargo install --git https://github.com/hardbyte/pgroles pgroles-cli
```

This installs the `pgroles` binary.

## Create a manifest

Create a file called `pgroles.yaml`:

```yaml
default_owner: app_owner

roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"

grants:
  - role: analytics
    privileges: [CONNECT]
    on: { type: database, name: mydb }
  - role: analytics
    privileges: [USAGE]
    on: { type: schema, name: public }
  - role: analytics
    privileges: [SELECT]
    on: { type: table, schema: public, name: "*" }
```

## Validate the manifest

Check the manifest is valid without connecting to a database:

```shell
pgroles validate
```

```
Manifest is valid.
  1 role(s) defined
  3 grant(s) defined
  0 default privilege(s) defined
  0 membership(s) defined
```

## Plan changes

See what SQL would be generated against a live database:

```shell
pgroles diff --database-url postgres://localhost/mydb
```

This shows the exact SQL statements needed to converge the database to match your manifest.

{% callout title="No changes are made" %}
The `diff` command (also available as `plan`) is read-only. It connects to your database to inspect the current state but does not execute any changes.
{% /callout %}

## Apply changes

When you're happy with the plan, apply it:

```shell
pgroles apply --database-url postgres://localhost/mydb
```

Or preview without executing:

```shell
pgroles apply --database-url postgres://localhost/mydb --dry-run
```

## Using environment variables

Instead of passing `--database-url` every time, set the `DATABASE_URL` environment variable:

```shell
export DATABASE_URL=postgres://localhost/mydb
pgroles diff
pgroles apply
```
