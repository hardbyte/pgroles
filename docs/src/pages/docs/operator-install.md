---
title: Install the operator
description: Install the pgroles operator with Helm, configure the chart, and manage CRD upgrades.
---

Getting the pgroles operator running in your cluster, and the chart values that matter. {% .lead %}

---

## Installation

## Helm

```shell
helm install pgroles-operator oci://ghcr.io/hardbyte/charts/pgroles-operator
```

## Rust crate

Add the operator crate from crates.io:

```shell
cargo add pgroles-operator
```

If you are embedding the reconciler or CRD types directly from source, depend on the repository in your `Cargo.toml`:

```toml
[dependencies]
pgroles-operator = { git = "https://github.com/hardbyte/pgroles" }
```

## Configuration

Key values you can override:

```yaml
# values.yaml
operator:
  image:
    repository: ghcr.io/hardbyte/pgroles-operator
    tag: ""  # defaults to Chart.appVersion

  env:
    - name: RUST_LOG
      value: "info,pgroles_operator=debug"

  # Required for GKE Workload Identity — see Database connection below.
  serviceAccount:
    annotations: {}

  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
```

The operator runs as `nobody` (UID 65534) with a read-only root filesystem, no capabilities, and seccomp enabled by default.

The chart ships CRDs in `charts/pgroles-operator/crds/`, so Helm installs them
on `helm install` and — by Helm's design — does **not** update them on
`helm upgrade`. Apply CRD changes yourself before upgrading the chart. To manage
CRDs out of band entirely, install with `--skip-crds`.

The Deployment is fixed at a single replica with a `Recreate` strategy and the
chart exposes no replica count. Per-database advisory locks make the operator
safe to run with more than one replica, but running multiple replicas today
requires patching the Deployment.

## Operational guidance

- Use one `PostgresPolicy` per database and credential boundary.
- Prefer a dedicated management role rather than an application login for reconciliation.
- Ensure the management role can grant every wildcard-managed privilege on every matching object, either by owning those objects or holding the required `WITH GRANT OPTION`.
- Validate and review the manifest with the CLI before handing it to the operator.
- Treat deletion as "stop managing", not "revert the database".
