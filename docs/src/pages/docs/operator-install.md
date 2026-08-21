---
title: Install the operator
description: Install the pgroles operator with Helm, configure the chart, and manage CRD upgrades.
---

Getting the pgroles operator running in your cluster, and the chart values that matter. {% .lead %}

---

For a complete first reconciliation, including a connection Secret, safe
additive policy, SQL review, and manual approval, use the
[operator quick start](/docs/operator-quick-start).

## Helm

```shell
helm install pgroles-operator oci://ghcr.io/thepartly/charts/pgroles-operator
```

## Embed the Rust library

This is not an alternative way to run the operator. If you are building a Rust
program which embeds its reconciler or CRD types, add the library crate from
crates.io:

```shell
cargo add pgroles-operator
```

To depend on the current repository source instead:

```toml
[dependencies]
pgroles-operator = { git = "https://github.com/thepartly/pgroles" }
```

## Configuration

Key values you can override:

```yaml
# values.yaml
operator:
  # Set this to avoid cluster-wide watches and grant only namespaced RBAC.
  watchNamespace: ""

  image:
    repository: ghcr.io/thepartly/pgroles-operator
    tag: ""  # defaults to Chart.appVersion

  env:
    - name: RUST_LOG
      value: "info,pgroles_operator=debug"

  # Required for GKE Workload Identity — see the Database connections page.
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

Set `operator.watchNamespace` when one operator instance should reconcile only
one namespace. The chart then configures `WATCH_NAMESPACE` and installs a
namespaced `Role` and `RoleBinding` instead of cluster-wide RBAC. Leave it empty
for the default cluster-wide deployment.

See [Database connections](/docs/operator-connections) for URL Secrets,
structured parameters, and GKE Workload Identity configuration.

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
