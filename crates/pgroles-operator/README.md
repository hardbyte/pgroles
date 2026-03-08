# pgroles-operator

Kubernetes operator crate for `pgroles`.

This crate contains the controller, CRD types, and reconciliation logic for
running `pgroles` continuously in Kubernetes against `PostgresPolicy`
resources.

## What It Includes

- `PostgresPolicy` CRD types
- Reconciler and controller wiring
- Status condition updates
- Secret-backed database connectivity
- CRD generation binary (`crdgen`)

## Install

This crate is maintained in-repo. It is publishable and included in the release workflow, but it is not yet available on crates.io in the current released version.

Library from source:

```toml
[dependencies]
pgroles-operator = { git = "https://github.com/hardbyte/pgroles", tag = "v0.1.2" }
```

## Intended Audience

- Contributors working on the operator implementation
- Platform teams evaluating the Kubernetes reconciliation model

Operator docs: <https://hardbyte.github.io/pgroles/docs/operator>
