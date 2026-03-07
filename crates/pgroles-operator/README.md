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

Library:

```toml
[dependencies]
pgroles-operator = "<current-release>"
```

Binary:

```bash
cargo install pgroles-operator
```

## Intended Audience

- Contributors working on the operator implementation
- Platform teams evaluating the Kubernetes reconciliation model

Operator docs: <https://hardbyte.github.io/pgroles/docs/operator>
