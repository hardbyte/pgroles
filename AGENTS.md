# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Build & Test Commands

```bash
# Build (SQLX_OFFLINE=true needed when no live database is available)
SQLX_OFFLINE=true cargo build --workspace

# Format + lint (always run before committing)
cargo fmt --all
SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings

# Unit tests (no database needed)
cargo test --workspace

# Integration tests (requires live PostgreSQL)
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
cargo test --workspace -- --include-ignored

# Run a single test
cargo test -p pgroles-core --lib diff::tests::diff_creates_new_roles -- --exact

# CRD drift check (CI enforces k8s/crd.yaml matches crdgen output)
cargo run --bin crdgen > /tmp/crd-generated.yaml && diff k8s/crd.yaml /tmp/crd-generated.yaml

# Regenerate CRD after modifying crd.rs
cargo run --bin crdgen > k8s/crd.yaml
```

### Local PostgreSQL for integration tests

```bash
docker run --rm --name pgroles-pg16 \
  -e POSTGRES_PASSWORD=testpassword \
  -e POSTGRES_DB=pgroles_test \
  -p 5432:5432 \
  postgres:16
```

## Architecture

### Data Pipeline

```
YAML → parse_manifest() → PolicyManifest
     → expand_manifest() → ExpandedManifest (profiles × schemas resolved)
     → RoleGraph::from_expanded() → RoleGraph (desired)

DB   → inspect() → RoleGraph (current)
     → detect_pg_version() → SqlContext

diff(current, desired) → Vec<Change> → sql::render_all_with_context() → SQL
```

### Workspace Crates

- **pgroles-core** — Pure library, no IO. Manifest parsing, profile expansion, diff engine, SQL rendering, manifest export. All collections use `BTreeMap`/`BTreeSet` for deterministic output.
- **pgroles-inspect** — Async database introspection via `sqlx`/`pg_catalog`. Version detection, cloud provider detection (RDS, Cloud SQL, AlloyDB, Azure), drop-role safety preflight.
- **pgroles-cli** — Binary crate. Thin orchestration over core + inspect. Subcommands: `validate`, `diff`/`plan`, `apply`, `inspect`, `generate`.
- **pgroles-operator** — Kubernetes operator (WIP). Reconciles `PostgresPolicy` CRDs (`pgroles.io/v1alpha1`). Has a `crdgen` binary for generating `k8s/crd.yaml`.
  - Health endpoints: `/livez`, `/readyz`
  - Metrics/telemetry: prefer OTLP export via OpenTelemetry Collector; do not add a built-in Prometheus scrape endpoint by default unless the change explicitly requires it.

### Diff Change Ordering

`diff()` assembles changes in dependency order: creates → alters/comments → grants → default privileges → membership removes → membership adds → default privilege revocations → revocations → drops. Retirement steps (terminate sessions, reassign owned, drop owned) are inserted immediately before the matching `DropRole` by `apply_role_retirements()`. `apply` executes the whole plan in a single transaction.

## CI

Four jobs in `.github/workflows/ci.yml`:
1. **Lint** — `cargo fmt --check`, `clippy -D warnings`, CRD drift check
2. **Unit Tests** — `cargo test --workspace`
3. **Integration Tests** — PG 16/17/18 matrix, `cargo test --workspace -- --include-ignored`
4. **E2E** — kind cluster, deploys operator plus an OpenTelemetry Collector, runs happy-path plus conflict/invalid/missing-secret/insufficient-privilege/secret-rotation operator scenarios, verifies roles in database, and verifies OTLP metrics export

## Release and Containers

- Published container images are multi-arch for `linux/amd64` and `linux/arm64`.
- `.github/workflows/release.yml` builds Linux binaries first, then assembles container images from those artifacts using `docker/Dockerfile.runtime`.
- `docker/Dockerfile` remains the source-build path for local Docker builds and any CI path that needs to compile from the repository contents.
- Keep `docker/Dockerfile` package-scoped (`--package pgroles-cli` / `--package pgroles-operator`) and preserve the BuildKit cache mounts for Cargo registry, git, and target directories.
- If you change binary names, targets, or release packaging, update both `build-binaries` and `docker/Dockerfile.runtime` together.
